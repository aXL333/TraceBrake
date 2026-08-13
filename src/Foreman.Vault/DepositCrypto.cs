using System.Security.Cryptography;
using System.Text;

namespace Foreman.Vault;

/// <summary>
/// ECIES (NIST P-256 ECDH -> HKDF-SHA256 -> AES-256-GCM) for the locked-vault DEPOSIT QUEUE. A self-signup that happens
/// while the vault is LOCKED cannot write the encrypted store (no key), so TraceBrake encrypts the freshly-generated
/// credential to the vault's DEPOSIT PUBLIC KEY - held in the clear, usable while locked - and queues the ciphertext.
/// On unlock the matching PRIVATE KEY (sealed inside the vault) decrypts it for operator review. All in-box: no rolled
/// crypto, no new dependency. Each deposit uses a fresh ephemeral keypair + random salt, so deposits are independent and
/// the public key alone can never recover a deposit (asymmetric: encrypt-only while locked).
/// </summary>
public static class DepositCrypto
{
    private const int SchemeVersion = 1;
    private const int NonceBytes = 12, TagBytes = 16, SaltBytes = 16;
    // Domain separation for the HKDF step (bound into key derivation; mismatch -> different key -> AES-GCM auth fails).
    private static readonly byte[] Info = Encoding.UTF8.GetBytes("foreman-vault-deposit/v1");

    /// <summary>One encrypted deposit: scheme version + ephemeral public key + HKDF salt + AES-GCM nonce/ciphertext/tag.</summary>
    public sealed record Envelope(int Version, string EphPubB64, string SaltB64, string NonceB64, string CtB64, string TagB64);

    // AES-GCM associated data: binds the envelope to THIS deposit key (SHA-256 of its SPKI) + the domain/version string,
    // mirroring VaultCrypto's header-as-AAD. An envelope therefore cannot be retargeted to a different deposit key, and a
    // future key rotation (new keypair) invalidates stale envelopes - they authenticate only under the original key.
    private static byte[] Aad(byte[] publicSpki)
    {
        var buf = new byte[Info.Length + publicSpki.Length];
        Buffer.BlockCopy(Info, 0, buf, 0, Info.Length);
        Buffer.BlockCopy(publicSpki, 0, buf, Info.Length, publicSpki.Length);
        return SHA256.HashData(buf);
    }

    /// <summary>Generate the vault's long-lived deposit keypair (P-256). Returns (SPKI public, PKCS#8 private).</summary>
    public static (byte[] PublicSpki, byte[] PrivatePkcs8) GenerateKeyPair()
    {
        using var ec = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        return (ec.ExportSubjectPublicKeyInfo(), ec.ExportPkcs8PrivateKey());
    }

    /// <summary>Encrypt <paramref name="plaintext"/> to the deposit public key. Locked-safe: needs only the public key.</summary>
    public static Envelope Encrypt(byte[] publicSpki, string plaintext)
    {
        using var eph = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var peer = ECDiffieHellman.Create();
        peer.ImportSubjectPublicKeyInfo(publicSpki, out _);

        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
        var shared = eph.DeriveRawSecretAgreement(peer.PublicKey);                          // ECDH shared point (x)
        var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 32, salt, Info);          // -> 32-byte AES-256 key
        Array.Clear(shared);
        var pt = Encoding.UTF8.GetBytes(plaintext);
        try
        {
            var ct = new byte[pt.Length];
            var tag = new byte[TagBytes];
            using var aes = new AesGcm(key, TagBytes);
            aes.Encrypt(nonce, pt, ct, tag, Aad(publicSpki));
            return new Envelope(SchemeVersion,
                Convert.ToBase64String(eph.ExportSubjectPublicKeyInfo()),
                Convert.ToBase64String(salt), Convert.ToBase64String(nonce),
                Convert.ToBase64String(ct), Convert.ToBase64String(tag));
        }
        finally { Array.Clear(key); Array.Clear(pt); }
    }

    /// <summary>Decrypt an envelope with the deposit private key (available only when the vault is unlocked).
    /// Throws <see cref="CryptographicException"/> on a wrong key or any tamper (AES-GCM auth).</summary>
    public static string Decrypt(byte[] privatePkcs8, Envelope env)
    {
        if (env.Version != SchemeVersion)
            throw new NotSupportedException($"unsupported deposit envelope version {env.Version}");
        using var priv = ECDiffieHellman.Create();
        priv.ImportPkcs8PrivateKey(privatePkcs8, out _);
        using var ephPub = ECDiffieHellman.Create();
        ephPub.ImportSubjectPublicKeyInfo(Convert.FromBase64String(env.EphPubB64), out _);

        var shared = priv.DeriveRawSecretAgreement(ephPub.PublicKey);
        var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 32, Convert.FromBase64String(env.SaltB64), Info);
        Array.Clear(shared);
        var nonce = Convert.FromBase64String(env.NonceB64);
        var ct = Convert.FromBase64String(env.CtB64);
        var tag = Convert.FromBase64String(env.TagB64);
        if (nonce.Length != NonceBytes || tag.Length != TagBytes)
            throw new FormatException("corrupt deposit envelope (nonce/tag size)");   // align malformed lines with corruption handling
        var pt = new byte[ct.Length];
        try
        {
            using var aes = new AesGcm(key, TagBytes);
            // AAD = SHA-256(domain ‖ THIS private key's own public SPKI): an envelope encrypted to a different deposit
            // key (or a swapped sidecar key) fails authentication here, not just via the ECDH key mismatch.
            aes.Decrypt(nonce, ct, tag, pt, Aad(priv.ExportSubjectPublicKeyInfo()));   // throws on wrong key / tamper
            return Encoding.UTF8.GetString(pt);
        }
        finally { Array.Clear(key); Array.Clear(pt); }
    }
}
