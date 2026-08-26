using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Konscious.Security.Cryptography;

namespace Foreman.Vault;

/// <summary>
/// The native vault envelope: Argon2id (composite key = master password + TPM-sealed component) → AES-256-GCM (AEAD).
/// We do not roll a cipher — only this small, standard KDF→AEAD envelope. The header (version + KDF params + salt) is
/// bound as AES-GCM associated data, so flipping any of it fails authentication; the params also feed the KDF, so the
/// key changes too (double-bound). Wrong password, wrong key component, or any tamper → <see cref="CryptographicException"/>.
/// </summary>
internal static class VaultCrypto
{
    public const string Magic = "FOREMANVAULT";
    public const int Version = 1;
    private const int KeyBytes = 32, SaltBytes = 16, NonceBytes = 12, TagBytes = 16;
    private const int MemKib = 65536, Iters = 3, Par = 1;   // Argon2id: 64 MiB, 3 passes, 1 lane
    internal const int MaxPlaintextBytes = 8 * 1024 * 1024;
    internal const int MaxEnvelopeBytes = AeadVaultStore.MaxEnvelopeBytes;
    private const int MaxPasswordBytes = 4096;

    private sealed record Envelope(
        string Magic, int Version, string Kdf,
        int MemoryKib, int Iterations, int Parallelism,
        string SaltB64, string NonceB64, string CtB64, string TagB64);

    /// <summary>Both the master password AND the TPM-sealed component are required: password‖component is the Argon2 input.</summary>
    private static byte[] DeriveKey(string masterPassword, byte[] keyComponent, byte[] salt, int memKib, int iters, int par)
    {
        if (memKib != MemKib || iters != Iters || par != Par)
            throw new FormatException("unsupported vault KDF parameters");
        if (salt.Length != SaltBytes) throw new FormatException("corrupt vault salt size");
        if (keyComponent is not { Length: KeyBytes }) throw new FormatException("invalid vault key component size");
        if (Encoding.UTF8.GetByteCount(masterPassword ?? string.Empty) > MaxPasswordBytes)
            throw new FormatException("vault password exceeds the maximum encoded size");
        var pw = Encoding.UTF8.GetBytes(masterPassword ?? string.Empty);
        var input = new byte[pw.Length + (keyComponent?.Length ?? 0)];
        Buffer.BlockCopy(pw, 0, input, 0, pw.Length);
        if (keyComponent is { Length: > 0 }) Buffer.BlockCopy(keyComponent, 0, input, pw.Length, keyComponent.Length);
        try
        {
            using var argon = new Argon2id(input)
            { Salt = salt, MemorySize = memKib, Iterations = iters, DegreeOfParallelism = par };
            return argon.GetBytes(KeyBytes);
        }
        finally { Array.Clear(input); Array.Clear(pw); }
    }

    public static string Encrypt(string plaintextJson, string masterPassword, byte[] keyComponent)
    {
        plaintextJson ??= string.Empty;
        if (Encoding.UTF8.GetByteCount(plaintextJson) > MaxPlaintextBytes)
            throw new InvalidOperationException("vault document exceeds the maximum size");
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
        var key = DeriveKey(masterPassword, keyComponent, salt, MemKib, Iters, Par);
        var pt = Encoding.UTF8.GetBytes(plaintextJson);
        try
        {
            var ct = new byte[pt.Length];
            var tag = new byte[TagBytes];
            using var aes = new AesGcm(key, TagBytes);
            aes.Encrypt(nonce, pt, ct, tag, Aad(salt, MemKib, Iters, Par));
            var env = new Envelope(Magic, Version, "argon2id", MemKib, Iters, Par,
                Convert.ToBase64String(salt), Convert.ToBase64String(nonce),
                Convert.ToBase64String(ct), Convert.ToBase64String(tag));
            return JsonSerializer.Serialize(env);
        }
        finally { Array.Clear(key); Array.Clear(pt); }
    }

    public static string Decrypt(string envelopeJson, string masterPassword, byte[] keyComponent)
    {
        if (envelopeJson is null || Encoding.UTF8.GetByteCount(envelopeJson) > MaxEnvelopeBytes)
            throw new FormatException("vault envelope exceeds the maximum size");
        var env = JsonSerializer.Deserialize<Envelope>(envelopeJson) ?? throw new FormatException("not a vault file");
        if (env.Magic != Magic) throw new FormatException("not a TraceBrake vault file");
        if (env.Version != Version) throw new NotSupportedException($"unsupported vault version {env.Version}");
        if (!string.Equals(env.Kdf, "argon2id", StringComparison.Ordinal) ||
            env.MemoryKib != MemKib || env.Iterations != Iters || env.Parallelism != Par)
            throw new FormatException("unsupported vault KDF parameters");

        RejectOversizedBase64(env.SaltB64, SaltBytes, "salt");
        RejectOversizedBase64(env.NonceB64, NonceBytes, "nonce");
        RejectOversizedBase64(env.TagB64, TagBytes, "tag");
        RejectOversizedBase64(env.CtB64, MaxPlaintextBytes, "ciphertext");

        var salt = Convert.FromBase64String(env.SaltB64);
        var nonce = Convert.FromBase64String(env.NonceB64);
        var ct = Convert.FromBase64String(env.CtB64);
        var tag = Convert.FromBase64String(env.TagB64);
        if (salt.Length != SaltBytes || nonce.Length != NonceBytes || tag.Length != TagBytes || ct.Length > MaxPlaintextBytes)
            throw new FormatException("corrupt vault envelope field size");
        var key = DeriveKey(masterPassword, keyComponent, salt, env.MemoryKib, env.Iterations, env.Parallelism);
        var pt = new byte[ct.Length];
        try
        {
            using var aes = new AesGcm(key, TagBytes);
            aes.Decrypt(nonce, ct, tag, pt, Aad(salt, env.MemoryKib, env.Iterations, env.Parallelism)); // throws on wrong key / tamper
            return Encoding.UTF8.GetString(pt);
        }
        finally { Array.Clear(key); Array.Clear(pt); }
    }

    private static byte[] Aad(byte[] salt, int mem, int iters, int par) =>
        Encoding.UTF8.GetBytes($"{Magic}|{Version}|argon2id|{mem}|{iters}|{par}|{Convert.ToBase64String(salt)}");

    private static void RejectOversizedBase64(string? value, int maxDecodedBytes, string field)
    {
        if (value is null || value.Length > ((maxDecodedBytes + 2L) / 3L) * 4L)
            throw new FormatException($"vault {field} exceeds the maximum size");
    }
}
