using System.Security.Cryptography;
using Foreman.Vault;

namespace Foreman.Vault.Tests;

public sealed class DepositCryptoTests
{
    [Fact]
    public void RoundTrip_PublicEncrypt_PrivateDecrypt()
    {
        var (pub, priv) = DepositCrypto.GenerateKeyPair();
        var env = DepositCrypto.Encrypt(pub, "hunter2");
        Assert.Equal("hunter2", DepositCrypto.Decrypt(priv, env));
    }

    [Fact]   // a deposit encrypted to one vault's public key cannot be read with another vault's private key
    public void WrongPrivateKey_Throws()
    {
        var (pubA, _) = DepositCrypto.GenerateKeyPair();
        var (_, privB) = DepositCrypto.GenerateKeyPair();
        var env = DepositCrypto.Encrypt(pubA, "secret");
        Assert.ThrowsAny<CryptographicException>(() => DepositCrypto.Decrypt(privB, env));
    }

    [Fact]   // AES-GCM authenticates: flipping the tag (or any ciphertext) fails closed
    public void TamperedTag_Throws()
    {
        var (pub, priv) = DepositCrypto.GenerateKeyPair();
        var env = DepositCrypto.Encrypt(pub, "secret");
        var tag = Convert.FromBase64String(env.TagB64);
        tag[0] ^= 0xFF;
        Assert.ThrowsAny<CryptographicException>(
            () => DepositCrypto.Decrypt(priv, env with { TagB64 = Convert.ToBase64String(tag) }));
    }

    [Fact]   // fresh ephemeral keypair + nonce per call, so identical plaintexts produce distinct envelopes
    public void EachEncryption_IsRandomized()
    {
        var (pub, _) = DepositCrypto.GenerateKeyPair();
        var a = DepositCrypto.Encrypt(pub, "same");
        var b = DepositCrypto.Encrypt(pub, "same");
        Assert.NotEqual(a.CtB64, b.CtB64);
        Assert.NotEqual(a.EphPubB64, b.EphPubB64);
    }

    [Fact]   // a future scheme version is rejected with a clear error, not misparsed as tamper
    public void UnsupportedVersion_Throws()
    {
        var (pub, priv) = DepositCrypto.GenerateKeyPair();
        var env = DepositCrypto.Encrypt(pub, "secret");
        Assert.Throws<NotSupportedException>(() => DepositCrypto.Decrypt(priv, env with { Version = 999 }));
    }

    [Fact]
    public void OversizedEncodedCiphertext_IsRejectedBeforeBase64Allocation()
    {
        var (_, priv) = DepositCrypto.GenerateKeyPair();
        var env = new DepositCrypto.Envelope(1, "AA==", "AA==", "AA==",
            new string('A', ((DepositCrypto.MaxCiphertextBytes + 2) / 3 * 4) + 4), "AA==");

        var ex = Assert.Throws<FormatException>(() => DepositCrypto.Decrypt(priv, env));
        Assert.Contains("ciphertext", ex.Message);
    }
}
