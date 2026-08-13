using System.Security.Cryptography;

namespace Foreman.Vault;

/// <summary>Generates strong random passwords for "let TraceBrake pick one" (self-signup / rotation). Uniform + unbiased
/// (cryptographic RNG); excludes visually ambiguous characters (0/O, 1/l/I) so an operator can read one off if needed.</summary>
public static class VaultPasswordGenerator
{
    private const string Charset =
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+";

    public static string Generate(int length = 20) =>
        RandomNumberGenerator.GetString(Charset, Math.Max(1, length));
}
