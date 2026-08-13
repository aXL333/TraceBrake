using Foreman.Core.Events;
using Foreman.Core.Ipc.Guardian;
using Foreman.Core.Settings;

namespace Foreman.Guardian;

/// <summary>
/// The guardian's authority logic, kept independent of the pipe transport so it is unit-testable without any
/// process/IPC. This is where the operations that move behind the SYSTEM boundary live: signing the event-log
/// head with the SYSTEM-held key (step 4) and, later, computing/verifying the settings seal with the SYSTEM-held
/// secret (step 7).
///
/// KEY CUSTODY: the head-seal key is created/opened in the guardian's process. When the guardian runs as the
/// LocalSystem service the key is SYSTEM-scoped, so the medium-IL agent can neither extract nor USE it — that is
/// the privilege boundary that finally makes the seal unforgeable. Signing reuses <see cref="SignedHeadSigner"/>
/// so the payload format and base64 encoding are byte-identical to what the app's verifier expects.
/// </summary>
public sealed class GuardianAuthority : IDisposable
{
    /// <summary>Default CNG key name; matches the app's Phase B key name so the migration story is a re-pin, not a re-key.</summary>
    public const string DefaultHeadKeyName = "Foreman.LogHeadSeal.v1";

    private readonly IHeadSealKey? _headKey;
    private readonly SignedHeadSigner? _signer;
    private readonly Func<string> _settingsSecret;

    /// <summary>
    /// Production ctor: opens (or creates) the TPM/PCP key in the current process context. Test ctor: inject a
    /// software <see cref="IHeadSealKey"/> and/or a fixed settings secret to exercise the round-trips without a
    /// TPM or %ProgramData% access.
    /// </summary>
    public GuardianAuthority(IHeadSealKey? headKey, Func<string>? settingsSecret = null)
    {
        _headKey = headKey;
        // Sign against the key's own public half; the app pins that same public key via GetPinnedHeadKey.
        _signer = _headKey is null ? null : new SignedHeadSigner(_headKey, _headKey.PublicKey);
        _settingsSecret = settingsSecret ?? new GuardianSecret().Get;
    }

    /// <summary>Opens the real TPM/PCP key (null on a no-TPM box). Separate from the ctor so tests stay TPM-free.</summary>
    public static GuardianAuthority CreateWithTpmKey(string keyName = DefaultHeadKeyName) =>
        new(TpmHeadSealKey.OpenOrCreate(keyName));

    /// <summary>Three-part assembly version string, surfaced in Hello + the --version smoke verb.</summary>
    public static string Version =>
        typeof(GuardianAuthority).Assembly.GetName().Version?.ToString(3) ?? "0.1";

    /// <summary>True once the guardian holds a usable head-seal key (no-TPM box ⇒ false).</summary>
    public bool HeadKeyAvailable => _headKey is not null;

    public HelloResult Hello() => new() { GuardianVersion = Version, HeadKeyAvailable = HeadKeyAvailable };

    /// <summary>Signs (headHash|count) with the SYSTEM-held key; null when no key (no-TPM ⇒ unsigned, app tolerates).</summary>
    public string? SealHead(string headHash, long recordCount) => _signer?.SealHead(headHash, recordCount);

    /// <summary>Base64 SubjectPublicKeyInfo of the head-seal key, for the app to pin; null when unavailable.</summary>
    public string? GetPinnedHeadKey() => _headKey is null ? null : Convert.ToBase64String(_headKey.PublicKey);

    /// <summary>
    /// Seals the settings security projection with the SYSTEM-held secret, tagged with the guardian scheme so the
    /// app/local path recognise it. Step 7: the secret never leaves the SYSTEM boundary, so the agent can't forge
    /// a weakened-settings seal. (Client auth already ensures only the genuine TraceBrake can call this.)
    /// </summary>
    public string SealSettings(string projection) =>
        SettingsSeal.GuardianScheme + SettingsSeal.ComputeMac(projection, _settingsSecret());

    /// <summary>Verifies a guardian-scheme settings seal against the projection, using the SYSTEM-held secret.</summary>
    public SettingsSealVerdict VerifySettings(string projection, string? storedSeal)
    {
        if (string.IsNullOrEmpty(storedSeal)) return SettingsSealVerdict.Unsealed;
        var mac = storedSeal.StartsWith(SettingsSeal.GuardianScheme, StringComparison.Ordinal)
            ? storedSeal[SettingsSeal.GuardianScheme.Length..]
            : storedSeal;
        return SettingsSeal.MacEquals(SettingsSeal.ComputeMac(projection, _settingsSecret()), mac)
            ? SettingsSealVerdict.Sealed
            : SettingsSealVerdict.Tampered;
    }

    public void Dispose() => (_headKey as IDisposable)?.Dispose();
}
