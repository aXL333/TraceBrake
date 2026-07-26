using System.Threading;
using Foreman.Core.Ipc.Guardian;
using Foreman.Core.Settings;

namespace Foreman.App;

/// <summary>
/// Settings sealer that keeps the secret behind the SYSTEM boundary via the guardian (circle-back Phase A,
/// step 7). Compute + verify of a guardian-scheme ("g1:") seal go through the pipe; a pre-opt-in LOCAL seal is
/// verified locally for one migration cycle (the next save re-seals it as guardian-scheme). Availability-safe: if
/// the guardian is unreachable for a guardian-scheme seal, it returns Unverified — not Sealed (which would be a
/// lie: nothing was checked) and not Tampered (don't cry false tamper on a transient outage of an auto-start
/// service). The seal is neither confirmed nor refuted; the app surfaces a notice rather than blocking load.
/// </summary>
internal sealed class GuardianSettingsSealer : ISettingsSealer
{
    private readonly GuardianPipeClient _client;
    private readonly Func<string?> _localSecret;   // the install secret, for migrating a pre-opt-in local seal
    private readonly int _timeoutMs;

    public GuardianSettingsSealer(GuardianPipeClient client, Func<string?> localSecret, int timeoutMs = 2000)
    {
        _client = client;
        _localSecret = localSecret;
        _timeoutMs = timeoutMs;
    }

    /// <summary>
    /// Returns a guardian-backed sealer iff the service is installed AND the pipe is confirmed SYSTEM-owned
    /// (anti-squat); otherwise null, so the caller keeps the local install-secret path. Bounded; never throws.
    /// </summary>
    public static ISettingsSealer? TryCreate(Func<string?> localSecret)
    {
        if (!GuardianDiscovery.IsGuardianInstalled()) return null;
        var client = new GuardianPipeClient();
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            if (!client.IsServerSystemOwnedAsync(cts.Token).GetAwaiter().GetResult())
                return new UnavailableGuardianSettingsSealer(localSecret);
            if (!GuardianTrust.IsAccepted(client.HelloAsync(cts.Token).GetAwaiter().GetResult()))
                return new UnavailableGuardianSettingsSealer(localSecret);
        }
        catch
        {
            return new UnavailableGuardianSettingsSealer(localSecret);
        }
        return new GuardianSettingsSealer(client, localSecret);
    }

    public string? Compute(ForemanSettings settings)
    {
        try
        {
            using var cts = new CancellationTokenSource(_timeoutMs);
            var res = _client.SealSettingsAsync(
                new SealSettingsArgs { SecurityProjection = SettingsSeal.SecurityProjection(settings) }, cts.Token)
                .GetAwaiter().GetResult();
            return res.Seal;   // already "g1:"-prefixed by the guardian; null if unavailable (keep the old seal)
        }
        catch
        {
            return null;
        }
    }

    public SettingsSealVerdict Verify(ForemanSettings settings, string? storedSeal)
    {
        if (string.IsNullOrEmpty(storedSeal)) return SettingsSealVerdict.Unsealed;

        if (storedSeal.StartsWith(SettingsSeal.GuardianScheme, StringComparison.Ordinal))
        {
            try
            {
                using var cts = new CancellationTokenSource(_timeoutMs);
                var res = _client.VerifySettingsAsync(
                    SettingsSeal.SecurityProjection(settings), storedSeal, cts.Token).GetAwaiter().GetResult();
                if (res is null) return SettingsSealVerdict.Unverified;   // guardian unreachable → can't confirm OR refute
                var verdict = Enum.TryParse<SettingsSealVerdict>(res.Verdict, out var v)
                    ? v
                    : SettingsSealVerdict.Unsealed;
                if (verdict != SettingsSealVerdict.Tampered) return verdict;

                // g1 predates projection versioning. Verify once against the retained predecessor, then let the
                // store reseal the unchanged settings under the current projection.
                var legacy = _client.VerifySettingsAsync(
                    SettingsSeal.LegacySecurityProjectionV1(settings), storedSeal, cts.Token).GetAwaiter().GetResult();
                return legacy is not null &&
                       Enum.TryParse<SettingsSealVerdict>(legacy.Verdict, out var legacyVerdict) &&
                       legacyVerdict == SettingsSealVerdict.Sealed
                    ? SettingsSealVerdict.LegacySealed
                    : SettingsSealVerdict.Tampered;
            }
            catch
            {
                return SettingsSealVerdict.Unverified;   // transient outage of the SYSTEM service → unverified, not a clean pass
            }
        }

        // A non-guardian (local) seal under guardian mode = the pre-opt-in seal. Verify it locally this once; the
        // next Save re-seals as guardian-scheme. SettingsSeal.Verify treats a g1: seal as Unsealed, so this only
        // ever sees a genuine local seal here.
        var secret = _localSecret();
        return string.IsNullOrEmpty(secret)
            ? SettingsSealVerdict.Unsealed
            : SettingsSeal.Verify(settings, storedSeal, secret);
    }
}
