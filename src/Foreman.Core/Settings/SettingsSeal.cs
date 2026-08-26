using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Foreman.Core.Settings;

/// <summary>The result of checking settings.json's security subset against its sidecar seal.</summary>
public enum SettingsSealVerdict
{
    /// <summary>Seal present and matches — the security posture is exactly what TraceBrake last wrote.</summary>
    Sealed,
    /// <summary>Seal present but does NOT match — settings were edited by something other than Foreman.</summary>
    Tampered,
    /// <summary>No seal yet (first run / freshly upgraded) — adopt + seal, don't treat as tamper.</summary>
    Unsealed,
    /// <summary>
    /// A guardian-scheme seal was present but the guardian (the SYSTEM authority that holds the key) was
    /// unreachable, so the seal could be neither confirmed nor refuted. NOT a clean Sealed — the security
    /// posture is unverified this launch. The app surfaces this as a notice rather than blocking load.
    /// </summary>
    Unverified,
    /// <summary>
    /// A valid seal from a recognised older projection. Preserve the settings and upgrade the seal.
    /// </summary>
    LegacySealed,
}

/// <summary>
/// Tamper-DETECTION for the security-significant subset of settings.json.
///
/// Against the primary adversary — a monitored agent running as the SAME user — tampering cannot be PREVENTED:
/// there is no privilege boundary, so the agent can read the install secret and recompute any seal. What IS
/// achievable, and what this provides, is DETECTION. TraceBrake re-seals on every save (<see cref="Compute"/>), so
/// any edit it did not make — another principal, accidental corruption, or a naive agent that flips a flag
/// without re-sealing — is caught at load (<see cref="Verify"/>) and can be reverted + alerted. A durable OS-event
/// witness distinguishes an established install from a genuine first run if the seal and recovery pair are deleted.
/// There is no settings-file SACL today, and a sophisticated same-user process that can read the local key can still
/// recompute a local seal; the opt-in SYSTEM guardian is the privilege boundary for that stronger threat model.
/// </summary>
public static class SettingsSeal
{
    public const string LocalScheme = "l2:";
    /// <summary>Previous security projection, before editable universal Trust capability profiles were added.</summary>
    public static string LegacySecurityProjectionV2(ForemanSettings s)
    {
        var projection = new
        {
            presenceEnabled = s.PresenceLock.Enabled,
            presenceScope   = (int)s.PresenceLock.Scope,
            presenceCred    = s.PresenceLock.CredentialId ?? "",
            eventLogPersist = s.EventLogPersist,
            hashChain       = s.LogIntegrity.HashChainEnabled,
            runElevated     = s.RunElevated,
            scanMcpTools    = s.ScanMcpTools,
            monitorAll      = s.MonitorAllProcesses,
            peerBinding     = s.McpPeerBindingEnforce,
            autoExtPair     = s.AllowAutoExtensionPairing,   // re-enabling code-less extension auto-pair is a weakening
            decoyEnabled    = s.DecoyCredentials.Enabled,
            decoyReadAudit  = s.DecoyCredentials.EnableReadAuditing,
            osEventLog      = s.OsEventLog.Enabled,
            // Desktop CU + Local Agent Host: a silent edit here grants desktop input authority or redirects which exe
            // TraceBrake launches as the agent - seal them so any change flips the verdict to Tampered (revert + alert).
            cuDesktop       = s.CuDesktopEnabled,
            cuDriverHost    = s.CuDriverHostEnabled,
            cuAutoGrant     = s.CuDesktopAutoGrant,
            cuDriver        = s.CuDriver ?? "",
            cuAgentCommand  = s.CuAgentCommand ?? "",
            cuAgentArgs     = s.CuAgentArguments ?? "",
            cuAgentWorkDir  = s.CuAgentWorkingDir ?? "",
            // ADB activation grants an external-device control path and the executable path is process-launch
            // authority. Seal enablement, binary identity, and the enrolled device set.
            adbEnabled      = s.AdbBridge.Enabled,
            adbExecutable   = s.AdbBridge.ExecutablePath ?? "",
            adbExecutableSha256 = s.AdbBridge.ExecutableSha256 ?? "",
            adbDevices      = s.AdbBridge.EnrolledDeviceSerials
                                .Select(static x => (x ?? string.Empty).Trim().ToLowerInvariant())
                                .Where(static x => x.Length > 0)
                                .Order(StringComparer.Ordinal)
                                .ToArray(),
            disabled        = s.DisabledHarnesses.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray(),
            emergency       = s.EmergencyRuleIds.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray(),
            trust           = s.HarnessTrust.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                                            .Select(kv => $"{kv.Key.ToLowerInvariant()}={kv.Value}").ToArray(),
            capabilities    = s.HarnessCapabilityRestrictions.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                                            .Select(kv => $"{kv.Key.ToLowerInvariant()}={(int)kv.Value.ComputerUse}:{(int)kv.Value.BrowserUse}").ToArray(),
            mutes           = s.Mutes.OrderBy(MuteKey, StringComparer.Ordinal).Select(MuteKey).ToArray(),
        };
        return JsonSerializer.Serialize(projection);
    }

    /// <summary>
    /// Deny-by-default projection: every persisted setting is sealed. This intentionally avoids a hand-maintained
    /// security-field allowlist, because a newly added authority/evidence setting must not silently fall outside the
    /// seal until somebody remembers to update a second file. Object/dictionary keys are canonicalized; arrays whose
    /// semantics are sets are sorted so harmless serialization order changes do not create false tamper alarms.
    /// </summary>
    public static string SecurityProjection(ForemanSettings s)
    {
        ArgumentNullException.ThrowIfNull(s);
        var node = JsonSerializer.SerializeToNode(s)
                   ?? throw new InvalidOperationException("Could not project TraceBrake settings.");
        return Canonicalize(node, "$", propertyName: null).ToJsonString();
    }

    private static JsonNode Canonicalize(JsonNode node, string path, string? propertyName)
    {
        if (node is JsonObject obj)
        {
            var canonical = new JsonObject();
            foreach (var item in obj.OrderBy(static p => p.Key, StringComparer.Ordinal))
                canonical[item.Key] = item.Value is null
                    ? null
                    : Canonicalize(item.Value, path + "." + item.Key, item.Key);
            return canonical;
        }

        if (node is JsonArray array)
        {
            var items = array.Select(item => item is null
                    ? null
                    : Canonicalize(item, path + "[]", propertyName))
                .ToList();
            if (IsSetLikeArray(path, propertyName))
                items.Sort(static (a, b) => StringComparer.Ordinal.Compare(a?.ToJsonString(), b?.ToJsonString()));
            var canonical = new JsonArray();
            foreach (var item in items) canonical.Add(item);
            return canonical;
        }

        return node.DeepClone();
    }

    private static bool IsSetLikeArray(string path, string? propertyName) => propertyName is
        nameof(ForemanSettings.DisabledHarnesses) or
        nameof(ForemanSettings.EmergencyRuleIds) or
        nameof(ForemanSettings.PairedExtensionOrigins) or
        nameof(ForemanSettings.CustomHarnessExes) or
        nameof(ForemanSettings.Mutes) or
        "EnrolledDeviceSerials" or
        "PlantedPaths" or
        "TargetHarnessIds" or
        "MinimumSeverities"
        || path.Contains(".HarnessModalities.", StringComparison.Ordinal);

    /// <summary>Previous projection retained to verify and migrate seals written before deny-by-default coverage.</summary>
    public static string LegacySecurityProjectionV3(ForemanSettings s)
    {
        var projection = new
        {
            presenceEnabled = s.PresenceLock.Enabled,
            presenceScope   = (int)s.PresenceLock.Scope,
            presenceCred    = s.PresenceLock.CredentialId ?? "",
            eventLogPersist = s.EventLogPersist,
            hashChain       = s.LogIntegrity.HashChainEnabled,
            runElevated     = s.RunElevated,
            scanMcpTools    = s.ScanMcpTools,
            monitorAll      = s.MonitorAllProcesses,
            peerBinding     = s.McpPeerBindingEnforce,
            autoExtPair     = s.AllowAutoExtensionPairing,
            decoyEnabled    = s.DecoyCredentials.Enabled,
            decoyReadAudit  = s.DecoyCredentials.EnableReadAuditing,
            osEventLog      = s.OsEventLog.Enabled,
            cuDesktop       = s.CuDesktopEnabled,
            cuDriverHost    = s.CuDriverHostEnabled,
            cuAutoGrant     = s.CuDesktopAutoGrant,
            cuDriver        = s.CuDriver ?? "",
            cuAgentCommand  = s.CuAgentCommand ?? "",
            cuAgentArgs     = s.CuAgentArguments ?? "",
            cuAgentWorkDir  = s.CuAgentWorkingDir ?? "",
            adbEnabled      = s.AdbBridge.Enabled,
            adbExecutable   = s.AdbBridge.ExecutablePath ?? "",
            adbExecutableSha256 = s.AdbBridge.ExecutableSha256 ?? "",
            adbDevices      = s.AdbBridge.EnrolledDeviceSerials
                                .Select(static x => (x ?? string.Empty).Trim().ToLowerInvariant())
                                .Where(static x => x.Length > 0)
                                .Order(StringComparer.Ordinal)
                                .ToArray(),
            disabled        = s.DisabledHarnesses.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray(),
            emergency       = s.EmergencyRuleIds.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray(),
            trust           = s.HarnessTrust.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                                            .Select(kv => $"{kv.Key.ToLowerInvariant()}={kv.Value}").ToArray(),
            universalTrust  = (s.UniversalTrust ?? new UniversalTrustSettings()).SecurityProjection(),
            capabilities    = s.HarnessCapabilityRestrictions.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                                            .Select(kv => $"{kv.Key.ToLowerInvariant()}={(int)kv.Value.ComputerUse}:{(int)kv.Value.BrowserUse}").ToArray(),
            mutes           = s.Mutes.OrderBy(MuteKey, StringComparer.Ordinal).Select(MuteKey).ToArray(),
        };
        return JsonSerializer.Serialize(projection);
    }

    /// <summary>Previous release projection retained only to verify and migrate pre-ADB seals.</summary>
    public static string LegacySecurityProjectionV1(ForemanSettings s)
    {
        var projection = new
        {
            presenceEnabled = s.PresenceLock.Enabled,
            presenceScope   = (int)s.PresenceLock.Scope,
            presenceCred    = s.PresenceLock.CredentialId ?? "",
            eventLogPersist = s.EventLogPersist,
            hashChain       = s.LogIntegrity.HashChainEnabled,
            runElevated     = s.RunElevated,
            scanMcpTools    = s.ScanMcpTools,
            monitorAll      = s.MonitorAllProcesses,
            peerBinding     = s.McpPeerBindingEnforce,
            autoExtPair     = s.AllowAutoExtensionPairing,
            decoyEnabled    = s.DecoyCredentials.Enabled,
            decoyReadAudit  = s.DecoyCredentials.EnableReadAuditing,
            osEventLog      = s.OsEventLog.Enabled,
            cuDesktop       = s.CuDesktopEnabled,
            cuDriverHost    = s.CuDriverHostEnabled,
            cuAutoGrant     = s.CuDesktopAutoGrant,
            cuDriver        = s.CuDriver ?? "",
            cuAgentCommand  = s.CuAgentCommand ?? "",
            cuAgentArgs     = s.CuAgentArguments ?? "",
            cuAgentWorkDir  = s.CuAgentWorkingDir ?? "",
            disabled        = s.DisabledHarnesses.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray(),
            emergency       = s.EmergencyRuleIds.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray(),
            trust           = s.HarnessTrust.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                                            .Select(kv => $"{kv.Key.ToLowerInvariant()}={kv.Value}").ToArray(),
            capabilities    = s.HarnessCapabilityRestrictions.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                                            .Select(kv => $"{kv.Key.ToLowerInvariant()}={(int)kv.Value.ComputerUse}:{(int)kv.Value.BrowserUse}").ToArray(),
            mutes           = s.Mutes.OrderBy(MuteKey, StringComparer.Ordinal).Select(MuteKey).ToArray(),
        };
        return JsonSerializer.Serialize(projection);
    }

    private static string MuteKey(Models.MuteEntry m) => $"{m.Scope}|{m.Value}|{m.Until:O}";

    /// <summary>
    /// Prefix marking a seal computed behind the SYSTEM boundary by the guardian (circle-back Phase A, step 7). It
    /// lets the local verify path recognise a guardian-scheme seal it CAN'T check (e.g. after opting out) and treat
    /// it as Unsealed → adopt + re-seal locally, rather than crying false tamper.
    /// </summary>
    public const string GuardianScheme = "g1:";

    /// <summary>HMAC-SHA256(secret, projection), base64 — the raw MAC, shared by the local path and the guardian.</summary>
    public static string ComputeMac(string projection, string secret)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(projection)));
    }

    /// <summary>Constant-time compare of a candidate MAC to the stored one.</summary>
    public static bool MacEquals(string computedMac, string storedMac)
    {
        var a = Encoding.UTF8.GetBytes(computedMac);
        var b = Encoding.UTF8.GetBytes(storedMac);
        return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    }

    /// <summary>HMAC-SHA256(install secret, security projection), base64. The seal written next to settings.json.</summary>
    public static string Compute(ForemanSettings s, string secret) =>
        LocalScheme + ComputeMac(SecurityProjection(s), secret);

    /// <summary>
    /// Compares the loaded settings' security subset to the stored seal (constant-time). A seal carrying the
    /// guardian scheme prefix is NOT verifiable with the local secret, so it reads as Unsealed (adopt + re-seal),
    /// never Tampered — that's the graceful opt-out path when the guardian is no longer present.
    /// </summary>
    public static SettingsSealVerdict Verify(ForemanSettings loaded, string? storedSeal, string secret)
    {
        if (string.IsNullOrEmpty(storedSeal)) return SettingsSealVerdict.Unsealed;
        if (storedSeal.StartsWith(GuardianScheme, StringComparison.Ordinal)) return SettingsSealVerdict.Unsealed;
        if (storedSeal.StartsWith(LocalScheme, StringComparison.Ordinal))
        {
            var mac = storedSeal[LocalScheme.Length..];
            if (MacEquals(ComputeMac(SecurityProjection(loaded), secret), mac))
                return SettingsSealVerdict.Sealed;
            if (MacEquals(ComputeMac(LegacySecurityProjectionV3(loaded), secret), mac))
                return SettingsSealVerdict.LegacySealed;
            if (MacEquals(ComputeMac(LegacySecurityProjectionV2(loaded), secret), mac))
                return SettingsSealVerdict.LegacySealed;
            return SettingsSealVerdict.Tampered;
        }

        if (storedSeal.Contains(':', StringComparison.Ordinal))
            return SettingsSealVerdict.Tampered;
        if (MacEquals(ComputeMac(SecurityProjection(loaded), secret), storedSeal) ||
            MacEquals(ComputeMac(LegacySecurityProjectionV3(loaded), secret), storedSeal) ||
            MacEquals(ComputeMac(LegacySecurityProjectionV2(loaded), secret), storedSeal) ||
            MacEquals(ComputeMac(LegacySecurityProjectionV1(loaded), secret), storedSeal))
            return SettingsSealVerdict.LegacySealed;
        return SettingsSealVerdict.Tampered;
    }
}

/// <summary>
/// Fail-safe used while an installed Guardian is temporarily unreachable. It never creates a local replacement for
/// a guardian seal, and classifies g1 evidence as unverified rather than absent.
/// </summary>
public sealed class UnavailableGuardianSettingsSealer : ISettingsSealer
{
    private readonly Func<string?> _localSecret;

    public UnavailableGuardianSettingsSealer(Func<string?> localSecret) => _localSecret = localSecret;

    public string? Compute(ForemanSettings settings) => null;

    public SettingsSealVerdict Verify(ForemanSettings settings, string? storedSeal)
    {
        if (storedSeal?.StartsWith(SettingsSeal.GuardianScheme, StringComparison.Ordinal) == true)
            return SettingsSealVerdict.Unverified;
        var secret = _localSecret();
        return string.IsNullOrEmpty(secret)
            ? SettingsSealVerdict.Unsealed
            : SettingsSeal.Verify(settings, storedSeal, secret);
    }
}

/// <summary>
/// Seam for WHO computes/verifies the settings seal (circle-back Phase A, step 7). The default local path keys it
/// by the install secret; the guardian-backed implementation keeps the secret behind the SYSTEM boundary so a
/// same-user agent can't read it to forge the seal. <see cref="SettingsStore"/> uses this when set, else its local
/// secret path.
/// </summary>
public interface ISettingsSealer
{
    /// <summary>Computes the seal string (including any scheme prefix) to write next to settings.json; null if unavailable.</summary>
    string? Compute(ForemanSettings settings);

    /// <summary>Verifies the stored seal against the loaded settings.</summary>
    SettingsSealVerdict Verify(ForemanSettings settings, string? storedSeal);
}
