using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Foreman.Core.Settings;

public sealed class SettingsStore
{
    private static readonly string _path = Path.Combine(ProductIdentity.LocalDataRoot, "settings.json");

    private static readonly JsonSerializerOptions _opts = new() { WriteIndented = true };

    /// <summary>
    /// Set by <see cref="Load()"/> when settings.json existed but could not be parsed: the unreadable
    /// file is quarantined (renamed to <c>settings.json.&lt;timestamp&gt;.bad</c>) and defaults are loaded.
    /// The app reads this AFTER the event bus is wired and surfaces a notice — so a corrupt settings file
    /// no longer silently resets security-relevant posture (mutes, emergency rule IDs) without warning.
    /// </summary>
    public static string? LastLoadFault { get; private set; }
    public static string? LastSaveFault { get; private set; }
    private static readonly object _blockedSaveGate = new();
    private static readonly HashSet<string> _unverifiedLoadPaths = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Supplies the install secret used to HMAC-seal the security-significant settings. Set once by the App at
    /// startup (BEFORE the first <see cref="Load()"/>) from the MCP install token. Null → sealing/verification is
    /// skipped (e.g. in tests), so this never blocks load/save. See <see cref="SettingsSeal"/>.
    /// </summary>
    public static Func<string?>? IntegritySecret { get; set; }

    /// <summary>
    /// Optional guardian-backed sealer (circle-back Phase A, step 7). When set, settings sealing/verification runs
    /// through it (the secret stays behind the SYSTEM boundary) instead of the local <see cref="IntegritySecret"/>
    /// path. Null → the local secret path (the default / casual user). The App sets this only when the opt-in
    /// guardian is installed and verified.
    /// </summary>
    public static ISettingsSealer? Sealer { get; set; }

    /// <summary>Optional durable witness that this installation has successfully sealed settings before.</summary>
    public static Func<bool>? HasPriorSealEvidence { get; set; }

    /// <summary>Best-effort writer paired with <see cref="HasPriorSealEvidence"/>.</summary>
    public static Action? RecordSealEvidence { get; set; }

    /// <summary>True only during a documented local MCP-token rotation.</summary>
    public static Func<bool>? IntegritySecretRecentlyRegenerated { get; set; }

    /// <summary>
    /// Best-effort, secret-free observer invoked after a successful save. The App routes this into TraceBrake's
    /// hash-chained event stream and OS-event-log handoff. Tests and non-App hosts may leave it null.
    /// </summary>
    public static Action<SettingsSaveAudit>? SaveAuditSink { get; set; }

    /// <summary>Best-effort observer for a save refused before any primary settings bytes were replaced.</summary>
    public static Action<string>? SaveFailureSink { get; set; }

    /// <summary>
    /// The seal verdict from the most recent <see cref="Load()"/>: Tampered means settings.json was edited by
    /// something other than Foreman. A tampered object is never returned: Load first restores a sealed last-known-good
    /// snapshot, or falls back to safe defaults when no verified recovery exists. The App still reads this verdict
    /// after the event bus is wired so the attempted edit remains operator-visible.
    /// </summary>
    public static SettingsSealVerdict LastSealVerdict { get; private set; } = SettingsSealVerdict.Unsealed;
    /// <summary>True when this load rejected the primary but returned a verified last-known-good snapshot.</summary>
    public static bool RecoveryRestored { get; private set; }

    public static ForemanSettings Load() => Load(_path);

    public static void Save(ForemanSettings settings) => Save(settings, _path);

    /// <summary>Loads from an explicit path. Quarantines an unreadable file and records <see cref="LastLoadFault"/>.</summary>
    public static ForemanSettings Load(string path)
    {
        LastLoadFault = null;
        LastSaveFault = null;
        LastSealVerdict = SettingsSealVerdict.Unsealed;
        RecoveryRestored = false;
        lock (_blockedSaveGate) _unverifiedLoadPaths.Remove(Path.GetFullPath(path));
        if (!File.Exists(path))
        {
            var missingSealer = Sealer;
            var missingSecret = missingSealer is null ? IntegritySecret?.Invoke() : null;
            var recovered = TryReadRecovery(path, missingSealer, missingSecret);
            if (recovered is not null)
            {
                LastSealVerdict = SettingsSealVerdict.Tampered;
                TryRestorePrimary(path, recovered.Value.Json, recovered.Value.Seal);
                RecoveryRestored = true;
                LastLoadFault = "settings.json was removed after settings sealing had been established. The sealed " +
                                "last-known-good settings were restored before TraceBrake initialised.";
                return recovered.Value.Settings;
            }
            if (SafeHasPriorSealEvidence(path))
            {
                LastSealVerdict = SettingsSealVerdict.Tampered;
                LastLoadFault = "settings.json was removed after settings sealing had been established. No verified " +
                                "recovery snapshot was available, so fail-safe defaults were loaded.";
                BlockSavesForUnverifiedPath(path);
                return GuardianUnavailableFailSafe();
            }
            return new ForemanSettings();
        }
        var loadSealer = Sealer;
        var loadSecret = loadSealer is null ? IntegritySecret?.Invoke() : null;
        try
        {
            var json = File.ReadAllText(path);
            var settings = Deserialize(json);

            // Tamper check: a same-user agent can edit this file directly to weaken posture (disable the presence
            // lock / log persistence) — bypassing the UI gates entirely. TraceBrake re-seals on every save, so a
            // mismatch here means the file was changed by something other than Foreman. We can't PREVENT that
            // (no privilege boundary), but the App turns this verdict into a loud Critical + OS-event-log entry.
            var sealer = loadSealer;
            var secret = loadSecret;
            var storedSeal = ReadSeal(path);
            LastSealVerdict = Verify(settings, storedSeal, sealer, secret);

            if (LastSealVerdict == SettingsSealVerdict.LegacySealed)
            {
                if (TryUpgradeSeal(path, json, settings, sealer, secret))
                {
                    LastSealVerdict = SettingsSealVerdict.Sealed;
                    TryRecordSealEvidence();
                }
                else
                {
                    LastSealVerdict = SettingsSealVerdict.Unverified;
                    LastLoadFault = "Settings matched a retained legacy seal, but the SYSTEM Guardian could not " +
                                    "re-seal the current projection. The primary was left untouched and fail-safe " +
                                    "defaults were loaded for this session.";
                    BlockSavesForUnverifiedPath(path);
                    return GuardianUnavailableFailSafe();
                }
                return settings;
            }
            if (LastSealVerdict == SettingsSealVerdict.Sealed)
            {
                // Keep a verified recovery copy of the exact settings TraceBrake last accepted. It is deliberately
                // separate from settings.json so a later direct edit can be reverted before startup consumes it.
                TryWriteRecovery(path, json, storedSeal!);
                TryRecordSealEvidence();
            }
            else if (LastSealVerdict == SettingsSealVerdict.Unverified)
            {
                // A guardian seal that cannot be verified is not authority to initialize sensitive subsystems.
                // Keep the primary untouched for a later healthy launch, but consume only safe defaults now.
                LastLoadFault = "The SYSTEM guardian could not verify settings this launch. The settings file was " +
                                "left untouched, but safe defaults were loaded so unverified computer-use, trust, " +
                                "monitoring, and evidence settings cannot take effect.";
                BlockSavesForUnverifiedPath(path);
                return GuardianUnavailableFailSafe();
            }
            else if (LastSealVerdict == SettingsSealVerdict.Tampered &&
                     TryAdoptAfterLocalSecretRotation(path, json, settings, sealer, secret))
            {
                LastSealVerdict = SettingsSealVerdict.Sealed;
                LastLoadFault = "The MCP authentication token was recently regenerated. Existing settings matched " +
                                "the last-known-good snapshot and were re-sealed with the new local integrity key.";
                TryRecordSealEvidence();
                return settings;
            }
            else
            {
                var recovered = TryReadRecovery(path, sealer, secret);
                var establishedSealWasRemoved = LastSealVerdict == SettingsSealVerdict.Unsealed &&
                    (recovered is not null || SafeHasPriorSealEvidence(path));

                if (LastSealVerdict != SettingsSealVerdict.Tampered && !establishedSealWasRemoved)
                    return settings;

                LastSealVerdict = SettingsSealVerdict.Tampered;
                QuarantineTampered(path);
                if (recovered is not null)
                {
                    TryRestorePrimary(path, recovered.Value.Json, recovered.Value.Seal);
                    RecoveryRestored = true;
                    LastLoadFault = "A direct edit to security-significant settings was rejected before TraceBrake " +
                                    "initialised. The sealed last-known-good settings were restored; the attempted " +
                                    "file was quarantined with a .tampered suffix.";
                    return recovered.Value.Settings;
                }

                LastLoadFault = "A direct edit to security-significant settings was rejected before TraceBrake " +
                                "initialised. No verified recovery snapshot was available, so fail-safe defaults were " +
                                "loaded and the attempted file was quarantined with a .tampered suffix.";
                BlockSavesForUnverifiedPath(path);
                return GuardianUnavailableFailSafe();
            }

            return settings;
        }
        catch (Exception ex)
        {
            var quarantine = Quarantine(path);
            var recovered = TryReadRecovery(path, loadSealer, loadSecret);
            if (recovered is not null)
            {
                TryRestorePrimary(path, recovered.Value.Json, recovered.Value.Seal);
                LastSealVerdict = SettingsSealVerdict.Tampered;
                RecoveryRestored = true;
                LastLoadFault = $"settings.json could not be read ({ex.Message}). The unreadable primary was " +
                                $"quarantined as {Path.GetFileName(quarantine)} and the sealed last-known-good " +
                                "settings were restored.";
                return recovered.Value.Settings;
            }
            if (SafeHasPriorSealEvidence(path))
            {
                LastSealVerdict = SettingsSealVerdict.Tampered;
                BlockSavesForUnverifiedPath(path);
            }
            LastLoadFault = quarantine is not null
                ? $"settings.json could not be read ({ex.Message}). It was moved to {Path.GetFileName(quarantine)} " +
                  "and defaults were loaded — re-apply your settings, or restore from the .bad file."
                : $"settings.json could not be read ({ex.Message}); defaults were loaded.";
            return LastSealVerdict == SettingsSealVerdict.Tampered
                ? GuardianUnavailableFailSafe()
                : new ForemanSettings();
        }
    }

    /// <summary>Saves to an explicit path atomically (temp file + swap), so a crash mid-write can't corrupt it.</summary>
    public static void Save(ForemanSettings settings, string path)
    {
        LastSaveFault = null;
        var fullPath = Path.GetFullPath(path);
        lock (_blockedSaveGate)
        {
            if (_unverifiedLoadPaths.Contains(fullPath))
            {
                ReportSaveFailure("Settings were not saved because this launch is using Guardian-unverified " +
                                  "fail-safe defaults. The verified primary remains untouched; restore the " +
                                  "Guardian service and restart TraceBrake before changing settings.");
                return;
            }
        }

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var json = JsonSerializer.Serialize(settings, _opts);
        var currentProjection = SettingsSeal.SecurityProjection(settings);
        string? priorJson = null;
        string? priorProjection = null;
        try
        {
            if (File.Exists(path))
            {
                priorJson = File.ReadAllText(path);
                priorProjection = SettingsSeal.SecurityProjection(Deserialize(priorJson));
            }
        }
        catch
        {
            // The write path remains authoritative. A missing prior comparison becomes an explicit unknown hash,
            // never a claim that the security posture was unchanged.
        }

        // Compute the replacement seal BEFORE publishing any settings bytes. A temporarily unavailable SYSTEM
        // Guardian is not permission to write an unsealed primary and discover the mismatch only next launch.
        string? seal;
        if (Sealer is { } sealer)
        {
            seal = sealer.Compute(settings);
            if (string.IsNullOrWhiteSpace(seal))
            {
                ReportSaveFailure("Settings were not saved because the SYSTEM Guardian could not seal the new " +
                                  "posture. The existing settings and seal remain authoritative.");
                return;
            }
        }
        else if (IntegritySecret?.Invoke() is { Length: > 0 } secret)
        {
            seal = SettingsSeal.Compute(settings, secret);
        }
        else
        {
            if (SafeHasPriorSealEvidence(path))
            {
                ReportSaveFailure("Settings were not saved because established seal authority is unavailable.");
                return;
            }
            seal = null; // intentionally unsealed headless/test host with no established authority
        }

        // Write to sibling temp files and atomically replace each destination. Recovery preserves the prior verified
        // pair if the process loses power between the two replacements.
        WriteAtomically(path, json);
        if (seal is not null)
        {
            WriteAtomically(SealPath(path), seal);
            TryWriteRecovery(path, json, seal);
            TryRecordSealEvidence();
        }

        try
        {
            SaveAuditSink?.Invoke(new SettingsSaveAudit(
                DateTimeOffset.UtcNow,
                SettingsChangeContext.Current ?? SettingsChangeAttribution.Unattributed(),
                !string.Equals(priorJson, json, StringComparison.Ordinal),
                priorProjection is null || !string.Equals(priorProjection, currentProjection, StringComparison.Ordinal),
                ProjectionHash(priorProjection),
                ProjectionHash(currentProjection)));
        }
        catch { /* evidence delivery must never corrupt or roll back a completed operator save */ }
    }

    private static void ReportSaveFailure(string message)
    {
        LastSaveFault = message;
        try { SaveFailureSink?.Invoke(message); } catch { }
    }

    private static void BlockSavesForUnverifiedPath(string path)
    {
        lock (_blockedSaveGate) _unverifiedLoadPaths.Add(Path.GetFullPath(path));
    }

    private static string ProjectionHash(string? projection)
    {
        if (projection is null) return "none";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(projection)))[..16];
    }

    private static ForemanSettings GuardianUnavailableFailSafe()
    {
        var safe = new ForemanSettings
        {
            // Degraded mode observes broadly and preserves both evidence channels. It grants no CU driver or
            // elevated executable authority, and the armed-without-a-credential presence lock makes every normal
            // weakening action fail closed until the SYSTEM authority can verify the real settings again.
            MonitorAllProcesses = true,
            CuDriver = null,
            CuTabOverride = false,
            CuDesktopEnabled = false,
            CuDriverHostEnabled = false,
            CuDesktopAutoGrant = false,
            AllowAutoExtensionPairing = false,
            EventLogPersist = true,
            McpPeerBindingEnforce = true,
        };
        safe.LogIntegrity.HashChainEnabled = true;
        safe.LogIntegrity.SealHeadEnabled = true;
        safe.OsEventLog.Enabled = true;
        safe.PresenceLock.Enabled = true;
        safe.PresenceLock.CredentialId = null;
        return safe;
    }

    private static string SealPath(string path) => path + ".seal";
    private static string RecoveryPath(string path) => path + ".lastgood";
    private static string RecoverySealPath(string path) => RecoveryPath(path) + ".seal";

    private static ForemanSettings Deserialize(string json) =>
        JsonSerializer.Deserialize<ForemanSettings>(json, _opts) ?? new ForemanSettings();

    private static SettingsSealVerdict Verify(
        ForemanSettings settings,
        string? seal,
        ISettingsSealer? sealer,
        string? secret) =>
        sealer is not null
            ? sealer.Verify(settings, seal)
            : !string.IsNullOrEmpty(secret)
                ? SettingsSeal.Verify(settings, seal, secret)
                : SettingsSealVerdict.Unsealed;

    private static (ForemanSettings Settings, string Json, string Seal)? TryReadRecovery(
        string path,
        ISettingsSealer? sealer,
        string? secret)
    {
        try
        {
            var json = File.ReadAllText(RecoveryPath(path));
            var seal = File.ReadAllText(RecoverySealPath(path)).Trim();
            var settings = Deserialize(json);
            var verdict = Verify(settings, seal, sealer, secret);
            return verdict is SettingsSealVerdict.Sealed or SettingsSealVerdict.LegacySealed
                ? (settings, json, seal)
                : null;
        }
        catch { return null; }
    }

    private static bool TryAdoptAfterLocalSecretRotation(
        string path,
        string currentJson,
        ForemanSettings settings,
        ISettingsSealer? sealer,
        string? newSecret)
    {
        if (sealer is not null || string.IsNullOrEmpty(newSecret) ||
            IntegritySecretRecentlyRegenerated?.Invoke() != true)
            return false;

        try
        {
            var recoveryJson = File.ReadAllText(RecoveryPath(path));
            var priorRecoverySeal = File.ReadAllText(RecoverySealPath(path)).Trim();
            if (priorRecoverySeal.Length == 0) return false;
            if (!string.Equals(currentJson, recoveryJson, StringComparison.Ordinal)) return false;

            var newSeal = SettingsSeal.Compute(settings, newSecret);
            WriteAtomically(SealPath(path), newSeal);
            TryWriteRecovery(path, currentJson, newSeal);
            return true;
        }
        catch { return false; }
    }

    private static bool TryUpgradeSeal(
        string path,
        string json,
        ForemanSettings settings,
        ISettingsSealer? sealer,
        string? secret)
    {
        try
        {
            var upgraded = sealer is not null
                ? sealer.Compute(settings)
                : !string.IsNullOrEmpty(secret) ? SettingsSeal.Compute(settings, secret) : null;
            if (string.IsNullOrEmpty(upgraded)) return false;
            WriteAtomically(SealPath(path), upgraded);
            TryWriteRecovery(path, json, upgraded);
            return true;
        }
        catch { return false; }
    }

    private static bool SafeHasPriorSealEvidence(string path)
    {
        // The OS-log witness is the durable signal, but surviving primary/recovery seal artefacts are also
        // evidence that this is not a pristine first run. Treating them as absent would make deleting only the
        // primary an easier posture-reset path whenever the OS event log is unavailable.
        try
        {
            if (File.Exists(SealPath(path)) || File.Exists(RecoverySealPath(path)))
                return true;
        }
        catch { }
        try { return HasPriorSealEvidence?.Invoke() == true; }
        catch { return false; }
    }

    private static void TryRecordSealEvidence()
    {
        try { RecordSealEvidence?.Invoke(); }
        catch { }
    }

    private static void TryWriteRecovery(string path, string json, string seal)
    {
        try
        {
            WriteAtomically(RecoveryPath(path), json);
            WriteAtomically(RecoverySealPath(path), seal);
        }
        catch { /* recovery is defense-in-depth; the primary sealed settings remain authoritative */ }
    }

    private static void TryRestorePrimary(string path, string json, string seal)
    {
        try
        {
            WriteAtomically(path, json);
            WriteAtomically(SealPath(path), seal);
        }
        catch { /* the verified in-memory recovery is still used for this launch */ }
    }

    private static void WriteAtomically(string path, string contents)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, contents);
        try
        {
            if (File.Exists(path))
                File.Replace(tmp, path, destinationBackupFileName: null);
            else
                File.Move(tmp, path);
        }
        catch
        {
            File.Copy(tmp, path, overwrite: true);
            try { File.Delete(tmp); } catch { }
        }
    }

    private static string? ReadSeal(string path)
    {
        try { return File.Exists(SealPath(path)) ? File.ReadAllText(SealPath(path)).Trim() : null; }
        catch { return null; }
    }

    private static string? Quarantine(string path)
    {
        try
        {
            var dest = $"{path}.{DateTime.Now:yyyyMMdd-HHmmss}.bad";
            File.Move(path, dest, overwrite: true);
            return dest;
        }
        catch { return null; }
    }

    private static void QuarantineTampered(string path)
    {
        var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        TryMove(path, $"{path}.{stamp}.tampered");
        TryMove(SealPath(path), $"{SealPath(path)}.{stamp}.tampered");
    }

    private static void TryMove(string source, string destination)
    {
        try { if (File.Exists(source)) File.Move(source, destination, overwrite: true); }
        catch { }
    }
}
