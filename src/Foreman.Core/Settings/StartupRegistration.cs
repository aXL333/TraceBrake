using System.IO;
using Foreman.Core;

namespace Foreman.Core.Settings;

/// <summary>
/// Pure logic for the "start TraceBrake when the user signs in" registration —
/// building, parsing, and repairing the HKCU Run value. The registry itself is
/// the single source of truth for whether the feature is on (no settings field),
/// so the JSON settings and the OS can never disagree. The actual registry I/O
/// lives in Foreman.App (StartupManager); this type stays platform-free so the
/// decisions are unit-testable.
/// </summary>
public static class StartupRegistration
{
    /// <summary>Value name under HKCU\Software\Microsoft\Windows\CurrentVersion\Run.</summary>
    public const string RunValueName = "TraceBrake";

    /// <summary>Older public startup value name, kept so upgrades preserve the user's setting.</summary>
    public const string LegacyRunValueName = "Foreman";

    /// <summary>
    /// Every older Run value name to clean up when managing the canonical entry. Includes the no-space variant
    /// "ForemanAgentSafety" that a prior build wrote: leaving it stranded a SECOND Run entry, so Windows launched
    /// TraceBrake twice at sign-in. The single-instance mutex blocked the duplicate, but it cost a stray "already
    /// running" prompt + a false "blocked duplicate" in the OS log every logon. <see cref="LegacyRunValueName"/>
    /// is included so callers can iterate this one list.
    /// </summary>
    public static readonly string[] LegacyRunValueNames = { LegacyRunValueName, "ForemanAgentSafety", "Foreman Agent Safety" };

    /// <summary>Relative registry path of the per-user Run key.</summary>
    public const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";

    /// <summary>Builds the Run value for an exe path. Always quoted — paths contain spaces.</summary>
    public static string BuildCommand(string exePath) => $"\"{exePath}\"";

    /// <summary>
    /// Extracts the exe path from an existing Run value: quoted token if quoted,
    /// up to and including ".exe" otherwise, whole value as a last resort.
    /// Returns null for empty or malformed (unterminated quote) values.
    /// </summary>
    public static string? ParseExePath(string? runValue)
    {
        if (string.IsNullOrWhiteSpace(runValue)) return null;
        var v = runValue.Trim();

        if (v.StartsWith('"'))
        {
            var end = v.IndexOf('"', 1);
            return end > 1 ? v[1..end] : null;
        }

        var exe = v.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        return exe >= 0 ? v[..(exe + 4)] : v;
    }

    /// <summary>
    /// True when the registered entry should be rewritten to point at the running exe.
    /// Heals a moved/renamed install (registered exe no longer exists) and malformed
    /// values. An existing legacy Foreman.exe is also replaced when the current product
    /// is TraceBrake.exe; other existing targets remain authoritative, so a Debug build
    /// run from bin\ cannot steal the entry from a published TraceBrake install.
    /// No-ops when the feature is off (no value).
    /// </summary>
    public static bool NeedsRepair(string? existingValue, string currentExePath, Func<string, bool> fileExists)
    {
        if (string.IsNullOrWhiteSpace(existingValue)) return false;   // feature off — nothing to repair

        var registered = ParseExePath(existingValue);
        if (registered is null) return true;                          // malformed — rewrite

        if (string.Equals(registered, currentExePath, StringComparison.OrdinalIgnoreCase))
            return false;                                             // already us

        // Product-rename invariant: once TraceBrake is running, a Run value must never remain pointed at the
        // legacy Foreman.exe merely because that old file still exists. This also covers the observed sibling
        // path where an earlier migration had already renamed the REGISTRY VALUE to "TraceBrake" while copying
        // its old target verbatim, so the registration no longer carried a legacy-name signal of its own.
        if (string.Equals(Path.GetFileName(currentExePath), ProductIdentity.ExecutableName, StringComparison.OrdinalIgnoreCase)
            && string.Equals(Path.GetFileName(registered), ProductIdentity.LegacyExecutableName, StringComparison.OrdinalIgnoreCase))
            return true;

        return !fileExists(registered);                               // heal only if the target is gone
    }

    /// <summary>Why an auto-start target's drive may be missing at logon. SystemDrive = safe.</summary>
    public enum StartupDriveRisk { SystemDrive, NonSystemFixed, Removable, Network, Unknown }

    /// <summary>
    /// Classifies the risk that an auto-start exe won't be reachable at sign-in because of WHERE it lives.
    /// HKCU Run entries fire early at logon and fail SILENTLY when the path's drive isn't mounted — so a target
    /// on anything but the system drive can leave TraceBrake quietly not starting: a removable stick, a network
    /// share, or a secondary/external FIXED disk (e.g. W:) that was disconnected or mounted late. Note a USB or
    /// external drive often reports as Fixed, so "not the system drive" — not just DriveType.Removable — is the
    /// signal that matters. <paramref name="driveType"/> is the OS-reported type of the target's drive,
    /// gathered by the caller (kept as a parameter so this stays platform-free and unit-testable).
    /// </summary>
    public static StartupDriveRisk ClassifyDriveRisk(string? exePath, string? systemDriveRoot, DriveType driveType)
    {
        var root = string.IsNullOrWhiteSpace(exePath) ? null : Path.GetPathRoot(exePath);
        if (string.IsNullOrEmpty(root) || string.IsNullOrEmpty(systemDriveRoot)) return StartupDriveRisk.Unknown;

        if (driveType == DriveType.Removable) return StartupDriveRisk.Removable;
        if (driveType == DriveType.Network)   return StartupDriveRisk.Network;

        return string.Equals(root.TrimEnd('\\', '/'), systemDriveRoot.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase)
            ? StartupDriveRisk.SystemDrive
            : StartupDriveRisk.NonSystemFixed;   // e.g. W: — a fixed but non-system disk that can be disconnected/late
    }

    /// <summary>A user-facing warning for a risky auto-start drive, or null when it's safe (system drive / unknown).</summary>
    public static string? DescribeDriveRisk(StartupDriveRisk risk, string? exePath)
    {
        var drive = (string.IsNullOrWhiteSpace(exePath) ? null : Path.GetPathRoot(exePath)?.TrimEnd('\\', '/')) ?? "that drive";
        return risk switch
        {
            StartupDriveRisk.Removable =>
                $"Start-with-Windows points at a removable drive ({drive}). TraceBrake won't start at sign-in whenever that drive is unplugged — install it on the system drive instead.",
            StartupDriveRisk.Network =>
                $"Start-with-Windows points at a network drive ({drive}). TraceBrake won't start at sign-in until that share is connected — install it on the system drive instead.",
            StartupDriveRisk.NonSystemFixed =>
                $"Start-with-Windows points at {drive}, not the system drive. If {drive} is disconnected or mounts late at sign-in, TraceBrake silently won't start — install it on the system drive instead.",
            _ => null,   // SystemDrive / Unknown — no warning
        };
    }
}
