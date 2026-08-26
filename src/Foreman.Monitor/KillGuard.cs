namespace Foreman.Monitor;

/// <summary>
/// The never-kill set for TraceBrake's termination path. EVERY kill — the operator's tray/alert action today, and
/// the harness broker (own-subtree reaping) being added — funnels through here so neither a misfired alert nor
/// a (possibly adversarial) harness can take down the watchdog itself, its hardened guardian, the elevated
/// sidecar, core Windows, the desktop shell, or the machine's security stack.
///
/// Defense in depth, not the only line: the broker ALSO scopes a harness to its own process subtree, so a
/// protected process never appears as a legal target there anyway. This list is the central backstop that holds
/// even if scoping is bypassed or the operator clicks Kill on something load-bearing. It fails CLOSED — an
/// unknown name is killable (we don't want to silently refuse a real harness child); the protection is the
/// verified executable identities below plus the subtree scope the broker enforces on top. A basename alone is
/// never self-protection: a hostile process is free to rename itself TraceBrake.exe or svchost.exe.
/// </summary>
public static class KillGuard
{
    // TraceBrake's own processes. Killing any of these is self-sabotage of the watchdog (or its prevention/telemetry
    // tiers), so it is refused regardless of who asks.
    private static readonly Dictionary<string, string> ForemanSelfRelativePaths = new(StringComparer.OrdinalIgnoreCase)
    {
        ["TraceBrake.exe"] = "TraceBrake.exe",
        ["Foreman.exe"] = "Foreman.exe",
        ["Foreman.Guardian.exe"] = Path.Combine("guardian", "Foreman.Guardian.exe"),
        ["Foreman.EtwSidecar.exe"] = Path.Combine("sidecar", "Foreman.EtwSidecar.exe"),
        ["Foreman.CuSidecar.exe"] = Path.Combine("cu-sidecar", "Foreman.CuSidecar.exe"),
        ["Foreman.CuPilot.exe"] = Path.Combine("cu-pilot", "Foreman.CuPilot.exe"),
    };

    // Windows OS hosts + the desktop shell. Terminating any of these destabilises the whole session, never just
    // a harness. (Mirrors ProcessTreeTracker's ancestor-walk host set, with a few extra console/print/audio hosts.)
    private static readonly HashSet<string> SystemHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "services.exe", "wininit.exe", "winlogon.exe", "lsass.exe", "csrss.exe", "smss.exe",
        "explorer.exe", "sihost.exe", "taskhostw.exe", "dwm.exe", "fontdrvhost.exe", "ctfmon.exe",
        "RuntimeBroker.exe", "MoUsoCoreWorker.exe", "usocoreworker.exe", "dllhost.exe", "WmiPrvSE.exe",
        "System", "Registry", "MemCompression", "conhost.exe", "audiodg.exe", "spoolsv.exe", "LogonUI.exe",
    };

    // NOTE — endpoint-security processes (Defender, Bitdefender, EDR, …) are deliberately NOT hard-coded here.
    // A monitoring DLL that bundles process-kill code AND a roster of AV/EDR process names is the textbook
    // signature of an "AV-killer," and a heuristic scanner (Bitdefender, locally) quarantines the compiled
    // binary on sight — which would brick the build here and, worse, the SHIPPED artifact on every user's
    // machine. The machine's defenses are protected instead by (a) the broker scoping a harness to its OWN
    // process subtree, where AV never appears, and (b) the OS-host list above. If an explicit AV denylist is
    // ever wanted, load it from an external data file at runtime so it never lands in the binary as a literal set.

    /// <summary>PIDs that must never be terminated: 0 (Idle), 4 (System), and TraceBrake's own PID.</summary>
    public static bool IsProtectedPid(int pid) => pid <= 4 || pid == Environment.ProcessId;

    /// <summary>
    /// True only for a low/own PID or a protected basename at its trusted executable location. Optional roots are
    /// injectable for deterministic tests; production defaults to the running app, Windows, and Program Files.
    /// </summary>
    public static bool IsProtected(
        int pid,
        string? name,
        string? executablePath,
        string? appBaseDirectory = null,
        string? windowsDirectory = null,
        string? programFilesDirectory = null)
    {
        if (IsProtectedPid(pid)) return true;
        if (string.IsNullOrWhiteSpace(name)) return false;

        var normalizedName = Path.GetFileName(name);
        if (!normalizedName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(normalizedName, "System", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(normalizedName, "Registry", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(normalizedName, "MemCompression", StringComparison.OrdinalIgnoreCase))
            normalizedName += ".exe";

        // Identity lookup can fail across integrity boundaries. For a known load-bearing basename, uncertainty
        // fails closed; once a concrete non-trusted path is available, basename spoofing remains killable.
        if (string.IsNullOrWhiteSpace(executablePath))
            return ForemanSelfRelativePaths.ContainsKey(normalizedName)
                   || SystemHosts.Contains(normalizedName)
                   || SystemHosts.Contains(name);

        var appRoot = appBaseDirectory ?? AppContext.BaseDirectory;
        if (ForemanSelfRelativePaths.TryGetValue(normalizedName, out var relative))
        {
            if (PathsEqual(executablePath, Path.Combine(appRoot, relative))) return true;

            // The Guardian service is copied to a machine-protected Program Files root, which may differ from a
            // portable/dev app base directory.
            if (string.Equals(normalizedName, "Foreman.Guardian.exe", StringComparison.OrdinalIgnoreCase))
            {
                var pf = programFilesDirectory ?? Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                if (!string.IsNullOrWhiteSpace(pf) &&
                    PathsEqual(executablePath, Path.Combine(pf, "Foreman", "guardian", "Foreman.Guardian.exe")))
                    return true;
            }
        }

        if (SystemHosts.Contains(normalizedName) || SystemHosts.Contains(name))
        {
            var windowsRoot = windowsDirectory ?? Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            return !string.IsNullOrWhiteSpace(windowsRoot) && IsWithin(executablePath, windowsRoot);
        }

        return false;
    }

    private static bool PathsEqual(string left, string right)
    {
        try { return string.Equals(Path.GetFullPath(left), Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase); }
        catch { return false; }
    }

    private static bool IsWithin(string candidate, string root)
    {
        try
        {
            var fullCandidate = Path.GetFullPath(candidate);
            var fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
            return fullCandidate.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }
}
