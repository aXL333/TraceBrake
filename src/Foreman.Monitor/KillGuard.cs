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
/// explicit set below plus the subtree scope the broker enforces on top.
/// </summary>
public static class KillGuard
{
    // TraceBrake's own processes. Killing any of these is self-sabotage of the watchdog (or its prevention/telemetry
    // tiers), so it is refused regardless of who asks.
    private static readonly HashSet<string> ForemanSelf = new(StringComparer.OrdinalIgnoreCase)
    {
        "TraceBrake.exe", "Foreman.exe", "Foreman.Guardian.exe", "Foreman.EtwSidecar.exe",
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

    /// <summary>True if this process must never be terminated — by low/own PID, or by a protected process name.</summary>
    public static bool IsProtected(int pid, string? name) =>
        IsProtectedPid(pid)
        || (name is not null && (ForemanSelf.Contains(name) || SystemHosts.Contains(name)));
}
