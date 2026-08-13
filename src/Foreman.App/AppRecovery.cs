using System.Runtime.InteropServices;

namespace Foreman.App;

/// <summary>
/// Watchdog-of-the-watchdog (B9 clever improvement #1): asks Windows to RESTART TraceBrake if it terminates
/// abnormally, and recognises when the current launch IS such a restart.
///
/// <see cref="RegisterApplicationRestart"/> is the same Windows Error Reporting mechanism Windows uses to bring
/// an app back after a crash/hang/update. We register on every launch with a sentinel argument so the respawned
/// instance can tell "Windows restarted me" from a normal start. The OS only restarts an app that ran for at
/// least ~60s (its built-in anti-restart-loop guard), and we exclude OS patch/reboot so we don't fight Windows
/// Update. A hard <c>TerminateProcess</c> kill is NOT guaranteed to trigger the OS restart — but that case is
/// still DETECTED on the next launch by the dangling-Started signal in the OS event log
/// (<see cref="Foreman.Core.Events.LifecycleForensics"/>), so the kill never goes unnoticed either way.
/// </summary>
internal static class AppRecovery
{
    /// <summary>Argument Windows passes to the restarted instance so it knows it was auto-recovered.</summary>
    public const string RestartSentinel = "/foreman-restarted";

    // RESTART_NO_PATCH (4) | RESTART_NO_REBOOT (8): restart on crash/hang, but not for OS update or after a reboot.
    private const int RestartFlags = 0x4 | 0x8;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegisterApplicationRestart(string? pwzCommandline, int dwFlags);

    /// <summary>Registers TraceBrake for OS-driven restart on abnormal termination. Best-effort; never throws.</summary>
    public static void RegisterForRestart()
    {
        try { RegisterApplicationRestart(RestartSentinel, RestartFlags); }
        catch { /* unsupported / older OS — the OS-event-log kill detection still covers us */ }
    }

    /// <summary>True when this process was started by Windows as an abnormal-termination restart.</summary>
    public static bool WasRestartedByOs(IEnumerable<string>? args) =>
        args is not null && args.Any(a => string.Equals(a, RestartSentinel, StringComparison.OrdinalIgnoreCase));
}
