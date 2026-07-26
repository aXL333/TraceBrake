using Foreman.Core.Models;

namespace Foreman.Core.Health;

/// <summary>
/// Keeps the elevated sidecar's liveness honestly reflected to the operator and recovers a crashed one. Pure
/// state machine — no timers or IO — so the App ticks it on a periodic timer and injects the effects, and it is
/// unit-tested without elevation.
///
/// It closes two gaps in the fire-and-forget launch model:
///   • A CRASHED sidecar (seen connected, then dropped while the feature is still enabled) used to stay dead,
///     silently, until the next settings toggle or app restart. It is now auto-relaunched a bounded number of
///     times, with a High notice, then left with a standing notice if it keeps dying.
///   • A sidecar that NEVER comes up (declined UAC, missing/blocked helper) used to surface only as a passive
///     Setup-tab row. It now raises a High notice — but is deliberately NOT auto-relaunched, since re-invoking a
///     declined launch just re-prompts UAC on a loop. A decline is stated once, not nagged.
///
/// One grace tick is always allowed before acting, so a settings-toggle restart's brief disconnect or a slow
/// first launch is not mistaken for a failure.
/// </summary>
public sealed class SidecarSupervisor
{
    private readonly Func<bool> _expectedUp;
    private readonly Func<bool> _isConnected;
    private readonly Func<bool> _launchDeclined;
    private readonly Func<bool> _launchInProgress;
    private readonly Action _relaunch;
    private readonly Action<ForemanSeverity, string> _notify;
    private readonly int _maxRelaunch;
    private readonly int _graceTicks;

    private bool _wasConnected;       // seen connected at least once this expected-up episode
    private int _relaunchAttempts;    // relaunches tried this down-spell
    private int _downTicks;           // consecutive ticks expected-up but not connected
    private bool _downNotified;       // a down notice already emitted this down-spell
    private bool _exhaustedNotified;  // the give-up notice already emitted this down-spell

    public SidecarSupervisor(
        Func<bool> expectedUp,
        Func<bool> isConnected,
        Func<bool> launchDeclined,
        Action relaunch,
        Action<ForemanSeverity, string> notify,
        int maxRelaunch = 2,
        int graceTicks = 1,
        Func<bool>? launchInProgress = null)
    {
        _expectedUp = expectedUp;
        _isConnected = isConnected;
        _launchDeclined = launchDeclined;   // last launch attempt failed to START (declined UAC / missing helper)
        _launchInProgress = launchInProgress ?? (() => false);
        _relaunch = relaunch;
        _notify = notify;
        _maxRelaunch = Math.Max(0, maxRelaunch);
        _graceTicks = Math.Max(0, graceTicks);
    }

    /// <summary>Advance the state machine one step. Call on a periodic timer (e.g. every ~30s).</summary>
    public void Tick()
    {
        if (!_expectedUp())
        {
            // Feature off (or not yet enabled): nothing to supervise; forget the last episode.
            ResetEpisode();
            return;
        }

        if (_isConnected())
        {
            if (_downNotified)
                TryNotify(ForemanSeverity.Info,
                    "The elevated helper reconnected — decoy read-auditing / network capture is active again.");
            _wasConnected = true;
            _relaunchAttempts = 0;
            _downTicks = 0;
            _downNotified = false;
            _exhaustedNotified = false;
            return;
        }

        // Process.Start(... UseShellExecute=true) waits for the operator to answer UAC. The helper is necessarily
        // disconnected during that wait and its pipe handshake. Do not accumulate down ticks or spend the relaunch
        // budget while a real launch is already pending, or watchdog ticks can stack UAC prompts.
        if (_launchInProgress())
        {
            _downTicks = 0;
            return;
        }

        // Expected up but not connected. Ride out one grace tick so a settings-toggle restart's brief disconnect
        // (or a slow first launch) is not mistaken for a failure.
        if (++_downTicks <= _graceTicks) return;

        // A genuine CRASH is: we saw it connected, and the most recent launch attempt did NOT fail to start (the
        // process ran and the pipe later broke). Only that is auto-recovered — bounded — since re-launching pops a
        // fresh UAC prompt. A DECLINED re-elevation (launchDeclined) or a never-connected launch is NOT relaunched,
        // so a user who declines the admin prompt is told once, never nagged with a loop of prompts.
        if (_wasConnected && !_launchDeclined())
        {
            if (_relaunchAttempts < _maxRelaunch)
            {
                if (!_downNotified)
                {
                    TryNotify(ForemanSeverity.High,
                        "The elevated helper stopped unexpectedly — decoy read-auditing / network capture is not " +
                        "active. Relaunching it (this may prompt for administrator).");
                    _downNotified = true;
                }
                _relaunchAttempts++;
                try { _relaunch(); }
                catch
                {
                    TryNotify(ForemanSeverity.High,
                        "The elevated helper relaunch failed before it could start. Monitoring remains degraded.");
                }
                return;
            }
            if (!_exhaustedNotified)
            {
                TryNotify(ForemanSeverity.High,
                    "The elevated helper keeps stopping — decoy read-auditing / network capture is OFF. Re-enable it " +
                    "in Settings to retry (you'll be prompted for administrator).");
                _exhaustedNotified = true;
            }
            return;
        }

        // Never connected, or the (re)launch was declined / failed to start → state it once, do NOT re-prompt UAC.
        if (!_downNotified)
        {
            TryNotify(ForemanSeverity.High,
                "The elevated helper isn't running, so decoy read-auditing / network capture is OFF. If you declined " +
                "the administrator prompt, re-enable it in Settings to try again.");
            _downNotified = true;
        }
    }

    /// <summary>
    /// Starts a new supervision episode. Settings code calls this at the toggle boundary so a rapid off-to-on
    /// transition cannot retain stale state merely because it happened between periodic watchdog ticks.
    /// </summary>
    public void ResetEpisode()
    {
        _wasConnected = false;
        _relaunchAttempts = 0;
        _downTicks = 0;
        _downNotified = false;
        _exhaustedNotified = false;
    }

    private void TryNotify(ForemanSeverity severity, string message)
    {
        try { _notify(severity, message); }
        catch { /* notification failure must not suppress the recovery action */ }
    }
}
