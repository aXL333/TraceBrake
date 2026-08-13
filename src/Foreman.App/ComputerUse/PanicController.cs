using System.Runtime.Versioning;
using Foreman.App.Security;
using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.Core.Notifications;
using Foreman.Core.Security;

namespace Foreman.App.ComputerUse;

/// <summary>
/// Orchestrates the computer-use panic kill. HALT is the safe direction and is unguarded + idempotent: it sets the
/// process-global <see cref="CuPanicState"/> (every CU executor checks it before each action) and makes the stop
/// LOUD — a Critical event on the bus + a durable OS-event-log <see cref="OsEventIds.ProtectiveAction"/> record, so
/// it survives even if TraceBrake is later killed. RESUME is the dangerous direction and is gated behind operator
/// presence (Windows Hello) via <see cref="PresenceGuard"/>; an agent can never un-halt itself, and resume is
/// deliberately NOT exposed over MCP. Wired to the global <see cref="PanicHotkey"/> and the tray STOP item.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PanicController
{
    private readonly CuPanicState _panic;
    private readonly EventBus _bus;
    private readonly IOsEventLogSink _osLog;
    private readonly Func<bool> _osLogEnabled;

    public PanicController(CuPanicState panic, EventBus bus, IOsEventLogSink osLog, Func<bool> osLogEnabled)
    {
        _panic = panic;
        _bus = bus;
        _osLog = osLog;
        _osLogEnabled = osLogEnabled;
    }

    public bool IsHalted => _panic.IsHalted;

    /// <summary>Halt all TraceBrake-mediated computer/browser use now. No gate (safe direction). Loud only on the first halt.</summary>
    public void Halt(string trigger)
    {
        if (!_panic.Halt()) return;   // already halted — don't double-log
        _bus.Publish(new MonitoringNoticeEvent(
            DateTimeOffset.UtcNow, ForemanSeverity.Critical, "Foreman.ComputerUse",
            $"PANIC: computer use HALTED ({trigger}). All TraceBrake-mediated browser/desktop/Android actions are stopped. " +
            "Resume requires operator presence."));
        if (_osLogEnabled())
            _osLog.Write(OsEventIds.ProtectiveAction, OsEventCategory.Security, ForemanSeverity.Critical,
                $"Computer-use panic halt ({trigger}). Mediated computer use stopped; resume is operator + presence gated.");
    }

    /// <summary>Resume computer use (operator only). Presence-gated; returns (ok, message) for the caller to surface.</summary>
    public async Task<(bool Ok, string Message)> ResumeAsync()
    {
        if (!_panic.IsHalted) return (true, "Computer use is not halted.");
        // The panic STOP is the operator's emergency brake; releasing it is a CU-sovereignty action that demands a
        // FRESH presence tap REGARDLESS of the lock being off / unconfigured, and never rides the approval cache
        // (spec INV-16). forcePresence + freshTap, not the defaults - shipping without these left resume ungated.
        if (!await PresenceGuard.AuthorizeAsync(WeakeningAction.ResumeComputerUse,
                "resume computer use after a panic stop", forcePresence: true, freshTap: true).ConfigureAwait(false))
            return (false, "Presence not verified — computer use stays halted.");

        _panic.Resume();
        _bus.Publish(new MonitoringNoticeEvent(
            DateTimeOffset.UtcNow, ForemanSeverity.Medium, "Foreman.ComputerUse",
            "Computer use RESUMED by operator (presence-verified)."));
        if (_osLogEnabled())
            _osLog.Write(OsEventIds.ProtectiveAction, OsEventCategory.Security, ForemanSeverity.Medium,
                "Computer-use resumed by operator (presence-verified).");
        return (true, "Computer use resumed.");
    }
}
