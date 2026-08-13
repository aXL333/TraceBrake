using Foreman.Core.Behavior;
using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.Core.Security;

namespace Foreman.Core.Notifications;

/// <summary>
/// Subscribes to the <see cref="EventBus"/> and mirrors the SECURITY-significant subset of events to the OS
/// event log (the blackbox handoff). It mirrors only what a Defender-style external record should carry —
/// escalations (Alarm+), command/credential detections, permission violations, decoy tripwires, and anything
/// High+ — NOT routine hang / orphan / non-zero-exit / info noise (that stays in the on-disk JSONL + UI).
///
/// Secrets are redacted (<see cref="SecretRedactor"/>) before anything reaches the OS log — the system log is an
/// egress boundary just like the disk log. Lifecycle events (start/stop/crash) are written DIRECTLY by the host
/// (they can't depend on the bus, e.g. a crash on the way down), not through this forwarder.
/// </summary>
public sealed class OsEventLogForwarder : IEventSink
{
    private readonly IOsEventLogSink _sink;
    private readonly Func<bool> _enabled;

    public OsEventLogForwarder(IOsEventLogSink sink, Func<bool>? enabled = null)
    {
        _sink = sink;
        _enabled = enabled ?? (() => true);
    }

    public void OnEvent(ForemanEvent evt)
    {
        if (!_enabled() || !_sink.IsAvailable) return;
        if (!ShouldMirror(evt)) return;

        var (id, category) = Classify(evt);
        var redacted = SecretRedactor.RedactEvent(evt);   // never leak secrets to the OS log
        _sink.Write(id, category, evt.Severity, BuildMessage(redacted));
    }

    /// <summary>
    /// The OS-log mirror set — deliberately its OWN policy, NOT <see cref="AuditPolicy"/> (that decides peer-LLM
    /// audit routing and excludes TraceBrake's own monitoring notices). For the blackbox handoff we keep the log
    /// high-signal — no routine hang/orphan/non-zero-exit/info — but we DO want serious monitoring-health notices
    /// (WMI watcher degraded, MCP server down) recorded externally. So: security-in-kind events always, escalations
    /// once Alarm+, monitoring notices and everything else only at High+.
    /// </summary>
    public static bool ShouldMirror(ForemanEvent evt) => evt switch
    {
        InfoEvent or HangDetectedEvent or OrphanDetectedEvent or NonzeroExitEvent => false,
        CommandAlertEvent or PermissionViolationEvent => true,
        EscalationEvent e => e.NewLevel >= EscalationLevel.Alarm,
        _ => evt.Severity >= ForemanSeverity.High,
    };

    private static (int id, OsEventCategory category) Classify(ForemanEvent evt) => evt switch
    {
        EscalationEvent e when e.NewLevel >= EscalationLevel.Emergency => (OsEventIds.EscalationEmergency, OsEventCategory.Security),
        EscalationEvent                                                => (OsEventIds.EscalationAlarm, OsEventCategory.Security),
        CommandAlertEvent c when IsDecoy(c)                            => (OsEventIds.DecoyTripwire, OsEventCategory.Security),
        CommandAlertEvent                                             => (OsEventIds.CommandAlert, OsEventCategory.Security),
        PermissionViolationEvent                                      => (OsEventIds.PermissionViolation, OsEventCategory.Security),
        // Monitoring-health notices (WMI watcher degraded, MCP server bind failure) surface as Health, split by source.
        MonitoringNoticeEvent m when m.Source.Contains("Mcp", StringComparison.OrdinalIgnoreCase)
                                                                      => (OsEventIds.McpServerStateChanged, OsEventCategory.Health),
        MonitoringNoticeEvent                                         => (OsEventIds.MonitoringDegraded, OsEventCategory.Health),
        _                                                            => (OsEventIds.SecuritySignificant, OsEventCategory.Security),
    };

    // The decoy honeytoken rule (cred-040) is the highest-signal tripwire — give it its own event ID.
    private static bool IsDecoy(CommandAlertEvent c) =>
        !string.IsNullOrEmpty(c.RuleId) && c.RuleId.StartsWith("cred-040", StringComparison.OrdinalIgnoreCase);

    // Concise one-liner for the OS log. evt is already redacted; its Message is the human-readable summary, which
    // we enrich with the rule id (CommandAlert) for SIEM filtering.
    private static string BuildMessage(ForemanEvent evt)
    {
        var rule = evt is CommandAlertEvent c && !string.IsNullOrEmpty(c.RuleId) ? $" [rule={c.RuleId}]" : "";
        return $"{evt.Source}: {evt.Message}{rule}";
    }
}
