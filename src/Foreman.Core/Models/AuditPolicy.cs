using Foreman.Core.Behavior;

namespace Foreman.Core.Models;

/// <summary>
/// Decides whether an alert is "alarming behavior" worth routing to a cross-LLM auditor (a DIFFERENT
/// agent reviewing this one), versus operational housekeeping (hangs / orphans / mess) that belongs to
/// the offending harness itself via "Ask Harness".
///
/// Cross-LLM audit is reserved for security-relevant events; hangs, orphans, non-zero exits, TraceBrake's
/// own info/monitoring notices, and MCP-inventory/tool-scan notices never route to a peer auditor.
/// </summary>
public static class AuditPolicy
{
    public static bool QualifiesForAudit(ForemanEvent evt)
    {
        // Operational housekeeping + TraceBrake's own notices are never peer-audited.
        if (evt is HangDetectedEvent or OrphanDetectedEvent or NonzeroExitEvent
                or InfoEvent or MonitoringNoticeEvent)
            return false;

        // Security-relevant categories qualify regardless of severity — a flagged command or a
        // permission violation is alarming-in-kind even when scored Medium.
        if (evt is CommandAlertEvent or PermissionViolationEvent)
            return true;

        // Behavior escalation qualifies once it reaches Alarm (High/Critical-equivalent).
        if (evt is EscalationEvent esc)
            return esc.NewLevel >= EscalationLevel.Alarm;

        // Anything else: only High or above.
        return evt.Severity >= ForemanSeverity.High;
    }
}
