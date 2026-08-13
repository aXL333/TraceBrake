using Foreman.Core.Behavior;
using Foreman.Core.Models;

namespace Foreman.Core.Alerts;

/// <summary>
/// Automatic, non-destructive responses TraceBrake can take when a harness escalates. Deliberately a
/// closed set of SAFE actions — there is no auto-kill or auto-mute here; destructive/silencing actions
/// stay manual + confirmed. That omission is the core "within reason" guardrail.
/// </summary>
[Flags]
public enum EscalationAction
{
    None               = 0,
    AskHarness         = 1,   // ask the offending harness to justify/correct via its own MCP session + mailbox
    AdversarialAudit   = 2,   // route the alert to a DIFFERENT harness/API for an independent review
    RequestSelfCleanup = 4,   // ask the harness to wrap up / stop leftover children
}

/// <summary>Operator-configured auto-responses per escalation tier (Watch never acts).</summary>
public sealed class AlertResponseSettings
{
    public EscalationAction OnAlert     { get; set; } = EscalationAction.None;
    public EscalationAction OnAlarm     { get; set; } = EscalationAction.AskHarness;
    public EscalationAction OnEmergency { get; set; } = EscalationAction.AskHarness | EscalationAction.AdversarialAudit;

    /// <summary>Per-harness, per-action cooldown so an oscillating harness can't trigger a storm of asks/audits.</summary>
    public int CooldownMinutes { get; set; } = 15;
}

/// <summary>
/// Pure rules for which auto-responses are permitted and which actually fire for a given event/tier.
/// Keeps the destructive-action guardrail and the audit-scope guardrail in one tested place.
/// </summary>
public static class AlertResponsePolicy
{
    /// <summary>The only actions an operator may configure — all non-destructive. Anything else is clamped off.</summary>
    public const EscalationAction Allowed =
        EscalationAction.AskHarness | EscalationAction.AdversarialAudit | EscalationAction.RequestSelfCleanup;

    /// <summary>Clamps a configured value to the allowed (non-destructive) set.</summary>
    public static EscalationAction Sanitize(EscalationAction configured) => configured & Allowed;

    /// <summary>The configured actions for a tier, clamped to the allowed set.</summary>
    public static EscalationAction ForLevel(AlertResponseSettings s, EscalationLevel level) => Sanitize(level switch
    {
        EscalationLevel.Alert     => s.OnAlert,
        EscalationLevel.Alarm     => s.OnAlarm,
        EscalationLevel.Emergency => s.OnEmergency,
        _                         => EscalationAction.None,   // Watch
    });

    /// <summary>
    /// The actions that should ACTUALLY fire for this event: clamped to allowed, then gated —
    /// AdversarialAudit only fires for audit-worthy events (<see cref="AuditPolicy"/>), so housekeeping
    /// (a hang/orphan that escalated) is never routed to a peer auditor even if the tier enables audit.
    /// </summary>
    public static EscalationAction Effective(EscalationAction configured, ForemanEvent evt)
    {
        var a = Sanitize(configured);
        if (a.HasFlag(EscalationAction.AdversarialAudit) && !AuditPolicy.QualifiesForAudit(evt))
            a &= ~EscalationAction.AdversarialAudit;
        return a;
    }
}
