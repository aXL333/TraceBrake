using Foreman.Core.Alerts;

namespace Foreman.Core.Settings;

/// <summary>
/// Maps a per-harness Trust level (1=locked-down … 5=hands-off) onto TraceBrake's existing knobs, so one slider
/// drives behavior coherently. Trust 3 is the neutral level (== today's global defaults), lower fires sooner /
/// responds harder, higher is more permissive.
///
/// Two guardrails are baked in and non-negotiable, regardless of level:
///  - The always-escalate <c>EmergencyRuleIds</c> set is NEVER shrunk below the global baseline (Trust 1 only
///    ADDS ids). A looser Trust raises the count thresholds, but the catastrophic single-action patterns
///    (LSASS dump, ransomware VSS-delete, reverse shells, …) still jump straight to Emergency at every level.
///  - Auto-responses remain clamped by <see cref="AlertResponsePolicy.Sanitize"/> (no auto-kill/auto-mute is
///    even expressible), and Critical command alerts always notify (handled in the notification path).
/// </summary>
public static class TrustPreset
{
    /// <summary>High-value ids Trust 1 adds on top of the global baseline (deduped). cred-018/win-009 are
    /// already in the default set; cred-001 (generic credential-file read) is the meaningful addition.</summary>
    private static readonly string[] LockdownExtraEmergencyIds = ["cred-001", "cred-018", "win-009"];

    /// <summary>Escalation thresholds for a level, over the global baseline. Level 3 (and out-of-range) returns
    /// the baseline unchanged.</summary>
    public static EscalationThresholds Thresholds(int level, ForemanSettings baseline)
    {
        var lvl = Math.Clamp(level, 1, 5);
        if (lvl == 3) return EscalationThresholds.FromGlobal(baseline);   // neutral = today's globals, verbatim

        // Never shrink the always-escalate set below the baseline; Trust 1 adds a few high-value ids.
        var ids = lvl == 1
            ? baseline.EmergencyRuleIds.Concat(LockdownExtraEmergencyIds)
                      .Distinct(StringComparer.OrdinalIgnoreCase).ToArray()
            : baseline.EmergencyRuleIds;

        //                          mediumCount, highCount, uniqueRules, categories, emergencyTotal
        return lvl switch
        {
            1 => new(1, 1, 3, 2, 5,  ids),   // locked-down: fire on the first hint
            2 => new(2, 1, 4, 2, 7,  ids),   // strict
            4 => new(5, 3, 7, 3, 15, ids),   // trusted: more rope before escalating
            5 => new(8, 5, 10, 4, 25, ids),  // hands-off: only sustained or catastrophic behavior escalates
            _ => EscalationThresholds.FromGlobal(baseline),
        };
    }

    /// <summary>Auto-response tiers for a level. Level 3 returns the default settings (None / AskHarness /
    /// Ask+Audit). Lower = respond harder; higher = quieter, but Emergency always at least asks the harness.</summary>
    public static AlertResponseSettings Responses(int level)
    {
        const EscalationAction ask     = EscalationAction.AskHarness;
        const EscalationAction audit   = EscalationAction.AdversarialAudit;
        const EscalationAction cleanup = EscalationAction.RequestSelfCleanup;

        return Math.Clamp(level, 1, 5) switch
        {
            1 => new() { OnAlert = ask,                OnAlarm = ask | audit, OnEmergency = ask | audit | cleanup },
            2 => new() { OnAlert = ask,                OnAlarm = ask | audit, OnEmergency = ask | audit },
            4 => new() { OnAlert = EscalationAction.None, OnAlarm = ask,      OnEmergency = ask | audit },
            5 => new() { OnAlert = EscalationAction.None, OnAlarm = EscalationAction.None, OnEmergency = ask },
            _ => new(),   // level 3: defaults (OnAlert None, OnAlarm AskHarness, OnEmergency Ask|Audit)
        };
    }
}
