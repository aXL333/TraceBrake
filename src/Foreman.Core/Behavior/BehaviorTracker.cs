using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.Core.Settings;
using System.Collections.Concurrent;
using System.Text;

namespace Foreman.Core.Behavior;

/// <summary>
/// Subscribes to the EventBus and maintains per-harness behavioral profiles.
/// When a profile crosses a severity threshold, publishes an EscalationEvent.
///
/// Keying strategy:
///   - Known harness → HarnessType ("claude-code", "aider", "custom:myagent.exe")
///   - Unclassified  → "proc:{processName}"
/// </summary>
public sealed class BehaviorTracker : IEventSink
{
    private readonly ConcurrentDictionary<string, BehaviorProfile> _profiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly ForemanSettings _settings;
    private readonly EventBus _bus;
    private readonly Func<int, ProcessRecord?> _lookupByPid;
    private readonly Func<int, ProcessRecord?> _findHarnessAncestor;
    private readonly Func<string, EscalationThresholds> _resolveThresholds;

    public IEnumerable<BehaviorProfile> Profiles => _profiles.Values;

    public BehaviorTracker(
        ForemanSettings settings,
        EventBus bus,
        Func<int, ProcessRecord?> lookupByPid,
        Func<int, ProcessRecord?> findHarnessAncestor,
        Func<string, EscalationThresholds>? resolveThresholds = null)
    {
        _settings            = settings;
        _bus                 = bus;
        _lookupByPid         = lookupByPid;
        _findHarnessAncestor = findHarnessAncestor;
        // Per-harness Trust thresholds; defaults to the flat global baseline (unchanged behavior + tests).
        _resolveThresholds   = resolveThresholds ?? (_ => EscalationThresholds.FromGlobal(settings));
        bus.Subscribe(this);
    }

    // ── IEventSink ───────────────────────────────────────────────────────────

    void IEventSink.OnEvent(ForemanEvent evt)
    {
        // "test-*" rules are synthetic (tray → Send test alert): they must light up the
        // notification path without feeding escalation — a drill is not behavior.
        if (evt is CommandAlertEvent cmd &&
            !cmd.RuleId.StartsWith("test-", StringComparison.OrdinalIgnoreCase))
        {
            ProcessCommandAlert(cmd);
        }
    }

    // ── Core logic ───────────────────────────────────────────────────────────

    private void ProcessCommandAlert(CommandAlertEvent cmd)
    {
        var key     = GetHarnessKey(cmd.ProcessId, cmd.Source);
        var profile = _profiles.GetOrAdd(key, k => new BehaviorProfile(k));

        var oldLevel = profile.CurrentLevel;
        profile.RecordAlert(cmd);
        var newLevel = Evaluate(profile);

        if (newLevel > oldLevel)
        {
            profile.CurrentLevel = newLevel;
            PublishEscalation(profile, newLevel, oldLevel, cmd);
        }
    }

    // ── Threshold evaluation ─────────────────────────────────────────────────

    private EscalationLevel Evaluate(BehaviorProfile p)
    {
        // Per-harness Trust thresholds (level 3 / unset == the global baseline). The unconditional clauses
        // below (cred+priv+net, Critical>=2, Critical>=1, High>=1, 2 categories) are deliberately NOT
        // Trust-tunable — they're the floor that holds even for a "hands-off" harness.
        var t = _resolveThresholds(p.HarnessId);

        // ── Emergency ────────────────────────────────────────────────────────
        // specific high-risk rules always jump straight to Emergency
        if (t.EmergencyRuleIds.Any(id => p.HasRule(id)))
            return EscalationLevel.Emergency;

        // pure volume threshold
        if (p.TotalAlerts >= t.EmergencyLevelTotalAlerts)
            return EscalationLevel.Emergency;

        // all 3 major categories: credential + privilege + network = comprehensive attack
        if (p.HasCategory("cred") && p.HasCategory("priv") && p.HasCategory("net"))
            return EscalationLevel.Emergency;

        // multiple critical alerts
        if (p.GetSeverityCount("Critical") >= 2)
            return EscalationLevel.Emergency;

        // ── Alarm ────────────────────────────────────────────────────────────
        if (p.GetSeverityCount("Critical") >= 1)
            return EscalationLevel.Alarm;

        if (p.UniqueRulesCount >= t.AlarmLevelUniqueRules)
            return EscalationLevel.Alarm;

        if (p.CategoryCount >= t.AlarmLevelCategories)
            return EscalationLevel.Alarm;

        if (p.GetSeverityCount("High") >= t.AlarmLevelHighCount)
            return EscalationLevel.Alarm;

        // ── Alert ────────────────────────────────────────────────────────────
        if (p.GetSeverityCount("High") >= 1)
            return EscalationLevel.Alert;

        if (p.GetSeverityCount("Medium") >= t.AlertLevelMediumCount)
            return EscalationLevel.Alert;

        // two threat categories simultaneously = Alert
        if (p.CategoryCount >= 2)
            return EscalationLevel.Alert;

        return EscalationLevel.Watch;
    }

    // ── Event publishing ─────────────────────────────────────────────────────

    private void PublishEscalation(
        BehaviorProfile profile,
        EscalationLevel newLevel,
        EscalationLevel oldLevel,
        CommandAlertEvent trigger)
    {
        var reason = BuildReason(profile, newLevel, trigger);

        _bus.Publish(new EscalationEvent(
            DateTimeOffset.UtcNow,
            newLevel,
            oldLevel,
            profile.HarnessId,
            profile.DisplayName,
            reason,
            profile.TotalAlerts,
            profile.UniqueRulesCount,
            profile.CategoryCount,
            profile.Categories.ToArray(),
            trigger.RuleId,
            trigger.RuleName,
            trigger.CommandLine));
    }

    private static string BuildReason(BehaviorProfile p, EscalationLevel newLevel, CommandAlertEvent trigger)
    {
        var sb = new StringBuilder();
        sb.Append(newLevel switch
        {
            EscalationLevel.Emergency => "Emergency",
            EscalationLevel.Alarm     => "Alarm",
            EscalationLevel.Alert     => "Alert",
            _                         => "Watch",
        });
        sb.Append($" — {p.TotalAlerts} alert(s), {p.UniqueRulesCount} unique rule(s)");

        if (p.CategoryCount > 0)
            sb.Append($", categories: {string.Join(", ", p.Categories)}");

        if (!string.IsNullOrEmpty(trigger.RuleName))
            sb.Append($". Trigger: [{trigger.RuleId}] {trigger.RuleName}");

        return sb.ToString();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private string GetHarnessKey(int processId, string source)
    {
        var rec = _lookupByPid(processId);
        if (rec?.HarnessType is { } ht) return ht;

        // The process itself matched no harness rule, but it may be a child of one —
        // e.g. a PowerShell hook or shell spawned by claude-code. Attribute it to the
        // harness ancestor so its alerts accrue to that harness's profile rather than a
        // bogus "proc:powershell.exe" bucket.
        if (_findHarnessAncestor(processId)?.HarnessType is { } ancestorHt) return ancestorHt;

        // extract process name from "processName (pid 12345)"
        var idx  = source.IndexOf(" (pid", StringComparison.Ordinal);
        var name = idx > 0 ? source[..idx] : source;
        return $"proc:{name}";
    }

    public BehaviorProfile? GetProfile(string harnessId) =>
        _profiles.TryGetValue(harnessId, out var p) ? p : null;

    public void ResetProfile(string harnessId)
    {
        if (_profiles.TryGetValue(harnessId, out var p))
            p.Reset();
    }
}
