using Foreman.Core.Models;

namespace Foreman.Core.Alerts;

/// <summary>
/// Numeric, command-free snapshot captured when a hang candidate is raised. SchemaVersion
/// lets a future trainer reject incompatible rows rather than silently mixing feature sets.
/// None of these values influences detection yet; this is shadow-only learning telemetry.
/// </summary>
public sealed record HangFeatureSnapshot(
    int SchemaVersion,
    int SilentMinutes,
    int UptimeMinutes,
    double SilentFraction,
    ulong ReadOperations,
    ulong WriteOperations,
    int TreeProcessCount,
    int RecentlyActiveTreeProcesses,
    int TreeIdleMinutes,
    int OperatorIdleMinutes,
    HarnessActivity HarnessActivity,
    int EffectiveThresholdMinutes,
    double ThresholdMultiplier,
    bool DirectHarnessChild);

public enum HangOutcomeKind
{
    IoResumed,
    ProcessExited,
    OperatorConfirmedHung,
    OperatorExpectedIdle,
    OperatorUnsure,
}

public sealed record HangTrainingRow(
    string AlertId,
    DateTimeOffset ObservedAt,
    string ProcessName,
    HangFeatureSnapshot Features,
    int? Label,
    bool GoldLabel,
    HangOutcomeKind? LatestOutcome);

public static class HangLearning
{
    public const int FeatureSchemaVersion = 1;

    public static HangFeatureSnapshot Capture(
        ProcessRecord process,
        ProcessRecord? harness,
        IReadOnlyList<ProcessRecord> tree,
        int operatorIdleMinutes,
        HarnessActivity activity,
        IdleThresholdResult threshold,
        int activityWindowMinutes)
    {
        ArgumentNullException.ThrowIfNull(process);
        tree ??= [];

        var now = DateTimeOffset.UtcNow;
        var uptime = Math.Max(0, process.UptimeMinutes);
        var silent = Math.Max(0, process.SilentMinutes);
        var recentCutoff = now - TimeSpan.FromMinutes(Math.Max(1, activityWindowMinutes));
        var liveTree = tree.Where(p => p.State != ProcessState.Terminated).ToList();
        var recentlyActive = liveTree.Count(p => !p.IoCountersUnavailable && p.LastIoChangeTime >= recentCutoff);
        var treeIdle = liveTree.Count == 0
            ? silent
            : Math.Max(0, (int)(now - liveTree.Max(p => p.LastIoChangeTime)).TotalMinutes);

        return new HangFeatureSnapshot(
            FeatureSchemaVersion,
            silent,
            uptime,
            uptime == 0 ? 1.0 : Math.Clamp((double)silent / uptime, 0.0, 1.0),
            process.LastReadOps,
            process.LastWriteOps,
            liveTree.Count,
            recentlyActive,
            treeIdle,
            Math.Max(0, operatorIdleMinutes),
            activity,
            Math.Max(1, threshold.EffectiveMinutes),
            Math.Max(1.0, threshold.Multiplier),
            harness is not null && process.ParentPid == harness.Pid);
    }

    public static HangOutcomeEvent Outcome(
        HangDetectedEvent hang,
        HangOutcomeKind outcome,
        DateTimeOffset timestamp,
        bool operatorLabeled) =>
        new(timestamp, "Foreman.HangLearning", OutcomeMessage(hang, outcome),
            hang.Id, hang.ProcessId, hang.ProcessStartTime, outcome, operatorLabeled);

    /// <summary>
    /// Joins append-only candidates and outcomes. Only explicit human binary labels become
    /// supervised labels; recovery, exit, and "unsure" remain useful outcomes but label=null.
    /// </summary>
    public static IReadOnlyList<HangTrainingRow> BuildRows(IEnumerable<ForemanEvent> events)
    {
        var all = events.ToList();
        var outcomes = all.OfType<HangOutcomeEvent>()
            .GroupBy(o => o.HangAlertId, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.OrderBy(o => o.Timestamp).ToList(), StringComparer.Ordinal);

        var rows = new List<HangTrainingRow>();
        foreach (var hang in all.OfType<HangDetectedEvent>().Where(h => h.LearningFeatures is not null))
        {
            outcomes.TryGetValue(hang.Id, out var candidates);
            var latest = candidates?.LastOrDefault();
            var gold = candidates?.LastOrDefault(o => o.OperatorLabeled &&
                o.Outcome is HangOutcomeKind.OperatorConfirmedHung or HangOutcomeKind.OperatorExpectedIdle);
            var label = gold?.Outcome switch
            {
                HangOutcomeKind.OperatorConfirmedHung => 1,
                HangOutcomeKind.OperatorExpectedIdle => 0,
                _ => (int?)null,
            };
            rows.Add(new HangTrainingRow(
                hang.Id, hang.Timestamp, hang.ProcessName, hang.LearningFeatures!, label,
                gold is not null, latest?.Outcome));
        }
        return rows;
    }

    private static string OutcomeMessage(HangDetectedEvent hang, HangOutcomeKind outcome) => outcome switch
    {
        HangOutcomeKind.IoResumed => $"Hang candidate [{hang.Id}] observed I/O resume for {hang.ProcessName} (pid {hang.ProcessId}).",
        HangOutcomeKind.ProcessExited => $"Hang candidate [{hang.Id}] process exited: {hang.ProcessName} (pid {hang.ProcessId}).",
        HangOutcomeKind.OperatorConfirmedHung => $"Operator labelled hang candidate [{hang.Id}] as actually hung.",
        HangOutcomeKind.OperatorExpectedIdle => $"Operator labelled hang candidate [{hang.Id}] as expected idle.",
        _ => $"Operator marked hang candidate [{hang.Id}] as unsure.",
    };
}
