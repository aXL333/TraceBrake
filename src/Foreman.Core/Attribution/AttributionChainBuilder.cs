using Foreman.Core.Models;
using Foreman.Core.Security;

namespace Foreman.Core.Attribution;

public enum AttributionNodeKind
{
    Harness,
    Process,
    Action,
    Detector,
    Policy,
    Outcome,
    System,
}

public enum AttributionConfidence
{
    Observed,
    Inferred,
}

/// <summary>
/// One node in an ordered explanation of how an event was attributed. Relationship describes the
/// incoming edge; the first node deliberately has no relationship.
/// </summary>
public sealed record AttributionStep(
    AttributionNodeKind Kind,
    string Title,
    string Detail,
    string Relationship = "",
    AttributionConfidence RelationshipConfidence = AttributionConfidence.Observed,
    string Evidence = "");

public sealed record AttributionChain(string Summary, IReadOnlyList<AttributionStep> Steps)
{
    public int InferredLinks => Steps.Count(s => s.RelationshipConfidence == AttributionConfidence.Inferred);
    public int ObservedLinks => Steps.Count - InferredLinks;
}

/// <summary>
/// Produces a conservative, human-readable attribution chain from durable event-time facts and,
/// when available, the current process tree. It never turns a missing relationship into a fact:
/// source-text and live-tree fallbacks are explicitly marked as inferred.
/// </summary>
public static class AttributionChainBuilder
{
    private const int MaxDetailLength = 120;

    public static AttributionChain Build(
        ForemanEvent evt,
        Func<int, ProcessRecord?>? getProcessByPid = null,
        Func<int, ProcessRecord?>? getHarnessAncestorByPid = null)
    {
        ArgumentNullException.ThrowIfNull(evt);

        var steps = evt switch
        {
            CommandAlertEvent command => BuildCommand(command, getProcessByPid, getHarnessAncestorByPid),
            HangDetectedEvent hang => BuildHang(hang),
            OrphanDetectedEvent orphan => BuildOrphan(orphan),
            PermissionViolationEvent permission => BuildPermission(permission, getProcessByPid, getHarnessAncestorByPid),
            NonzeroExitEvent exit => BuildExit(exit, getProcessByPid, getHarnessAncestorByPid),
            EscalationEvent escalation => BuildEscalation(escalation),
            MonitoringNoticeEvent monitoring => BuildNotice(monitoring),
            _ => BuildGeneric(evt),
        };

        return new AttributionChain(BuildSummary(steps), steps);
    }

    private static List<AttributionStep> BuildCommand(
        CommandAlertEvent evt,
        Func<int, ProcessRecord?>? getProcess,
        Func<int, ProcessRecord?>? getAncestor)
    {
        var steps = new List<AttributionStep>();
        var process = ValidForEvent(evt, SafeResolve(getProcess, evt.ProcessId));
        var ancestor = process?.IsHarness == true
            ? process
            : evt.ProcessStartTime is null ? SafeResolve(getAncestor, evt.ProcessId) : null;
        var processPinned = IsIdentityPinned(evt, process);
        var harnessObserved = processPinned && process?.HarnessType is not null;

        AddHarness(
            steps,
            process?.HarnessType ?? ancestor?.HarnessType,
            ancestor?.Pid ?? (process?.IsHarness == true ? process.Pid : null),
            relationship: "owns",
            confidence: harnessObserved ? AttributionConfidence.Observed : AttributionConfidence.Inferred,
            evidence: harnessObserved
                ? "PID and process start time matched the tracked harness lineage"
                : ancestor is not null || process?.HarnessType is not null
                    ? "Current process-tree attribution; no event-time identity pin"
                    : "No retained harness lineage");

        var processName = process?.Name;
        var processConfidence = processPinned ? AttributionConfidence.Observed : AttributionConfidence.Inferred;
        if (string.IsNullOrWhiteSpace(processName))
        {
            processName = ExtractProcessName(evt.Source);
        }

        steps.Add(new AttributionStep(
            AttributionNodeKind.Process,
            Blank(processName, "Unknown process"),
            evt.ProcessId > 0 ? $"pid {evt.ProcessId}" : "pid unavailable",
            steps.Count == 0 ? "" : "launched",
            processConfidence,
            processConfidence == AttributionConfidence.Observed
                ? "PID and process start time matched the process monitor snapshot"
                : process is not null ? "Current PID snapshot; event-time identity was not retained" : "Derived from event source label"));

        steps.Add(new AttributionStep(
            AttributionNodeKind.Action,
            "Command observed",
            Clean(evt.CommandLine, "Command text unavailable"),
            "executed",
            AttributionConfidence.Observed,
            "Command telemetry captured with the alert"));

        steps.Add(new AttributionStep(
            AttributionNodeKind.Detector,
            "Rule matched",
            Clean($"{evt.RuleId} · {evt.RuleName}", "Unnamed command rule"),
            "matched",
            AttributionConfidence.Observed,
            "TraceBrake command-pattern detector"));

        AddOutcome(steps, evt, "Command alert recorded");
        return steps;
    }

    private static List<AttributionStep> BuildHang(HangDetectedEvent evt)
    {
        var steps = new List<AttributionStep>();
        AddHarness(steps, evt.ParentHarnessType, evt.ParentHarnessPid, "owns",
            AttributionConfidence.Observed, "Harness lineage captured when the alert was created");

        if (evt.SpawnerPid is not null || !string.IsNullOrWhiteSpace(evt.SpawnerName))
        {
            var spawnerPid = evt.SpawnerPid ?? 0;
            steps.Add(new AttributionStep(
                AttributionNodeKind.Process,
                Blank(evt.SpawnerName, "Spawner process"),
                spawnerPid > 0 ? $"pid {spawnerPid}" : "pid unavailable",
                steps.Count == 0 ? "" : "spawned",
                AttributionConfidence.Observed,
                "Direct spawner captured at event time"));
        }

        steps.Add(new AttributionStep(
            AttributionNodeKind.Process,
            Blank(evt.ProcessName, "Silent process"),
            evt.ProcessId > 0 ? $"pid {evt.ProcessId} · up {evt.UptimeMinutes} min" : $"up {evt.UptimeMinutes} min",
            steps.Count == 0 ? "" : "started",
            AttributionConfidence.Observed,
            "Process monitor identity"));

        steps.Add(new AttributionStep(
            AttributionNodeKind.Detector,
            "No I/O detected",
            $"Silent for {evt.SilentMinutes} min",
            "became silent",
            AttributionConfidence.Observed,
            "I/O counter sampling"));

        AddOutcome(steps, evt, "Hang alert recorded");
        return steps;
    }

    private static List<AttributionStep> BuildOrphan(OrphanDetectedEvent evt)
    {
        var steps = new List<AttributionStep>();
        AddHarness(steps, evt.HarnessType, evt.HarnessPid, "owns",
            AttributionConfidence.Observed, "Harness lineage captured when the alert was created");

        steps.Add(new AttributionStep(
            AttributionNodeKind.Process,
            Blank(evt.DeadParentName, "Former parent"),
            evt.DeadParentPid > 0 ? $"pid {evt.DeadParentPid} · exited" : "exited",
            steps.Count == 0 ? "" : "contained",
            AttributionConfidence.Observed,
            "Recorded parent process identity"));

        steps.Add(new AttributionStep(
            AttributionNodeKind.Process,
            Blank(evt.ProcessName, "Orphaned child"),
            evt.ProcessId > 0 ? $"pid {evt.ProcessId} · up {evt.UptimeMinutes} min" : $"up {evt.UptimeMinutes} min",
            "left running",
            AttributionConfidence.Observed,
            "Child remained after its recorded parent exited"));

        AddOutcome(steps, evt, "Orphan alert recorded");
        return steps;
    }

    private static List<AttributionStep> BuildPermission(
        PermissionViolationEvent evt,
        Func<int, ProcessRecord?>? getProcess,
        Func<int, ProcessRecord?>? getAncestor)
    {
        var steps = new List<AttributionStep>();
        var process = ValidForEvent(evt, SafeResolve(getProcess, evt.ProcessId));
        var ancestor = process?.IsHarness == true
            ? process
            : evt.ProcessStartTime is null ? SafeResolve(getAncestor, evt.ProcessId) : null;
        var processPinned = IsIdentityPinned(evt, process);
        AddHarness(steps, process?.HarnessType ?? ancestor?.HarnessType, ancestor?.Pid,
            "owns", processPinned && process?.HarnessType is not null ? AttributionConfidence.Observed : AttributionConfidence.Inferred,
            processPinned && process?.HarnessType is not null
                ? "PID and process start time matched the tracked harness lineage"
                : ancestor is null && process?.HarnessType is null ? "No retained harness lineage" : "Current process-tree attribution; no event-time identity pin");

        steps.Add(new AttributionStep(
            AttributionNodeKind.Process,
            Blank(process?.Name ?? ExtractProcessName(evt.Source), "Unknown process"),
            evt.ProcessId > 0 ? $"pid {evt.ProcessId}" : "pid unavailable",
            steps.Count == 0 ? "" : "acted through",
            processPinned ? AttributionConfidence.Observed : AttributionConfidence.Inferred,
            processPinned ? "PID and process start time matched the process monitor snapshot"
                : process is null ? "Derived from event source label" : "Current PID snapshot; event-time identity was not retained"));

        steps.Add(new AttributionStep(
            AttributionNodeKind.Action,
            Blank(evt.ViolationType, "Restricted action"),
            Clean(evt.Detail, "No further detail captured"),
            "attempted",
            AttributionConfidence.Observed,
            "Permission monitor event"));

        steps.Add(new AttributionStep(
            AttributionNodeKind.Policy,
            "Profile boundary crossed",
            Blank(evt.ProfileName, "Unnamed profile"),
            "violated",
            AttributionConfidence.Observed,
            "Assigned TraceBrake permission profile"));

        AddOutcome(steps, evt, "Violation recorded");
        return steps;
    }

    private static List<AttributionStep> BuildExit(
        NonzeroExitEvent evt,
        Func<int, ProcessRecord?>? getProcess,
        Func<int, ProcessRecord?>? getAncestor)
    {
        var steps = new List<AttributionStep>();
        var process = ValidForEvent(evt, SafeResolve(getProcess, evt.ProcessId));
        var ancestor = evt.ProcessStartTime is null ? SafeResolve(getAncestor, evt.ProcessId) : null;
        var processPinned = IsIdentityPinned(evt, process);
        AddHarness(steps, process?.HarnessType ?? ancestor?.HarnessType, evt.ParentHarnessPid ?? ancestor?.Pid,
            "owns", processPinned && process?.HarnessType is not null ? AttributionConfidence.Observed : AttributionConfidence.Inferred,
            processPinned && process?.HarnessType is not null
                ? "PID and process start time matched the tracked harness lineage"
                : process?.HarnessType is null && ancestor is null ? "No retained harness lineage" : "Current process-tree attribution; no event-time identity pin");

        steps.Add(new AttributionStep(
            AttributionNodeKind.Process,
            Blank(evt.ProcessName, "Exited process"),
            evt.ProcessId > 0 ? $"pid {evt.ProcessId}" : "pid unavailable",
            steps.Count == 0 ? "" : "launched",
            AttributionConfidence.Observed,
            "Process exit event"));

        steps.Add(new AttributionStep(
            AttributionNodeKind.Detector,
            "Non-zero exit",
            $"Exit code {evt.ExitCode}",
            "returned",
            AttributionConfidence.Observed,
            "Recorded process exit code"));

        AddOutcome(steps, evt, "Failure recorded");
        return steps;
    }

    private static List<AttributionStep> BuildEscalation(EscalationEvent evt)
    {
        var steps = new List<AttributionStep>
        {
            new(AttributionNodeKind.Harness, Blank(evt.HarnessDisplayName, evt.HarnessId),
                Blank(evt.HarnessId, "Harness id unavailable"), Evidence: "Behavior profile owner"),
            new(AttributionNodeKind.Detector, "Session behaviour",
                $"{evt.TotalAlerts} alerts · {evt.UniqueRules} rules · {evt.CategoryCount} categories",
                "accumulated", AttributionConfidence.Observed, "Session behavior metrics"),
            new(AttributionNodeKind.Detector, "Trigger rule",
                Clean($"{evt.TriggerRuleId} · {evt.TriggerRuleName}", "Trigger unavailable"),
                "crossed threshold", AttributionConfidence.Observed, Blank(evt.Reason, "Escalation threshold")),
            new(AttributionNodeKind.Outcome, $"{evt.OldLevel} → {evt.NewLevel}",
                "Behavior level raised", "escalated to", AttributionConfidence.Observed, "BehaviorTracker decision"),
        };
        return steps;
    }

    private static List<AttributionStep> BuildNotice(MonitoringNoticeEvent evt)
    {
        var steps = new List<AttributionStep>
        {
            new(AttributionNodeKind.System, FriendlySource(evt.Source),
                evt.Origin == EventOrigin.Agent ? "Agent-originated report" : "TraceBrake subsystem",
                Evidence: "Publisher-assigned event origin"),
            new(AttributionNodeKind.Action, "Monitoring activity", Clean(evt.Message, "Notice detail unavailable"),
                "reported", AttributionConfidence.Observed, "Monitoring notice payload"),
        };
        AddOutcome(steps, evt, "Operator review requested");
        return steps;
    }

    private static List<AttributionStep> BuildGeneric(ForemanEvent evt)
    {
        var steps = new List<AttributionStep>
        {
            new(AttributionNodeKind.System, FriendlySource(evt.Source),
                evt.Origin == EventOrigin.Agent ? "Agent-originated report" : "TraceBrake subsystem",
                Evidence: "Publisher-assigned event origin"),
            new(AttributionNodeKind.Action, "Event published", Clean(evt.Message, "No event detail captured"),
                "reported", AttributionConfidence.Observed, "Event bus record"),
        };
        AddOutcome(steps, evt, "Recorded in event log");
        return steps;
    }

    private static void AddHarness(
        ICollection<AttributionStep> steps,
        string? harnessType,
        int? pid,
        string relationship,
        AttributionConfidence confidence,
        string evidence)
    {
        if (string.IsNullOrWhiteSpace(harnessType)) return;
        steps.Add(new AttributionStep(
            AttributionNodeKind.Harness,
            FriendlyHarness(harnessType),
            pid is > 0 ? $"Harness · pid {pid}" : "Harness",
            steps.Count == 0 ? "" : relationship,
            confidence,
            evidence));
    }

    private static void AddOutcome(ICollection<AttributionStep> steps, ForemanEvent evt, string openTitle)
    {
        var (title, detail) = evt switch
        {
            { AutoResolved: true } => ("Auto-resolved", Blank(evt.ResolvedReason, "Condition cleared")),
            { Acknowledged: true } => ("Acknowledged", "Reviewed by the operator or authorised client"),
            _ => (openTitle, evt.Severity >= ForemanSeverity.High ? "High-priority operator attention" : $"{evt.Severity} severity"),
        };

        steps.Add(new AttributionStep(
            AttributionNodeKind.Outcome,
            title,
            detail,
            "produced",
            AttributionConfidence.Observed,
            $"TraceBrake event {evt.Id}"));
    }

    private static string BuildSummary(IReadOnlyList<AttributionStep> steps)
    {
        var inferred = steps.Count(s => s.RelationshipConfidence == AttributionConfidence.Inferred);
        return inferred == 0
            ? "This path is reconstructed from event-time telemetry and recorded TraceBrake decisions."
            : $"This path contains {inferred} inferred element{(inferred == 1 ? "" : "s")} because complete process lineage was not retained. Dashed links and INFERRED nodes are estimates, not proof.";
    }

    private static ProcessRecord? SafeResolve(Func<int, ProcessRecord?>? resolver, int pid)
    {
        if (resolver is null || pid <= 0) return null;
        try { return resolver(pid); }
        catch { return null; }
    }

    private static ProcessRecord? ValidForEvent(ForemanEvent evt, ProcessRecord? process)
    {
        if (process is null || evt.ProcessStartTime is null) return process;
        return Math.Abs((process.StartTime - evt.ProcessStartTime.Value).TotalSeconds) <= 1 ? process : null;
    }

    private static bool IsIdentityPinned(ForemanEvent evt, ProcessRecord? process) =>
        process is not null && evt.ProcessStartTime is not null &&
        Math.Abs((process.StartTime - evt.ProcessStartTime.Value).TotalSeconds) <= 1;

    private static string FriendlyHarness(string harness) => harness.Trim().ToLowerInvariant() switch
    {
        "codex" or "codex-cli" => "Codex",
        "claude" or "claude-code" => "Claude Code",
        "cursor" or "cursoragent" => "Cursor Agent",
        "chatgpt" => "ChatGPT",
        _ => harness.Trim(),
    };

    private static string FriendlySource(string source) => source.Trim() switch
    {
        "Foreman" => "TraceBrake",
        var value when value.StartsWith("Foreman.", StringComparison.OrdinalIgnoreCase) =>
            "TraceBrake · " + value["Foreman.".Length..],
        "" => "Unknown source",
        var value => value,
    };

    private static string ExtractProcessName(string source)
    {
        if (string.IsNullOrWhiteSpace(source)) return string.Empty;
        var pidMarker = source.IndexOf(" (pid", StringComparison.OrdinalIgnoreCase);
        return (pidMarker > 0 ? source[..pidMarker] : source).Trim();
    }

    private static string Clean(string? value, string fallback)
    {
        var clean = SecretRedactor.Redact(Blank(value, fallback)).Replace('\r', ' ').Replace('\n', ' ').Trim();
        return clean.Length <= MaxDetailLength ? clean : clean[..(MaxDetailLength - 1)] + "…";
    }

    private static string Blank(string? value, string fallback) =>
        string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
}
