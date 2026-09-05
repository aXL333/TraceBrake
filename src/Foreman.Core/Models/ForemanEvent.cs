using Foreman.Core.Behavior;
using System.Text.Json.Serialization;

namespace Foreman.Core.Models;

public enum EventOrigin
{
    Host = 0,
    Agent = 1,
}

[JsonPolymorphic(TypeDiscriminatorPropertyName = "type")]
[JsonDerivedType(typeof(CommandAlertEvent),       "command")]
[JsonDerivedType(typeof(HangDetectedEvent),       "hang")]
[JsonDerivedType(typeof(OrphanDetectedEvent),     "orphan")]
[JsonDerivedType(typeof(PermissionViolationEvent),"permission")]
[JsonDerivedType(typeof(NonzeroExitEvent),        "exit")]
[JsonDerivedType(typeof(InfoEvent),               "info")]
[JsonDerivedType(typeof(MonitoringNoticeEvent),   "monitoring")]
[JsonDerivedType(typeof(EscalationEvent),         "escalation")]
[JsonDerivedType(typeof(HangOutcomeEvent),         "hang-outcome")]
public abstract record ForemanEvent(
    DateTimeOffset Timestamp,
    ForemanSeverity Severity,
    string Source,
    string Message
)
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N")[..12];
    public bool Acknowledged { get; set; }
    /// <summary>Publisher-assigned provenance. Never infer this from Source or other attacker-controlled text.</summary>
    public EventOrigin Origin { get; init; } = EventOrigin.Host;

    /// <summary>
    /// Set by the alert lifecycle (<see cref="Foreman.Core.Alerts.AlertResolver"/>) when the underlying
    /// condition has cleared on its own — a hung process resumed I/O or exited, an orphan exited, a
    /// point-in-time alert aged out. Distinct from <see cref="Acknowledged"/> (an operator action); both
    /// drop the alert from the "active" set so the tray/dashboard/MCP stop counting it.
    /// </summary>
    public bool AutoResolved { get; set; }

    /// <summary>Human-readable reason this alert auto-resolved (e.g. "I/O resumed"), null while open.</summary>
    public string? ResolvedReason { get; set; }

    /// <summary>
    /// WMI CreationDate of the process this alert is about, when known. Pins the kill target's
    /// identity: a later Kill validates this against the currently-tracked record for the PID,
    /// so a recycled PID (which has a different CreationDate) is refused rather than killed.
    /// </summary>
    public DateTimeOffset? ProcessStartTime { get; init; }

    /// <summary>
    /// Append-time local ordering metadata set by EventLogStore. Event Timestamp remains the source/provider
    /// wall-clock label; Sequence is the local ordering truth, and MonotonicTicks is the local interval truth
    /// within TemporalSessionId.
    /// </summary>
    public string? TemporalSessionId { get; init; }
    public long? Sequence { get; init; }
    public DateTimeOffset? RecordedAtUtc { get; init; }
    public long? MonotonicTicks { get; init; }
    public long? MonotonicFrequency { get; init; }
    public string[] TemporalAnomalies { get; init; } = [];

    /// <summary>
    /// Append-only hash-chain link, set at WRITE TIME by <see cref="Foreman.Core.Events.EventLogStore"/>, not
    /// in the ctor — the in-memory copy on the EventBus carries the default (null). <see cref="PrevHash"/> is
    /// the hash of the previous on-disk record (empty string for the genesis record); <see cref="Hash"/> is
    /// SHA-256 over (PrevHash + this record's canonical, redacted serialization). Null on a pre-chain "legacy"
    /// record. Inert to existing readers (LogWindow/MCP only read Id/Timestamp/Severity/Source/Message).
    /// </summary>
    public string? PrevHash { get; init; }

    /// <summary>Content+chain hash of this on-disk record (hex). See <see cref="PrevHash"/>.</summary>
    public string? Hash { get; init; }
}

public sealed record CommandAlertEvent(
    DateTimeOffset Timestamp,
    ForemanSeverity Severity,
    string Source,
    string Message,
    string CommandLine,
    string RuleId,
    string RuleName,
    string RuleDescription,
    string RuleGuidance,
    int ProcessId
) : ForemanEvent(Timestamp, Severity, Source, Message);

public sealed record HangDetectedEvent(
    DateTimeOffset Timestamp,
    string Source,
    string Message,
    int ProcessId,
    string ProcessName,
    int UptimeMinutes,
    int SilentMinutes,
    int? SpawnerPid,
    string? SpawnerName,
    int? ParentHarnessPid,
    string? ParentHarnessType,
    string? ParentHarnessName,
    Foreman.Core.Alerts.HangFeatureSnapshot? LearningFeatures = null
) : ForemanEvent(Timestamp, ForemanSeverity.Medium, Source, Message);

/// <summary>
/// Append-only outcome/label for a prior hang candidate. Automatic recovery is observational
/// evidence only; OperatorLabeled binary outcomes are the sole gold labels for training.
/// </summary>
public sealed record HangOutcomeEvent(
    DateTimeOffset Timestamp,
    string Source,
    string Message,
    string HangAlertId,
    int ProcessId,
    DateTimeOffset? HangProcessStartTime,
    Foreman.Core.Alerts.HangOutcomeKind Outcome,
    bool OperatorLabeled
) : ForemanEvent(Timestamp, ForemanSeverity.Info, Source, Message);

public sealed record OrphanDetectedEvent(
    DateTimeOffset Timestamp,
    string Source,
    string Message,
    int ProcessId,
    string ProcessName,
    int DeadParentPid,
    string DeadParentName,
    int UptimeMinutes,
    // The harness tree this orphan belongs to (orphan alerts are scoped to harness lineage). Nullable for
    // backward-compatible deserialization of events logged before attribution existed.
    int? HarnessPid = null,
    string? HarnessType = null,
    string? HarnessName = null
) : ForemanEvent(Timestamp, ForemanSeverity.Medium, Source, Message);

public sealed record PermissionViolationEvent(
    DateTimeOffset Timestamp,
    string Source,
    string Message,
    int ProcessId,
    string ProfileName,
    string ViolationType,
    string Detail
) : ForemanEvent(Timestamp, ForemanSeverity.High, Source, Message);

public sealed record NonzeroExitEvent(
    DateTimeOffset Timestamp,
    string Source,
    string Message,
    int ProcessId,
    string ProcessName,
    int ExitCode,
    int? ParentHarnessPid
) : ForemanEvent(Timestamp, ForemanSeverity.Low, Source, Message);

/// <summary>Informational / lifecycle event — startup, scan complete, status changes.</summary>
public sealed record InfoEvent(
    DateTimeOffset Timestamp,
    string Source,
    string Message
) : ForemanEvent(Timestamp, ForemanSeverity.Info, Source, Message);

/// <summary>
/// A monitoring-control action worth surfacing at a chosen severity — e.g. an MCP-initiated
/// behavior-metrics reset that wiped a real escalation. Publishing these as a visible alert
/// (rather than a silent Info) means such actions cannot be used to quietly self-exonerate.
/// </summary>
public sealed record MonitoringNoticeEvent(
    DateTimeOffset Timestamp,
    ForemanSeverity Severity,
    string Source,
    string Message
) : ForemanEvent(Timestamp, Severity, Source, Message);

/// <summary>
/// Published by BehaviorTracker whenever a harness crosses an escalation threshold.
/// The level only increases within a session (reset clears it).
/// </summary>
public sealed record EscalationEvent(
    DateTimeOffset Timestamp,
    EscalationLevel NewLevel,
    EscalationLevel OldLevel,
    string HarnessId,
    string HarnessDisplayName,
    string Reason,
    int TotalAlerts,
    int UniqueRules,
    int CategoryCount,
    string[] CategoryList,
    string TriggerRuleId,
    string TriggerRuleName,
    string TriggerDetail = ""
) : ForemanEvent(
    Timestamp,
    NewLevel >= EscalationLevel.Emergency ? ForemanSeverity.Critical :
    NewLevel >= EscalationLevel.Alarm     ? ForemanSeverity.High     :
                                            ForemanSeverity.Medium,
    "Foreman.Behavior",
    $"[{NewLevel.ToString().ToUpperInvariant()}] {HarnessDisplayName} — {TotalAlerts} alert(s), " +
    $"{UniqueRules} rule(s), trigger: {TriggerRuleName}");
