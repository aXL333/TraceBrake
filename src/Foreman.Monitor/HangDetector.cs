using Foreman.Core.Alerts;
using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.Core.Settings;
using System.Collections.Concurrent;
using System.Linq;

namespace Foreman.Monitor;

/// <summary>
/// Emits HangDetected events when a harness child process has had zero I/O for longer
/// than the threshold.
///
/// Scope: by default (MonitorAllProcesses == false) only processes that live inside a
/// harness process tree are candidates — and the harness process itself is excluded,
/// because an agent idling while it waits for user input is normal, not a hang. This is
/// what stops idle system processes (RuntimeBroker, WinStore.App, svchost, explorer…)
/// and the harness itself from producing noise.
///
/// De-duplication: alerts fire once per *hang episode*. A permanently-idle process is
/// reported a single time; it only re-alerts if its I/O resumes and it then hangs again.
/// </summary>
public sealed class HangDetector
{
    private readonly EventBus _bus;
    private readonly ForemanSettings _settings;
    private readonly ProcessTreeTracker _tree;
    private readonly IUserInputProvider? _operator;

    // key: (pid, process start-time) → the LastIoChangeTime snapshot at the moment we last alerted. Keyed by the
    // COMPOSITE, not the bare pid, so a REUSED pid is a distinct slot: a new process can't inherit a dead one's
    // dedup/cooldown state and have its own hang silently suppressed. We only re-alert if this advances.
    private readonly ConcurrentDictionary<(int Pid, long StartTicks), DateTimeOffset> _alertedEpoch = new();

    // key: (pid, start-time) → wall-clock time we last alerted. A bursty child that keeps waking briefly then
    // idling past the threshold would otherwise produce a fresh "no I/O" alert every cycle; the
    // cooldown (HangRealertCooldownMinutes) rate-limits re-alerts per process so they can't breed.
    private readonly ConcurrentDictionary<(int Pid, long StartTicks), DateTimeOffset> _lastAlertAt = new();

    // Processes that legitimately sit idle or are part of TraceBrake's own monitoring stack.
    // A no-I/O alert on these is noise rather than an actionable stalled harness child.
    private static readonly HashSet<string> _ignoredHangProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "conhost.exe",
        "Foreman.App",
        "Foreman.App.exe",
        "Foreman",
        "Foreman.exe",
        "TraceBrake.exe",
    };

    public HangDetector(EventBus bus, ForemanSettings settings, ProcessTreeTracker tree,
        IUserInputProvider? operatorActivity = null)
    {
        _bus = bus;
        _settings = settings;
        _tree = tree;
        _operator = operatorActivity;
    }

    public void Check(ProcessRecord record)
    {
        if (record.State == ProcessState.Terminated) return;
        if (record.IoCountersUnavailable) return;
        if (_ignoredHangProcessNames.Contains(record.Name)) return;

        // ── Scope: only harness *children* are hang candidates ───────────────────
        // FindHarnessAncestor returns the nearest IsHarness ancestor (possibly the
        // record itself). When MonitorAllProcesses is off we require a harness ancestor
        // AND that the record is not the harness itself.
        var harness = _tree.FindHarnessAncestor(record.Pid);
        if (!_settings.MonitorAllProcesses)
        {
            if (harness is null) return;            // not inside any harness tree
            if (harness.Pid == record.Pid) return;  // this IS the harness, not a child
        }

        // Local-model hosts (LM Studio, Ollama, …) run inference servers that sit I/O-silent between prompts by
        // design — a quiet stretch is expected, not a stall. Don't hang-flag them or their children.
        if (KnownHarnesses.IsLocalModelHost(harness?.HarnessType)) return;

        var baseThreshold = _settings.HangThresholdMinutes;
        var silent        = record.SilentMinutes;
        var uptime        = record.UptimeMinutes;

        // Cheap gate first: the context scaling only ever LENGTHENS the threshold (it never tightens below the
        // base), so anything under the base can't be a hang regardless of context — bail before the (relatively
        // expensive) tree-activity scan. This keeps the per-poll cost on the common, busy-process path tiny.
        if (uptime < baseThreshold || silent < baseThreshold) return;

        // Context-scale the idle threshold. A process quiet for 30 min means something very different depending
        // on whether the human is even at the keyboard and whether the harness is running work vs parked waiting
        // for input. Monotonic — the effective threshold is always >= base, so this can only quiet expected idle,
        // never create an alert or shorten the window.
        var scaled    = IdleThresholdPolicy.Effective(
            baseThreshold,
            _operator?.MinutesSinceLastInput ?? 0,
            ClassifyHarnessActivity(harness),
            _settings.IdleThresholdScaling);
        var threshold = scaled.EffectiveMinutes;

        if (uptime < threshold || silent < threshold) return;

        // ── De-dupe per hang episode ─────────────────────────────────────────────
        // If LastIoChangeTime hasn't moved since our last alert, this is the same
        // silent stretch we already reported — stay quiet. When the process resumes
        // I/O, ProcessTreeTracker.UpdateIoCounters advances LastIoChangeTime, so a
        // subsequent hang produces a fresh alert.
        // Composite key (pid + start-time) so PID reuse can't suppress a fresh process's hang.
        var key = (record.Pid, record.StartTime.UtcTicks);
        if (_alertedEpoch.TryGetValue(key, out var epoch) && epoch == record.LastIoChangeTime)
            return;

        // ── Re-alert cooldown ────────────────────────────────────────────────────
        // This is a NEW silent episode (I/O resumed since our last alert, then idled again). Without
        // a cooldown, a process with bursty I/O re-alerts on every idle stretch — the "breeding" noise.
        // Mark the episode seen so it won't re-trigger the instant the cooldown lapses, then stay quiet.
        var cooldown = TimeSpan.FromMinutes(_settings.HangRealertCooldownMinutes);
        if (cooldown > TimeSpan.Zero
            && _lastAlertAt.TryGetValue(key, out var last)
            && DateTimeOffset.UtcNow - last < cooldown)
        {
            _alertedEpoch[key] = record.LastIoChangeTime;
            return;
        }

        _alertedEpoch[key] = record.LastIoChangeTime;
        _lastAlertAt[key]  = DateTimeOffset.UtcNow;
        record.State = ProcessState.Hanging;

        // If we have an owning harness, name it in the message and event so the user
        // can see *which* harness the hung child belongs to.
        var isChild   = harness is not null && harness.Pid != record.Pid;
        var ownerType = isChild ? harness!.HarnessType : null;
        var ownerName = isChild ? harness!.Name : null;
        int? ownerPid = isChild ? harness!.Pid : null;

        int? spawnerPid = record.ParentPid > 0 ? record.ParentPid : null;
        var spawner = spawnerPid is int parentPid ? _tree.GetByPid(parentPid) : null;
        var spawnerName = spawner?.Name;
        var spawnerLabel = spawnerPid is int parent
            ? ownerPid == parent
                ? DescribeOwner(ownerType, ownerName, parent)
                : DescribeProcess(spawnerName, parent)
            : null;
        var spawnerNote = spawnerLabel is not null ? $", spawned by {spawnerLabel}" : "";
        var ownerNote = isChild && ownerPid != spawnerPid
            ? $", owned by {DescribeOwner(ownerType, ownerName, harness!.Pid)}"
            : "";

        // When context-scaling held the alert past the base threshold, say so in the message — the operator
        // should see WHY a process they'd expect at 30 min only surfaced later (e.g. they were away).
        var scaledNote = scaled.Multiplier > 1.0 ? $" — idle threshold {scaled.Reason}" : "";

        _bus.Publish(new HangDetectedEvent(
            DateTimeOffset.UtcNow,
            "Foreman.Monitor",
            $"{record.Name} (pid {record.Pid}){spawnerNote}{ownerNote} has had no I/O for {silent} min (running {uptime} min){scaledNote}",
            record.Pid,
            record.Name,
            uptime,
            silent,
            spawnerPid,
            spawnerName,
            ownerPid,
            ownerType,
            ownerName
        ) { ProcessStartTime = record.StartTime });
    }

    /// <summary>Drops the per-process alert state when a process exits (called by the poller/watcher).</summary>
    public void Forget(int pid)
    {
        // Keys are composite now; drop every (pid, *) entry on exit so a dead process leaves no state behind
        // for a future reuse of the same pid.
        foreach (var k in _alertedEpoch.Keys) if (k.Pid == pid) _alertedEpoch.TryRemove(k, out _);
        foreach (var k in _lastAlertAt.Keys)  if (k.Pid == pid) _lastAlertAt.TryRemove(k, out _);
    }

    /// <summary>
    /// Is the owning harness running work right now, or parked at rest? "Active" = some process in the harness
    /// subtree did I/O within the activity window; "AtRest" = the whole tree has gone quiet. Returns Unknown
    /// (→ no relaxation) when there's no owning harness or scaling is off, so we never relax on missing data.
    /// Note: trees are keyed by harness TYPE, so two same-type instances merge — that can only read as "more
    /// active" (less relaxation), which is the safe direction.
    /// </summary>
    private HarnessActivity ClassifyHarnessActivity(ProcessRecord? harness)
    {
        if (!_settings.IdleThresholdScaling.Enabled) return HarnessActivity.Unknown;
        if (harness is null || string.IsNullOrEmpty(harness.HarnessType)) return HarnessActivity.Unknown;

        var tree = _tree.GetTreeByHarnessType(harness.HarnessType)
            .Where(r => r.State != ProcessState.Terminated)
            .ToList();
        if (tree.Count == 0) return HarnessActivity.Unknown;

        var treeIdle = IdleCleanupPolicy.TreeIdleMinutes(tree, DateTimeOffset.UtcNow);
        return treeIdle < _settings.IdleThresholdScaling.ActivityWindowMinutes
            ? HarnessActivity.Active
            : HarnessActivity.AtRest;
    }

    private static string DescribeOwner(string? harnessType, string? processName, int pid)
    {
        var label = string.IsNullOrWhiteSpace(harnessType) ? "harness" : harnessType;
        return string.IsNullOrWhiteSpace(processName)
            ? $"{label} pid {pid}"
            : $"{label} ({processName}, pid {pid})";
    }

    private static string DescribeProcess(string? processName, int pid) =>
        string.IsNullOrWhiteSpace(processName)
            ? $"pid {pid}"
            : $"{processName} (pid {pid})";
}
