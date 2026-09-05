using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.Core.Settings;
using Foreman.Monitor;

namespace Foreman.Monitor.Tests;

/// <summary>
/// Regression coverage for the hang-detection scoping + de-duplication fixes.
///
/// Background: idle Windows system processes (RuntimeBroker.exe, WinStore.App.exe, …)
/// were being reported as hangs, and a permanently-idle process re-alerted on every
/// suppress-window tick. Hang detection must be scoped to harness *children* and must
/// alert only once per hang episode.
///
/// EventBus is a process-wide singleton, so each test uses a unique PID range and filters
/// captured events by those PIDs to stay isolated from other tests.
/// </summary>
public sealed class HangDetectorTests
{
    private readonly EventBus _bus = new();   // isolated per test (xUnit makes a fresh instance per method)
    private static readonly TimeSpan Old = TimeSpan.FromMinutes(20);  // > default 10-min threshold

    private static ProcessRecord Idle(int pid, int parentPid, string name, bool isHarness = false, string? harnessType = null)
    {
        var past = DateTimeOffset.UtcNow - Old;
        return new ProcessRecord
        {
            Pid              = pid,
            ParentPid        = parentPid,
            Name             = name,
            StartTime        = past,
            LastIoChangeTime = past,
            IsHarness        = isHarness,
            HarnessType      = harnessType,
            State            = ProcessState.Active,
        };
    }

    /// <summary>Subscribes a handler that captures HangDetectedEvents for the given PIDs only.</summary>
    private List<HangDetectedEvent> CaptureHangsFor(params int[] pids)
    {
        var set = new HashSet<int>(pids);
        var hits = new List<HangDetectedEvent>();
        _bus.Subscribe(evt =>
        {
            if (evt is HangDetectedEvent h && set.Contains(h.ProcessId))
            {
                lock (hits) hits.Add(h);
            }
        });
        return hits;
    }

    [Fact]
    public void IdleSystemProcess_WithNoHarnessAncestor_DoesNotAlert()
    {
        var tree = new ProcessTreeTracker();
        var rb   = Idle(900_101, 900_100, "RuntimeBroker.exe");  // parent not tracked → no ancestor
        tree.OnProcessCreated(rb);

        var hits = CaptureHangsFor(rb.Pid);
        var sut  = new HangDetector(_bus, new ForemanSettings { HangThresholdMinutes = 10 }, tree);

        sut.Check(rb);

        Assert.Empty(hits);
    }

    [Fact]
    public void IdleHarnessChild_Alerts_Once_AndNamesTheHarness()
    {
        var tree    = new ProcessTreeTracker();
        var harness = Idle(900_201, 900_200, "node.exe", isHarness: true, harnessType: "claude-code");
        var child   = Idle(900_202, harness.Pid, "bash.exe");
        tree.OnProcessCreated(harness);
        tree.OnProcessCreated(child);

        var hits = CaptureHangsFor(child.Pid);
        var sut  = new HangDetector(_bus, new ForemanSettings { HangThresholdMinutes = 10 }, tree);

        sut.Check(child);
        sut.Check(child);   // same hang episode — must NOT produce a second alert

        Assert.Single(hits);
        Assert.Equal(ForemanSeverity.Medium, hits[0].Severity);
        Assert.Equal(harness.Pid, hits[0].SpawnerPid);
        Assert.Equal("node.exe", hits[0].SpawnerName);
        Assert.Equal(harness.Pid, hits[0].ParentHarnessPid);
        Assert.Equal("claude-code", hits[0].ParentHarnessType);
        Assert.Equal("node.exe", hits[0].ParentHarnessName);
        Assert.Contains("claude-code", hits[0].Message);
        var features = Assert.IsType<Foreman.Core.Alerts.HangFeatureSnapshot>(hits[0].LearningFeatures);
        Assert.Equal(Foreman.Core.Alerts.HangLearning.FeatureSchemaVersion, features.SchemaVersion);
        Assert.True(features.SilentMinutes >= 10);
        Assert.True(features.UptimeMinutes >= features.SilentMinutes);
        Assert.Equal(Foreman.Core.Alerts.HarnessActivity.AtRest, features.HarnessActivity);
        Assert.True(features.DirectHarnessChild);
        Assert.Equal(2, features.TreeProcessCount);
    }

    [Fact]
    public void HarnessProcessItself_Idle_DoesNotAlert()
    {
        // An agent idling while it waits for user input is normal, not a hang.
        var tree    = new ProcessTreeTracker();
        var harness = Idle(900_301, 900_300, "node.exe", isHarness: true, harnessType: "claude-code");
        tree.OnProcessCreated(harness);

        var hits = CaptureHangsFor(harness.Pid);
        var sut  = new HangDetector(_bus, new ForemanSettings { HangThresholdMinutes = 10 }, tree);

        sut.Check(harness);

        Assert.Empty(hits);
    }

    [Fact]
    public void HangEpisode_ReArms_WhenIoResumesThenHangsAgain()
    {
        var tree    = new ProcessTreeTracker();
        var harness = Idle(900_401, 900_400, "node.exe", isHarness: true, harnessType: "claude-code");
        var child   = Idle(900_402, harness.Pid, "python.exe");
        tree.OnProcessCreated(harness);
        tree.OnProcessCreated(child);

        var hits = CaptureHangsFor(child.Pid);
        // Cooldown 0 so re-arm is immediate (this test is about the epoch re-arm, not the rate-limit).
        var sut  = new HangDetector(_bus, new ForemanSettings { HangThresholdMinutes = 10, HangRealertCooldownMinutes = 0 }, tree);

        sut.Check(child);   // first hang episode → alert #1

        // Simulate I/O resuming and the process hanging again: LastIoChangeTime advances
        // to a new (still-stale) timestamp. The epoch no longer matches → fresh alert.
        child.LastIoChangeTime = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(15);
        child.State = ProcessState.Active;
        sut.Check(child);   // second, distinct hang episode → alert #2

        Assert.Equal(2, hits.Count);
    }

    [Fact]
    public void BurstyChild_ReHangingWithinCooldown_DoesNotReAlert()
    {
        // A child that wakes briefly then idles past the threshold again must NOT re-alert while the
        // re-alert cooldown is in effect — this is the fix for "breeding" no-I/O alerts.
        var tree    = new ProcessTreeTracker();
        var harness = Idle(900_901, 900_900, "node.exe", isHarness: true, harnessType: "claude-code");
        var child   = Idle(900_902, harness.Pid, "tsserver.exe");
        tree.OnProcessCreated(harness);
        tree.OnProcessCreated(child);

        var hits = CaptureHangsFor(child.Pid);
        // Default 60-min cooldown.
        var sut  = new HangDetector(_bus, new ForemanSettings { HangThresholdMinutes = 10 }, tree);

        sut.Check(child);                                   // first idle episode → alert #1

        for (var i = 0; i < 5; i++)                         // five rapid wake/re-idle cycles
        {
            child.LastIoChangeTime = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(15);
            child.State = ProcessState.Active;
            sut.Check(child);                               // within cooldown → suppressed
        }

        Assert.Single(hits);   // still only the one alert, not six
    }

    [Fact]
    public void MonitorAllProcesses_True_AlertsOnLoneIdleProcess()
    {
        var tree = new ProcessTreeTracker();
        var rb   = Idle(900_501, 900_500, "RuntimeBroker.exe");
        tree.OnProcessCreated(rb);

        var hits     = CaptureHangsFor(rb.Pid);
        var settings = new ForemanSettings { HangThresholdMinutes = 10, MonitorAllProcesses = true };
        var sut      = new HangDetector(_bus, settings, tree);

        sut.Check(rb);

        Assert.Single(hits);
        Assert.Equal(rb.ParentPid, hits[0].SpawnerPid);
        Assert.Null(hits[0].ParentHarnessPid);  // no harness owner
    }

    [Fact]
    public void NestedHarnessChild_AttributesDirectSpawnerAndHarnessOwner()
    {
        var tree = new ProcessTreeTracker();
        var harness = Idle(900_801, 900_800, "codex.exe", isHarness: true, harnessType: "codex");
        var shell = Idle(900_802, harness.Pid, "powershell.exe");
        var child = Idle(900_803, shell.Pid, "dotnet.exe");
        tree.OnProcessCreated(harness);
        tree.OnProcessCreated(shell);
        tree.OnProcessCreated(child);

        var hits = CaptureHangsFor(child.Pid);
        var sut = new HangDetector(_bus, new ForemanSettings { HangThresholdMinutes = 10 }, tree);

        sut.Check(child);

        Assert.Single(hits);
        Assert.Equal(shell.Pid, hits[0].SpawnerPid);
        Assert.Equal("powershell.exe", hits[0].SpawnerName);
        Assert.Equal(harness.Pid, hits[0].ParentHarnessPid);
        Assert.Equal("codex", hits[0].ParentHarnessType);
        Assert.Equal("codex.exe", hits[0].ParentHarnessName);
        Assert.Contains("powershell.exe", hits[0].Message);
        Assert.Contains("codex", hits[0].Message);
    }

    [Fact]
    public void InfrastructureChild_ConhostUnderHarness_DoesNotAlert()
    {
        // conhost.exe is a real harness descendant but a passive console host — idling is
        // normal, so it must not be flagged even though it is inside a harness tree.
        var tree    = new ProcessTreeTracker();
        var harness = Idle(900_601, 900_600, "codex.exe", isHarness: true, harnessType: "codex");
        var conhost = Idle(900_602, harness.Pid, "conhost.exe");
        tree.OnProcessCreated(harness);
        tree.OnProcessCreated(conhost);

        var hits = CaptureHangsFor(conhost.Pid);
        var sut  = new HangDetector(_bus, new ForemanSettings { HangThresholdMinutes = 10 }, tree);

        sut.Check(conhost);

        Assert.Empty(hits);
    }

    [Fact]
    public void ForemanAppProcess_IsIgnored_ByHangDetector()
    {
        var tree = new ProcessTreeTracker();
        var foreman = Idle(900_701, 900_700, "Foreman.App.exe");
        tree.OnProcessCreated(foreman);

        var hits = CaptureHangsFor(foreman.Pid);
        var settings = new ForemanSettings { HangThresholdMinutes = 10, MonitorAllProcesses = true };
        var sut = new HangDetector(_bus, settings, tree);

        sut.Check(foreman);

        Assert.Empty(hits);
    }

    // ── Context-scaled idle threshold (operator presence + harness task-activity) ──────────────────────────

    private static ProcessRecord IdleFor(int pid, int parentPid, string name, int silentMin, int uptimeMin,
        bool isHarness = false, string? harnessType = null)
    {
        var now = DateTimeOffset.UtcNow;
        return new ProcessRecord
        {
            Pid              = pid,
            ParentPid        = parentPid,
            Name             = name,
            StartTime        = now - TimeSpan.FromMinutes(uptimeMin),
            LastIoChangeTime = now - TimeSpan.FromMinutes(silentMin),
            IsHarness        = isHarness,
            HarnessType      = harnessType,
            State            = ProcessState.Active,
        };
    }

    private sealed class FakeOperator : IUserInputProvider
    {
        public int Minutes { get; init; }
        public int MinutesSinceLastInput => Minutes;
    }

    [Fact]   // operator AWAY + harness at rest → the threshold lengthens, so a child that would alert is HELD
    public void OperatorAway_HoldsHangThatWouldFireWhenPresent()
    {
        var tree    = new ProcessTreeTracker();
        var harness = IdleFor(901_001, 901_000, "node.exe", silentMin: 200, uptimeMin: 300, isHarness: true, harnessType: "claude-code");
        var child   = IdleFor(901_002, harness.Pid, "bash.exe", silentMin: 60, uptimeMin: 200);
        tree.OnProcessCreated(harness);
        tree.OnProcessCreated(child);

        var hits = CaptureHangsFor(child.Pid);
        // base 30, away 90m (×3) × at-rest (×1.5) → capped ×4 → effective 120m. 60m silent is held.
        var sut = new HangDetector(_bus, new ForemanSettings { HangThresholdMinutes = 30 }, tree,
            new FakeOperator { Minutes = 90 });

        sut.Check(child);

        Assert.Empty(hits);
    }

    [Fact]   // same child, operator PRESENT → fires at the at-rest-scaled threshold (still relaxed, but lower)
    public void OperatorPresent_FiresAtScaledThreshold()
    {
        var tree    = new ProcessTreeTracker();
        var harness = IdleFor(901_101, 901_100, "node.exe", silentMin: 200, uptimeMin: 300, isHarness: true, harnessType: "claude-code");
        var child   = IdleFor(901_102, harness.Pid, "bash.exe", silentMin: 60, uptimeMin: 200);
        tree.OnProcessCreated(harness);
        tree.OnProcessCreated(child);

        var hits = CaptureHangsFor(child.Pid);
        // base 30, present (×1) × at-rest (×1.5) → effective 45m. 60m silent ≥ 45 → fires.
        var sut = new HangDetector(_bus, new ForemanSettings { HangThresholdMinutes = 30 }, tree,
            new FakeOperator { Minutes = 0 });

        sut.Check(child);

        Assert.Single(hits);
        Assert.Contains("idle threshold", hits[0].Message);   // the scaling reason is surfaced
    }

    [Fact]   // scaling OFF → the flat base threshold, regardless of operator/activity
    public void ScalingDisabled_UsesFlatBase()
    {
        var tree    = new ProcessTreeTracker();
        var harness = IdleFor(901_201, 901_200, "node.exe", silentMin: 200, uptimeMin: 300, isHarness: true, harnessType: "claude-code");
        var child   = IdleFor(901_202, harness.Pid, "bash.exe", silentMin: 40, uptimeMin: 200);
        tree.OnProcessCreated(harness);
        tree.OnProcessCreated(child);

        var hits = CaptureHangsFor(child.Pid);
        var settings = new ForemanSettings
        {
            HangThresholdMinutes = 30,
            IdleThresholdScaling = new Foreman.Core.Alerts.IdleThresholdScalingSettings { Enabled = false },
        };
        // operator very away — but scaling is off, so 40m ≥ base 30 → fires anyway.
        var sut = new HangDetector(_bus, settings, tree, new FakeOperator { Minutes = 600 });

        sut.Check(child);

        Assert.Single(hits);
    }

    [Fact]   // a harness actively running work gets NO at-rest relaxation (a busy sibling keeps the tree "active")
    public void HarnessRunningTask_NoAtRestRelaxation()
    {
        var tree    = new ProcessTreeTracker();
        var harness = IdleFor(901_301, 901_300, "node.exe", silentMin: 1, uptimeMin: 300, isHarness: true, harnessType: "claude-code");
        var busy    = IdleFor(901_302, harness.Pid, "tsc.exe",  silentMin: 1,  uptimeMin: 100);  // recent I/O → tree active
        var child   = IdleFor(901_303, harness.Pid, "bash.exe", silentMin: 35, uptimeMin: 100);
        tree.OnProcessCreated(harness);
        tree.OnProcessCreated(busy);
        tree.OnProcessCreated(child);

        var hits = CaptureHangsFor(child.Pid);
        // present + active → no factors → effective stays at base 30. 35 ≥ 30 → fires.
        var sut = new HangDetector(_bus, new ForemanSettings { HangThresholdMinutes = 30 }, tree,
            new FakeOperator { Minutes = 0 });

        sut.Check(child);

        Assert.Single(hits);
    }

    [Fact]   // B7/#39: a REUSED pid gets a fresh hang slot — a dead process's dedup state can't suppress the new one
    public void ReusedPid_IsNotSuppressedByDeadProcessState()
    {
        var tree    = new ProcessTreeTracker();
        var harness = IdleFor(902_001, 902_000, "node.exe", silentMin: 200, uptimeMin: 300, isHarness: true, harnessType: "claude-code");
        var first   = IdleFor(902_002, harness.Pid, "bash.exe", silentMin: 40, uptimeMin: 50);
        tree.OnProcessCreated(harness);
        tree.OnProcessCreated(first);

        var hits = CaptureHangsFor(902_002);
        // Flat threshold (scaling off) so the test is about PID-reuse dedup, not context scaling.
        var settings = new ForemanSettings
        {
            HangThresholdMinutes = 30,
            IdleThresholdScaling = new Foreman.Core.Alerts.IdleThresholdScalingSettings { Enabled = false },
        };
        var sut = new HangDetector(_bus, settings, tree);

        sut.Check(first);          // first process → alert #1
        sut.Forget(first.Pid);     // first process exits

        // A NEW process reuses pid 902_002 with a DIFFERENT start time — must still alert, not be suppressed.
        var reused = IdleFor(902_002, harness.Pid, "python.exe", silentMin: 40, uptimeMin: 45);
        tree.OnProcessCreated(reused);
        sut.Check(reused);         // distinct (pid, start) slot → alert #2

        Assert.Equal(2, hits.Count);
    }

    [Fact]   // contrast to the above: same 35m child, but the whole tree is at rest → held below the 45m at-rest threshold
    public void HarnessAtRest_PresentOperator_HoldsBelowAtRestThreshold()
    {
        var tree    = new ProcessTreeTracker();
        var harness = IdleFor(901_401, 901_400, "node.exe", silentMin: 200, uptimeMin: 300, isHarness: true, harnessType: "claude-code");
        var child   = IdleFor(901_402, harness.Pid, "bash.exe", silentMin: 35, uptimeMin: 200);
        tree.OnProcessCreated(harness);
        tree.OnProcessCreated(child);

        var hits = CaptureHangsFor(child.Pid);
        // present + at-rest → 30×1.5 = 45m effective. 35 < 45 → held.
        var sut = new HangDetector(_bus, new ForemanSettings { HangThresholdMinutes = 30 }, tree,
            new FakeOperator { Minutes = 0 });

        sut.Check(child);

        Assert.Empty(hits);
    }
}
