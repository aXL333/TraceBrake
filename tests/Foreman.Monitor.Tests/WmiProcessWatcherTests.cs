using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.Core.Settings;
using Foreman.Core.Termination;
using Foreman.Monitor;
using Foreman.Monitor.Wmi;
using System.Reflection;

namespace Foreman.Monitor.Tests;

public sealed class WmiProcessWatcherTests
{
    [Fact]
    public void ParseDmtfDate_PreservesWmiUtcOffset()
    {
        var method = typeof(WmiProcessWatcher).GetMethod(
            "ParseDmtfDate",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var parsed = (DateTimeOffset)method!.Invoke(null, ["20260608205253.127537+570"])!;

        Assert.Equal(TimeSpan.FromMinutes(570), parsed.Offset);
        Assert.Equal(2026, parsed.Year);
        Assert.Equal(6, parsed.Month);
        Assert.Equal(8, parsed.Day);
        Assert.Equal(20, parsed.Hour);
        Assert.Equal(52, parsed.Minute);
        Assert.Equal(53, parsed.Second);
        Assert.Equal(
            new DateTimeOffset(2026, 6, 8, 11, 22, 53, 127, TimeSpan.Zero).AddTicks(5370),
            parsed.ToUniversalTime());
    }

    [Fact]
    public void IoPoller_DisposeAfterStart_DoesNotThrowOnCancellation()
    {
        var tree = new ProcessTreeTracker();
        var hang = new HangDetector(new EventBus(), new ForemanSettings(), tree);
        var poller = new IoPoller(
            tree,
            hang,
            new ForemanSettings { IoPollerIntervalSeconds = 60 },
            new EventBus());

        poller.Start();
        poller.Dispose();
    }

    [Fact]
    public void ReconciliationOrphan_UsesDeadParentLedgerEntry_NotChildPid()
    {
        var now = new DateTimeOffset(2026, 8, 26, 12, 0, 0, TimeSpan.Zero);
        var parent = new ProcessRecord
        {
            Pid = 700_001,
            Name = "codex.exe",
            StartTime = now.AddMinutes(-5),
            IsHarness = true,
            HarnessType = "codex",
        };
        var child = new ProcessRecord
        {
            Pid = 700_002,
            ParentPid = parent.Pid,
            Name = "node.exe",
            StartTime = now.AddMinutes(-4),
        };
        var orphan = new ProcessTreeTracker.OrphanedChild(child, parent);
        var method = typeof(IoPoller).GetMethod(
            "PublishReconciledOrphans",
            BindingFlags.NonPublic | BindingFlags.Instance)!;

        var expectedBus = new EventBus();
        var expectedTree = new ProcessTreeTracker();
        var expectedPoller = new IoPoller(
            expectedTree,
            new HangDetector(expectedBus, new ForemanSettings(), expectedTree),
            new ForemanSettings(),
            expectedBus)
        {
            ExpectedTerminations = new ExpectedTerminationLedger(TimeSpan.FromMinutes(1), () => now),
        };
        expectedPoller.ExpectedTerminations.Record(parent.Pid, parent.StartTime, "operator:test", "test");

        method.Invoke(expectedPoller, [new[] { orphan }]);

        Assert.DoesNotContain(expectedBus.GetHistory(), static e => e is OrphanDetectedEvent);

        var rawBus = new EventBus();
        var rawTree = new ProcessTreeTracker();
        var rawPoller = new IoPoller(
            rawTree,
            new HangDetector(rawBus, new ForemanSettings(), rawTree),
            new ForemanSettings(),
            rawBus);

        method.Invoke(rawPoller, [new[] { orphan }]);

        Assert.Contains(rawBus.GetHistory(), static e => e is OrphanDetectedEvent);
    }
}
