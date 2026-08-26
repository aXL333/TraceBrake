using Foreman.Core.Models;
using Foreman.Core.Termination;
using Foreman.Monitor;

namespace Foreman.Monitor.Tests;

/// <summary>
/// The kill path only ever terminates a process Foreman tracks whose identity (PID + captured
/// WMI start time) still matches the live record. These cover the security-critical refusals;
/// none of them reach an actual Process.Kill (each is rejected before that point).
/// </summary>
public sealed class ProcessTreeKillTests
{
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static ProcessRecord Rec(int pid, string name, DateTimeOffset start, string path = "", int parentPid = 0)
        => new() { Pid = pid, ParentPid = parentPid, Name = name, StartTime = start, ExecutablePath = path };

    private sealed class FakeTerminator : IProcessTerminator
    {
        public readonly Dictionary<int, (DateTimeOffset Start, string? Path)> Live = [];
        public readonly List<int> Killed = [];

        public bool TryTerminate(int pid, DateTimeOffset expectedStartTime, bool entireProcessTree,
            Func<string?, bool> isProtectedExecutable)
        {
            if (!Live.TryGetValue(pid, out var live)) return false;
            if (Math.Abs((live.Start - expectedStartTime).TotalSeconds) > 1) return false;
            if (isProtectedExecutable(live.Path)) return false;
            Assert.True(entireProcessTree);
            Killed.Add(pid);
            return true;
        }
    }

    [Fact]
    public void KillProcess_UntrackedPid_IsRefused()
    {
        var tree = new ProcessTreeTracker();
        // A bare PID Foreman never tracked (e.g. a forged target) — refused, no OS call.
        Assert.False(tree.KillProcess(999_999, T0));
    }

    [Fact]
    public void KillProcess_SystemPid_IsRefused()
    {
        var tree = new ProcessTreeTracker();
        tree.OnProcessCreated(Rec(4, "System", T0));
        Assert.False(tree.KillProcess(4, T0));   // PID 0/4 are never killable
    }

    [Fact]
    public void KillProcess_ForemanOwnPid_IsRefused()
    {
        var tree = new ProcessTreeTracker();
        var self = Environment.ProcessId;
        tree.OnProcessCreated(Rec(self, "Foreman.App", T0));

        Assert.False(tree.KillProcess(self, T0));                               // never self-terminate
        Assert.False(System.Diagnostics.Process.GetCurrentProcess().HasExited);  // and prove we didn't
    }

    [Fact]
    public void KillProcess_NullStartTime_IsRefused()
    {
        var tree = new ProcessTreeTracker();
        tree.OnProcessCreated(Rec(940_001, "cmd.exe", T0));
        // No identity pin from the alert → refuse rather than kill a bare PID.
        Assert.False(tree.KillProcess(940_001, expectedStartTime: null));
    }

    [Fact]
    public void KillProcess_RecycledPid_StartTimeMismatch_IsRefused()
    {
        var tree = new ProcessTreeTracker();
        // The currently-tracked record for this PID started at a different time than the alert
        // captured — i.e. the PID was recycled. Must refuse before touching the OS.
        tree.OnProcessCreated(Rec(940_002, "newproc.exe", T0));
        Assert.False(tree.KillProcess(940_002, expectedStartTime: T0.AddMinutes(-5)));
    }

    [Fact]
    public void KillProcess_LiveOsStartTimeMismatch_IsRefusedEvenWhenTrackerMatchesAlert()
    {
        var os = new FakeTerminator();
        os.Live[940_003] = (T0.AddMinutes(5), @"C:\temp\replacement.exe");
        var tree = new ProcessTreeTracker(os);
        tree.OnProcessCreated(Rec(940_003, "replacement.exe", T0, @"C:\temp\replacement.exe"));

        Assert.False(tree.KillProcess(940_003, T0));
        Assert.Empty(os.Killed);
    }

    [Fact]
    public void KillProcess_ImpostorTraceBrakeBasenameOutsideTrustedPath_IsKillable()
    {
        var os = new FakeTerminator();
        os.Live[940_004] = (T0, @"C:\temp\TraceBrake.exe");
        var tree = new ProcessTreeTracker(os);
        tree.OnProcessCreated(Rec(940_004, "TraceBrake.exe", T0, @"C:\temp\TraceBrake.exe"));

        Assert.True(tree.KillProcess(940_004, T0));
        Assert.Equal([940_004], os.Killed);
    }

    [Fact]
    public void KillHarness_IdentityPinsAndTerminatesOnlyTreeRoot()
    {
        var os = new FakeTerminator();
        os.Live[940_010] = (T0, @"C:\agents\agent.exe");
        os.Live[940_011] = (T0.AddSeconds(1), @"C:\agents\child.exe");
        var tree = new ProcessTreeTracker(os);
        var root = Rec(940_010, "agent.exe", T0, @"C:\agents\agent.exe");
        root.IsHarness = true;
        root.HarnessType = "codex";
        tree.OnProcessCreated(root);
        tree.OnProcessCreated(Rec(940_011, "child.exe", T0.AddSeconds(1), @"C:\agents\child.exe", 940_010));

        var result = tree.KillHarness("codex");

        Assert.Equal([940_010], os.Killed);
        Assert.True(result.Complete);
        Assert.Equal(2, result.MatchingProcessCount);
        Assert.Equal(1, result.RootCount);
        Assert.Equal(1, result.TerminatedRootCount);
        Assert.Equal(0, result.FailedRootCount);
    }

    [Fact]
    public void KillHarness_RecordsSuccessfulBrokeredRootButWithdrawsFailedAttempt()
    {
        var now = T0.AddMinutes(1);
        var ledger = new ExpectedTerminationLedger(TimeSpan.FromMinutes(2), () => now);
        var os = new FakeTerminator();
        os.Live[940_012] = (T0, @"C:\agents\good.exe");
        os.Live[940_013] = (T0.AddMinutes(5), @"C:\agents\reused.exe");
        var tree = new ProcessTreeTracker(os);
        foreach (var (pid, path) in new[]
                 {
                     (940_012, @"C:\agents\good.exe"),
                     (940_013, @"C:\agents\stale.exe"),
                 })
        {
            var rec = Rec(pid, Path.GetFileName(path), T0, path);
            rec.IsHarness = true;
            rec.HarnessType = "codex";
            tree.OnProcessCreated(rec);
        }

        var result = tree.KillHarness("codex", ledger, "operator:test", "test kill");

        Assert.Equal(1, result.TerminatedRootCount);
        Assert.Equal(1, result.FailedRootCount);
        Assert.True(ledger.WasExpected(940_012, T0, out var expected));
        Assert.Equal("operator:test", expected!.ByHarness);
        Assert.False(ledger.WasExpected(940_013));
    }

    [Fact]
    public void KillHarness_LiveIdentityFailure_IsReportedInsteadOfClaimingSuccess()
    {
        var os = new FakeTerminator();
        // The tracker still has the old Codex process, but the OS PID now belongs to a later process.
        os.Live[940_020] = (T0.AddMinutes(5), @"C:\agents\replacement.exe");
        var tree = new ProcessTreeTracker(os);
        var root = Rec(940_020, "codex.exe", T0, @"C:\agents\codex.exe");
        root.IsHarness = true;
        root.HarnessType = "codex";
        tree.OnProcessCreated(root);

        var result = tree.KillHarness("codex");

        Assert.Empty(os.Killed);
        Assert.False(result.Complete);
        Assert.False(result.AnyTerminated);
        Assert.Equal(1, result.FailedRootCount);
        Assert.Contains("Could not end any", result.OperatorMessage);
    }

    [Fact]
    public void KillHarness_RefusesTreeContainingVerifiedTraceBrakeDescendant()
    {
        var os = new FakeTerminator();
        os.Live[940_030] = (T0, @"C:\agents\agent.exe");
        var tree = new ProcessTreeTracker(os);
        var root = Rec(940_030, "agent.exe", T0, @"C:\agents\agent.exe");
        root.IsHarness = true;
        root.HarnessType = "codex";
        tree.OnProcessCreated(root);
        tree.OnProcessCreated(Rec(940_031, "Foreman.CuSidecar.exe", T0.AddSeconds(1),
            Path.Combine(AppContext.BaseDirectory, "cu-sidecar", "Foreman.CuSidecar.exe"), 940_030));

        var result = tree.KillHarness("codex");

        Assert.Empty(os.Killed);
        Assert.Equal(1, result.ProtectedRootCount);
        Assert.False(result.AnyTerminated);
    }

    [Fact]
    public void KillHarness_NoMatchingTree_IsReportedAsNoTarget()
    {
        var tree = new ProcessTreeTracker(new FakeTerminator());

        var result = tree.KillHarness("codex");

        Assert.False(result.HasTargets);
        Assert.False(result.Complete);
        Assert.Contains("already have exited", result.OperatorMessage);
    }

    [Fact]
    public void KillGuard_ProtectsVerifiedSelfAndSystemPathsButNotRenamedImpostors()
    {
        const string app = @"C:\Program Files\TraceBrake";
        const string windows = @"C:\Windows";
        const string programFiles = @"C:\Program Files";

        Assert.True(KillGuard.IsProtected(500, "Foreman.CuSidecar.exe",
            @"C:\Program Files\TraceBrake\cu-sidecar\Foreman.CuSidecar.exe", app, windows, programFiles));
        Assert.True(KillGuard.IsProtected(501, "svchost.exe",
            @"C:\Windows\System32\svchost.exe", app, windows, programFiles));
        Assert.False(KillGuard.IsProtected(502, "TraceBrake.exe",
            @"C:\temp\TraceBrake.exe", app, windows, programFiles));
        Assert.False(KillGuard.IsProtected(503, "svchost.exe",
            @"C:\agents\svchost.exe", app, windows, programFiles));
        Assert.True(KillGuard.IsProtected(504, "Foreman.CuPilot.exe",
            null, app, windows, programFiles));
        Assert.True(KillGuard.IsProtected(505, "svchost.exe",
            null, app, windows, programFiles));
    }
}
