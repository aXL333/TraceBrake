using Foreman.Core.Alerts;
using Foreman.Core.Events;
using Foreman.Core.Models;

namespace Foreman.Core.Tests.Alerts;

/// <summary>
/// Alert lifecycle: hangs auto-resolve when the process exits or resumes I/O, orphans when the process
/// exits, nonzero-exits age out; command/permission/escalation alerts stay active until acknowledged.
/// EventBus is a process-wide singleton; these tests don't assert on it, they inspect the event flags.
/// </summary>
public sealed class AlertResolverTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UnixEpoch.AddDays(1000);

    private static AlertResolver Resolver() =>
        new(new EventBus(), () => [], () => []);   // isolated bus; providers unused — we call Evaluate directly

    private static ProcessRecord Proc(int pid, DateTimeOffset start, int silentMinutes, bool unavailable = false) => new()
    {
        Pid = pid, Name = "p.exe", StartTime = start,
        LastIoChangeTime = Now - TimeSpan.FromMinutes(silentMinutes),
        IoCountersUnavailable = unavailable, State = ProcessState.Active,
    };

    private static HangDetectedEvent Hang(int pid, DateTimeOffset start, int ago) =>
        new(Now - TimeSpan.FromMinutes(ago), "Foreman.Monitor", "bash hung", pid, "bash", 30, 30, null, null, null, null, null)
        { ProcessStartTime = start };

    private static OrphanDetectedEvent Orphan(int pid, DateTimeOffset start) =>
        new(Now, "Foreman.Monitor", "orphaned", pid, "bash", 99, "node", 5) { ProcessStartTime = start };

    // ── Hang ────────────────────────────────────────────────────────────────────
    [Fact]
    public void Hang_ResolvesWhenProcessGone()
    {
        var start = Now.AddHours(-2);
        var h = Hang(5000, start, ago: 20);
        Resolver().Evaluate([h], snapshot: [], Now);   // empty snapshot → process exited
        Assert.True(h.AutoResolved);
        Assert.Equal("the process exited", h.ResolvedReason);
    }

    [Fact]
    public void Hang_ResolvesWhenIoResumed()
    {
        var start = Now.AddHours(-2);
        var h = Hang(5001, start, ago: 20);
        var live = Proc(5001, start, silentMinutes: 1);   // last I/O 1 min ago = after the 20-min-old alert
        Resolver().Evaluate([h], [live], Now);
        Assert.True(h.AutoResolved);
        Assert.Equal("I/O resumed", h.ResolvedReason);
    }

    [Fact]
    public void Hang_Resolution_PublishesAppendOnlyOutcome()
    {
        var bus = new EventBus();
        var outcomes = new List<HangOutcomeEvent>();
        bus.Subscribe(e => { if (e is HangOutcomeEvent outcome) outcomes.Add(outcome); });
        var resolver = new AlertResolver(bus, () => [], () => []);
        var start = Now.AddHours(-2);
        var h = Hang(5010, start, ago: 20);

        resolver.Evaluate([h], [], Now);

        var outcome = Assert.Single(outcomes);
        Assert.Equal(h.Id, outcome.HangAlertId);
        Assert.Equal(HangOutcomeKind.ProcessExited, outcome.Outcome);
        Assert.False(outcome.OperatorLabeled);
    }

    [Fact]
    public void Hang_StaysOpenWhileStillSilent()
    {
        var start = Now.AddHours(-2);
        var h = Hang(5002, start, ago: 5);
        var live = Proc(5002, start, silentMinutes: 30);  // last I/O before the alert → still hung
        Resolver().Evaluate([h], [live], Now);
        Assert.False(h.AutoResolved);
    }

    [Fact]
    public void Hang_PidReused_DifferentStart_ResolvesAsExited()
    {
        var h = Hang(5003, Now.AddHours(-3), ago: 20);
        var imposter = Proc(5003, Now.AddMinutes(-1), silentMinutes: 0);  // same pid, different start
        Resolver().Evaluate([h], [imposter], Now);
        Assert.True(h.AutoResolved);
        Assert.Equal("the process exited", h.ResolvedReason);
    }

    [Fact]
    public void Hang_UnavailableCounters_StaysOpen()
    {
        var start = Now.AddHours(-2);
        var h = Hang(5004, start, ago: 20);
        var live = Proc(5004, start, silentMinutes: 0, unavailable: true);
        Resolver().Evaluate([h], [live], Now);
        Assert.False(h.AutoResolved);   // can't tell → leave it for the operator
    }

    // ── Orphan ──────────────────────────────────────────────────────────────────
    [Fact]
    public void Orphan_ResolvesWhenProcessExits()
    {
        var o = Orphan(6000, Now.AddHours(-1));
        Resolver().Evaluate([o], [], Now);
        Assert.True(o.AutoResolved);
    }

    [Fact]
    public void Orphan_StaysOpenWhileAlive()
    {
        var start = Now.AddHours(-1);
        var o = Orphan(6001, start);
        Resolver().Evaluate([o], [Proc(6001, start, silentMinutes: 5)], Now);
        Assert.False(o.AutoResolved);
    }

    // ── Expiry & non-resolving kinds ──────────────────────────────────────────────
    [Fact]
    public void NonzeroExit_AgesOutAfterWindow()
    {
        var old = new NonzeroExitEvent(Now.AddHours(-9), "Foreman.Monitor", "exited 1", 700, "node", 1, null);
        var fresh = new NonzeroExitEvent(Now.AddHours(-1), "Foreman.Monitor", "exited 1", 701, "node", 1, null);
        Resolver().Evaluate([old, fresh], [], Now);   // ExpireAfter default 8h
        Assert.True(old.AutoResolved);
        Assert.False(fresh.AutoResolved);
    }

    [Fact]
    public void CommandAlert_NeverAutoResolves()
    {
        var cmd = new CommandAlertEvent(Now.AddHours(-50), ForemanSeverity.Critical, "src", "msg",
            "rm -rf /", "del-001", "rule", "desc", "guide", 800);
        Resolver().Evaluate([cmd], [], Now);
        Assert.False(cmd.AutoResolved);   // a dangerous command that ran needs operator review, not auto-clearing
    }

    [Fact]
    public void AlreadyAcknowledged_IsSkipped()
    {
        var o = Orphan(6002, Now.AddHours(-1));
        o.Acknowledged = true;
        var n = Resolver().Evaluate([o], [], Now);
        Assert.Equal(0, n);
        Assert.False(o.AutoResolved);   // ack already removed it from active; don't double-handle
    }

    [Fact]
    public void IsActive_ReflectsBothFlags()
    {
        var o = Orphan(6003, Now.AddHours(-1));
        Assert.True(AlertActivity.IsActive(o));
        o.AutoResolved = true;
        Assert.False(AlertActivity.IsActive(o));   // resolved → not active everywhere
    }
}
