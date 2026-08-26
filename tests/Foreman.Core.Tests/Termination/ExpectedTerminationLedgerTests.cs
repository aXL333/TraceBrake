using Foreman.Core.Termination;

namespace Foreman.Core.Tests.Termination;

/// <summary>
/// The ledger is what tells an authorised (brokered) kill from a raw one: a death with a matching entry inside
/// the window is "expected → quiet"; without one it stays loud. Covers match, PID-reuse rejection, and expiry.
/// </summary>
public sealed class ExpectedTerminationLedgerTests
{
    private DateTimeOffset _now = new(2026, 6, 18, 12, 0, 0, TimeSpan.Zero);

    private ExpectedTerminationLedger New(TimeSpan? window = null) => new(window, () => _now);

    [Fact]
    public void RecordedKill_IsExpected_WithinWindow()
    {
        var l = New();
        l.Record(1234, _now, "codex", "runaway child");
        Assert.True(l.WasExpected(1234, _now, out var m));
        Assert.Equal("codex", m!.ByHarness);
    }

    [Fact]
    public void UnrecordedKill_IsNotExpected()
    {
        var l = New();
        Assert.False(l.WasExpected(9999, _now, out _));   // a raw kill — the loud path
    }

    [Fact]
    public void RecycledPid_DifferentStartTime_IsNotExpected()
    {
        var l = New();
        l.Record(1234, _now, "codex", "x");
        // Same PID, but the process that just died started 5s later — a recycled PID, not the brokered one.
        Assert.False(l.WasExpected(1234, _now.AddSeconds(5), out _));
    }

    [Fact]
    public void Match_IgnoresStartTime_WhenEitherSideUnknown()
    {
        var l = New();
        l.Record(1234, startTime: null, "codex", "x");          // broker didn't capture a start time
        Assert.True(l.WasExpected(1234, _now, out _));          // still matches on PID alone
        var l2 = New();
        l2.Record(1234, _now, "codex", "x");
        Assert.True(l2.WasExpected(1234, startTime: null, out _));
    }

    [Fact]
    public void Entry_Expires_AfterWindow()
    {
        var l = New(TimeSpan.FromSeconds(30));
        l.Record(1234, _now, "codex", "x");
        _now = _now.AddSeconds(31);
        Assert.False(l.WasExpected(1234, null, out _));   // window lapsed — no longer excused
    }

    [Fact]
    public void WasExpected_DoesNotConsumeEntry()
    {
        var l = New();
        l.Record(1234, _now, "codex", "x");
        // One brokered kill fans out into orphan + exit + command-detection events — all must read as expected.
        Assert.True(l.WasExpected(1234, _now, out _));
        Assert.True(l.WasExpected(1234, _now, out _));
        Assert.True(l.WasExpected(1234));
    }

    [Fact]
    public void FailedBrokerKill_CanWithdrawExpectationWithoutExcusingLaterRawKill()
    {
        var l = New();
        l.Record(1234, _now, "codex", "requested");

        Assert.True(l.Remove(1234, _now));
        Assert.False(l.WasExpected(1234, _now, out _));
        Assert.False(l.Remove(1234, _now));
    }
}
