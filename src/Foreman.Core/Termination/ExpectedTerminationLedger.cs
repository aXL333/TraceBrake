namespace Foreman.Core.Termination;

/// <summary>
/// The record of terminations TraceBrake BROKERED on a harness's behalf (the request_process_kill tool). It is what
/// lets the detection layer tell an AUTHORISED kill from a raw, un-attributed one — the whole "authed = quiet,
/// raw = loud" inversion.
///
/// When a brokered kill lands, the monitor observes the same process death it would for any kill (an orphaned
/// child, a non-zero exit, a kill command on the wire). A matching ledger entry within a short window means
/// "expected — stay quiet"; a death with NO entry is the loud signal worth surfacing.
///
/// Process-global (one watchdog per machine), thread-safe, self-pruning. Lives in Core so the McpServer broker
/// (producer) and the Monitor detection path (consumer) — which don't reference each other — can share it.
/// </summary>
public sealed class ExpectedTerminationLedger
{
    /// <summary>One brokered termination: the target, who asked, why, and when TraceBrake recorded it.</summary>
    public sealed record Entry(int Pid, DateTimeOffset? StartTime, string ByHarness, string Reason, DateTimeOffset At);

    private readonly object _gate = new();
    private readonly List<Entry> _entries = new();
    private readonly TimeSpan _window;
    private readonly Func<DateTimeOffset> _now;

    /// <param name="window">How long a brokered kill counts as "expected" after it's recorded (default 30s — long
    /// enough to cover the WMI termination + orphan/exit events that follow, short enough that a later, unrelated
    /// raw kill of a recycled PID isn't silently excused).</param>
    public ExpectedTerminationLedger(TimeSpan? window = null, Func<DateTimeOffset>? now = null)
    {
        _window = window ?? TimeSpan.FromSeconds(30);
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>Record that <paramref name="byHarness"/> had TraceBrake terminate <paramref name="pid"/>. Call this
    /// BEFORE issuing the kill so the entry is in place when the termination events fire moments later.</summary>
    public void Record(int pid, DateTimeOffset? startTime, string byHarness, string reason)
    {
        lock (_gate)
        {
            Prune();
            _entries.Add(new Entry(pid, startTime, byHarness, reason, _now()));
        }
    }

    /// <summary>
    /// True if a brokered kill of this process was recorded within the window. Matches on PID and — when both
    /// sides carry it — start time (±1s, same WMI source), so a recycled PID's later death isn't mistaken for the
    /// brokered one. Does NOT consume the entry: one brokered kill yields several detection events (orphan + exit +
    /// command), and every one of them should read as expected until the window lapses.
    /// </summary>
    public bool WasExpected(int pid, DateTimeOffset? startTime, out Entry? match)
    {
        lock (_gate)
        {
            Prune();
            match = _entries.FirstOrDefault(e =>
                e.Pid == pid &&
                (startTime is null || e.StartTime is null
                 || Math.Abs((e.StartTime.Value - startTime.Value).TotalSeconds) <= 1));
            return match is not null;
        }
    }

    /// <summary>Convenience overload when the caller has no start time to match on.</summary>
    public bool WasExpected(int pid) => WasExpected(pid, null, out _);

    private void Prune()
    {
        var cutoff = _now() - _window;
        _entries.RemoveAll(e => e.At < cutoff);
    }
}
