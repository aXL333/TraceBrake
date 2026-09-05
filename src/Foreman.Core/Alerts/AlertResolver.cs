using Foreman.Core.Events;
using Foreman.Core.Models;

namespace Foreman.Core.Alerts;

/// <summary>
/// Gives alerts a lifecycle so the tray doesn't sit amber forever after the underlying problem is gone.
/// Periodically re-evaluates open alerts and auto-resolves the ones whose condition has cleared:
///   • a hang resolves when its process exits or resumes I/O,
///   • an orphan resolves when the process exits,
///   • a point-in-time alert (nonzero exit) ages out after <see cref="ExpireAfter"/>.
/// Command/permission/escalation alerts have no natural resolution — they represent something that
/// happened and stay active until the operator acknowledges them.
///
/// It mutates the shared <see cref="ForemanEvent"/> instances (the same objects the tray, dashboard,
/// and MCP state hold via the EventBus history), so a resolution shows up everywhere at once — and
/// publishes a one-line Info notice to the log so the operator can see what cleared.
/// </summary>
public sealed class AlertResolver : IDisposable
{
    private readonly EventBus _bus;
    private readonly Func<IReadOnlyList<ForemanEvent>> _alerts;
    private readonly Func<IReadOnlyList<ProcessRecord>> _snapshot;
    private readonly Action? _onChanged;
    private readonly CancellationTokenSource _cts = new();
    private Task? _task;

    /// <summary>How long a point-in-time alert (e.g. nonzero exit) stays active before it ages out.</summary>
    public TimeSpan ExpireAfter { get; set; } = TimeSpan.FromHours(8);

    public AlertResolver(
        EventBus bus,
        Func<IReadOnlyList<ForemanEvent>> alerts,
        Func<IReadOnlyList<ProcessRecord>> snapshot,
        Action? onChanged = null)
    {
        _bus = bus;
        _alerts = alerts;
        _snapshot = snapshot;
        _onChanged = onChanged;
    }

    public void Start() => _task = RunAsync(_cts.Token);

    private async Task RunAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(15));
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            try
            {
                if (Evaluate(_alerts(), _snapshot(), DateTimeOffset.UtcNow) > 0)
                    _onChanged?.Invoke();
            }
            catch { /* a single bad sweep must not kill the loop */ }
        }
    }

    /// <summary>
    /// Auto-resolves any open alert whose condition has cleared. Returns the number resolved this pass.
    /// Pure enough to unit-test: pass crafted alerts + a process snapshot and inspect the flags.
    /// </summary>
    public int Evaluate(IReadOnlyList<ForemanEvent> alerts, IReadOnlyList<ProcessRecord> snapshot, DateTimeOffset now)
    {
        var resolved = 0;
        foreach (var e in alerts)
        {
            if (e.Acknowledged || e.AutoResolved || e.Severity <= ForemanSeverity.Info) continue;

            var reason = e switch
            {
                HangDetectedEvent h    => HangReason(h, snapshot),
                OrphanDetectedEvent o  => FindLive(snapshot, o.ProcessId, o.ProcessStartTime) is null ? "the process exited" : null,
                NonzeroExitEvent       => now - e.Timestamp >= ExpireAfter ? "aged out" : null,
                _                      => null,
            };
            if (reason is null) continue;

            e.AutoResolved = true;
            e.ResolvedReason = reason;
            resolved++;
            if (e is HangDetectedEvent hang)
            {
                var outcome = reason == "I/O resumed"
                    ? HangOutcomeKind.IoResumed
                    : HangOutcomeKind.ProcessExited;
                _bus.Publish(HangLearning.Outcome(hang, outcome, now, operatorLabeled: false));
            }
            else
            {
                _bus.Publish(new InfoEvent(now, "Foreman.Alerts",
                    $"Alert auto-resolved ({reason}): {Trim(e.Message)}"));
            }
        }
        return resolved;
    }

    private static string? HangReason(HangDetectedEvent h, IReadOnlyList<ProcessRecord> snapshot)
    {
        var live = FindLive(snapshot, h.ProcessId, h.ProcessStartTime);
        if (live is null) return "the process exited";
        if (live.IoCountersUnavailable) return null;             // can't tell — leave it open
        if (live.LastIoChangeTime > h.Timestamp) return "I/O resumed";
        return null;
    }

    // Matches a live (non-terminated) process by pid, verifying start time when known so a recycled
    // PID isn't mistaken for the original — if the original is gone, the alert resolves as "exited".
    private static ProcessRecord? FindLive(IReadOnlyList<ProcessRecord> snapshot, int pid, DateTimeOffset? startTime)
    {
        foreach (var p in snapshot)
            if (p.Pid == pid && p.State != ProcessState.Terminated &&
                (startTime is null || Math.Abs((p.StartTime - startTime.Value).TotalSeconds) <= 1))
                return p;
        return null;
    }

    private static string Trim(string s) => s.Length <= 100 ? s : s[..100] + "…";

    public void Dispose()
    {
        _cts.Cancel();
        try { _task?.GetAwaiter().GetResult(); }
        catch (OperationCanceledException) { /* normal shutdown */ }
        _cts.Dispose();
    }
}
