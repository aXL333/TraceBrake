using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.Core.Settings;
using Foreman.Core.Termination;
using System.Runtime.InteropServices;

namespace Foreman.Monitor;

/// <summary>
/// Polls I/O counters for all tracked processes every N seconds.
/// Drives HangDetector and feeds ProcessTreeTracker.
/// </summary>
public sealed class IoPoller : IDisposable
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessIoCounters(nint hProcess, out IoCounters counters);

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    private readonly ProcessTreeTracker _tree;
    private readonly HangDetector _hangDetector;
    private readonly ForemanSettings _settings;
    private readonly EventBus _bus;
    private readonly CancellationTokenSource _cts = new();
    private Task? _task;
    private bool _reconcileDegraded;   // true after a reconciliation pass throws, until one succeeds again

    /// <summary>Shared broker ledger used when reconciliation observes an exit whose WMI event was missed.</summary>
    public ExpectedTerminationLedger? ExpectedTerminations { get; set; }

    // A record must survive at least this long before the reconciler may evict it, so a process created
    // just after the live-PID snapshot is never mistaken for dead.
    private static readonly TimeSpan PruneMinAge = TimeSpan.FromSeconds(60);

    public IoPoller(ProcessTreeTracker tree, HangDetector hangDetector, ForemanSettings settings, EventBus bus)
    {
        _tree = tree;
        _hangDetector = hangDetector;
        _settings = settings;
        _bus = bus;
    }

    public void Start()
    {
        _task = RunAsync(_cts.Token);
    }

    private async Task RunAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(_settings.IoPollerIntervalSeconds));
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            // Reconcile first: evict records whose process has exited (covers WMI termination events
            // dropped under load, which would otherwise leak the tree to thousands of dead entries —
            // and shrinks the set this poll then iterates).
            ReconcileTree();
            foreach (var record in _tree.GetAll())
            {
                PollRecord(record);
            }
        }
    }

    private void ReconcileTree()
    {
        try
        {
            var outcome = _tree.PruneDeadProcesses(PruneMinAge);
            if (_reconcileDegraded)
            {
                _reconcileDegraded = false;
                _bus.Publish(new MonitoringNoticeEvent(
                    DateTimeOffset.UtcNow, ForemanSeverity.Low, "Foreman.Monitor",
                    "Process-tree reconciliation recovered."));
            }
            foreach (var rec in outcome.Evicted)
                _hangDetector.Forget(rec.Pid);   // drop any hang-alert state held for the gone pids

            // Orphan recovery: a parent whose WMI termination event was DROPPED never went through
            // OnProcessDeleted, so its surviving children were never flagged orphaned. Emit them now —
            // mirroring the WMI path's local-model-host suppression (a local-model host shedding children
            // on exit is normal teardown, not an abandoned orphan).
            PublishReconciledOrphans(outcome.Orphans);

            // Surface only a meaningful catch-up (the first pass after drift), not routine churn.
            if (outcome.Evicted.Count >= 10)
                _bus.Publish(new MonitoringNoticeEvent(
                    DateTimeOffset.UtcNow, ForemanSeverity.Low, "Foreman.Monitor",
                    $"Process-tree reconciliation evicted {outcome.Evicted.Count} stale record(s) whose processes had already exited."));
        }
        catch (Exception ex)
        {
            // Never break the I/O poll loop — but a PERSISTENT janitor failure silently regresses to the
            // stale-record leak this exists to prevent, so surface the first occurrence (and the recovery
            // above), then stay quiet so a recurring fault can't flood.
            if (!_reconcileDegraded)
            {
                _reconcileDegraded = true;
                try
                {
                    _bus.Publish(new MonitoringNoticeEvent(
                        DateTimeOffset.UtcNow, ForemanSeverity.Medium, "Foreman.Monitor",
                        $"Process-tree reconciliation is failing ({ex.GetType().Name}); the monitored-process list may drift until it recovers."));
                }
                catch { }
            }
        }
    }

    private void PublishReconciledOrphans(IEnumerable<ProcessTreeTracker.OrphanedChild> orphans)
    {
        foreach (var o in orphans)
        {
            // The expectation is for the parent/root whose brokered termination caused the orphan observation,
            // not for the still-live child. Checking the child PID would miss the exact process-tree-kill path.
            if (ExpectedTerminations?.WasExpected(o.Parent.Pid, o.Parent.StartTime, out _) == true) continue;
            if (KnownHarnesses.IsLocalModelHost(o.Parent.HarnessType)) continue;
            var harness = _tree.AttributeOrphanHarness(o.Child, o.Parent);
            if (harness is null) continue;   // not part of a harness tree — ignore (Windows process churn)
            _bus.Publish(new OrphanDetectedEvent(
                DateTimeOffset.UtcNow, "Foreman.Monitor",
                $"{o.Child.Name} (pid {o.Child.Pid}) is orphaned — parent {o.Parent.Name} (pid {o.Parent.Pid}) " +
                $"exited (its termination event was missed; caught by reconciliation) [harness: {harness.HarnessType ?? harness.Name}]",
                o.Child.Pid, o.Child.Name, o.Parent.Pid, o.Parent.Name, o.Child.UptimeMinutes,
                harness.Pid, harness.HarnessType, harness.Name)
                { ProcessStartTime = o.Child.StartTime });
        }
    }

    private void PollRecord(ProcessRecord record)
    {
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById(record.Pid);
            if (GetProcessIoCounters(proc.Handle, out var counters))
            {
                _tree.UpdateIoCounters(record.Pid, counters.ReadOperationCount, counters.WriteOperationCount);
            }
        }
        catch (ArgumentException)
        {
            // process no longer exists — WMI termination event will handle tree cleanup;
            // drop any hang-alert state we held for this pid so the dict can't grow forever
            _hangDetector.Forget(record.Pid);
            return;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // access denied (elevated process) — mark counters unavailable but keep tracking
            record.IoCountersUnavailable = true;
        }
        catch { }

        _hangDetector.Check(record);
    }

    public void Dispose()
    {
        _cts.Cancel();
        try
        {
            _task?.GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown path: PeriodicTimer observes the cancelled token.
        }
        _cts.Dispose();
    }
}
