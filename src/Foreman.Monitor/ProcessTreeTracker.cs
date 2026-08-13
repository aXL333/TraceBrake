using Foreman.Core.Models;
using System.Collections.Concurrent;
using System.Diagnostics;

namespace Foreman.Monitor;

/// <summary>
/// Thread-safe store of all tracked processes. Keyed by (pid, startTimeMs) to survive PID reuse.
/// </summary>
public sealed class ProcessTreeTracker
{
    private readonly ConcurrentDictionary<string, ProcessRecord> _records = new();
    // secondary lookup: pid → key (last winner wins on reuse)
    private readonly ConcurrentDictionary<int, string> _pidIndex = new();

    // Keys seen ABSENT from the live OS process set on the previous Prune pass. A record must be absent on
    // TWO consecutive passes before eviction (see Prune), so the WMI deletion event — and the orphan /
    // nonzero-exit accounting that ONLY OnProcessDeleted performs — reliably wins the race for a process that
    // has only just exited. Touched solely on the IoPoller (prune) thread.
    private readonly HashSet<string> _absentSincePrevPrune = new();

    /// <summary>A still-live child left orphaned because the reconciler evicted its (WMI-missed-dead) parent.</summary>
    public sealed record OrphanedChild(ProcessRecord Child, ProcessRecord Parent);

    /// <summary>What one reconciliation pass produced: the evicted dead records + any children it orphaned.</summary>
    public sealed record PruneOutcome(IReadOnlyList<ProcessRecord> Evicted, IReadOnlyList<OrphanedChild> Orphans);

    public IEnumerable<ProcessRecord> GetAll() => _records.Values;

    public ProcessRecord? GetByPid(int pid)
    {
        if (_pidIndex.TryGetValue(pid, out var key) && _records.TryGetValue(key, out var rec))
            return rec;
        return null;
    }

    public void OnProcessCreated(ProcessRecord record)
    {
        _records[record.Key] = record;
        _pidIndex[record.Pid] = record.Key;
    }

    /// <summary>
    /// Called when a process exits. Returns all live children that are now orphaned.
    /// </summary>
    public IReadOnlyList<ProcessRecord> OnProcessDeleted(
        int pid,
        DateTimeOffset? startTime,
        out ProcessRecord? deleted)
    {
        deleted = null;

        string? key = null;
        if (startTime is not null)
        {
            var stableKey = $"{pid}:{startTime.Value.ToUnixTimeMilliseconds()}";
            if (_records.ContainsKey(stableKey))
                key = stableKey;
        }

        if (key is null && !_pidIndex.TryGetValue(pid, out key)) return [];

        _records.TryRemove(key, out deleted);
        if (_pidIndex.TryGetValue(pid, out var indexedKey) && indexedKey == key)
            _pidIndex.TryRemove(pid, out _);

        // find children whose parent was this pid and are still alive
        var orphans = _records.Values
            .Where(r => r.ParentPid == pid && r.State != ProcessState.Terminated)
            .ToList();
        foreach (var orphan in orphans)
            orphan.State = ProcessState.Orphaned;
        return orphans;
    }

    /// <summary>
    /// Reconciliation pass: evicts tracked records whose process is no longer live, so the tree can't
    /// accumulate stale entries when a WMI termination event is dropped under load (the classic
    /// "thousands of monitored processes vs hundreds real" drift). A record is removed ONLY when its PID
    /// is absent from <paramref name="livePids"/> — a PID missing from the full OS process list is
    /// definitively gone — so a live process is never evicted on uncertainty. Records younger than
    /// <paramref name="minAge"/> are kept, since they may simply post-date a snapshot taken a moment
    /// before they were created. Returns the evicted records so the caller can log the reconciliation.
    ///
    /// Two-pass grace: a record is evicted only after it has been absent on TWO consecutive passes. The WMI
    /// deletion event (WITHIN ~2s) — and the orphan + nonzero-exit accounting that ONLY
    /// <see cref="OnProcessDeleted"/> performs — therefore reliably wins the race for a just-exited process
    /// (its record is removed by that handler before this janitor's second pass), so reconciliation only ever
    /// cleans up records WMI genuinely missed. Without the grace, a Prune tick landing in the WMI delivery
    /// window would remove the record first and silently suppress those events.
    ///
    /// Deterministic for testing (call twice with the PID still absent to cross the grace);
    /// <see cref="PruneDeadProcesses"/> supplies the live set. State (<see cref="_absentSincePrevPrune"/>) is
    /// touched only on the single prune thread. NOTE: a reused PID keeps BOTH its records alive here (the live
    /// PID protects them); that rarer case is handled by <see cref="OnProcessCreated"/> re-pointing the index.
    /// </summary>
    public PruneOutcome Prune(IReadOnlySet<int> livePids, DateTimeOffset now, TimeSpan minAge)
    {
        List<ProcessRecord>? evicted = null;
        var absentNow = new HashSet<string>();
        foreach (var rec in _records.Values)   // ConcurrentDictionary snapshot enumeration is safe under concurrent writes
        {
            if (livePids.Contains(rec.Pid)) continue;     // still alive
            if (now - rec.StartTime < minAge) continue;   // too young — may post-date the live snapshot

            absentNow.Add(rec.Key);
            // Grace: defer eviction until a record has been absent on two consecutive passes, so the WMI
            // deletion event (and its orphan / nonzero-exit accounting) wins the race for a just-exited process.
            if (!_absentSincePrevPrune.Contains(rec.Key)) continue;

            if (_records.TryRemove(rec.Key, out var removed))
            {
                // Only drop the pid→key index if it still points at the record we removed (a PID reused
                // after the snapshot would have re-pointed the index at the newer record — leave that).
                if (_pidIndex.TryGetValue(rec.Pid, out var idxKey) && idxKey == rec.Key)
                    _pidIndex.TryRemove(rec.Pid, out _);
                (evicted ??= []).Add(removed);
            }
        }
        // Carry this pass's absentees forward as the grace baseline for the next pass.
        _absentSincePrevPrune.Clear();
        _absentSincePrevPrune.UnionWith(absentNow);

        // Orphan recovery: the WMI delete watcher flags orphaned children in OnProcessDeleted; when that delete
        // event is DROPPED (the very case this reconciler cleans up), those children were never flagged. So for
        // each parent we just evicted, mark any still-live, not-yet-flagged child orphaned and surface it. No
        // double-emit: the two-pass grace means a WMI-HANDLED parent is already gone before we'd evict it, so
        // this only fires for genuinely-missed deaths.
        List<OrphanedChild>? orphans = null;
        if (evicted is { Count: > 0 })
        {
            var evictedByPid = new Dictionary<int, ProcessRecord>();
            foreach (var p in evicted) evictedByPid[p.Pid] = p;   // last wins on the rare same-pid dup
            foreach (var rec in _records.Values)
            {
                if (rec.State is ProcessState.Orphaned or ProcessState.Terminated) continue;
                if (!evictedByPid.TryGetValue(rec.ParentPid, out var parent)) continue;
                rec.State = ProcessState.Orphaned;
                (orphans ??= []).Add(new OrphanedChild(rec, parent));
            }
        }

        return new PruneOutcome(evicted ?? [], orphans ?? []);
    }

    /// <summary>
    /// Gathers the live OS PID set and prunes dead records against it. Best-effort: a process that exits
    /// mid-enumeration simply isn't in the set (and is pruned on the next pass).
    /// </summary>
    public PruneOutcome PruneDeadProcesses(TimeSpan minAge)
    {
        var live = new HashSet<int>();
        foreach (var p in Process.GetProcesses())
        {
            live.Add(p.Id);
            p.Dispose();
        }
        return Prune(live, DateTimeOffset.UtcNow, minAge);
    }

    public bool IsTrackedHarness(int pid)
    {
        var rec = GetByPid(pid);
        return rec?.IsHarness ?? false;
    }

    /// <summary>
    /// Walks the parent chain from <paramref name="pid"/> (inclusive) and returns the first
    /// record matching <paramref name="match"/>, or null.
    ///
    /// Safe against PID reuse, missing parents, and cycles: the walk stops as soon as a
    /// parent is no longer tracked, and a visited-set prevents infinite loops. Failing to
    /// find a match returns null, so callers fail *toward silence* (no false attribution).
    /// </summary>
    private ProcessRecord? WalkAncestors(int pid, Func<ProcessRecord, bool> match)
    {
        var seen = new HashSet<int>();
        var current = GetByPid(pid);
        while (current is not null && seen.Add(current.Pid))
        {
            if (match(current)) return current;
            // A genuine harness subtree never descends THROUGH a Windows OS host (svchost, services, sihost,
            // …) — a real harness child hits its harness match first. So an OS host appearing as an ANCESTOR
            // means this parent edge is stale / a reused PID / an unreliable WMI ParentProcessId: stop here
            // rather than mis-attributing an unrelated OS process to a harness (which then floods hang notices).
            if (IsSystemHost(current.Name)) break;
            if (current.ParentPid == 0 || current.ParentPid == current.Pid) break;
            current = GetByPid(current.ParentPid);
        }
        return null;
    }

    // Windows OS hosts that never sit INSIDE a harness's process subtree. Hitting one while walking ANCESTORS
    // marks the chain above it untrustworthy (PID reuse / stale ppid), so the walk stops and attributes nothing.
    private static readonly HashSet<string> SystemHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "services.exe", "wininit.exe", "winlogon.exe", "lsass.exe", "csrss.exe", "smss.exe",
        "explorer.exe", "sihost.exe", "taskhostw.exe", "dwm.exe", "fontdrvhost.exe", "ctfmon.exe",
        "RuntimeBroker.exe", "MoUsoCoreWorker.exe", "usocoreworker.exe", "dllhost.exe", "WmiPrvSE.exe",
        "System", "Registry", "MemCompression",
    };

    private static bool IsSystemHost(string? name) => name is not null && SystemHosts.Contains(name);

    /// <summary>
    /// Nearest ancestor (including the process itself) that is an actively-monitored harness
    /// (IsHarness == true). Used to scope hang detection to harness trees.
    /// </summary>
    public ProcessRecord? FindHarnessAncestor(int pid) => WalkAncestors(pid, static r => r.IsHarness);

    /// <summary>
    /// Nearest ancestor (including the process itself) that carries a HarnessType — even a
    /// disabled one. Used to *attribute* a child process to the harness it belongs to: a
    /// PowerShell hook or a shell spawned by claude-code matches no harness rule itself, but
    /// its parent chain leads back to the harness node process.
    /// </summary>
    public ProcessRecord? FindHarnessTypeAncestor(int pid) => WalkAncestors(pid, static r => r.HarnessType is not null);

    /// <summary>
    /// The harness an orphaned <paramref name="child"/> belongs to, or null if it is not part of any harness
    /// tree. Used to SCOPE orphan alerts to harness subtrees — a re-parented Windows process (e.g. SIHClient.exe
    /// whose upfc.exe launcher exits) has no harness lineage and returns null, so it is ignored rather than
    /// flagged as an "orphaned harness child" — and to ATTRIBUTE the orphans that do matter.
    ///
    /// <paramref name="deadParent"/> is the just-exited parent record (already removed from the tree by
    /// <see cref="OnProcessDeleted"/>, or evicted by <see cref="Prune"/>) — we still hold the object, and the
    /// chain ABOVE it stays in the tree, so resolve in order: the parent itself if it is harness-typed; else the
    /// parent's nearest harness-typed ANCESTOR (walked from the grandparent, since the parent is gone); else the
    /// child itself if IT is a harness node whose plain (non-harness) launcher just died. Fails toward silence
    /// (returns null, no false attribution) when no harness is provable — like <see cref="WalkAncestors"/>.
    /// </summary>
    public ProcessRecord? AttributeOrphanHarness(ProcessRecord child, ProcessRecord? deadParent)
    {
        if (deadParent?.HarnessType is not null) return deadParent;
        if (deadParent is not null && FindHarnessTypeAncestor(deadParent.ParentPid) is { } ancestor) return ancestor;
        if (child.HarnessType is not null) return child;
        return null;
    }

    /// <summary>
    /// Nearest ancestor (including the process itself) with a matched permission profile.
    /// </summary>
    public ProcessRecord? FindProfileAncestor(int pid) => WalkAncestors(pid, static r => r.ProfileName is not null);

    /// <summary>
    /// Nearest ancestor (including the process itself) whose command line is a package install
    /// (npm/pnpm/yarn/bun install, node-gyp, pip/uv install, python setup.py). Used to escalate a
    /// credential/network rule that fires INSIDE an install subtree — the Miasma / Phantom-Gyp
    /// install-time detonation, where such a read is almost never legitimate.
    /// </summary>
    public ProcessRecord? FindInstallAncestor(int pid) =>
        WalkAncestors(pid, static r => Foreman.Core.Security.InstallSubtree.IsPackageInstall(r.CommandLine));

    public void UpdateIoCounters(int pid, ulong readOps, ulong writeOps)
    {
        if (!_pidIndex.TryGetValue(pid, out var key)) return;
        if (!_records.TryGetValue(key, out var rec)) return;

        if (readOps != rec.LastReadOps || writeOps != rec.LastWriteOps)
        {
            rec.LastReadOps = readOps;
            rec.LastWriteOps = writeOps;
            rec.LastIoChangeTime = DateTimeOffset.UtcNow;
            rec.State = ProcessState.Active;
        }
    }

    public void SetState(int pid, ProcessState state)
    {
        if (!_pidIndex.TryGetValue(pid, out var key)) return;
        if (_records.TryGetValue(key, out var rec))
            rec.State = state;
    }

    /// <summary>
    /// Returns all currently tracked processes whose HarnessType matches
    /// (case-insensitive). Used by BehaviorMetricsWindow / EscalationAlarmWindow.
    /// </summary>
    public IEnumerable<ProcessRecord> GetByHarnessType(string harnessType) =>
        _records.Values.Where(r =>
            string.Equals(r.HarnessType, harnessType, StringComparison.OrdinalIgnoreCase));

    public IEnumerable<ProcessRecord> GetTreeByHarnessType(string harnessType) =>
        _records.Values.Where(r =>
            string.Equals(r.HarnessType, harnessType, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(FindHarnessTypeAncestor(r.Pid)?.HarnessType, harnessType, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Terminates every tracked process in the matching harness tree. Driven by the LIVE tree
    /// (not a stale alert), so each record is current by construction. Skips TraceBrake itself and
    /// the low system PIDs. Silently ignores processes that have already exited.
    /// </summary>
    public void KillHarness(string harnessType)
    {
        foreach (var rec in GetTreeByHarnessType(harnessType).ToList())
        {
            if (KillGuard.IsProtected(rec.Pid, rec.Name)) continue;   // never the OS, the shell, AV, or TraceBrake's own
            try
            {
                using var proc = Process.GetProcessById(rec.Pid);
                proc.Kill(entireProcessTree: rec.IsHarness);
                SetState(rec.Pid, ProcessState.Terminated);
            }
            catch { /* already exited or access denied */ }
        }
    }

    /// <summary>
    /// Terminates the process identified by <paramref name="pid"/> AND <paramref name="expectedStartTime"/>
    /// (the WMI CreationDate captured on the originating alert), plus its descendant tree.
    ///
    /// Identity is proven by comparing the alert's captured start time against the CURRENTLY-tracked
    /// record for that PID — both are the same WMI source, so equal means "same process" and a recycled
    /// PID (which has a different CreationDate, or is no longer tracked) is refused. This is what makes a
    /// stale alert safe: it cannot kill an unrelated process that later inherited the PID.
    ///
    /// Returns false when the target can't be verified, isn't tracked, has exited, or access is denied.
    /// </summary>
    public bool KillProcess(int pid, DateTimeOffset? expectedStartTime)
    {
        if (KillGuard.IsProtectedPid(pid)) return false;
        if (expectedStartTime is not { } expected) return false;   // no identity pin → never kill a bare PID

        var rec = GetByPid(pid);
        if (rec is null) return false;                             // not tracked (exited or never seen)
        if (KillGuard.IsProtected(pid, rec.Name)) return false;    // protected by name (Foreman/guardian/sidecar/OS/AV)
        if (Math.Abs((rec.StartTime - expected).TotalSeconds) > 1) return false;  // PID reused since the alert

        try
        {
            using var proc = Process.GetProcessById(pid);
            proc.Kill(entireProcessTree: true);
            SetState(pid, ProcessState.Terminated);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
