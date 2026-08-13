using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.Core.Settings;
using Foreman.Core.Termination;

namespace Foreman.Monitor;

/// <summary>
/// "Idle Harness self-cleanup": watches each harness's process tree and, when it looks
/// abandoned (everything I/O-silent past the threshold), asks the harness over MCP to pack
/// up cleanly — checkpoint work, stop leftover children, release resources — via the
/// Ask-Harness mailbox plus a live push when the harness has an MCP session.
///
/// Two triggers: automatic (opt-in via <see cref="ForemanSettings.IdleCleanupEnabled"/>,
/// driven by a 60s timer) and manual (<see cref="TriggerCleanup"/>, wired to the Process
/// Monitor's per-harness context menu — always available regardless of the setting).
///
/// All decisions live in <see cref="IdleCleanupPolicy"/> (pure, tested). The MCP pieces are
/// injected by the App composition root, because Monitor must not reference McpServer.
/// </summary>
public sealed class IdleHarnessDetector : IDisposable
{
    private readonly EventBus _bus;
    private readonly ForemanSettings _settings;
    private readonly ProcessTreeTracker _tree;
    private readonly CancellationTokenSource _cts = new();
    private readonly object _gate = new();
    private readonly Dictionary<string, CleanupState> _state = new(StringComparer.OrdinalIgnoreCase);
    private Task? _task;

    private sealed class CleanupState
    {
        public DateTimeOffset RequestedAt;
        public string RequestId = "";
        public bool Escalated;
    }

    /// <summary>(harnessId, alertId, systemPrompt, userPrompt, pid, processName) → mailbox requestId, or null if unavailable. Wired by App.</summary>
    public Func<string, string, string, string, int?, string?, string?>? CreateCleanupRequest { get; set; }

    /// <summary>(harnessId, systemPrompt, userPrompt, requestId) → best-effort live delivery to the harness's MCP session. Wired by App.</summary>
    public Func<string, string, string, string, Task>? PushToOffender { get; set; }

    /// <summary>requestId → is the mailbox request still unanswered. Wired by App.</summary>
    public Func<string, bool>? IsRequestPending { get; set; }

    /// <summary>Injected by App: the brokered-termination ledger, so the reaps <see cref="PrepareForUpdate"/> performs are
    /// recorded as EXPECTED (quiet) terminations. Null until wired / in tests, in which case reaps just aren't ledgered.</summary>
    public ExpectedTerminationLedger? ExpectedTerminations { get; set; }

    public IdleHarnessDetector(EventBus bus, ForemanSettings settings, ProcessTreeTracker tree)
    {
        _bus = bus;
        _settings = settings;
        _tree = tree;
    }

    public void Start() => _task = RunAsync(_cts.Token);

    private async Task RunAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(60));
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            try { CheckNow(); }
            catch { /* a single bad sweep must not kill the loop */ }
        }
    }

    /// <summary>One detection sweep. Public (with injectable clock) so tests drive it directly.</summary>
    public void CheckNow(DateTimeOffset? nowOverride = null)
    {
        var now = nowOverride ?? DateTimeOffset.UtcNow;

        var types = _tree.GetAll()
            .Where(r => r.IsHarness && r.HarnessType is not null && r.State != ProcessState.Terminated)
            .Select(r => r.HarnessType!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var type in types)
        {
            if (_settings.DisabledHarnesses.Contains(type)) continue;
            // A local-model host (LM Studio, Ollama, …) idling between prompts is normal, not abandoned work —
            // never auto-nag it to "clean up". The manual Process-Monitor trigger still works if the operator wants it.
            if (KnownHarnesses.IsLocalModelHost(type)) continue;

            var tree = _tree.GetTreeByHarnessType(type)
                .Where(r => r.State != ProcessState.Terminated)
                .ToList();
            var idle = IdleCleanupPolicy.IsTreeIdle(tree, _settings.IdleCleanupAfterMinutes, now);

            CleanupState? st;
            lock (_gate) _state.TryGetValue(type, out st);

            // 1) Unanswered earlier request + still idle → visible notice (once per request).
            if (st is not null &&
                IdleCleanupPolicy.ShouldEscalate(
                    st.RequestedAt,
                    stillPending: IsRequestPending?.Invoke(st.RequestId) == true,
                    stillIdle: idle,
                    alreadyEscalated: st.Escalated,
                    _settings.IdleCleanupGraceMinutes, now))
            {
                st.Escalated = true;
                var ago = (int)(now - st.RequestedAt).TotalMinutes;
                _bus.Publish(new MonitoringNoticeEvent(
                    now, ForemanSeverity.Low, "Foreman.IdleCleanup",
                    $"'{type}' hasn't answered the self-cleanup request from {ago} minute(s) ago and is still idle — " +
                    "check on it, or use Dashboard → Behavior / Process Monitor to kill the harness tree."));
            }

            // 2) Auto-request (opt-in), once per cooldown window.
            if (_settings.IdleCleanupEnabled && idle &&
                IdleCleanupPolicy.ShouldAutoRequest(st?.RequestedAt, _settings.IdleCleanupCooldownMinutes, now))
            {
                TriggerCleanupCore(type, tree, manual: false, now);
            }
        }
    }

    /// <summary>
    /// Manual trigger (Process Monitor context menu). Always allowed — no idle/enabled gating —
    /// but shares the same state so the auto path won't immediately re-ask.
    /// </summary>
    public (bool Ok, string Message) TriggerCleanup(string harnessType, bool manual = true)
    {
        var tree = _tree.GetTreeByHarnessType(harnessType)
            .Where(r => r.State != ProcessState.Terminated)
            .ToList();
        if (tree.Count == 0)
            return (false, $"No running processes found for '{harnessType}'.");

        return TriggerCleanupCore(harnessType, tree, manual, DateTimeOffset.UtcNow);
    }

    /// <summary>Cooperative "prep for update" request: like a manual cleanup but framed as an imminent restart, so an
    /// ACTIVE agent checkpoints/commits rather than being told it looks idle. Shares cleanup state with the auto path.</summary>
    public (bool Ok, string Message) RequestUpdatePrep(string harnessType)
    {
        var tree = _tree.GetTreeByHarnessType(harnessType)
            .Where(r => r.State != ProcessState.Terminated)
            .ToList();
        if (tree.Count == 0)
            return (false, $"No running processes found for '{harnessType}'.");

        return TriggerCleanupCore(harnessType, tree, manual: true, DateTimeOffset.UtcNow, updatePrep: true);
    }

    /// <summary>
    /// Operator "Prep sessions for update": cooperate with the living, reap the abandoned, so an update or restart
    /// lands clean. Works PER SESSION (per root harness process tree), NOT per harness type: an idle session is reaped
    /// while an active session of the SAME type is spared and asked to checkpoint. Active sessions are never killed;
    /// local-model hosts and disabled harnesses are skipped. The reap goes through
    /// <see cref="ProcessTreeTracker.KillProcess"/>, which identity-pins the PID (start-time) and skips KillGuard-protected
    /// processes, so it can never take down Foreman/Guardian/sidecar/OS. Reaped PIDs are recorded in the termination
    /// ledger as EXPECTED for when the brokered-kill suppression consumer is wired; until then their exits still surface
    /// as exit/orphan events in the log (the reap is honest, not silent).
    /// </summary>
    public (bool Ok, string Message) PrepareForUpdate(DateTimeOffset? nowOverride = null)
    {
        var now = nowOverride ?? DateTimeOffset.UtcNow;
        var all = _tree.GetAll().ToList();

        // Index children by parent so each ROOT harness process is reaped/classified as its OWN session tree, instead
        // of lumping every instance of a harness type together (which would let one idle session's reap take down an
        // active same-type session).
        var childrenByParent = all
            .GroupBy(r => r.ParentPid)
            .ToDictionary(g => g.Key, g => g.ToList());
        var roots = all
            .Where(r => r.IsHarness && r.HarnessType is not null && r.State != ProcessState.Terminated)
            .ToList();

        int reapedSessions = 0, reapedProcs = 0, skipped = 0;
        var reaped = new List<string>();
        var checkpointTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var root in roots)
        {
            var type = root.HarnessType!;
            try
            {
                if (_settings.DisabledHarnesses.Contains(type)) { skipped++; continue; }

                var subtree = CollectSubtree(root, childrenByParent);   // this session only: root + live descendants

                switch (IdleCleanupPolicy.ClassifyForUpdatePrep(
                            type, subtree, KnownHarnesses.IsLocalModelHost(type), _settings.IdleCleanupAfterMinutes, now))
                {
                    case UpdatePrepDisposition.Reap:
                        // Record each PID as EXPECTED before the kill (ledger contract: record first), then reap THIS
                        // session's tree only - identity-pinned to the root's start time; KillProcess kills the whole
                        // tree and refuses protected PIDs and a recycled PID.
                        foreach (var p in subtree)
                            ExpectedTerminations?.Record(p.Pid, p.StartTime, "operator:update-prep", $"prep '{type}' for update");
                        if (_tree.KillProcess(root.Pid, root.StartTime))
                        {
                            reapedSessions++;
                            reapedProcs += subtree.Count;
                            reaped.Add($"{type} pid {root.Pid} ({IdleCleanupPolicy.TreeIdleMinutes(subtree, now)}m idle)");
                        }
                        break;

                    case UpdatePrepDisposition.Checkpoint:
                        // Active session -> cooperative checkpoint. The mailbox addresses a harness by TYPE, so coalesce
                        // to one request per type even when a type has several active sessions; idle siblings are still
                        // reaped individually above.
                        checkpointTypes.Add(type);
                        break;

                    default:
                        skipped++;
                        break;
                }
            }
            catch { skipped++; /* one bad session must never abort the whole sweep */ }
        }

        int asked = 0;
        foreach (var type in checkpointTypes)
        {
            try { if (RequestUpdatePrep(type).Ok) asked++; }
            catch { /* best-effort; a failed ask is reflected in the count, never thrown to the UI */ }
        }

        var msg =
            $"Update prep: reaped {reapedSessions} idle session(s) ({reapedProcs} process(es))" +
            (reaped.Count > 0 ? " — " + string.Join("; ", reaped) : "") +
            $"; asked {asked} active harness type(s) to checkpoint" +
            (checkpointTypes.Count > 0 ? " (" + string.Join(", ", checkpointTypes) + ")" : "") + "." +
            (skipped > 0 ? $" Skipped {skipped} (local-model/disabled/unreapable)." : "");
        _bus.Publish(new InfoEvent(now, "Foreman.UpdatePrep", msg));
        return (true, msg);
    }

    // The live process subtree rooted at a harness process: the root plus its descendants by parent chain (terminated
    // records excluded). Cycle-guarded. This is the unit PrepareForUpdate reaps, so each session is handled independently.
    private static List<ProcessRecord> CollectSubtree(
        ProcessRecord root, IReadOnlyDictionary<int, List<ProcessRecord>> childrenByParent)
    {
        var result = new List<ProcessRecord>();
        var seen = new HashSet<int>();
        var stack = new Stack<ProcessRecord>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var r = stack.Pop();
            if (r.State == ProcessState.Terminated || !seen.Add(r.Pid)) continue;
            result.Add(r);
            if (childrenByParent.TryGetValue(r.Pid, out var kids))
                foreach (var k in kids)
                    if (k.Pid != r.Pid) stack.Push(k);
        }
        return result;
    }

    private (bool Ok, string Message) TriggerCleanupCore(
        string harnessType, IReadOnlyList<ProcessRecord> tree, bool manual, DateTimeOffset now, bool updatePrep = false)
    {
        var create = CreateCleanupRequest;
        if (create is null)
            return (false, "The MCP mailbox isn't wired up yet — try again in a moment.");

        var root = tree.Where(r => r.IsHarness).OrderBy(r => r.StartTime).FirstOrDefault() ?? tree[0];
        var idleMinutes = IdleCleanupPolicy.TreeIdleMinutes(tree, now);
        var childNames = tree.Where(r => !r.IsHarness).Select(r => r.Name).ToList();
        var (system, user) = updatePrep
            ? IdleCleanupPolicy.BuildUpdatePrepPrompts(harnessType, childNames)
            : IdleCleanupPolicy.BuildPrompts(harnessType, idleMinutes, childNames, manual);

        // Log entry first; its id becomes the mailbox request's alertId so the two stay linked.
        var evt = new InfoEvent(
            now, "Foreman.IdleCleanup",
            updatePrep
                ? $"Update-prep checkpoint requested for '{harnessType}' — asked to save/commit and stop leftover children before a restart."
                : $"Self-cleanup requested for '{harnessType}' ({(manual ? "manual" : $"idle {idleMinutes}m")}) — " +
                  "asked to checkpoint work, stop leftover children, and reply or exit.");
        _bus.Publish(evt);

        var requestId = create(harnessType, evt.Id, system, user, root.Pid, root.Name);
        if (requestId is null)
            return (false, "Could not queue the cleanup request on the MCP mailbox.");

        lock (_gate)
            _state[harnessType] = new CleanupState { RequestedAt = now, RequestId = requestId };

        // Best-effort live delivery; the mailbox copy survives either way.
        if (PushToOffender is { } push)
            _ = SafePush(push, harnessType, system, user, requestId);

        return (true,
            $"Cleanup request {requestId} queued for '{harnessType}'. It's delivered live if the agent is " +
            "connected to TraceBrake's MCP, and waits in the mailbox (list_ask_harness_requests) either way.");
    }

    private static async Task SafePush(
        Func<string, string, string, string, Task> push,
        string harnessType, string system, string user, string requestId)
    {
        try { await push(harnessType, system, user, requestId).ConfigureAwait(false); }
        catch { /* delivery is best-effort; the mailbox request remains */ }
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _task?.GetAwaiter().GetResult(); }
        catch (OperationCanceledException) { /* normal shutdown */ }
        _cts.Dispose();
    }
}
