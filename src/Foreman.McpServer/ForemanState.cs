using Foreman.Core.Alerts;
using Foreman.Core.Behavior;
using Foreman.Core.Events;
using Foreman.Core.Mcp;
using Foreman.Core.Models;
using Foreman.Core.Profiles;
using Foreman.Core.Security;
using Foreman.Core.Settings;
using System.Collections.Concurrent;

namespace Foreman.McpServer;

/// <summary>
/// Shared in-process state bag threadsafely accessed by MCP tools and the alert dispatcher.
/// </summary>
public sealed class ForemanState : IEventSink
{
    private readonly BoundedEventHistory _eventLog = new(MaxEvents);
    private readonly ConcurrentDictionary<string, ForemanEvent> _alertById = new();
    private readonly ConcurrentDictionary<string, AskHarnessRequest> _askRequests = new();
    private readonly ConcurrentDictionary<string, HarnessContextUsage> _contextUsage = new(StringComparer.OrdinalIgnoreCase);
    private const int MaxEvents = 1000;
    private const int MaxAlerts = 1000;
    private const int MaxAgentReportedAlerts = 200;
    private const int MaxAskHarnessRequests = 200;
    private readonly SuspiciousCommandAlertLimiter _suspiciousCommandAlerts = new();
    private readonly SuspiciousCommandAlertLimiter _taskStartAnnouncements =
        new(permitLimit: 8, window: TimeSpan.FromMinutes(1));
    private readonly SuspiciousCommandAlertLimiter _harnessMail =
        new(permitLimit: 6, window: TimeSpan.FromMinutes(1));
    private const int MaxPendingHarnessMailPerSender = 20;

    public DateTimeOffset StartTime { get; } = DateTimeOffset.UtcNow;
    public int McpPort { get; set; } = 54321;
    public LlmTriageSettings LlmTriage { get; set; } = new();
    /// <summary>Per-harness enabled modality ids (the restricted "sysprompt"); empty → catalog defaults.</summary>
    public Dictionary<string, List<string>> HarnessModalities { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, HarnessCapabilityRestrictions> HarnessCapabilityRestrictions { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    // injected from MonitorService / BehaviorTracker after construction
    public Func<IEnumerable<ProcessRecord>>?       GetProcessSnapshot  { get; set; }
    public Func<IEnumerable<BehaviorProfile>>?     GetBehaviorProfiles { get; set; }
    public Func<string, HarnessProfile?>?          GetProfileByName    { get; set; }
    public Func<string, string?>?                  GetDefaultProfileNameByHarnessId { get; set; }
    public Func<int, ProcessRecord?>?              FindHarnessAncestorByPid { get; set; }
    public Func<int>?                              GetMcpSessionCount { get; set; }
    public Func<IReadOnlyList<McpClientInfo>>?      GetMcpClients { get; set; }
    public Func<IEnumerable<McpServerEntry>>?      GetMcpInventory    { get; set; }
    public Func<(IReadOnlyList<McpToolFinding> Findings, string Summary)>? GetMcpToolScan { get; set; }

    /// <summary>Resets behavioral metrics for a specific harness ID. Returns false if not found.</summary>
    public Action<string>? ResetBehaviorProfile { get; set; }

    /// <summary>
    /// Terminates a process via TraceBrake's hardened kill path (KillGuard never-kill set + start-time identity pin).
    /// Wired by the App to ProcessTreeTracker.KillProcess; null in tests / headless, where the broker reports the
    /// capability as unavailable rather than pretending to kill. (pid, expectedStartTime) -> true if terminated.
    /// </summary>
    public Func<int, DateTimeOffset?, bool>? KillProcessByPid { get; set; }

    /// <summary>
    /// Pushes an Ask-Harness request to a target's LIVE MCP session (sampling/notification) and returns a short
    /// delivery status ("sampled" | "notified" | "no_session"). Wired by the App to SseSessionManager.AskOffenderAsync;
    /// null in tests / headless, where request_harness_review just queues the request for the target's next poll.
    /// (targetHarnessId, systemPrompt, prompt, requestId) -> status.
    /// </summary>
    public Func<string, string, string, string, Task<string>>? DeliverHarnessAsk { get; set; }

    /// <summary>
    /// Terminations TraceBrake BROKERED for a harness (request_process_kill). Shared with the Monitor detection path
    /// (via the App) so an authorised kill reads as expected/quiet while a raw, un-attributed kill stays loud.
    /// </summary>
    public Foreman.Core.Termination.ExpectedTerminationLedger ExpectedTerminations { get; } = new();

    public int ActiveAlerts => _alertById.Values.Count(AlertActivity.IsActive);
    public bool HasCritical => _alertById.Values.Any(e => AlertActivity.IsActive(e) && e.Severity >= ForemanSeverity.High);
    public int ProcessCount => GetProcessSnapshot?.Invoke().Count() ?? 0;
    public int McpSessionCount => GetMcpSessionCount?.Invoke() ?? 0;
    public int PendingAskHarnessCount => _askRequests.Values.Count(static r => r.Status == AskHarnessStatus.Pending);

    internal bool TryAdmitSuspiciousCommandAlert(string callerKey, DateTimeOffset now, out TimeSpan retryAfter) =>
        _suspiciousCommandAlerts.TryAcquire(callerKey, now, out retryAfter);

    internal bool TryAdmitTaskStart(string callerKey, DateTimeOffset now, out TimeSpan retryAfter) =>
        _taskStartAnnouncements.TryAcquire(callerKey, now, out retryAfter);

    internal bool TryAdmitHarnessMail(string senderHarnessId, DateTimeOffset now, out TimeSpan retryAfter)
    {
        if (!_harnessMail.TryAcquire(senderHarnessId, now, out retryAfter)) return false;
        var pending = _askRequests.Values.Count(r =>
            r.Status == AskHarnessStatus.Pending
            && string.Equals(r.SenderHarnessId, senderHarnessId, StringComparison.OrdinalIgnoreCase));
        if (pending < MaxPendingHarnessMailPerSender) return true;
        retryAfter = TimeSpan.FromMinutes(1);
        return false;
    }

    /// <summary>LiveWeave webpage builder command queue (agent → extension).</summary>
    public LiveWeaveBroker LiveWeave { get; } = new();

    /// <summary>Computer-use panic state (halted?). Injected by the App; null in tests/headless → reported as not halted.</summary>
    public CuPanicState? Panic { get; set; }

    /// <summary>The mediated computer-use broker (Held-state, audited). Injected by the App; null in tests/headless
    /// (unless a test sets it), in which case the cu_* tools report the capability as unavailable.</summary>
    public Foreman.Core.ComputerUse.CuBroker? Cu { get; set; }

    /// <summary>
    /// Local bounded ADB executor/status. Null when the operator has not enabled the Android bridge. Android actions
    /// are submitted through <see cref="Cu"/> like every other modality and claimed only by the in-process pump.
    /// </summary>
    public Foreman.Core.ComputerUse.AdbBridgeExecutor? Adb { get; set; }

    /// <summary>App-wired presence gate for approving any HELD computer-use action (INV-16): returns true only on a
    /// fresh Hello/FIDO2 tap, so an operator bearer token alone cannot approve browser/desktop/Android effects. Null
    /// in tests/headless means remote approvals fail closed.</summary>
    public Func<Foreman.Core.ComputerUse.CuModality, Task<bool>>? CuPresenceApprovalGate { get; set; }

    /// <summary>
    /// App-wired fresh-presence gate for high-impact mutations requested with the raw operator bearer token.
    /// The detail is an operator-facing description only; authority comes from the live Hello/FIDO2 assertion.
    /// Explicit in-process calls do not traverse this MCP gate.
    /// </summary>
    public Func<string, Task<bool>>? McpOperatorPresenceGate { get; set; }

    /// <summary>App-wired credential-vault resolver for the browser-extension EXECUTOR (cu_resolve_vault). Inputs:
    /// (text-with-{{vault:}}, live target origin, the action's submitting harness). Applies the per-release presence tap
    /// + domain-binding + ACL, and returns the resolved plaintext ONLY on success. Null in tests/headless (vault
    /// unavailable). The returned value is handed to the peer-bound extension to fill, and is never logged. Queued is
    /// true only for a self-signup that was DEPOSITED for operator review (vault locked) rather than committed to the
    /// store — the audit line must say "QUEUED", not "CREATED", so an operator doesn't read the credential as live.</summary>
    public Func<string, string, string?, Task<(bool Ok, string? Value, string Reason, bool Queued)>>? ResolveVaultAsync { get; set; }

    void IEventSink.OnEvent(ForemanEvent evt)
    {
        if (evt.Severity > ForemanSeverity.Info)
        {
            _alertById[evt.Id] = evt;

            foreach (var stale in EventRetentionPolicy.SelectAgentQuotaVictims(
                         _alertById.Values.ToArray(), MaxAgentReportedAlerts))
                _alertById.TryRemove(stale.Id, out _);

            // Bound the alert store like the event queue — a connected agent can mint events,
            // so an uncapped dictionary is attacker-inflatable memory + count poisoning.
            // Evict acknowledged first, then oldest, so live signal survives the longest.
            if (_alertById.Count > MaxAlerts)
            {
                var protectArrival = !EventRetentionPolicy.IsAgentReported(evt) &&
                                     evt.Severity >= ForemanSeverity.High ? evt.Id : null;
                foreach (var stale in EventRetentionPolicy.SelectVictims(
                             _alertById.Values.ToArray(), _alertById.Count - MaxAlerts, protectArrival))
                {
                    _alertById.TryRemove(stale.Id, out _);
                }
            }
        }
        _eventLog.Add(evt);
    }

    public void AddEvent(ForemanEvent evt) => ((IEventSink)this).OnEvent(evt);

    public bool AcknowledgeAlert(string alertId)
    {
        if (!_alertById.TryGetValue(alertId, out var evt)) return false;
        evt.Acknowledged = true;
        return true;
    }

    /// <summary>Returns the tracked alert with the given id, or null. Used to gate ack by severity.</summary>
    /// <summary>Record an agent's self-reported context/token budget (latest wins).</summary>
    public void SetContextUsage(string harnessId, HarnessContextUsage usage)
    {
        if (!string.IsNullOrWhiteSpace(harnessId)) _contextUsage[harnessId] = usage;
    }

    /// <summary>The latest context usage a harness reported, or null if it never has.</summary>
    public HarnessContextUsage? GetContextUsage(string harnessId) =>
        harnessId is not null && _contextUsage.TryGetValue(harnessId, out var u) ? u : null;

    public ForemanEvent? GetAlert(string alertId) =>
        _alertById.TryGetValue(alertId, out var evt) ? evt : null;

    /// <summary>Current escalation level for a harness, or null if it has no profile yet.</summary>
    public EscalationLevel? GetEscalationLevel(string harnessId) =>
        GetBehaviorProfiles?.Invoke()
            .FirstOrDefault(p => string.Equals(p.HarnessId, harnessId, StringComparison.OrdinalIgnoreCase))
            ?.CurrentLevel;

    public IEnumerable<ProcessRecord> GetProcesses(bool includeChildren) =>
        GetProcessSnapshot?.Invoke()
            .Where(p => includeChildren || p.IsHarness) ?? [];

    public ProcessRecord? GetProcess(int pid) =>
        GetProcessSnapshot?.Invoke().FirstOrDefault(p => p.Pid == pid);

    public IEnumerable<ProcessRecord> GetProcessesForHarness(string harnessId, bool includeChildren)
    {
        var snapshot = GetProcessSnapshot?.Invoke().ToList() ?? [];
        if (!includeChildren)
        {
            return snapshot.Where(p =>
                string.Equals(p.HarnessType, harnessId, StringComparison.OrdinalIgnoreCase));
        }

        return snapshot.Where(p =>
            string.Equals(p.HarnessType, harnessId, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(FindHarnessAncestorByPid?.Invoke(p.Pid)?.HarnessType, harnessId, StringComparison.OrdinalIgnoreCase));
    }

    public HarnessProfile? ResolveProfile(string? profileName, string? harnessId, int? processId)
    {
        if (!string.IsNullOrWhiteSpace(profileName) && GetProfileByName?.Invoke(profileName) is { } explicitProfile)
            return explicitProfile;

        if (processId is int pid)
        {
            var proc = GetProcess(pid);
            if (proc?.ProfileName is not null && GetProfileByName?.Invoke(proc.ProfileName) is { } processProfile)
                return processProfile;

            var ancestor = FindHarnessAncestorByPid?.Invoke(pid);
            if (ancestor?.ProfileName is not null && GetProfileByName?.Invoke(ancestor.ProfileName) is { } ancestorProfile)
                return ancestorProfile;
        }

        if (!string.IsNullOrWhiteSpace(harnessId) &&
            GetDefaultProfileNameByHarnessId?.Invoke(harnessId) is { } defaultProfileName)
        {
            return GetProfileByName?.Invoke(defaultProfileName);
        }

        return null;
    }

    public string? ResolveHarnessId(string? harnessId, int? processId)
    {
        if (!string.IsNullOrWhiteSpace(harnessId)) return harnessId;

        if (processId is int pid)
        {
            var proc = GetProcess(pid);
            if (proc?.HarnessType is not null) return proc.HarnessType;
            var ancestor = FindHarnessAncestorByPid?.Invoke(pid);
            if (ancestor?.HarnessType is not null) return ancestor.HarnessType;
        }

        return null;
    }

    /// <summary>
    /// Resolves the harness an event concerns, for caller-scoping. CommandAlert/Hang/Orphan/Permission/
    /// Exit resolve via their ProcessId; Escalation carries its HarnessId. Returns null when the event is
    /// not attributable to a single harness (Info, monitoring notices) — non-operators are denied those.
    /// </summary>
    public string? ResolveAlertHarness(ForemanEvent evt) => evt switch
    {
        EscalationEvent esc          => esc.HarnessId,
        CommandAlertEvent c          => ResolveHarnessId(null, c.ProcessId),
        HangDetectedEvent h          => ResolveHarnessId(null, h.ParentHarnessPid ?? h.ProcessId),
        OrphanDetectedEvent o        => ResolveHarnessId(null, o.ProcessId),
        PermissionViolationEvent v   => ResolveHarnessId(null, v.ProcessId),
        NonzeroExitEvent x           => ResolveHarnessId(null, x.ParentHarnessPid ?? x.ProcessId),
        _                            => null,
    };

    /// <summary>Like <see cref="GetEvents(int, ForemanSeverity?)"/> but, when scopeHarness is set, only events attributable to it.</summary>
    public IEnumerable<object> GetEvents(int limit, ForemanSeverity? minSeverity, string? scopeHarness)
    {
        if (scopeHarness is null) return GetEvents(limit, minSeverity);
        return _eventLog.Snapshot()
            .Where(e => minSeverity is null || e.Severity >= minSeverity)
            .Where(e => string.Equals(ResolveAlertHarness(e), scopeHarness, StringComparison.OrdinalIgnoreCase))
            .TakeLast(limit)
            .Select(ProjectEvent);
    }

    public IEnumerable<object> GetEvents(int limit, ForemanSeverity? minSeverity)
    {
        return _eventLog.Snapshot()
            .Where(e => minSeverity is null || e.Severity >= minSeverity)
            .TakeLast(limit)
            .Select(ProjectEvent);
    }

    private static object ProjectEvent(ForemanEvent e) => new
    {
        id        = e.Id,
        timestamp = e.Timestamp,
        sequence  = e.Sequence,
        recordedAtUtc = e.RecordedAtUtc,
        temporalSessionId = e.TemporalSessionId,
        monotonicTicks = e.MonotonicTicks,
        monotonicFrequency = e.MonotonicFrequency,
        temporalAnomalies = e.TemporalAnomalies,
        severity  = e.Severity.ToString(),
        source    = e.Source,
        message   = SecretRedactor.Redact(e.Message),   // egress to a connected agent — mask secrets
        acked     = e.Acknowledged,
    };

    public AskHarnessRequest CreateAskHarnessRequest(
        string harnessId,
        string systemPrompt,
        string prompt,
        string alertId,
        int? processId,
        string? processName,
        string? senderHarnessId = null,
        string requestKind = "ask_harness")
    {
        var request = new AskHarnessRequest(
            Guid.NewGuid().ToString("N")[..12],
            DateTimeOffset.UtcNow,
            alertId,
            harnessId,
            processId,
            processName,
            systemPrompt,
            prompt,
            AskHarnessStatus.Pending,
            SenderHarnessId: string.IsNullOrWhiteSpace(senderHarnessId) ? null : senderHarnessId.Trim().ToLowerInvariant(),
            RequestKind: string.IsNullOrWhiteSpace(requestKind) ? "ask_harness" : requestKind.Trim().ToLowerInvariant());

        _askRequests[request.RequestId] = request;
        PruneAskHarnessRequests();
        return request;
    }

    public IReadOnlyList<AskHarnessRequest> ListAskHarnessRequests(
        string? harnessId,
        int? processId,
        bool includeAnswered,
        int limit)
    {
        var resolvedHarness = ResolveHarnessId(harnessId, processId);
        var query = _askRequests.Values.AsEnumerable();

        if (!string.IsNullOrWhiteSpace(resolvedHarness))
        {
            query = query.Where(r =>
                string.Equals(r.HarnessId, resolvedHarness, StringComparison.OrdinalIgnoreCase));
        }

        if (!includeAnswered)
            query = query.Where(static r => r.Status == AskHarnessStatus.Pending);

        return query
            .OrderByDescending(static r => r.CreatedAt)
            .Take(Math.Clamp(limit, 1, 50))
            .ToList();
    }

    public AskHarnessRequest? GetAskHarnessRequest(string requestId) =>
        _askRequests.TryGetValue(requestId, out var request) ? request : null;

    public (bool Ok, string Reason, AskHarnessRequest? Request) ReplyToAskHarnessRequest(
        string requestId,
        string replyText,
        string? actionTaken,
        string? harnessId,
        int? processId)
    {
        if (!_askRequests.TryGetValue(requestId, out var request))
            return (false, "No Ask Harness request exists with that id.", null);

        // Identity is required: an anonymous reply (no harnessId/processId) previously
        // short-circuited the ownership check, letting any connected client answer any
        // harness's request — including forging "I cleaned up" for idle-cleanup asks.
        var resolvedHarness = ResolveHarnessId(harnessId, processId);
        if (string.IsNullOrWhiteSpace(resolvedHarness))
        {
            return (false,
                $"Identify yourself to reply: pass harnessId (\"{request.HarnessId}\") or a processId belonging to it.",
                request);
        }

        if (!string.Equals(request.HarnessId, resolvedHarness, StringComparison.OrdinalIgnoreCase))
        {
            return (false,
                $"Request {requestId} belongs to '{request.HarnessId}', not '{resolvedHarness}'.",
                request);
        }

        // Already answered → don't silently clobber the recorded reply; report it and keep the original.
        while (true)
        {
            if (request.Status == AskHarnessStatus.Answered)
                return (false, $"Request {requestId} was already answered at {request.RepliedAt:u}.", request);

            var wasExpired = request.Status == AskHarnessStatus.Expired;
            var updated = request with
            {
                Status = AskHarnessStatus.Answered,
                RepliedAt = DateTimeOffset.UtcNow,
                ReplyText = replyText,
                ActionTaken = string.IsNullOrWhiteSpace(actionTaken) ? null : actionTaken.Trim(),
            };

            if (_askRequests.TryUpdate(requestId, updated, request))
                return (true, wasExpired ? "Late reply recorded (request had already expired)." : "Reply recorded.", updated);

            if (!_askRequests.TryGetValue(requestId, out request))
                return (false, "No Ask Harness request exists with that id.", null);
        }
    }

    public int CountAskHarnessRequests(string? harnessId = null, bool includeAnswered = false)
    {
        var query = _askRequests.Values.AsEnumerable();
        if (!string.IsNullOrWhiteSpace(harnessId))
            query = query.Where(r => string.Equals(r.HarnessId, harnessId, StringComparison.OrdinalIgnoreCase));
        if (!includeAnswered)
            query = query.Where(static r => r.Status == AskHarnessStatus.Pending);
        return query.Count();
    }

    /// <summary>
    /// Ages out pending Ask-Harness requests unanswered past <paramref name="ttl"/> — a harness that never
    /// connected, disconnected mid-request, or ignored the prompt. Transitions them pending → expired (a
    /// terminal, evictable state distinct from "answered") and RETURNS the newly-expired ones so the caller
    /// logs each — the record is never silently dropped (see <see cref="AskHarnessStatus"/>). Race-safe: a
    /// reply landing during the sweep wins (compare-and-swap on the record value). Pure w.r.t.
    /// <paramref name="now"/> so it is unit-testable with a fixed clock. <paramref name="ttl"/> &lt;= 0 disables it.
    /// </summary>
    public IReadOnlyList<AskHarnessRequest> ExpireStale(DateTimeOffset now, TimeSpan ttl)
    {
        if (ttl <= TimeSpan.Zero) return [];
        var expired = new List<AskHarnessRequest>();
        foreach (var r in _askRequests.Values)
        {
            if (r.Status != AskHarnessStatus.Pending || now - r.CreatedAt < ttl) continue;
            var aged = r with { Status = AskHarnessStatus.Expired };
            if (_askRequests.TryUpdate(r.RequestId, aged, r))   // skip if a reply changed it mid-sweep
                expired.Add(aged);
        }
        return expired;
    }

    private void PruneAskHarnessRequests()
    {
        foreach (var id in SelectPruneVictims(_askRequests.Values.ToArray(), MaxAskHarnessRequests))
            _askRequests.TryRemove(id, out _);
    }

    /// <summary>
    /// Chooses which requests to drop when the store exceeds <paramref name="cap"/>: terminal
    /// (answered/expired) requests oldest-first, spilling into oldest PENDING only if still over cap — so a
    /// still-open obligation is never evicted before a resolved one. Pure + static for unit-testing.
    /// </summary>
    public static IEnumerable<string> SelectPruneVictims(IReadOnlyCollection<AskHarnessRequest> all, int cap)
    {
        if (all.Count <= cap) return [];
        return all
            .OrderByDescending(r => AskHarnessStatus.IsTerminal(r.Status))   // terminal (resolved) first
            .ThenBy(r => r.CreatedAt)                                        // then oldest first
            .Take(all.Count - cap)
            .Select(r => r.RequestId)
            .ToList();
    }
}
