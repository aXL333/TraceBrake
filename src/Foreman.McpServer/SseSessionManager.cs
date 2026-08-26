// Alias avoids the Foreman.McpServer namespace shadowing ModelContextProtocol.Server.McpServer
using McpServerType = global::ModelContextProtocol.Server.McpServer;
using System.Collections.Concurrent;
using ModelContextProtocol.Protocol;

namespace Foreman.McpServer;

/// <summary>A connected MCP client's self-announced identity and the capabilities it advertised.</summary>
public sealed record McpClientInfo(
    string Name,
    string? Version,
    bool Sampling,
    bool Elicitation,
    string? AuthenticatedHarnessId = null,
    bool IsOperator = false);

/// <summary>How an "Ask Harness" request to the offender's own session was delivered.</summary>
public enum AskOutcome { Sampled, Notified, NoSession }

/// <summary>
/// Result of asking the offending harness to justify/act. <see cref="ReplyText"/> is non-null only
/// for <see cref="AskOutcome.Sampled"/> (a true round-trip); for a notification it's fire-and-forget.
/// </summary>
public sealed record AskOffenderResult(AskOutcome Outcome, string? ReplyText, string? MatchedClient, string? RequestId = null);

/// <summary>
/// Tracks live MCP SSE sessions and broadcasts server-initiated notifications
/// (notifications/message) to all connected clients.
/// </summary>
public sealed class SseSessionManager
{
    private sealed record Entry(McpServerType Server, DateTimeOffset At, CallerScope Caller);
    private readonly ConcurrentDictionary<string, Entry> _sessions = new();
    // These are short-lived per-request transport sessions; a disconnect that doesn't Unregister leaks an entry, so
    // an entry older than this is almost certainly dead -> reaped. MaxSessions hard-caps a runaway leak (and the
    // broadcast amplification / dashboard inflation it caused: 241 live entries vs 3 real clients).
    private static readonly TimeSpan StaleTtl = TimeSpan.FromMinutes(15);
    private const int MaxSessions = 128;

    // Sticky activity, keyed by harness id (from the authenticated token). These clients use short-lived
    // per-request MCP sessions, so the live _sessions set reads ~0 between calls — the dashboard would flicker
    // "No MCP"/"restart to link" even for a connected, working agent. MarkSeen records each authenticated
    // request so the UI can treat a harness that has talked to TraceBrake within a TTL as connected.
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recent = new(StringComparer.OrdinalIgnoreCase);

    public int Count { get { Prune(); return _sessions.Count; } }

    // Reap leaked (long-stale) registrations; bounded O(n) with MaxSessions, so cheap to call on every access.
    private void Prune()
    {
        var cutoff = DateTimeOffset.UtcNow - StaleTtl;
        foreach (var kv in _sessions)
            if (kv.Value.At < cutoff) _sessions.TryRemove(kv.Key, out _);
    }

    /// <summary>Record that an authenticated request from this harness just arrived (drives sticky "connected").</summary>
    public void MarkSeen(string? harnessId)
    {
        if (!string.IsNullOrWhiteSpace(harnessId))
            _recent[harnessId] = DateTimeOffset.UtcNow;
    }

    /// <summary>Harness ids that made an authenticated MCP request within <paramref name="ttl"/>; prunes older entries.</summary>
    public IReadOnlyCollection<string> RecentlyActiveHarnessIds(TimeSpan ttl)
    {
        var cutoff = DateTimeOffset.UtcNow - ttl;
        foreach (var kv in _recent)
            if (kv.Value < cutoff) _recent.TryRemove(kv.Key, out _);
        return _recent.Keys.ToArray();
    }

    /// <summary>Registers a connected session. Returns the session key for later unregistration.</summary>
    public string Register(McpServerType server, CallerScope caller)
    {
        Prune();
        // Bound a registration leak: if we're at the cap after pruning, evict the oldest entry.
        if (_sessions.Count >= MaxSessions)
        {
            var oldest = _sessions.OrderBy(kv => kv.Value.At).FirstOrDefault();
            if (oldest.Key is not null) _sessions.TryRemove(oldest.Key, out _);
        }
        var id = Guid.NewGuid().ToString("N")[..8];
        _sessions[id] = new Entry(server, DateTimeOffset.UtcNow,
            caller.IsAuthenticated ? caller : CallerScope.Unauthenticated);
        return id;
    }

    public void Unregister(string id) => _sessions.TryRemove(id, out _);

    /// <summary>
    /// Snapshot of every connected client's announced identity + capabilities. Used by the dashboard
    /// to show which agents are connected and whether each supports the sampling round-trip that makes
    /// Ask Harness a true poll (vs. a one-way notification).
    /// </summary>
    public IReadOnlyList<McpClientInfo> DescribeSessions()
    {
        Prune();
        return _sessions.Values.Select(e => new McpClientInfo(
            ClientLabel(e.Server) ?? "unknown client",
            e.Server.ClientInfo?.Version,
            e.Server.ClientCapabilities?.Sampling is not null,
            e.Server.ClientCapabilities?.Elicitation is not null,
            e.Caller.IsOperator ? null : e.Caller.HarnessId,
            e.Caller.IsOperator)).ToList();
    }

    /// <summary>
    /// Pushes notifications/message to every currently-connected MCP client.
    /// Failures on individual sessions are swallowed so a dead client can't block others.
    /// </summary>
    public async Task BroadcastNotificationAsync(string level, string logger, object data, string? targetHarnessId)
    {
        Prune();
        if (_sessions.IsEmpty) return;

        var snapshot = _sessions.ToArray()
            .Where(item => CanReceiveAlert(item.Value.Caller, targetHarnessId))
            .ToArray();
        await Task.WhenAll(snapshot.Select(item =>
            SendNotificationAsync(item.Key, item.Value, new { level, logger, data }))).ConfigureAwait(false);
    }

    /// <summary>
    /// "Ask Harness": deliver a justify/act prompt to the OFFENDING harness's own session, by the
    /// highest-fidelity channel available. Ladder:
    ///   1. <b>Sampling round-trip</b> — if a matching session advertises the sampling capability,
    ///      ask its model and return the reply (a true poll).
    ///   2. <b>Targeted notification</b> — else push the prompt into matching session(s) fire-and-forget.
    ///   3. <b>NoSession</b> — the offender isn't connected to TraceBrake's MCP; caller falls back to clipboard.
    /// Session→harness matching is by the client's self-announced name (advisory only, never auth).
    /// </summary>
    public async Task<AskOffenderResult> AskOffenderAsync(
        string harnessId,
        string systemPrompt,
        string userPrompt,
        string? requestId = null,
        CancellationToken ct = default)
    {
        Prune();
        var matches = _sessions.ToArray()
            .Where(item => CanReceiveAsk(item.Value.Caller, harnessId))
            .ToList();

        // 1) true round-trip via sampling, on the first matching session that supports it
        var sampler = matches.FirstOrDefault(item => item.Value.Server.ClientCapabilities?.Sampling is not null);
        if (sampler.Value is not null)
        {
            try
            {
                var req = new CreateMessageRequestParams
                {
                    SystemPrompt = systemPrompt,
                    MaxTokens    = 1000,
                    Messages     = [new SamplingMessage
                    {
                        Role    = Role.User,
                        Content = [new TextContentBlock { Text = userPrompt }],
                    }],
                };
                var res = await sampler.Value.Server.SampleAsync(req, ct).ConfigureAwait(false);
                return new AskOffenderResult(
                    AskOutcome.Sampled, ExtractText(res.Content), ClientLabel(sampler.Value.Server), requestId);
            }
            catch { /* client declined / errored / timed out — degrade to notification */ }
        }

        // 2) targeted, fire-and-forget notification to matching sessions
        if (matches.Count > 0)
        {
            var data = new { type = "ask_harness", harnessId, requestId, prompt = userPrompt };
            var sent = await Task.WhenAll(matches.Select(item =>
                SendNotificationAsync(
                    item.Key, item.Value,
                    new { level = "warning", logger = "foreman", data }))).ConfigureAwait(false);
            var firstSuccess = Array.FindIndex(sent, success => success);
            if (firstSuccess >= 0)
                return new AskOffenderResult(
                    AskOutcome.Notified, null, ClientLabel(matches[firstSuccess].Value.Server), requestId);
        }

        // 3) offender not connected to TraceBrake's MCP
        return new AskOffenderResult(AskOutcome.NoSession, null, null, requestId);
    }

    private async Task<bool> SendNotificationAsync(string key, Entry entry, object payload)
    {
        try
        {
            await entry.Server.SendNotificationAsync("notifications/message", payload).ConfigureAwait(false);
            return true;
        }
        catch
        {
            // Failed transports are dead now, not in 15 minutes. Remove only the exact entry we attempted.
            if (_sessions.TryGetValue(key, out var current) && ReferenceEquals(current.Server, entry.Server))
                _sessions.TryRemove(key, out _);
            return false;
        }
    }

    private static string? ClientLabel(McpServerType s) =>
        !string.IsNullOrWhiteSpace(s.ClientInfo?.Title) ? s.ClientInfo!.Title : s.ClientInfo?.Name;

    private static string? ExtractText(IList<ContentBlock>? content)
    {
        if (content is null) return null;
        var joined = string.Join("\n",
            content.OfType<TextContentBlock>().Select(b => b.Text).Where(t => !string.IsNullOrWhiteSpace(t)));
        return string.IsNullOrWhiteSpace(joined) ? null : joined.Trim();
    }

    /// <summary>
    /// Best-effort match of an MCP client's self-announced name/title to a TraceBrake harness id
    /// (e.g. "Claude Code" ⇄ "claude-code"). Self-declared and not authoritative — multiple
    /// instances of one harness are indistinguishable — so it's used only for advisory delivery,
    /// never for authorization.
    /// </summary>
    public static bool MatchesHarness(string? clientName, string? clientTitle, string harnessId)
    {
        var h = Norm(harnessId);
        if (h.Length < 3) return false;
        foreach (var cand in new[] { Norm(clientName), Norm(clientTitle) })
        {
            if (cand.Length < 3) continue;
            // The announced name contains the full harness id ("claudecodemcp" ⊃ "claudecode"), or the
            // harness id BEGINS with the announced name ("claudecode" starts with "claude"). Prefix —
            // not substring — on the second case, so a generic "code" can't match opencode/t3-code.
            if (cand.Contains(h) || h.StartsWith(cand)) return true;
        }
        return false;
    }

    private static string Norm(string? s) =>
        new string((s ?? "").Where(char.IsLetterOrDigit).ToArray()).ToLowerInvariant();

    internal static bool CanReceiveAsk(CallerScope caller, string targetHarnessId) =>
        caller.IsAuthenticated && !caller.IsOperator
        && string.Equals(caller.HarnessId, targetHarnessId, StringComparison.OrdinalIgnoreCase);

    internal static bool CanReceiveAlert(CallerScope caller, string? targetHarnessId) =>
        caller.IsAuthenticated && (caller.IsOperator
            || (targetHarnessId is not null
                && string.Equals(caller.HarnessId, targetHarnessId, StringComparison.OrdinalIgnoreCase)));
}
