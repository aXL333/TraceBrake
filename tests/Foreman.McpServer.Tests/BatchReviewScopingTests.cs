using Foreman.Core.Behavior;
using Foreman.Core.Mcp;
using Foreman.Core.Models;
using Foreman.Core.Settings;
using Foreman.McpServer;
using Microsoft.AspNetCore.Http;
using System.Text.Json;

namespace Foreman.McpServer.Tests;

/// <summary>
/// Regression coverage for the Cursor-audit batch (S-1, S-3, S-4): a per-harness caller must not be able to
/// wipe its escalation with a stolen token (S-1), nor read a sibling harness's MCP servers / clients / tool
/// findings / audit route / integration (S-3), and secret-shaped text in Ask Harness prompts must be masked
/// at egress (S-4). Operator (the raw install token) stays unscoped.
/// </summary>
public sealed class BatchReviewScopingTests : IDisposable
{
    private const string Ghp = "ghp_0123456789abcdefghij0123456789abcdef"; // GitHub-PAT shape the redactor masks
    private readonly ForemanState _state;
    private string? _lastReset;

    public BatchReviewScopingTests()
    {
        _state = new ForemanState
        {
            GetBehaviorProfiles = () => [new BehaviorProfile("codex"), new BehaviorProfile("claude-code")],
            ResetBehaviorProfile = id => _lastReset = id,
            GetMcpClients = () =>
            [
                new McpClientInfo("codex-cli", "1.0", Sampling: false, Elicitation: false,
                    AuthenticatedHarnessId: "codex"),
                new McpClientInfo("claude-code", "1.0", Sampling: true, Elicitation: false,
                    AuthenticatedHarnessId: "claude-code"),
            ],
            GetMcpInventory = () =>
            [
                // codex's server carries a token in its stdio args — must be redacted at egress.
                new McpServerEntry("codex", "codex-srv", "stdio", $"node x --token {Ghp}", "global", "config.toml"),
                new McpServerEntry("claude-code", "claude-srv", "http", "http://localhost:9", "global", "settings.json"),
            ],
            GetMcpToolScan = () => (
                new List<McpToolFinding>
                {
                    new("codex-srv", "tool-a", "sig", "excerpt-a"),
                    new("claude-srv", "tool-b", "sig", "excerpt-b"),
                },
                "2 findings"),
        };
        ForemanMcpTools.SetState(_state);
    }

    public void Dispose() => ForemanMcpTools.SetState(new ForemanState());

    private sealed class FixedHttpContextAccessor : IHttpContextAccessor
    {
        public HttpContext? HttpContext { get; set; }
    }

    private static IHttpContextAccessor Caller(CallerScope scope)
    {
        var ctx = new DefaultHttpContext();
        ctx.Items[CallerScope.HttpItemKey] = scope;
        return new FixedHttpContextAccessor { HttpContext = ctx };
    }

    private static readonly IHttpContextAccessor AsCodex = Caller(new CallerScope("codex", IsOperator: false));
    private static readonly IHttpContextAccessor AsCodexStolen = Caller(new CallerScope("codex", IsOperator: false, PeerMismatch: true));
    private static readonly IHttpContextAccessor AsOperator = Caller(new CallerScope(null, IsOperator: true));

    private static JsonDocument J(object o) => JsonDocument.Parse(JsonSerializer.Serialize(o));

    // ── S-1: report_task_start(resetMetrics:true) from a stolen token must NOT reset ──────────────
    [Fact]
    public void ReportTaskStart_PeerMismatch_DoesNotReset_AndExplains()
    {
        using var doc = J(ForemanMcpTools.ReportTaskStart("new task", resetMetrics: true, http: AsCodexStolen));
        Assert.False(doc.RootElement.GetProperty("acknowledged").GetBoolean());
        Assert.False(doc.RootElement.GetProperty("metricsReset").GetBoolean());
        Assert.Contains("does not match", doc.RootElement.GetProperty("reason").GetString());
        Assert.Null(_lastReset);   // escalation history NOT wiped
    }

    [Fact]
    public void ReportTaskStart_PeerOk_AnnouncesButCannotReset()
    {
        using var doc = J(ForemanMcpTools.ReportTaskStart("new task", resetMetrics: true, http: AsCodex));
        Assert.True(doc.RootElement.GetProperty("acknowledged").GetBoolean());
        Assert.False(doc.RootElement.GetProperty("metricsReset").GetBoolean());
        Assert.Contains("cannot clear", doc.RootElement.GetProperty("metricsResetRefused").GetString());
        Assert.Null(_lastReset);
    }

    // ── S-4: secret-shaped text in an Ask Harness prompt is masked at egress ──────────────────────
    [Fact]
    public void ListAskHarnessRequests_RedactsSecretInPrompt()
    {
        _state.CreateAskHarnessRequest("codex", $"system uses {Ghp}", $"please justify token {Ghp}", "alert-1", null, null);
        using var doc = J(ForemanMcpTools.ListAskHarnessRequests(http: AsCodex));
        var req = doc.RootElement.GetProperty("requests").EnumerateArray().First();
        Assert.DoesNotContain(Ghp, req.GetProperty("Prompt").GetString());
        Assert.DoesNotContain(Ghp, req.GetProperty("SystemPrompt").GetString());
        Assert.Contains("[REDACTED]", req.GetProperty("Prompt").GetString());
    }

    // ── S-3: ListMcpServers scoped + Target redacted ─────────────────────────────────────────────
    [Fact]
    public void ListMcpServers_CodexCaller_SeesOnlyOwn_AndRedactsTarget()
    {
        using var doc = J(ForemanMcpTools.ListMcpServers(http: AsCodex));
        var servers = doc.RootElement.GetProperty("servers").EnumerateArray().ToList();
        Assert.Single(servers);
        Assert.Equal("codex", servers[0].GetProperty("Harness").GetString());
        Assert.DoesNotContain(Ghp, servers[0].GetProperty("Target").GetString());
        Assert.Contains("[REDACTED]", servers[0].GetProperty("Target").GetString());
    }

    [Fact]
    public void ListMcpServers_Operator_SeesAll_StillRedactsTarget()
    {
        using var doc = J(ForemanMcpTools.ListMcpServers(http: AsOperator));
        var servers = doc.RootElement.GetProperty("servers").EnumerateArray().ToList();
        Assert.Equal(2, servers.Count);
        Assert.All(servers, s => Assert.DoesNotContain(Ghp, s.GetProperty("Target").GetString()));
    }

    // ── S-3: ListConnectedMcpClients scoped ──────────────────────────────────────────────────────
    [Fact]
    public void ListConnectedMcpClients_CodexCaller_SeesOnlyOwnConnection()
    {
        using var doc = J(ForemanMcpTools.ListConnectedMcpClients(http: AsCodex));
        var names = doc.RootElement.GetProperty("clients").EnumerateArray().Select(c => c.GetProperty("Name").GetString()).ToList();
        Assert.Contains("codex-cli", names);
        Assert.DoesNotContain("claude-code", names);
    }

    [Fact]
    public void ListConnectedMcpClients_Operator_SeesAll()
    {
        using var doc = J(ForemanMcpTools.ListConnectedMcpClients(http: AsOperator));
        Assert.Equal(2, doc.RootElement.GetProperty("count").GetInt32());
    }

    // ── S-3: ListMcpToolFindings scoped to the caller's own servers ───────────────────────────────
    [Fact]
    public void ListMcpToolFindings_CodexCaller_SeesOnlyOwnServerFindings()
    {
        using var doc = J(ForemanMcpTools.ListMcpToolFindings(http: AsCodex));
        var servers = doc.RootElement.GetProperty("findings").EnumerateArray().Select(f => f.GetProperty("Server").GetString()).ToList();
        Assert.Contains("codex-srv", servers);
        Assert.DoesNotContain("claude-srv", servers);
    }

    // ── S-3: ValidateHarnessIntegration denies a sibling probe ────────────────────────────────────
    [Fact]
    public void ValidateHarnessIntegration_CodexCaller_DeniedOnSibling()
    {
        using var doc = J(ForemanMcpTools.ValidateHarnessIntegration("claude-code", http: AsCodex));
        Assert.True(doc.RootElement.TryGetProperty("error", out _));
    }

    [Fact]
    public void ValidateHarnessIntegration_CodexCaller_AllowedOnSelf()
    {
        using var doc = J(ForemanMcpTools.ValidateHarnessIntegration("codex", http: AsCodex));
        Assert.False(doc.RootElement.TryGetProperty("error", out _));
        Assert.Equal("codex", doc.RootElement.GetProperty("harnessId").GetString());
    }

    // ── S-3: GetAuditRoute denies a sibling lookup ───────────────────────────────────────────────
    [Fact]
    public void GetAuditRoute_CodexCaller_DeniedOnSibling()
    {
        using var doc = J(ForemanMcpTools.GetAuditRoute("claude-code", http: AsCodex));
        Assert.True(doc.RootElement.TryGetProperty("error", out _));
    }

    [Fact]
    public void GetAuditRoute_CodexCaller_AllowedOnSelf()
    {
        using var doc = J(ForemanMcpTools.GetAuditRoute("codex", http: AsCodex));
        Assert.False(doc.RootElement.TryGetProperty("error", out _));
    }

    // ── S-3: ListAuditPreferences shows only the prefs that route TO the caller ───────────────────
    [Fact]
    public void ListAuditPreferences_CodexCaller_FiltersToPrefsTargetingIt()
    {
        // Default prefs: codex→[claude-code,…] (NOT codex), claude-code→[codex,…], opencode→[codex,…].
        using var doc = J(ForemanMcpTools.ListAuditPreferences(http: AsCodex));
        var auditorIds = doc.RootElement.GetProperty("preferences").EnumerateArray()
            .Select(p => p.GetProperty("AuditorId").GetString()).ToHashSet();
        Assert.Contains("claude-code", auditorIds);   // audits codex → visible
        Assert.Contains("opencode", auditorIds);      // audits codex → visible
        Assert.DoesNotContain("codex", auditorIds);   // codex's own pref doesn't target codex → hidden
    }

    [Fact]
    public void ListAuditPreferences_Operator_SeesAll()
    {
        using var doc = J(ForemanMcpTools.ListAuditPreferences(http: AsOperator));
        Assert.Equal(3, doc.RootElement.GetProperty("preferences").GetArrayLength());
    }
}
