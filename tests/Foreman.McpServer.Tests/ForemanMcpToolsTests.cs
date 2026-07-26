using Foreman.Core.Heuristics;
using Foreman.Core.Mcp;
using Foreman.Core.Models;
using Foreman.Core.Profiles;
using System.Text.Json;

namespace Foreman.McpServer.Tests;

public sealed class ForemanMcpToolsTests : IDisposable
{
    private readonly string _profileDir = Path.Combine(Path.GetTempPath(), "foreman-mcp-profile-test-" + Guid.NewGuid().ToString("N"));
    private readonly ProfileStore _store;
    private readonly ProfileMatcher _matcher;
    private readonly ProcessRecord _harness;
    private readonly ProcessRecord _child;
    private readonly ForemanState _state;

    public ForemanMcpToolsTests()
    {
        PatternLibrary.Instance.Initialize();

        _store = new ProfileStore(_profileDir);
        _store.Initialize();
        _matcher = new ProfileMatcher(_store);

        _harness = new ProcessRecord
        {
            Pid = 930_001,
            ParentPid = 0,
            Name = "codex.exe",
            StartTime = DateTimeOffset.UtcNow,
            IsHarness = true,
            HarnessType = "codex",
            ProfileName = "codex-default",
        };
        _child = new ProcessRecord
        {
            Pid = 930_002,
            ParentPid = _harness.Pid,
            Name = "cmd.exe",
            StartTime = DateTimeOffset.UtcNow,
        };

        _state = new ForemanState
        {
            McpPort = 12345,
            GetProcessSnapshot = () => [_harness, _child],
            GetProfileByName = name => _matcher.Get(name),
            GetDefaultProfileNameByHarnessId = HarnessIntegrationRegistry.GetDefaultProfileName,
            FindHarnessAncestorByPid = pid => pid == _child.Pid || pid == _harness.Pid ? _harness : null,
            GetMcpSessionCount = () => 2,
            GetMcpClients = () => [new McpClientInfo("Codex CLI", "1.0", Sampling: false, Elicitation: false)],
        };
        ForemanMcpTools.SetState(_state);
    }

    [Fact]
    public void GetMyPermissions_ResolvesProfileFromHarnessId()
    {
        using var doc = ToJson(ForemanMcpTools.GetMyPermissions(harnessId: "codex"));

        Assert.Equal("codex", doc.RootElement.GetProperty("harnessId").GetString());
        Assert.Equal("codex-default", doc.RootElement.GetProperty("profileName").GetString());
        Assert.Contains("cred-001", doc.RootElement.GetProperty("commands").GetProperty("blockedPatterns").EnumerateArray().Select(e => e.GetString()));
    }

    [Fact]
    public void ReportSuspiciousCommand_AppliesProfileBlockedRules()
    {
        using var doc = ToJson(ForemanMcpTools.ReportSuspiciousCommand(
            "reg save HKLM\\SAM sam.hiv",
            harnessId: "codex"));

        Assert.Equal("escalate", doc.RootElement.GetProperty("decision").GetString());
        Assert.Equal("cred-001", doc.RootElement.GetProperty("matchedRule").GetString());
        Assert.True(doc.RootElement.GetProperty("profileBlocked").GetBoolean());
        Assert.Equal("codex-default", doc.RootElement.GetProperty("profileName").GetString());
    }

    [Fact]
    public void ReportSuspiciousCommand_AlertPublishingIsRateLimitedPerCaller()
    {
        JsonDocument? last = null;
        for (var i = 0; i < 13; i++)
        {
            last?.Dispose();
            last = ToJson(ForemanMcpTools.ReportSuspiciousCommand("reg save HKLM\\SAM sam.hiv"));
        }

        using (last)
        {
            Assert.True(last!.RootElement.GetProperty("rateLimited").GetBoolean());
            Assert.False(last.RootElement.GetProperty("alertPublished").GetBoolean());
            Assert.True(last.RootElement.GetProperty("retryAfterSeconds").GetInt32() > 0);
        }
    }

    [Fact]
    public void ListMonitoredProcesses_ScopesToHarnessTree()
    {
        using var doc = ToJson(ForemanMcpTools.ListMonitoredProcesses(harnessId: "codex"));

        Assert.Equal("codex", doc.RootElement.GetProperty("harnessId").GetString());
        var pids = doc.RootElement.GetProperty("processes").EnumerateArray()
            .Select(e => e.GetProperty("Pid").GetInt32())
            .ToHashSet();
        Assert.Contains(_harness.Pid, pids);
        Assert.Contains(_child.Pid, pids);
    }

    [Fact]
    public void IntegrationInstructions_AndValidation_ReportHarnessSetupState()
    {
        using var instructions = ToJson(ForemanMcpTools.GetIntegrationInstructions("claude-code"));
        Assert.Equal("claude-code", instructions.RootElement.GetProperty("harnessId").GetString());
        Assert.Contains("12345", instructions.RootElement.GetProperty("mcpConfigSnippet").GetString());

        using var validation = ToJson(ForemanMcpTools.ValidateHarnessIntegration("codex"));
        Assert.True(validation.RootElement.GetProperty("knownHarness").GetBoolean());
        Assert.True(validation.RootElement.GetProperty("profileLoaded").GetBoolean());
        Assert.Equal(2, validation.RootElement.GetProperty("runningProcessCount").GetInt32());
        Assert.Equal(2, validation.RootElement.GetProperty("mcpSessions").GetInt32());
        Assert.Equal("Codex CLI", validation.RootElement.GetProperty("connectedClients")[0].GetProperty("Name").GetString());
    }

    [Fact]
    public void GetMyInstructions_IncludesHighRiskCapabilityPolicy()
    {
        _state.HarnessCapabilityRestrictions["codex"] = new()
        {
            ComputerUse = HarnessCapabilityAccess.AskFirst,
            BrowserUse = HarnessCapabilityAccess.Block,
        };

        using var doc = ToJson(ForemanMcpTools.GetMyInstructions(harnessId: "codex"));
        var caps = doc.RootElement.GetProperty("highRiskCapabilities");

        Assert.Equal("AskFirst", caps.GetProperty("computerUse").GetProperty("access").GetString());
        Assert.False(caps.GetProperty("computerUse").GetProperty("allowed").GetBoolean());
        Assert.Equal("Block", caps.GetProperty("browserUse").GetProperty("access").GetString());
        Assert.False(caps.GetProperty("browserUse").GetProperty("allowed").GetBoolean());
        Assert.Contains("Playwright", caps.GetProperty("instruction").GetString());
    }

    [Fact]
    public void AskHarnessRequests_CanBePolledAndAnsweredByHarness()
    {
        var request = _state.CreateAskHarnessRequest(
            "codex",
            "system",
            "justify this action",
            "alert-1",
            _child.Pid,
            "cmd.exe");

        using var pending = ToJson(ForemanMcpTools.ListAskHarnessRequests(harnessId: "codex"));
        Assert.Equal(1, pending.RootElement.GetProperty("pendingCount").GetInt32());
        var returned = pending.RootElement.GetProperty("requests")[0];
        Assert.Equal(request.RequestId, returned.GetProperty("RequestId").GetString());
        Assert.Equal("justify this action", returned.GetProperty("Prompt").GetString());

        using var reply = ToJson(ForemanMcpTools.ReplyToAskHarnessRequest(
            request.RequestId,
            "I was waiting for a command to finish; I will stop it.",
            actionTaken: "operator should stop pid",
            harnessId: "codex"));

        Assert.True(reply.RootElement.GetProperty("accepted").GetBoolean());

        using var answered = ToJson(ForemanMcpTools.ListAskHarnessRequests(
            harnessId: "codex",
            includeAnswered: true));
        var answeredRequest = answered.RootElement.GetProperty("requests")[0];
        Assert.Equal("answered", answeredRequest.GetProperty("Status").GetString());
        Assert.Contains("waiting for a command", answeredRequest.GetProperty("ReplyText").GetString());
    }

    [Fact]
    public void AnonymousReply_IsRejected()
    {
        // Regression: an anonymous reply (no harnessId/processId) used to short-circuit the
        // ownership check, letting any connected client answer any harness's request —
        // including forging "I cleaned up" for idle-cleanup asks.
        var request = _state.CreateAskHarnessRequest(
            "codex", "system", "wrap up please", "alert-2", _harness.Pid, "codex.exe");

        var (ok, reason, _) = _state.ReplyToAskHarnessRequest(
            request.RequestId, "all done!", actionTaken: null, harnessId: null, processId: null);

        Assert.False(ok);
        Assert.Contains("Identify yourself", reason);
        Assert.Equal("pending", _state.GetAskHarnessRequest(request.RequestId)!.Status);
    }

    [Fact]
    public void AlertStore_IsBounded()
    {
        // A connected agent can mint alert-bearing events; the store must stay capped so
        // counts/memory can't be inflated without limit (acknowledged evict first).
        for (var i = 0; i < 1_200; i++)
        {
            _state.AddEvent(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow, ForemanSeverity.Medium, "test", $"flood {i}"));
        }

        Assert.True(_state.ActiveAlerts <= 1_000, $"ActiveAlerts={_state.ActiveAlerts} exceeded the cap");
    }

    [Fact]
    public void AlertStore_NoiseFloodDoesNotEvictUnresolvedCritical()
    {
        var critical = new MonitoringNoticeEvent(
            DateTimeOffset.UtcNow.AddMinutes(-5), ForemanSeverity.Critical, "test", "retain me");
        _state.AddEvent(critical);
        for (var i = 0; i < 1_100; i++)
        {
            _state.AddEvent(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow, ForemanSeverity.Medium, "test", $"noise {i}"));
        }

        Assert.Same(critical, _state.GetAlert(critical.Id));
        Assert.True(_state.HasCritical);
    }

    [Fact]
    public void AlertStore_AgentCriticalFloodCannotEvictArrivingHostHigh()
    {
        for (var i = 0; i < 1_100; i++)
        {
            _state.AddEvent(new CommandAlertEvent(
                DateTimeOffset.UtcNow.AddMilliseconds(i), ForemanSeverity.Critical,
                "MCP.ReportSuspiciousCommand", $"fabricated {i}", "rm -rf /", "del-001", "delete", "test", "none", 0)
                { Origin = EventOrigin.Agent });
        }

        var hostHigh = new MonitoringNoticeEvent(
            DateTimeOffset.UtcNow, ForemanSeverity.High, "Foreman.Settings", "genuine host alarm");
        _state.AddEvent(hostHigh);

        Assert.Same(hostHigh, _state.GetAlert(hostHigh.Id));
    }

    [Theory]
    [InlineData("t3-code", "t3-code-default")]
    [InlineData("opencode", "opencode-default")]
    public void IntegrationInstructions_IncludeNewHarnesses(string harnessId, string profileName)
    {
        using var instructions = ToJson(ForemanMcpTools.GetIntegrationInstructions(harnessId));
        Assert.Equal(harnessId, instructions.RootElement.GetProperty("harnessId").GetString());
        Assert.Equal(profileName, instructions.RootElement.GetProperty("defaultProfileName").GetString());
        Assert.Contains("12345", instructions.RootElement.GetProperty("mcpConfigSnippet").GetString());

        using var validation = ToJson(ForemanMcpTools.ValidateHarnessIntegration(harnessId));
        Assert.True(validation.RootElement.GetProperty("knownHarness").GetBoolean());
        Assert.True(validation.RootElement.GetProperty("integrationMetadata").GetBoolean());
        Assert.True(validation.RootElement.GetProperty("profileLoaded").GetBoolean());
    }

    [Fact]
    public void AuditRouting_SelectsPreferredNonSelfAuditor()
    {
        using var route = ToJson(ForemanMcpTools.GetAuditRoute("claude-code", severity: "High"));

        var selected = route.RootElement.GetProperty("selected");
        Assert.Equal("codex", selected.GetProperty("AuditorId").GetString());
        Assert.Equal("harness", selected.GetProperty("AuditorType").GetString());
        Assert.True(selected.GetProperty("available").GetBoolean());
    }

    [Fact]
    public void AuditRouting_CanRouteT3CodeToAvailableAgentAuditor()
    {
        using var route = ToJson(ForemanMcpTools.GetAuditRoute("t3-code", severity: "High", requireAvailable: true));

        var selected = route.RootElement.GetProperty("selected");
        Assert.Equal("codex", selected.GetProperty("AuditorId").GetString());
        Assert.True(selected.GetProperty("available").GetBoolean());
    }

    [Fact]
    public void AuditRouting_CanRequireAvailableAuditor()
    {
        using var route = ToJson(ForemanMcpTools.GetAuditRoute("codex", severity: "High", requireAvailable: true));

        Assert.Equal(0, route.RootElement.GetProperty("candidates").GetArrayLength());
        Assert.True(route.RootElement.GetProperty("reason").GetString()?.Contains("No available auditor") == true);
    }

    public void Dispose()
    {
        _store.Dispose();
        if (Directory.Exists(_profileDir))
            Directory.Delete(_profileDir, recursive: true);
    }

    private static JsonDocument ToJson(object value) =>
        JsonDocument.Parse(JsonSerializer.Serialize(value));
}
