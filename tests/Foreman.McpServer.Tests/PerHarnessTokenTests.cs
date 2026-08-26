using Foreman.Core.Behavior;
using Foreman.Core.Events;
using Foreman.Core.Heuristics;
using Foreman.Core.Mcp;
using Foreman.Core.Models;
using Foreman.Core.Profiles;
using Foreman.Core.Settings;
using Foreman.McpServer;
using Microsoft.AspNetCore.Http;
using System.Text.Json;

namespace Foreman.McpServer.Tests;

// ── Token scheme: mint / authenticate / forgery resistance ───────────────────────
public sealed class McpAuthTokenTests : IDisposable
{
    private readonly string _dir;
    private readonly McpAuthToken _token;

    public McpAuthTokenTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "foreman-token-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_dir);
        _token = new McpAuthToken(_dir);
    }

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    [Fact]
    public void InstallToken_AuthenticatesAsOperator()
    {
        var r = _token.Authenticate(_token.Value);
        Assert.True(r.Ok);
        Assert.True(r.IsOperator);
        Assert.Null(r.HarnessId);
    }

    [Fact]
    public void MintedToken_AuthenticatesAsThatHarness_NotOperator()
    {
        var minted = _token.MintHarnessToken("codex");
        var r = _token.Authenticate(minted);
        Assert.True(r.Ok);
        Assert.False(r.IsOperator);
        Assert.Equal("codex", r.HarnessId);
    }

    [Fact]
    public void Minted_IsCaseInsensitiveOnHarnessId()
        => Assert.Equal("claude-code", _token.Authenticate(_token.MintHarnessToken("Claude-Code")).HarnessId);

    [Fact]
    public void TamperedMac_IsRejected()
    {
        var minted = _token.MintHarnessToken("codex");
        var tampered = minted[..^2] + (minted.EndsWith("AA") ? "BB" : "AA");
        Assert.False(_token.Authenticate(tampered).Ok);
    }

    [Fact]
    public void SwappedHarnessId_WithOldMac_IsRejected()
    {
        // Take codex's mac, splice it onto a claude-code id → must fail (mac is bound to the id).
        var codex = _token.MintHarnessToken("codex");
        var mac = codex.Split('.')[2];
        var claudeIdB64 = _token.MintHarnessToken("claude-code").Split('.')[1];
        var forged = $"fmh1.{claudeIdB64}.{mac}";
        Assert.False(_token.Authenticate(forged).Ok);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("garbage")]
    [InlineData("fmh1.notbase64!.zzz")]
    [InlineData("fmh1.Y29kZXg")]            // missing mac segment
    public void Junk_IsRejected(string? presented) => Assert.False(_token.Authenticate(presented).Ok);

    // ── Stale-token detection: a token minted under a now-rotated secret reads as "stale, reconnect" ──
    [Fact]
    public void LooksLikeStaleHarnessToken_TokenFromRotatedSecret_IsStale_AndExtractsId()
    {
        var otherDir = Path.Combine(Path.GetTempPath(), "foreman-token-old-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(otherDir);
        try
        {
            var oldInstall = new McpAuthToken(otherDir);          // a different install secret
            var staleForUs = oldInstall.MintHarnessToken("cursor"); // valid there, orphaned here
            Assert.False(_token.Authenticate(staleForUs).Ok);
            Assert.True(_token.LooksLikeStaleHarnessToken(staleForUs, out var id));
            Assert.Equal("cursor", id);
        }
        finally { try { Directory.Delete(otherDir, true); } catch { } }
    }

    [Fact]
    public void LooksLikeStaleHarnessToken_CurrentlyValidToken_IsNotStale()
        => Assert.False(_token.LooksLikeStaleHarnessToken(_token.MintHarnessToken("codex"), out _));

    [Fact]
    public void LooksLikeStaleHarnessToken_OperatorToken_IsNotStale()
        => Assert.False(_token.LooksLikeStaleHarnessToken(_token.Value, out _));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("garbage")]
    [InlineData("fmh1.Y29kZXg")]        // missing mac segment
    [InlineData("fmh1.QmFkSWQ.zzz")]    // decodes to "BadId" — uppercase, not a plausible harness id
    public void LooksLikeStaleHarnessToken_JunkOrImplausibleId_IsFalse(string? presented)
        => Assert.False(_token.LooksLikeStaleHarnessToken(presented, out _));

    // ── Stale-token notice: only attributes "rotated" when the token file was actually written recently ──
    // Regression: a 20-day-untouched mcp.token (secret NOT rotated) used to still claim rotation as the cause.
    [Fact]
    public void StaleTokenNotice_OldTokenFile_DoesNotClaimRotation()
    {
        File.SetLastWriteTimeUtc(_token.TokenFilePath, DateTime.UtcNow.AddDays(-20));
        Assert.False(_token.RecentlyRegenerated());

        var notice = McpServerHost.BuildStaleTokenNotice("codex", _token.RecentlyRegenerated());
        Assert.DoesNotContain("rotat", notice, StringComparison.OrdinalIgnoreCase);   // no "rotated"/"rotation"
        Assert.Contains("reconnect", notice, StringComparison.OrdinalIgnoreCase);     // still points at the fix
        Assert.Contains("forged token", notice);                                      // still keeps the theft caveat
    }

    [Fact]
    public void StaleTokenNotice_FreshlyWrittenTokenFile_MayClaimRotation()
    {
        File.SetLastWriteTimeUtc(_token.TokenFilePath, DateTime.UtcNow);
        Assert.True(_token.RecentlyRegenerated());

        var notice = McpServerHost.BuildStaleTokenNotice("codex", _token.RecentlyRegenerated());
        Assert.Contains("rotated", notice, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("forged token", notice);
    }

    [Fact]
    public void StaleTokenNotice_RepeatedPollsFromSameHarness_PublishesOnce()
    {
        var bus = new EventBus();
        var notices = new List<MonitoringNoticeEvent>();
        bus.Subscribe(e =>
        {
            if (e is MonitoringNoticeEvent { Source: "Foreman.McpAuth" } m)
                notices.Add(m);
        });

        var otherDir = Path.Combine(Path.GetTempPath(), "foreman-token-stale-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(otherDir);
        try
        {
            var host = new McpServerHost(new ForemanSettings(), bus);
            var staleForUs = new McpAuthToken(otherDir).MintHarnessToken("browser-extension");

            host.MaybeReportStaleToken(staleForUs);
            host.MaybeReportStaleToken(staleForUs);
            host.MaybeReportStaleToken(staleForUs);

            var notice = Assert.Single(notices);
            Assert.Contains("browser-extension", notice.Message);
        }
        finally { try { Directory.Delete(otherDir, true); } catch { } }
    }
}

// ── Tool scoping: a per-harness caller can't see or act on another harness ───────
public sealed class CallerScopeToolTests : IDisposable
{
    private readonly string _profileDir;
    private readonly ProfileStore _store;
    private readonly ForemanState _state;
    private readonly ProcessRecord _codex, _codexChild, _claude;
    private string? _lastReset;
    private readonly List<int> _killed = new();

    public CallerScopeToolTests()
    {
        PatternLibrary.Instance.Initialize();
        _profileDir = Path.Combine(Path.GetTempPath(), "foreman-scope-" + Guid.NewGuid().ToString("N")[..8]);
        _store = new ProfileStore(_profileDir);
        _store.Initialize();

        _codex      = Proc(940_001, 0, "codex.exe", "codex");
        _codexChild = Proc(940_002, 940_001, "bash.exe", null);
        _claude     = Proc(940_011, 0, "node.exe", "claude-code");

        _state = new ForemanState
        {
            GetProcessSnapshot = () => [_codex, _codexChild, _claude],
            FindHarnessAncestorByPid = pid => pid == _codexChild.Pid ? _codex : null,
            GetBehaviorProfiles = () => [new BehaviorProfile("codex"), new BehaviorProfile("claude-code")],
            ResetBehaviorProfile = id => _lastReset = id,
            KillProcessByPid = (pid, _) => { _killed.Add(pid); return true; },
            McpOperatorPresenceGate = _ => System.Threading.Tasks.Task.FromResult(true),
        };
        _state.HarnessCapabilityRestrictions["codex"] = new HarnessCapabilityRestrictions
        {
            ComputerUse = HarnessCapabilityAccess.Allow,
            BrowserUse = HarnessCapabilityAccess.Allow,
        };
        _state.HarnessCapabilityRestrictions["claude-code"] = new HarnessCapabilityRestrictions
        {
            ComputerUse = HarnessCapabilityAccess.Allow,
            BrowserUse = HarnessCapabilityAccess.Allow,
        };
        ForemanMcpTools.SetState(_state);
    }

    public void Dispose() { try { Directory.Delete(_profileDir, true); } catch { } }

    private static ProcessRecord Proc(int pid, int parent, string name, string? harness) => new()
    {
        Pid = pid, ParentPid = parent, Name = name, StartTime = DateTimeOffset.UtcNow,
        IsHarness = harness is not null, HarnessType = harness,
    };

    // NB: the real HttpContextAccessor stores HttpContext in a shared AsyncLocal, so multiple instances
    // would alias each other in a test. This per-instance fake returns exactly the context we set.
    private sealed class FixedHttpContextAccessor : IHttpContextAccessor
    {
        public HttpContext? HttpContext { get; set; }
    }

    private static IHttpContextAccessor Caller(string? harnessId, bool isOperator)
    {
        var ctx = new DefaultHttpContext();
        ctx.Items[CallerScope.HttpItemKey] = new CallerScope(harnessId, isOperator);
        return new FixedHttpContextAccessor { HttpContext = ctx };
    }

    private static readonly IHttpContextAccessor AsCodex  = Caller("codex", false);
    private static readonly IHttpContextAccessor AsClaude = Caller("claude-code", false);
    private static readonly IHttpContextAccessor AsOperator = Caller(null, true);
    private static readonly IHttpContextAccessor AsLiveweave = Caller("liveweave", false);
    // A per-harness token presented by a different process than it claims (token theft) — may read its own, but
    // must never drive a mutation/kill.
    private static readonly IHttpContextAccessor AsCodexStolen =
        new FixedHttpContextAccessor { HttpContext = Ctx(new CallerScope("codex", IsOperator: false, PeerMismatch: true)) };
    private static DefaultHttpContext Ctx(CallerScope s) { var c = new DefaultHttpContext(); c.Items[CallerScope.HttpItemKey] = s; return c; }

    private static JsonDocument J(object o) => JsonDocument.Parse(JsonSerializer.Serialize(o));

    [Fact]
    public void ListMonitoredProcesses_Operator_SeesAllHarnesses()
    {
        using var doc = J(ForemanMcpTools.ListMonitoredProcesses(http: AsOperator));
        var pids = doc.RootElement.GetProperty("processes").EnumerateArray().Select(e => e.GetProperty("Pid").GetInt32()).ToHashSet();
        Assert.Contains(_codex.Pid, pids);
        Assert.Contains(_claude.Pid, pids);
    }

    [Fact]
    public void ListMonitoredProcesses_CodexCaller_SeesOnlyOwnTree()
    {
        using var doc = J(ForemanMcpTools.ListMonitoredProcesses(http: AsCodex));
        Assert.Equal("codex", doc.RootElement.GetProperty("harnessId").GetString());
        var pids = doc.RootElement.GetProperty("processes").EnumerateArray().Select(e => e.GetProperty("Pid").GetInt32()).ToHashSet();
        Assert.Contains(_codex.Pid, pids);
        Assert.Contains(_codexChild.Pid, pids);
        Assert.DoesNotContain(_claude.Pid, pids);   // can't see the sibling
    }

    [Fact]
    public void ListMonitoredProcesses_CodexCaller_CannotEnumerateClaudeByParam()
    {
        // Even if it asks for claude-code, the token scope wins.
        using var doc = J(ForemanMcpTools.ListMonitoredProcesses(harnessId: "claude-code", http: AsCodex));
        Assert.Equal("codex", doc.RootElement.GetProperty("harnessId").GetString());
        var pids = doc.RootElement.GetProperty("processes").EnumerateArray().Select(e => e.GetProperty("Pid").GetInt32()).ToHashSet();
        Assert.DoesNotContain(_claude.Pid, pids);
    }

    [Fact]
    public void QueryProcessDetail_CodexCaller_DeniedOnClaudeProcess()
    {
        using var doc = J(ForemanMcpTools.QueryProcessDetail(_claude.Pid, http: AsCodex));
        Assert.True(doc.RootElement.TryGetProperty("error", out _));
    }

    [Fact]
    public void QueryProcessDetail_CodexCaller_AllowedOnOwnChild()
    {
        using var doc = J(ForemanMcpTools.QueryProcessDetail(_codexChild.Pid, http: AsCodex));
        Assert.False(doc.RootElement.TryGetProperty("error", out _));
        Assert.Equal(_codexChild.Pid, doc.RootElement.GetProperty("pid").GetInt32());
    }

    [Fact]
    public void AcknowledgeAlert_CodexCaller_DeniedOnClaudeAlert()
    {
        var alert = new CommandAlertEvent(DateTimeOffset.UtcNow, ForemanSeverity.Medium, "src", "msg",
            "cmd", "del-009", "rule", "desc", "guide", _claude.Pid);
        _state.AddEvent(alert);

        using var doc = J(ForemanMcpTools.AcknowledgeAlert(alert.Id, http: AsCodex));
        Assert.False(doc.RootElement.GetProperty("acknowledged").GetBoolean());
        Assert.False(alert.Acknowledged);   // not silenced
    }

    [Fact]
    public async System.Threading.Tasks.Task ResetBehaviorMetrics_HarnessCannotClearAnyAccumulation()
    {
        using var doc = J(await ForemanMcpTools.ResetBehaviorMetrics("claude-code", http: AsCodex));
        Assert.False(doc.RootElement.GetProperty("reset").GetBoolean());
        Assert.Null(_lastReset);

        using var own = J(await ForemanMcpTools.ResetBehaviorMetrics("codex", http: AsCodex));
        Assert.False(own.RootElement.GetProperty("reset").GetBoolean());
        Assert.Null(_lastReset);
    }

    [Fact]
    public void ReportTaskStart_CodexCaller_CannotResetClaudeByParam()
    {
        using var doc = J(ForemanMcpTools.ReportTaskStart(
            "new task",
            resetMetrics: true,
            harnessId: "claude-code",
            http: AsCodex));

        Assert.False(doc.RootElement.GetProperty("acknowledged").GetBoolean());
        Assert.False(doc.RootElement.GetProperty("metricsReset").GetBoolean());
        Assert.Equal("codex", doc.RootElement.GetProperty("harnessId").GetString());
        Assert.Null(_lastReset);
    }

    [Fact]
    public void ReportTaskStart_CodexCaller_DefaultsToOwnHarnessScope()
    {
        using var doc = J(ForemanMcpTools.ReportTaskStart(
            "new task",
            resetMetrics: true,
            http: AsCodex));

        Assert.True(doc.RootElement.GetProperty("acknowledged").GetBoolean());
        Assert.False(doc.RootElement.GetProperty("metricsReset").GetBoolean());
        Assert.Equal("codex", doc.RootElement.GetProperty("harnessId").GetString());
        Assert.Null(_lastReset);
    }

    [Fact]
    public void GetBehaviorMetrics_CodexCaller_SeesOnlyOwnProfile()
    {
        using var doc = J(ForemanMcpTools.GetBehaviorMetrics(http: AsCodex));
        var ids = doc.RootElement.GetProperty("harnesses").EnumerateArray().Select(h => h.GetProperty("harnessId").GetString()).ToHashSet();
        Assert.Contains("codex", ids);
        Assert.DoesNotContain("claude-code", ids);
    }

    [Fact]
    public void ReplyToAskHarness_CodexCaller_CannotAnswerClaudeRequestByParam()
    {
        var req = _state.CreateAskHarnessRequest("claude-code", "sys", "justify", "alert-x", _claude.Pid, "node.exe");
        // Codex caller tries to answer claude's request, even passing harnessId=claude-code → must be rejected
        // because identity comes from the token (codex), and codex doesn't own this request.
        using var doc = J(ForemanMcpTools.ReplyToAskHarnessRequest(req.RequestId, "done", harnessId: "claude-code", http: AsCodex));
        Assert.False(doc.RootElement.GetProperty("accepted").GetBoolean());
        Assert.Equal("pending", _state.GetAskHarnessRequest(req.RequestId)!.Status);
    }

    [Fact]
    public void GetMyPermissions_CodexCaller_CannotReadClaudeByParam()
    {
        // get_MY_permissions: a scoped caller's token identity wins over the requested harnessId.
        using var doc = J(ForemanMcpTools.GetMyPermissions(harnessId: "claude-code", http: AsCodex));
        Assert.Equal("codex", doc.RootElement.GetProperty("harnessId").GetString());
    }

    [Fact]
    public void GetMyInstructions_CodexCaller_CannotReadClaudeByParam()
    {
        using var doc = J(ForemanMcpTools.GetMyInstructions(http: AsCodex, harnessId: "claude-code"));
        Assert.Equal("codex", doc.RootElement.GetProperty("harnessId").GetString());
    }

    [Fact]
    public void GetMyInstructions_Operator_CanQueryAnyHarness()
    {
        using var doc = J(ForemanMcpTools.GetMyInstructions(http: AsOperator, harnessId: "claude-code"));
        Assert.Equal("claude-code", doc.RootElement.GetProperty("harnessId").GetString());
    }

    [Fact]
    public void ReportUsage_CodexCaller_RecordsForItself_NotClaudeByParam()
    {
        using var doc = J(ForemanMcpTools.ReportUsage(percentRemaining: 40, harnessId: "claude-code", http: AsCodex));
        Assert.True(doc.RootElement.GetProperty("recorded").GetBoolean());
        Assert.Equal("codex", doc.RootElement.GetProperty("harnessId").GetString());   // token scope wins over param
        Assert.Equal(40, doc.RootElement.GetProperty("remainingPercent").GetDouble());
        Assert.NotNull(_state.GetContextUsage("codex"));
        Assert.Null(_state.GetContextUsage("claude-code"));    // not recorded for the sibling
    }

    [Fact]
    public void ReportUsage_DerivesRemainingPercentFromTokens()
    {
        using var doc = J(ForemanMcpTools.ReportUsage(tokensUsed: 75, tokensBudget: 100, http: AsCodex));
        Assert.Equal(25, doc.RootElement.GetProperty("remainingPercent").GetDouble());   // (100-75)/100
    }

    // ── ReportSuspiciousCommand: a scoped caller pre-checks against ITS OWN profile only ──────────
    // It must not probe a sibling's enforcement posture (echoed profileName) nor frame a sibling via a
    // sibling-attributed PermissionViolationEvent — the token identity wins over the params.
    [Fact]
    public void ReportSuspiciousCommand_CodexCaller_PinsToOwnHarness_IgnoresSiblingParams()
    {
        using var doc = J(ForemanMcpTools.ReportSuspiciousCommand(
            "echo hello world", harnessId: "claude-code", profileName: "claude-code-default", http: AsCodex));
        Assert.Equal("codex", doc.RootElement.GetProperty("harnessId").GetString());
    }

    [Fact]
    public void ReportSuspiciousCommand_Operator_MayTargetNamedHarness()
    {
        using var doc = J(ForemanMcpTools.ReportSuspiciousCommand(
            "echo hello world", harnessId: "claude-code", http: AsOperator));
        Assert.Equal("claude-code", doc.RootElement.GetProperty("harnessId").GetString());
    }

    [Fact]
    public void ReportSuspiciousCommand_PeerMismatchCannotMintAlertNoise()
    {
        using var doc = J(ForemanMcpTools.ReportSuspiciousCommand(
            "rm -rf /", http: AsCodexStolen));

        Assert.False(doc.RootElement.GetProperty("alertPublished").GetBoolean());
        Assert.False(doc.RootElement.GetProperty("rateLimited").GetBoolean());
    }

    // ── Process broker: own-tree reaping is executed + recorded; cross-tree is refused; theft is refused ──────
    [Fact]
    public async System.Threading.Tasks.Task RequestProcessKill_CodexCaller_ReapsOwnChild_AndRecordsExpected()
    {
        using var doc = J(await ForemanMcpTools.RequestProcessKill(_codexChild.Pid, "runaway hook", http: AsCodex));
        Assert.True(doc.RootElement.GetProperty("executed").GetBoolean());
        Assert.Equal("killed", doc.RootElement.GetProperty("status").GetString());
        Assert.Contains(_codexChild.Pid, _killed);
        Assert.True(_state.ExpectedTerminations.WasExpected(_codexChild.Pid));   // authorised → reads as quiet
    }

    [Fact]
    public async System.Threading.Tasks.Task RequestProcessKill_CodexCaller_CannotKillSibling_EscalatesNotExecutes()
    {
        using var doc = J(await ForemanMcpTools.RequestProcessKill(_claude.Pid, "stop the other agent", http: AsCodex));
        Assert.False(doc.RootElement.GetProperty("executed").GetBoolean());
        Assert.Equal("operator_approval_required", doc.RootElement.GetProperty("status").GetString());
        Assert.DoesNotContain(_claude.Pid, _killed);
        Assert.False(_state.ExpectedTerminations.WasExpected(_claude.Pid));   // not authorised → stays loud
    }

    [Fact]
    public async System.Threading.Tasks.Task RequestProcessKill_StolenToken_Refused_EvenOnOwnTree()
    {
        using var doc = J(await ForemanMcpTools.RequestProcessKill(_codexChild.Pid, "x", http: AsCodexStolen));
        Assert.False(doc.RootElement.GetProperty("executed").GetBoolean());
        Assert.Equal("refused", doc.RootElement.GetProperty("status").GetString());
        Assert.Empty(_killed);
    }

    [Fact]
    public async System.Threading.Tasks.Task RequestProcessKill_Operator_MayKillAnyTrackedPid()
    {
        using var doc = J(await ForemanMcpTools.RequestProcessKill(_claude.Pid, "operator cleanup", http: AsOperator));
        Assert.True(doc.RootElement.GetProperty("executed").GetBoolean());
        Assert.Contains(_claude.Pid, _killed);
    }

    [Fact]
    public async System.Threading.Tasks.Task RequestProcessKill_UnknownPid_NotFound()
    {
        using var doc = J(await ForemanMcpTools.RequestProcessKill(123456, http: AsCodex));
        Assert.Equal("not_found", doc.RootElement.GetProperty("status").GetString());
        Assert.Empty(_killed);
    }

    [Fact]
    public async System.Threading.Tasks.Task RequestProcessKill_SynchronousTerminationFailure_WithdrawsExpectedMarker()
    {
        _state.KillProcessByPid = (_, _) => false;

        using var doc = J(await ForemanMcpTools.RequestProcessKill(
            _codexChild.Pid, "attempt that Windows refuses", http: AsCodex));

        Assert.False(doc.RootElement.GetProperty("executed").GetBoolean());
        Assert.Equal("kill_failed", doc.RootElement.GetProperty("status").GetString());
        Assert.False(_state.ExpectedTerminations.WasExpected(_codexChild.Pid));
    }

    // ── LiveWeave driver gate: only the operator-chosen harness may drive the builder ────────────
    [Fact]
    public void LiveweaveCommand_NoDriverSet_RejectsHarness()
    {
        using var doc = J(ForemanMcpTools.LiveweaveCommand("new_canvas", http: AsCodex));
        Assert.False(doc.RootElement.GetProperty("accepted").GetBoolean());
        Assert.Contains("no harness driver selected", doc.RootElement.GetProperty("reason").GetString());
    }

    [Fact]
    public void LiveweaveCommand_ExplicitAnyDriver_AcceptsHarness()
    {
        _state.LiveWeave.SetDriver("any");

        using var doc = J(ForemanMcpTools.LiveweaveCommand("new_canvas", http: AsCodex));
        Assert.True(doc.RootElement.GetProperty("accepted").GetBoolean());
    }

    [Fact]
    public void LiveweaveCommand_BrowserUseRestricted_RejectsHarness()
    {
        _state.HarnessCapabilityRestrictions["codex"] = new()
        {
            BrowserUse = HarnessCapabilityAccess.Block,
        };

        using var doc = J(ForemanMcpTools.LiveweaveCommand("new_canvas", http: AsCodex));

        Assert.False(doc.RootElement.GetProperty("accepted").GetBoolean());
        Assert.Equal("blocked", doc.RootElement.GetProperty("status").GetString());
        Assert.Contains("Browser use is restricted", doc.RootElement.GetProperty("reason").GetString());
    }

    [Fact]
    public void LiveweaveCommand_DriverSet_AcceptsChosen_RejectsOthers()
    {
        _state.LiveWeave.SetDriver("codex");

        using var codex = J(ForemanMcpTools.LiveweaveCommand("new_canvas", http: AsCodex));
        Assert.True(codex.RootElement.GetProperty("accepted").GetBoolean());

        using var claude = J(ForemanMcpTools.LiveweaveCommand("new_canvas", http: AsClaude));
        Assert.False(claude.RootElement.GetProperty("accepted").GetBoolean());

        using var op = J(ForemanMcpTools.LiveweaveCommand("new_canvas", http: AsOperator));
        Assert.True(op.RootElement.GetProperty("accepted").GetBoolean());   // operator always may
    }

    [Fact]
    public void LiveweavePoll_OnlyLiveweaveHarnessMayPoll()
    {
        using var doc = J(ForemanMcpTools.LiveweavePollCommands(http: AsCodex));
        Assert.True(doc.RootElement.TryGetProperty("reason", out _));
    }

    [Fact]
    public void LiveweavePoll_DriverChangedAfterEnqueue_DropsStaleCommand()
    {
        _state.LiveWeave.SetDriver("claude-code");
        using var enq = J(ForemanMcpTools.LiveweaveCommand("new_canvas", http: AsClaude));
        Assert.True(enq.RootElement.GetProperty("accepted").GetBoolean());
        var cmdId = enq.RootElement.GetProperty("commandId").GetString();

        // Operator switches the driver to codex — the already-queued claude command must not be delivered…
        _state.LiveWeave.SetDriver("codex");
        using var poll = J(ForemanMcpTools.LiveweavePollCommands(driverHarness: "codex", http: AsLiveweave));
        Assert.Empty(poll.RootElement.GetProperty("commands").EnumerateArray());

        // …and is marked failed, so it doesn't sit pending forever.
        using var res = J(ForemanMcpTools.LiveweaveCommandResult(cmdId!));
        Assert.Equal("failed", res.RootElement.GetProperty("status").GetString());
    }

    [Fact]
    public void LiveweavePoll_ExtensionReportedDriverCannotSwitchBrokerAuthority()
    {
        _state.LiveWeave.SetDriver("codex");
        using var enq = J(ForemanMcpTools.LiveweaveCommand("new_canvas", http: AsCodex));

        using var poll = J(ForemanMcpTools.LiveweavePollCommands(
            driverHarness: "claude-code", http: AsLiveweave));

        Assert.True(poll.RootElement.GetProperty("driverMismatch").GetBoolean());
        Assert.Equal("codex", poll.RootElement.GetProperty("driver").GetString());
        Assert.Single(poll.RootElement.GetProperty("commands").EnumerateArray());
        Assert.Equal("codex", _state.LiveWeave.Driver);
    }

    [Fact]
    public void LiveweaveResult_CommandIdCapabilitySurvivesAuthenticatedHarnessHandoff()
    {
        _state.LiveWeave.SetDriver("claude-code");
        using var enq = J(ForemanMcpTools.LiveweaveCommand("new_canvas", http: AsClaude));
        var id = enq.RootElement.GetProperty("commandId").GetString()!;
        _ = ForemanMcpTools.LiveweavePollCommands(http: AsLiveweave);
        _ = ForemanMcpTools.LiveweaveCompleteCommand(id, ok: true, resultJson: "{\"revision\":2}", http: AsLiveweave);

        using var handedOff = J(ForemanMcpTools.LiveweaveCommandResult(id, http: AsCodex));

        Assert.True(handedOff.RootElement.GetProperty("found").GetBoolean());
        Assert.Equal("completed", handedOff.RootElement.GetProperty("status").GetString());
    }

    // ── Extension ingress is untrusted: sanitise/scope/cap everything the extension sends ─────────
    [Fact]
    public void LiveweavePoll_TabInfo_RedactsSecrets_KeepsOnlyKnownFields()
    {
        const string ghp = "ghp_0123456789abcdefghij0123456789abcdef";
        ForemanMcpTools.LiveweavePollCommands(
            tabInfoJson: $"{{\"url\":\"https://x.com/?token={ghp}\",\"title\":\"hi\",\"extensionVersion\":\"0.4.1\",\"canvasConnected\":true,\"evil\":\"DROPME\"}}",
            http: AsLiveweave);
        using var status = J(ForemanMcpTools.LiveweaveStatus(http: AsLiveweave));
        var raw = status.RootElement.GetRawText();
        Assert.DoesNotContain(ghp, raw);       // secret-shaped text in the URL is redacted
        Assert.DoesNotContain("DROPME", raw);  // unknown fields are dropped, not stored
        Assert.Equal("0.4.1", status.RootElement.GetProperty("tab").GetProperty("extensionVersion").GetString());
        Assert.True(status.RootElement.GetProperty("tab").GetProperty("canvasConnected").GetBoolean());
    }

    [Fact]
    public void LiveweavePoll_OversizedTabInfo_Dropped()
    {
        var big = "{\"url\":\"" + new string('a', 5000) + "\"}";
        ForemanMcpTools.LiveweavePollCommands(tabInfoJson: big, http: AsLiveweave);
        using var status = J(ForemanMcpTools.LiveweaveStatus(http: AsLiveweave));
        Assert.Equal(System.Text.Json.JsonValueKind.Null, status.RootElement.GetProperty("tab").ValueKind);
    }

    [Fact]
    public void LiveweaveComplete_OversizedResult_Rejected()
    {
        using var enq = J(ForemanMcpTools.LiveweaveCommand("new_canvas", http: AsOperator));
        var id = enq.RootElement.GetProperty("commandId").GetString();
        var big = "{\"x\":\"" + new string('a', 70000) + "\"}";
        using var done = J(ForemanMcpTools.LiveweaveCompleteCommand(id!, ok: true, resultJson: big, http: AsLiveweave));
        Assert.False(done.RootElement.GetProperty("accepted").GetBoolean());
    }

    [Fact]
    public void LiveweaveComplete_RedactsSecretInResult()
    {
        const string ghp = "ghp_0123456789abcdefghij0123456789abcdef";
        using var enq = J(ForemanMcpTools.LiveweaveCommand("scan", http: AsOperator));
        var id = enq.RootElement.GetProperty("commandId").GetString();
        _ = ForemanMcpTools.LiveweavePollCommands(http: AsLiveweave);
        using var completed = J(ForemanMcpTools.LiveweaveCompleteCommand(
            id!, ok: true, resultJson: $"{{\"leaked\":\"{ghp}\"}}", http: AsLiveweave));
        Assert.True(completed.RootElement.GetProperty("accepted").GetBoolean());
        using var res = J(ForemanMcpTools.LiveweaveCommandResult(id!));
        Assert.DoesNotContain(ghp, res.RootElement.GetRawText());   // result is redacted before it reaches the driver
    }

    // ── request_harness_review: bounded harness mail / outbound handoff ───────────────────────────
    [Fact]
    public async System.Threading.Tasks.Task LiveweaveRequestEdit_QueuesScopedOperatorTask_AndReturnsReply()
    {
        _state.LiveWeave.SetDriver("codex");
        _state.DeliverHarnessAsk = (_, _, _, _) => System.Threading.Tasks.Task.FromResult("notified");
        using var queued = J(await ForemanMcpTools.LiveweaveRequestEdit(
            "codex",
            "Make the card easier to read",
            "#card",
            "project-1",
            "Broken landing page",
            4,
            "https://example.test",
            "{\"tag\":\"section\",\"text\":\"untrusted site text\"}",
            http: AsLiveweave));

        Assert.True(queued.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("notified", queued.RootElement.GetProperty("delivered").GetString());
        var requestId = queued.RootElement.GetProperty("requestId").GetString();
        var request = Assert.IsType<AskHarnessRequest>(_state.GetAskHarnessRequest(requestId!));
        Assert.Equal("liveweave", request.SenderHarnessId);
        Assert.Equal("liveweave_edit", request.RequestKind);
        Assert.Contains("operator-initiated LiveWeave creation or edit request", request.SystemPrompt);
        Assert.Contains("Make the card easier to read", request.Prompt);
        Assert.Contains("BEGIN UNTRUSTED SELECTION SNAPSHOT", request.Prompt);

        using var replied = J(ForemanMcpTools.ReplyToAskHarnessRequest(
            requestId!, "Applied set_style and verified revision 5.", "LiveWeave edit completed", http: AsCodex));
        Assert.True(replied.RootElement.GetProperty("accepted").GetBoolean());

        using var result = J(ForemanMcpTools.LiveweaveEditRequestResult(requestId!, http: AsLiveweave));
        Assert.True(result.RootElement.GetProperty("found").GetBoolean());
        Assert.Equal("answered", result.RootElement.GetProperty("status").GetString());
        Assert.Contains("Applied set_style", result.RootElement.GetProperty("replyText").GetString());
    }

    [Fact]
    public async System.Threading.Tasks.Task LiveweaveRequestEdit_AtomicallySelectsTargetDriver()
    {
        _state.LiveWeave.SetDriver("claude-code");
        using var result = J(await ForemanMcpTools.LiveweaveRequestEdit(
            "codex", "Fix it", "#card", "project-1", "Page", 1, http: AsLiveweave));
        Assert.True(result.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("codex", _state.LiveWeave.Driver);
    }

    [Fact]
    public async System.Threading.Tasks.Task LiveweaveRequestEdit_RejectsNonExtensionCaller()
    {
        _state.LiveWeave.SetDriver("claude-code");
        using var result = J(await ForemanMcpTools.LiveweaveRequestEdit(
            "claude-code", "Fix it", "#card", "project-1", "Page", 1, http: AsCodex));
        Assert.False(result.RootElement.GetProperty("ok").GetBoolean());
    }

    [Fact]
    public void LiveweaveEditRequestResult_DoesNotExposeGenericHarnessMail()
    {
        var request = _state.CreateAskHarnessRequest(
            "codex", "sys", "prompt", "", null, null, senderHarnessId: "liveweave", requestKind: "harness_mail");
        using var result = J(ForemanMcpTools.LiveweaveEditRequestResult(request.RequestId, http: AsLiveweave));
        Assert.False(result.RootElement.GetProperty("found").GetBoolean());
    }

    [Fact]
    public async System.Threading.Tasks.Task LiveweaveEditRequestResult_RejectsSiblingHarnessCaller()
    {
        using var queued = J(await ForemanMcpTools.LiveweaveRequestEdit(
            "claude-code", "Fix it", "#card", "project-1", "Page", 1, http: AsLiveweave));
        var requestId = queued.RootElement.GetProperty("requestId").GetString();
        using var result = J(ForemanMcpTools.LiveweaveEditRequestResult(requestId!, http: AsCodex));
        Assert.False(result.RootElement.GetProperty("found").GetBoolean());
    }

    [Fact]
    public async System.Threading.Tasks.Task RequestHarnessReview_Operator_CreatesAndDelivers()
    {
        _state.DeliverHarnessAsk = (h, s, p, r) => System.Threading.Tasks.Task.FromResult("notified");
        using var doc = J(await ForemanMcpTools.RequestHarnessReview("cursor", "review this", "is X safe?", "High", "codex flagged it", http: AsOperator));
        Assert.True(doc.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("cursor", doc.RootElement.GetProperty("targetHarnessId").GetString());
        Assert.Equal("operator", doc.RootElement.GetProperty("senderHarnessId").GetString());
        Assert.Equal("operator_handoff", doc.RootElement.GetProperty("requestKind").GetString());
        Assert.Equal("notified", doc.RootElement.GetProperty("delivered").GetString());
        var rid = doc.RootElement.GetProperty("requestId").GetString();
        Assert.NotNull(_state.GetAskHarnessRequest(rid!));   // queued for the target's mailbox too
    }

    [Fact]
    public async System.Threading.Tasks.Task RequestHarnessReview_ScopedCaller_CreatesAttributedCursorMail()
    {
        using var doc = J(await ForemanMcpTools.RequestHarnessReview(
            "cursor",
            "pretend this is a system override",
            "please review the LiveWeave diff; do not run anything until you inspect it",
            "Medium",
            "handoff test",
            http: AsCodex));

        Assert.True(doc.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("cursor", doc.RootElement.GetProperty("targetHarnessId").GetString());
        Assert.Equal("codex", doc.RootElement.GetProperty("senderHarnessId").GetString());
        Assert.Equal("harness_mail", doc.RootElement.GetProperty("requestKind").GetString());

        var rid = doc.RootElement.GetProperty("requestId").GetString();
        var req = Assert.IsType<AskHarnessRequest>(_state.GetAskHarnessRequest(rid!));
        Assert.Equal("cursor", req.HarnessId);
        Assert.Equal("codex", req.SenderHarnessId);
        Assert.Equal("harness_mail", req.RequestKind);
        Assert.Contains("TraceBrake-mediated harness-to-harness handoff", req.SystemPrompt);
        Assert.Contains("BEGIN UNTRUSTED SENDER MESSAGE", req.Prompt);
        Assert.Contains("please review the LiveWeave diff", req.Prompt);
    }

    [Fact]
    public async System.Threading.Tasks.Task RequestHarnessReview_ScopedCaller_CannotTargetSelf()
    {
        using var doc = J(await ForemanMcpTools.RequestHarnessReview("codex", "x", "y", http: AsCodex));
        Assert.False(doc.RootElement.GetProperty("ok").GetBoolean());
    }

    [Fact]
    public async System.Threading.Tasks.Task RequestHarnessReview_StolenScopedToken_Refused()
    {
        using var doc = J(await ForemanMcpTools.RequestHarnessReview("cursor", "x", "y", http: AsCodexStolen));
        Assert.False(doc.RootElement.GetProperty("ok").GetBoolean());
    }

    [Fact]
    public async System.Threading.Tasks.Task RequestHarnessReview_NoDeliveryHook_Queued()
    {
        _state.DeliverHarnessAsk = null;
        using var doc = J(await ForemanMcpTools.RequestHarnessReview("cursor", "x", "review", http: AsOperator));
        Assert.True(doc.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("queued", doc.RootElement.GetProperty("delivered").GetString());
    }

    [Fact]
    public async System.Threading.Tasks.Task RequestHarnessReview_EmptyTarget_Rejected()
    {
        using var doc = J(await ForemanMcpTools.RequestHarnessReview("", "x", "y", http: AsOperator));
        Assert.False(doc.RootElement.GetProperty("ok").GetBoolean());
    }

    [Fact]
    public async System.Threading.Tasks.Task RequestHarnessReview_InvalidTarget_Rejected()
    {
        using var doc = J(await ForemanMcpTools.RequestHarnessReview("cursor\ncodex", "x", "y", http: AsOperator));
        Assert.False(doc.RootElement.GetProperty("ok").GetBoolean());
    }

    [Fact]
    public async System.Threading.Tasks.Task RequestHarnessReview_Metadata_RedactedAndBounded()
    {
        const string ghp = "ghp_0123456789abcdefghij0123456789abcdef";
        using var doc = J(await ForemanMcpTools.RequestHarnessReview(
            "cursor",
            "sys",
            "body",
            "High\nInjected",
            "reason\n" + ghp,
            http: AsCodex));

        Assert.True(doc.RootElement.GetProperty("ok").GetBoolean());
        Assert.DoesNotContain(ghp, doc.RootElement.GetRawText());

        var rid = doc.RootElement.GetProperty("requestId").GetString();
        var req = Assert.IsType<AskHarnessRequest>(_state.GetAskHarnessRequest(rid!));
        Assert.DoesNotContain(ghp, req.Prompt);
        Assert.DoesNotContain("\n" + ghp, doc.RootElement.GetProperty("severity").GetString());
    }

    [Fact]
    public void LiveweaveComplete_ResultPayload_ReturnedToDriver()
    {
        using var enq = J(ForemanMcpTools.LiveweaveCommand("scan", http: AsOperator));
        var id = enq.RootElement.GetProperty("commandId").GetString();

        _ = ForemanMcpTools.LiveweavePollCommands(http: AsLiveweave);
        using var completed = J(ForemanMcpTools.LiveweaveCompleteCommand(
            id!, ok: true, resultJson: "{\"title\":\"Sugar Loop\",\"htmlLength\":123}", http: AsLiveweave));
        Assert.True(completed.RootElement.GetProperty("accepted").GetBoolean());

        using var res = J(ForemanMcpTools.LiveweaveCommandResult(id!));
        Assert.Equal("completed", res.RootElement.GetProperty("status").GetString());
        Assert.Equal("Sugar Loop", res.RootElement.GetProperty("result").GetProperty("title").GetString());
        Assert.Equal(123, res.RootElement.GetProperty("result").GetProperty("htmlLength").GetInt32());
    }

    [Fact]
    public void LiveweaveCommand_AcceptPayload_ReportsExtensionNotConnected()
    {
        // No extension has polled, so the broker reports it disconnected — the accept payload should say so up front
        // (instead of a constant "must be open and paired" hint) so the driving agent knows it'll time out.
        using var enq = J(ForemanMcpTools.LiveweaveCommand("scan", http: AsOperator));
        Assert.True(enq.RootElement.GetProperty("accepted").GetBoolean());
        Assert.False(enq.RootElement.GetProperty("connected").GetBoolean());
        Assert.Contains("NOT connected", enq.RootElement.GetProperty("hint").GetString());
    }
}
