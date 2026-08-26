using System.Text.Json;
using Foreman.Core.ComputerUse;
using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.Core.Settings;

namespace Foreman.McpServer.Tests;

public sealed class CuToolsTests
{
    private sealed class FixedAuditor(CuVerdict verdict) : IAuditor
    {
        public Task<CuVerdict> JudgeAsync(CuAction a, CuContext c, CancellationToken ct = default) => Task.FromResult(verdict);
    }

    private sealed class AvailableAdbRunner : IAdbCommandRunner
    {
        public bool IsAvailable => true;
        public Task<AdbCommandResult> RunAsync(
            IReadOnlyList<string> arguments,
            int maxOutputBytes,
            TimeSpan timeout,
            CancellationToken ct = default) =>
            Task.FromResult(new AdbCommandResult(0, System.Text.Encoding.UTF8.GetBytes("device\n"), string.Empty));
        public void CancelCurrent() { }
    }

    private static JsonDocument Json(object o) => JsonDocument.Parse(JsonSerializer.Serialize(o));

    private static ForemanState StateWith(CuVerdict verdict)
    {
        var state = new ForemanState { Cu = new CuBroker(new FixedAuditor(verdict)) };
        state.Cu.SetDriver("codex");
        state.HarnessCapabilityRestrictions["codex"] = new Foreman.Core.Mcp.HarnessCapabilityRestrictions
        {
            ComputerUse = Foreman.Core.Mcp.HarnessCapabilityAccess.Allow,
            BrowserUse = Foreman.Core.Mcp.HarnessCapabilityAccess.Allow,
        };
        ForemanMcpTools.SetState(state);
        return state;
    }

    private static ForemanState StateWithAndroid(params string[] drivers)
    {
        var state = StateWith(CuVerdict.Allow("test"));
        state.Cu!.SetDrivers(drivers);
        foreach (var driver in drivers)
            state.HarnessCapabilityRestrictions[driver] = new Foreman.Core.Mcp.HarnessCapabilityRestrictions
            {
                ComputerUse = Foreman.Core.Mcp.HarnessCapabilityAccess.Allow,
                BrowserUse = Foreman.Core.Mcp.HarnessCapabilityAccess.Allow,
            };
        state.Cu.SetAndroidDevices(["device-1"]);
        state.Adb = new AdbBridgeExecutor(
            AdbBridgeOptions.Create(@"C:\Android\platform-tools\adb.exe", ["device-1"]),
            new AvailableAdbRunner());
        return state;
    }

    // A POCO IHttpContextAccessor (the real one uses a shared AsyncLocal) so each test can pose as a specific
    // non-operator harness and exercise the executor-identity gate on cu_poll_actions / cu_complete_action.
    private sealed class FixedHttpContextAccessor : Microsoft.AspNetCore.Http.IHttpContextAccessor
    {
        public Microsoft.AspNetCore.Http.HttpContext? HttpContext { get; set; }
    }
    private static Microsoft.AspNetCore.Http.IHttpContextAccessor AsHarness(string id)
    {
        var ctx = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        ctx.Items[CallerScope.HttpItemKey] = new CallerScope(id, IsOperator: false);
        return new FixedHttpContextAccessor { HttpContext = ctx };
    }
    private static Microsoft.AspNetCore.Http.IHttpContextAccessor AsOperator()
    {
        var ctx = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        ctx.Items[CallerScope.HttpItemKey] = new CallerScope(null, IsOperator: true);
        return new FixedHttpContextAccessor { HttpContext = ctx };
    }

    [Fact]
    public async Task CuSubmit_Allow_IsApproved()
    {
        StateWith(CuVerdict.Allow("test"));
        using var doc = Json(await ForemanMcpTools.CuSubmit("browser", "navigate", "{\"url\":\"https://example.com\"}", AsHarness("codex")));
        Assert.True(doc.RootElement.GetProperty("accepted").GetBoolean());
        Assert.Equal("approved", doc.RootElement.GetProperty("state").GetString());
    }

    [Fact]
    public async Task CuSubmit_Block_IsBlocked_AndNotAccepted()
    {
        StateWith(CuVerdict.Block("test", "dangerous"));
        using var doc = Json(await ForemanMcpTools.CuSubmit("browser", "navigate", "{\"url\":\"x\"}", AsHarness("codex")));
        Assert.False(doc.RootElement.GetProperty("accepted").GetBoolean());
        Assert.Equal("blocked", doc.RootElement.GetProperty("state").GetString());
    }

    [Fact]
    public async Task CuSubmit_BadModality_Rejected()
    {
        StateWith(CuVerdict.Allow("test"));
        using var doc = Json(await ForemanMcpTools.CuSubmit("hologram", "navigate", "{}", AsHarness("codex")));
        Assert.False(doc.RootElement.GetProperty("accepted").GetBoolean());
    }

    [Fact]
    public async Task CuSubmit_OversizedArgs_AreRejectedBeforeBroker()
    {
        StateWith(CuVerdict.Allow("test"));
        var oversized = "{\"text\":\"" + new string('a', 70 * 1024) + "\"}";
        using var doc = Json(await ForemanMcpTools.CuSubmit("browser", "type", oversized, AsHarness("codex")));
        Assert.False(doc.RootElement.GetProperty("accepted").GetBoolean());
        Assert.Contains("64 KiB", doc.RootElement.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task CuSubmit_DesktopOverMcp_Rejected()
    {
        // Desktop CU is operator-driven in-process only (INV-7 / Codex review #2) — never over MCP.
        StateWith(CuVerdict.Allow("test"));
        using var doc = Json(await ForemanMcpTools.CuSubmit("desktop", "click", "{}", AsHarness("codex")));
        Assert.False(doc.RootElement.GetProperty("accepted").GetBoolean());
    }

    [Fact]
    public async Task CuSubmit_Android_EverySelectedHarnessUsesUnifiedBroker()
    {
        StateWithAndroid("codex", "claude-code");

        using var codex = Json(await ForemanMcpTools.CuSubmit(
            "android", "screenshot", "{\"serial\":\"device-1\"}", AsHarness("codex")));
        using var claude = Json(await ForemanMcpTools.CuSubmit(
            "android", "ui_dump", "{\"serial\":\"device-1\"}", AsHarness("claude-code")));
        using var cursor = Json(await ForemanMcpTools.CuSubmit(
            "android", "logcat", "{\"serial\":\"device-1\"}", AsHarness("cursor")));

        Assert.True(codex.RootElement.GetProperty("accepted").GetBoolean());
        Assert.True(claude.RootElement.GetProperty("accepted").GetBoolean());
        Assert.False(cursor.RootElement.GetProperty("accepted").GetBoolean());
    }

    [Fact]
    public async Task CuSubmit_AndroidInstall_EverySelectedHarnessUsesUnifiedBrokerAndIsHeld()
    {
        var apk = Path.Combine(Path.GetTempPath(), $"foreman-{Guid.NewGuid():N}.apk");
        File.WriteAllText(apk, "MCP APK package bytes");
        try
        {
            StateWithAndroid("codex", "claude-code");
            var args = JsonSerializer.Serialize(new Dictionary<string, string>
            {
                ["serial"] = "device-1",
                ["apkPath"] = apk,
                ["replace"] = "true",
            });

            using var codex = Json(await ForemanMcpTools.CuSubmit(
                "android", "install", args, AsHarness("codex")));
            using var claude = Json(await ForemanMcpTools.CuSubmit(
                "android", "install", args, AsHarness("claude-code")));
            using var cursor = Json(await ForemanMcpTools.CuSubmit(
                "android", "install", args, AsHarness("cursor")));

            Assert.True(codex.RootElement.GetProperty("accepted").GetBoolean());
            Assert.Equal("held", codex.RootElement.GetProperty("state").GetString());
            Assert.True(claude.RootElement.GetProperty("accepted").GetBoolean());
            Assert.Equal("held", claude.RootElement.GetProperty("state").GetString());
            Assert.False(cursor.RootElement.GetProperty("accepted").GetBoolean());
        }
        finally
        {
            File.Delete(apk);
        }
    }

    [Fact]
    public async Task CuSubmit_Android_ComputerUsePolicyIsEnforced()
    {
        var state = StateWithAndroid("codex");
        state.HarnessCapabilityRestrictions["codex"] = new Foreman.Core.Mcp.HarnessCapabilityRestrictions
        {
            ComputerUse = Foreman.Core.Mcp.HarnessCapabilityAccess.Block,
        };

        using var result = Json(await ForemanMcpTools.CuSubmit(
            "android", "devices", "{}", AsHarness("codex")));

        Assert.False(result.RootElement.GetProperty("accepted").GetBoolean());
        Assert.Equal("blocked", result.RootElement.GetProperty("status").GetString());
    }

    [Fact]
    public async Task CuSubmit_BrowserAskFirst_EntersActionableHeldQueue()
    {
        var state = StateWith(CuVerdict.Allow("test"));
        state.Cu!.SetDriver("codex");
        state.HarnessCapabilityRestrictions["codex"] = new Foreman.Core.Mcp.HarnessCapabilityRestrictions
        {
            BrowserUse = Foreman.Core.Mcp.HarnessCapabilityAccess.AskFirst,
        };

        using var result = Json(await ForemanMcpTools.CuSubmit(
            "browser", "read", "{}", AsHarness("codex")));

        Assert.True(result.RootElement.GetProperty("accepted").GetBoolean());
        Assert.Equal("held", result.RootElement.GetProperty("state").GetString());
        Assert.Single(state.Cu.ListHeld());
    }

    [Fact]
    public async Task CuSubmit_AndroidMutatingAction_IsHeldAndRawShellIsBlocked()
    {
        StateWithAndroid("codex");

        using var tap = Json(await ForemanMcpTools.CuSubmit(
            "android", "tap", "{\"serial\":\"device-1\",\"x\":\"10\",\"y\":\"20\"}", AsHarness("codex")));
        using var shell = Json(await ForemanMcpTools.CuSubmit(
            "android", "shell", "{\"serial\":\"device-1\",\"command\":\"id\"}", AsHarness("codex")));

        Assert.True(tap.RootElement.GetProperty("accepted").GetBoolean());
        Assert.Equal("held", tap.RootElement.GetProperty("state").GetString());
        Assert.False(shell.RootElement.GetProperty("accepted").GetBoolean());
        Assert.Equal("blocked", shell.RootElement.GetProperty("state").GetString());
    }

    [Fact]
    public async Task CuPollActions_BrowserExecutorCannotDrainAndroidQueue()
    {
        var state = StateWithAndroid("codex");
        using var submit = Json(await ForemanMcpTools.CuSubmit(
            "android", "screenshot", "{\"serial\":\"device-1\"}", AsHarness("codex")));
        var actionId = submit.RootElement.GetProperty("actionId").GetString()!;

        using var poll = Json(ForemanMcpTools.CuPollActions(10, AsHarness("browser-extension")));

        Assert.Equal(0, poll.RootElement.GetProperty("actions").GetArrayLength());
        Assert.Equal(CuActionState.Approved, state.Cu!.Get(actionId)!.State);
    }

    [Fact]
    public async Task CuSubmit_AndroidBridgeDisabled_IsRefused()
    {
        var state = StateWith(CuVerdict.Allow("test"));
        state.Cu!.SetDriver("codex");
        state.Cu.SetAndroidDevices(["device-1"]);

        using var result = Json(await ForemanMcpTools.CuSubmit(
            "android", "screenshot", "{\"serial\":\"device-1\"}", AsHarness("codex")));

        Assert.False(result.RootElement.GetProperty("accepted").GetBoolean());
    }

    [Fact]
    public async Task CuAndroid_StatusAndHeldQueue_AreScopedToSubmittingHarness()
    {
        StateWithAndroid("codex", "claude-code");
        using var read = Json(await ForemanMcpTools.CuSubmit(
            "android", "screenshot", "{\"serial\":\"device-1\"}", AsHarness("codex")));
        var readId = read.RootElement.GetProperty("actionId").GetString()!;
        _ = await ForemanMcpTools.CuSubmit(
            "android", "tap", "{\"serial\":\"device-1\",\"x\":\"1\",\"y\":\"2\"}", AsHarness("codex"));

        using var ownerStatus = Json(ForemanMcpTools.CuActionStatus(readId, http: AsHarness("codex")));
        using var siblingStatus = Json(ForemanMcpTools.CuActionStatus(readId, http: AsHarness("claude-code")));
        using var ownerQueue = Json(ForemanMcpTools.CuStatus(AsHarness("codex")));
        using var siblingQueue = Json(ForemanMcpTools.CuStatus(AsHarness("claude-code")));

        Assert.True(ownerStatus.RootElement.GetProperty("found").GetBoolean());
        Assert.False(siblingStatus.RootElement.GetProperty("found").GetBoolean());
        Assert.Equal(1, ownerQueue.RootElement.GetProperty("heldCount").GetInt32());
        Assert.Equal(0, siblingQueue.RootElement.GetProperty("heldCount").GetInt32());
    }

    [Fact]
    public void CuStatus_ScopedHarnessGetsCapabilityWithoutSiblingOrDeviceInventory()
    {
        StateWithAndroid("codex", "claude-code");

        using var scoped = Json(ForemanMcpTools.CuStatus(AsHarness("codex")));
        using var op = Json(ForemanMcpTools.CuStatus(AsOperator()));

        Assert.True(scoped.RootElement.GetProperty("canDrive").GetBoolean());
        Assert.Equal(JsonValueKind.Null, scoped.RootElement.GetProperty("driver").ValueKind);
        Assert.Equal(JsonValueKind.Null, scoped.RootElement.GetProperty("android").GetProperty("executable").ValueKind);
        Assert.Empty(scoped.RootElement.GetProperty("android").GetProperty("enrolledDevices").EnumerateArray());
        Assert.Equal(1, scoped.RootElement.GetProperty("android").GetProperty("enrolledDeviceCount").GetInt32());

        Assert.Contains("claude-code", op.RootElement.GetProperty("driver").GetString());
        Assert.Equal("device-1", op.RootElement.GetProperty("android").GetProperty("enrolledDevices")[0].GetString());
    }

    [Fact]
    public async Task CuAndroid_HeldApprovalRequiresFreshPresenceGate()
    {
        var state = StateWithAndroid("codex");
        using var sub = Json(await ForemanMcpTools.CuSubmit(
            "android", "tap", "{\"serial\":\"device-1\",\"x\":\"1\",\"y\":\"2\"}", AsHarness("codex")));
        var id = sub.RootElement.GetProperty("actionId").GetString()!;

        using var denied = Json(await ForemanMcpTools.CuApprove(id, AsOperator()));
        Assert.False(denied.RootElement.GetProperty("ok").GetBoolean());

        state.CuPresenceApprovalGate = modality => Task.FromResult(modality == CuModality.Android);
        using var approved = Json(await ForemanMcpTools.CuApprove(id, AsOperator()));
        Assert.True(approved.RootElement.GetProperty("ok").GetBoolean());
    }

    [Fact]
    public async Task CuSubmit_Hold_OperatorApprove_PollExecute_Complete()
    {
        var state = StateWith(CuVerdict.Hold("test", "uncertain"));
        state.CuPresenceApprovalGate = _ => Task.FromResult(true);
        using var sub = Json(await ForemanMcpTools.CuSubmit("browser", "click", "{}", AsHarness("codex")));
        Assert.Equal("held", sub.RootElement.GetProperty("state").GetString());
        var actionId = sub.RootElement.GetProperty("actionId").GetString()!;

        using var appr = Json(await ForemanMcpTools.CuApprove(actionId, AsOperator()));
        Assert.True(appr.RootElement.GetProperty("ok").GetBoolean());

        using var poll = Json(ForemanMcpTools.CuPollActions(10, AsHarness("browser-extension")));
        Assert.Equal(1, poll.RootElement.GetProperty("actions").GetArrayLength());
        var executionToken = poll.RootElement.GetProperty("actions")[0].GetProperty("executionToken").GetString()!;

        using var st = Json(ForemanMcpTools.CuActionStatus(actionId, http: AsHarness("codex")));
        Assert.Equal("executing", st.RootElement.GetProperty("state").GetString());

        using var done = Json(ForemanMcpTools.CuCompleteAction(
            actionId, executionToken, ok: true, resultJson: null, error: null,
            http: AsHarness("browser-extension")));
        Assert.True(done.RootElement.GetProperty("accepted").GetBoolean());

        using var st2 = Json(ForemanMcpTools.CuActionStatus(actionId, http: AsHarness("codex")));
        Assert.Equal("completed", st2.RootElement.GetProperty("state").GetString());
    }

    [Fact]
    public async Task CuSubmit_Hold_OperatorReject_NotClaimable()
    {
        var state = StateWith(CuVerdict.Hold("test", "uncertain"));
        state.McpOperatorPresenceGate = _ => Task.FromResult(true);
        using var sub = Json(await ForemanMcpTools.CuSubmit("browser", "click", "{}", AsHarness("codex")));
        var actionId = sub.RootElement.GetProperty("actionId").GetString()!;

        using var rej = Json(await ForemanMcpTools.CuReject(actionId, "not now", AsOperator()));
        Assert.True(rej.RootElement.GetProperty("ok").GetBoolean());

        using var poll = Json(ForemanMcpTools.CuPollActions(10, AsHarness("browser-extension")));
        Assert.Equal(0, poll.RootElement.GetProperty("actions").GetArrayLength());
    }

    [Fact]
    public async Task CuSubmit_NotWired_ReportsUnavailable()
    {
        ForemanMcpTools.SetState(new ForemanState());   // Cu is null
        using var doc = Json(await ForemanMcpTools.CuSubmit("browser", "navigate", "{}", AsHarness("codex")));
        Assert.False(doc.RootElement.GetProperty("accepted").GetBoolean());
    }

    [Fact]
    public async Task CuStatus_SurfacesHeld()
    {
        StateWith(CuVerdict.Hold("test", "why"));
        _ = await ForemanMcpTools.CuSubmit("browser", "type", "{\"text\":\"x\"}", AsHarness("codex"));
        using var doc = Json(ForemanMcpTools.CuStatus(AsHarness("codex")));
        Assert.True(doc.RootElement.GetProperty("available").GetBoolean());
        Assert.True(doc.RootElement.GetProperty("heldCount").GetInt32() >= 1);
    }

    [Fact]
    public async Task CuPoll_NonExecutorHarness_Refused_ButBrowserExtensionAllowed()
    {
        StateWith(CuVerdict.Allow("test"));
        using var sub = Json(await ForemanMcpTools.CuSubmit("browser", "navigate", "{\"url\":\"https://example.com\"}", AsHarness("codex")));
        Assert.Equal("approved", sub.RootElement.GetProperty("state").GetString());

        // A submitting/driving harness (codex) must NOT be able to claim the approved action…
        using var codexPoll = Json(ForemanMcpTools.CuPollActions(10, AsHarness("codex")));
        Assert.Equal(0, codexPoll.RootElement.GetProperty("actions").GetArrayLength());

        // …only the browser-extension executor (or the operator) may.
        using var extPoll = Json(ForemanMcpTools.CuPollActions(10, AsHarness("browser-extension")));
        Assert.Equal(1, extPoll.RootElement.GetProperty("actions").GetArrayLength());
    }

    [Fact]
    public async Task CuComplete_NonExecutorHarness_Refused()
    {
        StateWith(CuVerdict.Allow("test"));
        using var sub = Json(await ForemanMcpTools.CuSubmit("browser", "navigate", "{\"url\":\"https://example.com\"}", AsHarness("codex")));
        var actionId = sub.RootElement.GetProperty("actionId").GetString()!;
        using var extPoll = Json(ForemanMcpTools.CuPollActions(10, AsHarness("browser-extension")));   // claim -> executing
        Assert.Equal(1, extPoll.RootElement.GetProperty("actions").GetArrayLength());
        var executionToken = extPoll.RootElement.GetProperty("actions")[0].GetProperty("executionToken").GetString()!;

        using var codexDone = Json(ForemanMcpTools.CuCompleteAction(
            actionId, executionToken, true, null, null, AsHarness("codex")));
        Assert.False(codexDone.RootElement.GetProperty("accepted").GetBoolean());
    }

    [Fact]
    public async Task CuSetDriver_GatesWhoMaySubmit()
    {
        var state = StateWith(CuVerdict.Allow("test"));
        state.Cu!.SetDriver(null);
        state.McpOperatorPresenceGate = _ => Task.FromResult(true);

        // Default: no driver -> a harness cannot submit (operator-only).
        using var noDrv = Json(await ForemanMcpTools.CuSubmit("browser", "read", "{}", AsHarness("codex")));
        Assert.False(noDrv.RootElement.GetProperty("accepted").GetBoolean());

        // Operator designates codex as the driver.
        using var set = Json(await ForemanMcpTools.CuSetDriver("codex", AsOperator()));
        Assert.True(set.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("codex", set.RootElement.GetProperty("driver").GetString());

        // codex may now submit...
        using var codexOk = Json(await ForemanMcpTools.CuSubmit("browser", "read", "{}", AsHarness("codex")));
        Assert.True(codexOk.RootElement.GetProperty("accepted").GetBoolean());

        // ...a different harness still may not.
        using var claudeNo = Json(await ForemanMcpTools.CuSubmit("browser", "read", "{}", AsHarness("claude-code")));
        Assert.False(claudeNo.RootElement.GetProperty("accepted").GetBoolean());
    }

    [Fact]
    public async Task CuSetDriver_OperatorOnly()
    {
        StateWith(CuVerdict.Allow("test"));
        using var doc = Json(await ForemanMcpTools.CuSetDriver("codex", AsHarness("codex")));
        Assert.False(doc.RootElement.GetProperty("ok").GetBoolean());
    }

    [Fact]
    public async Task CuSetDriver_PersisterReceivesAuthenticatedMcpProvenance()
    {
        var state = StateWith(CuVerdict.Allow("test"));
        state.McpOperatorPresenceGate = _ => Task.FromResult(true);
        SettingsChangeAttribution? observed = null;
        state.Cu!.DriverPersister = _ => observed = SettingsChangeContext.Current;

        using var doc = Json(await ForemanMcpTools.CuSetDriver("claude-code", AsOperator()));

        Assert.True(doc.RootElement.GetProperty("ok").GetBoolean());
        Assert.NotNull(observed);
        Assert.Equal(SettingsChangeOrigin.AuthenticatedMcp, observed!.Origin);
        Assert.Equal("operator-token", observed.Actor);
        Assert.Equal("cu_set_driver", observed.Operation);
        Assert.False(observed.Suspicious);
        Assert.Null(SettingsChangeContext.Current);
    }

    // ── cu_resolve_vault (the browser-extension executor's reference -> plaintext resolve) ──────────────────
    private static async Task<(string ActionId, string ExecutionToken)> ExecutingBrowserAction(string text)
    {
        using var sub = Json(await ForemanMcpTools.CuSubmit(
            "browser", "type", $"{{\"text\":\"{text}\"}}", AsHarness("codex")));
        var actionId = sub.RootElement.GetProperty("actionId").GetString()!;
        using var poll = Json(ForemanMcpTools.CuPollActions(10, AsHarness("browser-extension")));
        var token = poll.RootElement.GetProperty("actions")[0].GetProperty("executionToken").GetString()!;
        return (actionId, token);
    }

    private static async Task<(string ActionId, string ExecutionToken)> ExecutingBrowserActionArgs(string argsJson)
    {
        using var sub = Json(await ForemanMcpTools.CuSubmit(
            "browser", "type", argsJson, AsHarness("codex")));
        var actionId = sub.RootElement.GetProperty("actionId").GetString()!;
        using var poll = Json(ForemanMcpTools.CuPollActions(10, AsHarness("browser-extension")));
        var token = poll.RootElement.GetProperty("actions")[0].GetProperty("executionToken").GetString()!;
        return (actionId, token);
    }

    [Fact]
    public async Task CuResolveVault_Executor_ResolvesBoundReference()
    {
        var state = StateWith(CuVerdict.Allow("test"));
        state.ResolveVaultAsync = (_, _, _) => Task.FromResult<(bool Ok, string? Value, string Reason, bool Queued)>((true, "s3cret", "ok", false));
        var action = await ExecutingBrowserAction("login {{vault:github.com/password}}");

        using var res = Json(await ForemanMcpTools.CuResolveVault(
            action.ActionId, action.ExecutionToken, "{{vault:github.com/password}}", "github.com",
            AsHarness("browser-extension"), "text"));
        Assert.True(res.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("s3cret", res.RootElement.GetProperty("value").GetString());
    }

    [Fact]   // a signup must be the WHOLE field value; an EMBEDDED signup token is refused (it can never mint a credential)
    public async Task CuResolveVault_EmbeddedSignupToken_Refused()
    {
        var state = StateWith(CuVerdict.Allow("test"));
        state.ResolveVaultAsync = (_, _, _) => Task.FromResult<(bool Ok, string? Value, string Reason, bool Queued)>((true, "should-not-reach", "ok", false));
        var action = await ExecutingBrowserAction("x {{vault:example.com/signup}}");   // token smuggled inside other text

        using var res = Json(await ForemanMcpTools.CuResolveVault(
            action.ActionId, action.ExecutionToken, "{{vault:example.com/signup}}", "example.com",
            AsHarness("browser-extension"), "text"));
        Assert.False(res.RootElement.GetProperty("ok").GetBoolean());
    }

    [Fact]   // a whole-arg signup token IS accepted (reaches the SelfSignup write path)
    public async Task CuResolveVault_WholeArgSignupToken_Accepted()
    {
        var state = StateWith(CuVerdict.Allow("test"));
        state.ResolveVaultAsync = (_, _, _) => Task.FromResult<(bool Ok, string? Value, string Reason, bool Queued)>((true, "generated-pw", "ok", false));
        var action = await ExecutingBrowserAction("{{vault:example.com/signup}}");

        using var res = Json(await ForemanMcpTools.CuResolveVault(
            action.ActionId, action.ExecutionToken, "{{vault:example.com/signup}}", "example.com",
            AsHarness("browser-extension"), "text"));
        Assert.True(res.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("generated-pw", res.RootElement.GetProperty("value").GetString());
    }

    [Fact]
    public async Task CuResolveVault_EmbeddedPaymentCardToken_RefusedBeforeResolver()
    {
        var state = StateWith(CuVerdict.Allow("test"));
        var resolverCalled = false;
        state.ResolveVaultAsync = (_, _, _) =>
        {
            resolverCalled = true;
            return Task.FromResult<(bool Ok, string? Value, string Reason, bool Queued)>((true, "should-not-reach", "ok", false));
        };
        var token = "{{vault:shop.example/personal01/cardnumber}}";
        var action = await ExecutingBrowserAction("prefix " + token);

        using var res = Json(await ForemanMcpTools.CuResolveVault(
            action.ActionId, action.ExecutionToken, token, "shop.example",
            AsHarness("browser-extension"), "text"));

        Assert.False(res.RootElement.GetProperty("ok").GetBoolean());
        Assert.False(resolverCalled);
    }

    [Fact]
    public async Task CuResolveVault_WholeValueDecoyInDifferentArgument_CannotBlessEmbeddedCard()
    {
        var state = StateWith(CuVerdict.Allow("test"));
        var resolverCalled = false;
        state.ResolveVaultAsync = (_, _, _) =>
        {
            resolverCalled = true;
            return Task.FromResult<(bool Ok, string? Value, string Reason, bool Queued)>((true, "should-not-reach", "ok", false));
        };
        const string token = "{{vault:shop.example/personal01/cardnumber}}";
        var action = await ExecutingBrowserActionArgs(
            $"{{\"value\":\"prefix {token}\",\"x\":\"{token}\"}}");

        using var res = Json(await ForemanMcpTools.CuResolveVault(
            action.ActionId, action.ExecutionToken, token, "shop.example",
            AsHarness("browser-extension"), "value"));

        Assert.False(res.RootElement.GetProperty("ok").GetBoolean());
        Assert.False(resolverCalled);
    }

    [Fact]
    public async Task CuResolveVault_SubmittingHarness_Refused()
    {
        var state = StateWith(CuVerdict.Allow("test"));
        state.ResolveVaultAsync = (_, _, _) => Task.FromResult<(bool Ok, string? Value, string Reason, bool Queued)>((true, "x", "ok", false));
        var action = await ExecutingBrowserAction("{{vault:github.com/password}}");

        // A driving/submitting harness (not the browser-extension executor) can never resolve.
        using var res = Json(await ForemanMcpTools.CuResolveVault(
            action.ActionId, action.ExecutionToken, "{{vault:github.com/password}}", "github.com",
            AsHarness("codex"), "text"));
        Assert.False(res.RootElement.GetProperty("ok").GetBoolean());
    }

    [Fact]
    public async Task CuResolveVault_ReferenceNotInApprovedAction_Refused()
    {
        var state = StateWith(CuVerdict.Allow("test"));
        state.ResolveVaultAsync = (_, _, _) => Task.FromResult<(bool Ok, string? Value, string Reason, bool Queued)>((true, "x", "ok", false));
        var action = await ExecutingBrowserAction("{{vault:github.com/password}}");

        // A reference the agent never put in the approved action is refused — no resolving arbitrary credentials.
        using var res = Json(await ForemanMcpTools.CuResolveVault(
            action.ActionId, action.ExecutionToken, "{{vault:bank.com/password}}", "bank.com",
            AsHarness("browser-extension"), "text"));
        Assert.False(res.RootElement.GetProperty("ok").GetBoolean());
    }

    [Fact]
    public async Task CuResolveVault_WhilePanicHalted_Refused()
    {
        var state = StateWith(CuVerdict.Allow("test"));
        state.ResolveVaultAsync = (_, _, _) => Task.FromResult<(bool Ok, string? Value, string Reason, bool Queued)>((true, "s3cret", "ok", false));
        state.Panic = new Foreman.Core.Security.CuPanicState();
        state.Panic.Halt();
        using var res = Json(await ForemanMcpTools.CuResolveVault(
            "any", "invalid-token", "{{vault:github.com/password}}", "github.com",
            AsHarness("browser-extension"), "text"));
        Assert.False(res.RootElement.GetProperty("ok").GetBoolean());   // panic voids any credential release
    }

    [Fact]
    public async Task CuResolveVault_ReferenceCaseInsensitive_Accepted()
    {
        var state = StateWith(CuVerdict.Allow("test"));
        state.ResolveVaultAsync = (_, _, _) => Task.FromResult<(bool Ok, string? Value, string Reason, bool Queued)>((true, "s3cret", "ok", false));
        var action = await ExecutingBrowserAction("login {{vault:github.com/Password}}");   // capital P in the action
        using var res = Json(await ForemanMcpTools.CuResolveVault(
            action.ActionId, action.ExecutionToken, "{{vault:github.com/password}}", "github.com",
            AsHarness("browser-extension"), "text"));
        Assert.True(res.RootElement.GetProperty("ok").GetBoolean());    // whole-token, case-insensitive match
    }

    private static async Task<ForemanEvent?> CaptureSignupAudit(bool queued)
    {
        var state = StateWith(CuVerdict.Allow("test"));
        // The resolver reports whether the signup was DEPOSITED for review (vault locked) or committed to the store.
        state.ResolveVaultAsync = (_, _, _) =>
            Task.FromResult<(bool Ok, string? Value, string Reason, bool Queued)>((true, "generated-pw", "ok", queued));
        var action = await ExecutingBrowserAction("{{vault:example.com/signup}}");

        ForemanEvent? logged = null;
        void Handler(ForemanEvent e) { if (e.Message.Contains("vault credential for 'example.com'")) logged = e; }
        EventBus.Instance.Subscribe(Handler);
        try
        {
            using var res = Json(await ForemanMcpTools.CuResolveVault(
                action.ActionId, action.ExecutionToken, "{{vault:example.com/signup}}", "example.com",
                AsHarness("browser-extension"), "text"));
            Assert.True(res.RootElement.GetProperty("ok").GetBoolean());
        }
        finally { EventBus.Instance.Unsubscribe(Handler); }
        return logged;
    }

    [Fact]   // a LOCKED-vault signup is QUEUED for operator review, not committed — the audit must not claim "CREATED"
    public async Task CuResolveVault_QueuedSignup_AuditSaysQueuedNotCreated()
    {
        var logged = await CaptureSignupAudit(queued: true);

        Assert.NotNull(logged);
        Assert.Contains("QUEUED", logged!.Message);
        Assert.Contains("operator review", logged.Message);
        Assert.DoesNotContain("CREATED", logged.Message);   // nothing is live in the store yet — don't overstate it
    }

    [Fact]   // an UNLOCKED-vault signup IS committed to the store — the audit keeps saying "CREATED"
    public async Task CuResolveVault_CommittedSignup_AuditSaysCreated()
    {
        var logged = await CaptureSignupAudit(queued: false);

        Assert.NotNull(logged);
        Assert.Contains("CREATED", logged!.Message);
        Assert.DoesNotContain("QUEUED", logged.Message);
    }
}
