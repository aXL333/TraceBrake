using Foreman.Core.ComputerUse;

namespace Foreman.Core.Tests.ComputerUse;

public sealed class CuBrokerTests
{
    private const string BrowserExecutor = "test-browser-executor";

    private sealed class FixedAuditor(CuVerdict verdict) : IAuditor
    {
        public Task<CuVerdict> JudgeAsync(CuAction a, CuContext c, CancellationToken ct = default) => Task.FromResult(verdict);
    }

    private sealed class ThrowingAuditor : IAuditor
    {
        public Task<CuVerdict> JudgeAsync(CuAction a, CuContext c, CancellationToken ct = default)
            => throw new InvalidOperationException("boom");
    }

    private static CuAction Act(string verb = "click", string? byHarness = "operator") =>
        new(CuModality.Browser, verb, new Dictionary<string, string>(), ByHarness: byHarness);

    private static CuAction ActWith(string verb, Dictionary<string, string> args) =>
        new(CuModality.Browser, verb, args, ByHarness: "operator");

    private static IReadOnlyList<CuBrokerItem> Claim(CuBroker broker, int limit = 10) =>
        broker.Claim(limit, CuModality.Browser, BrowserExecutor);

    [Fact]
    public async Task Submit_Allow_BecomesApproved()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("test")));
        var item = await b.SubmitAsync(Act(), new CuContext());
        Assert.Equal(CuActionState.Approved, item.State);
    }

    [Fact]
    public async Task Submit_Hold_BecomesHeld_ThenApprove_ThenClaimExecutes()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Hold("test", "why")));
        var item = await b.SubmitAsync(Act(), new CuContext());
        Assert.Equal(CuActionState.Held, item.State);
        Assert.Single(b.ListHeld());

        Assert.True(b.ApproveHeld(item.ActionId).Ok);
        Assert.Equal(CuActionState.Approved, b.Get(item.ActionId)!.State);

        var claimed = Claim(b);
        Assert.Single(claimed);
        Assert.Equal(CuActionState.Executing, claimed[0].State);
    }

    [Fact]
    public async Task Submit_Hold_Reject_NeverClaimable()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Hold("test", "why")));
        var item = await b.SubmitAsync(Act(), new CuContext());
        Assert.True(b.RejectHeld(item.ActionId).Ok);
        Assert.Equal(CuActionState.Rejected, b.Get(item.ActionId)!.State);
        Assert.Empty(Claim(b));
    }

    [Fact]
    public async Task Submit_Block_BecomesBlocked_NeverClaimable()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Block("test", "bad")));
        var item = await b.SubmitAsync(Act(), new CuContext());
        Assert.Equal(CuActionState.Blocked, item.State);
        Assert.Empty(Claim(b));
    }

    [Theory]
    [InlineData("frobnicate")]
    [InlineData("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")]
    public async Task BrowserUnknownOrOverlengthVerb_IsStructurallyBlocked(string verb)
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("test")));
        var item = await b.SubmitAsync(Act(verb), new CuContext());
        Assert.Equal(CuActionState.Blocked, item.State);
        Assert.Contains("unsupported browser verb", item.Verdict!.Reason);
    }

    [Fact]
    public async Task ApproveHeld_OnNonHeld_Fails()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("test")));
        var item = await b.SubmitAsync(Act(), new CuContext());   // Approved, not Held
        Assert.False(b.ApproveHeld(item.ActionId).Ok);
    }

    [Fact]
    public async Task Claim_Then_Complete_Lifecycle()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("test")));
        var item = await b.SubmitAsync(Act(), new CuContext());
        var executing = Assert.Single(Claim(b));
        Assert.True(b.Complete(item.ActionId, ok: true, result: "done", error: null,
            CuModality.Browser, BrowserExecutor, executing.ExecutionToken!).Ok);
        Assert.Equal(CuActionState.Completed, b.Get(item.ActionId)!.State);
    }

    [Fact]
    public async Task Claim_SkipsHeld()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Hold("t", "h")));
        await b.SubmitAsync(Act(), new CuContext());
        Assert.Empty(Claim(b));   // Held is not claimable
    }

    [Fact]
    public async Task AuditorThrows_FailsClosedToHeld()
    {
        var b = new CuBroker(new ThrowingAuditor());
        var item = await b.SubmitAsync(Act(), new CuContext());
        Assert.Equal(CuActionState.Held, item.State);
    }

    [Fact]
    public async Task Halted_Submit_Blocked_And_Claim_Empty()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("test")), isHalted: () => true);
        var item = await b.SubmitAsync(Act(), new CuContext());
        Assert.Equal(CuActionState.Blocked, item.State);
        Assert.Empty(Claim(b));
    }

    [Fact]
    public async Task Driver_NonDriverHarness_RejectedAtClaim()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("test")));   // no driver set => operator only
        var item = await b.SubmitAsync(Act(byHarness: "y"), new CuContext());
        Assert.Equal(CuActionState.Approved, item.State);   // audit clears it...
        Assert.Empty(Claim(b));                          // ...but the driver re-check rejects it
        Assert.Equal(CuActionState.Rejected, b.Get(item.ActionId)!.State);
    }

    [Fact]
    public async Task Driver_AuthorizedHarness_Claims()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("test")));
        b.SetDriver("y");
        var item = await b.SubmitAsync(Act(byHarness: "y"), new CuContext());
        var claimed = Claim(b);
        Assert.Single(claimed);
        Assert.Equal(CuActionState.Executing, claimed[0].State);
    }

    [Fact]
    public void SetDrivers_AuthorizesEachInTheSet_NotOthers()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("t")));
        b.SetDrivers(["claude-code", "codex"]);
        Assert.Equal("claude-code,codex", b.Driver);
        Assert.True(b.CanDrive("claude-code", false));
        Assert.True(b.CanDrive("codex", false));
        Assert.False(b.CanDrive("gemini-cli", false));
        Assert.False(b.CanDrive(null, false));
    }

    [Fact]
    public void SetDriver_CommaList_RoundTripsThroughDriver()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("t")));
        b.SetDrivers(["claude-code", "codex"]);
        var persisted = b.Driver;                       // "claude-code,codex" (what gets saved to settings)
        var restored = new CuBroker(new FixedAuditor(CuVerdict.Allow("t")));
        restored.SetDriver(persisted);                  // restore via the single-string startup-seed path
        Assert.True(restored.CanDrive("claude-code", false));
        Assert.True(restored.CanDrive("codex", false));
        Assert.False(restored.CanDrive("cursor", false));
    }

    [Fact]
    public void SetDrivers_AnyCollapsesToWildcard()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("t")));
        b.SetDrivers(["claude-code", "any"]);
        Assert.Equal("*", b.Driver);
        Assert.True(b.CanDrive("anything-at-all", false));
    }

    [Fact]
    public void SetDrivers_Empty_IsOperatorOnly()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("t")));
        b.SetDrivers(["claude-code"]);
        b.SetDrivers(null);
        Assert.Null(b.Driver);
        Assert.False(b.CanDrive("claude-code", false));
        Assert.True(b.CanDrive("claude-code", true));   // operator is always allowed
    }

    [Fact]
    public void DriverPersister_ReceivesNormalizedJoinedString()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("t")));
        string? seen = "unset";
        b.DriverPersister = d => seen = d;
        b.SetDrivers(["Claude-Code", "CODEX"]);          // case-insensitive normalization
        Assert.Equal("claude-code,codex", seen);
    }

    [Fact]
    public void DriverPersisterFailure_DoesNotGrantOrRevokeLiveAuthority()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("t")));
        b.SetDriver("codex");
        b.DriverPersister = _ => throw new IOException("guardian unavailable");

        var change = b.SetDriver("claude-code");

        Assert.False(change.Ok);
        Assert.True(b.CanDrive("codex", false));
        Assert.False(b.CanDrive("claude-code", false));
    }

    [Fact]
    public void SetDrivers_PreservesPinnedAttentionTab()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("t")));
        b.SetDriver("claude-code");
        b.SetAttention("572647869");

        b.SetDrivers(["claude-code", "codex"]);

        Assert.Equal("572647869", b.AttentionTab);
        Assert.True(b.CanDrive("codex", false));
    }

    [Fact]
    public void Drivers_ReturnsSnapshotThatCannotMutateLiveAuthority()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("t")));
        b.SetDrivers(["codex"]);

        var exposed = Assert.IsType<string[]>(b.Drivers);
        exposed[0] = "attacker";

        Assert.True(b.CanDrive("codex", false));
        Assert.False(b.CanDrive("attacker", false));
    }

    [Fact]
    public async Task SetDrivers_RevokesRemovedDriversExecutingLease_ButKeepsRetainedDriverWork()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("t")));
        b.SetDrivers(["codex", "claude-code"]);
        var codex = await b.SubmitAsync(Act(byHarness: "codex"), new CuContext("codex"));
        var claimed = Assert.Single(b.Claim(1, CuModality.Browser, BrowserExecutor));
        Assert.Equal(codex.ActionId, claimed.ActionId);
        // Submit the retained driver's action only after the old driver's lease is active. This makes the
        // regression deterministic even on clocks whose DateTimeOffset resolution gives adjacent submissions
        // the same CreatedAt value.
        var claude = await b.SubmitAsync(Act(byHarness: "claude-code"), new CuContext("claude-code"));

        b.SetDrivers(["claude-code"]);

        Assert.Equal(CuActionState.Rejected, b.Get(codex.ActionId)!.State);
        Assert.False(b.ValidateExecution(codex.ActionId, CuModality.Browser,
            BrowserExecutor, claimed.ExecutionToken!).Ok);
        Assert.Equal(CuActionState.Approved, b.Get(claude.ActionId)!.State);
        Assert.Equal(claude.ActionId, Assert.Single(Claim(b)).ActionId);
    }

    // ── Pinned shared-attention excursion gate ───────────────────────────────────

    [Fact]
    public async Task Pin_OffTabStateChange_HeldEvenWhenAuditAllows()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("ok")));
        b.SetAttention("100");
        var item = await b.SubmitAsync(ActWith("goto", new() { ["tabId"] = "200", ["url"] = "https://x" }), new CuContext());
        Assert.Equal(CuActionState.Held, item.State);   // off-focus change is held for the operator
    }

    [Fact]
    public async Task Pin_OffTabRead_Approved()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("ok")));
        b.SetAttention("100");
        var item = await b.SubmitAsync(ActWith("read", new() { ["tabId"] = "200" }), new CuContext());
        Assert.Equal(CuActionState.Approved, item.State);   // read-only peek proceeds
    }

    [Fact]
    public async Task Pin_OnPinTab_Approved()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("ok")));
        b.SetAttention("100");
        var item = await b.SubmitAsync(ActWith("goto", new() { ["tabId"] = "100", ["url"] = "https://x" }), new CuContext());
        Assert.Equal(CuActionState.Approved, item.State);
    }

    [Fact]
    public async Task Pin_NoTabId_Approved_RunsInPinnedTab()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("ok")));
        b.SetAttention("100");
        var item = await b.SubmitAsync(ActWith("goto", new() { ["url"] = "https://x" }), new CuContext());
        Assert.Equal(CuActionState.Approved, item.State);   // no explicit tab -> executor runs it in the pin
    }

    [Fact]
    public async Task Pin_Navigate_HeldAsNewTabExcursion()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("ok")));
        b.SetAttention("100");
        var item = await b.SubmitAsync(ActWith("navigate", new() { ["url"] = "https://x" }), new CuContext());
        Assert.Equal(CuActionState.Held, item.State);   // navigate opens a NEW tab = leaving the focus
    }

    [Fact]
    public async Task NoPin_OffTabAction_Approved()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("ok")));
        var item = await b.SubmitAsync(ActWith("goto", new() { ["tabId"] = "200", ["url"] = "https://x" }), new CuContext());
        Assert.Equal(CuActionState.Approved, item.State);   // no pin -> no excursion concept
    }

    [Fact]
    public async Task Claim_ReGatesWhenPinMovesAfterApprove()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("ok")));
        b.SetAttention("100");
        var item = await b.SubmitAsync(ActWith("goto", new() { ["tabId"] = "100", ["url"] = "https://x" }), new CuContext());
        Assert.Equal(CuActionState.Approved, item.State);   // on-pin at submit
        b.SetAttention("200");                               // operator moves the pin (TOCTOU)
        Assert.Empty(Claim(b));                           // delivery re-gate holds it...
        Assert.Equal(CuActionState.Held, b.Get(item.ActionId)!.State);   // ...instead of running off-focus
    }

    [Fact]
    public async Task Claim_SubmitBeforePin_ReGatedAtDelivery()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("ok")));
        var item = await b.SubmitAsync(ActWith("goto", new() { ["tabId"] = "500", ["url"] = "https://evil" }), new CuContext());
        Assert.Equal(CuActionState.Approved, item.State);   // no pin yet -> approved
        b.SetAttention("742");                               // operator pins a different tab afterwards
        Assert.Empty(Claim(b));
        Assert.Equal(CuActionState.Held, b.Get(item.ActionId)!.State);   // off-focus change caught at delivery
    }

    [Fact]
    public async Task Claim_DoesNotReHoldOperatorApprovedExcursion()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("ok")));
        b.SetAttention("100");
        var item = await b.SubmitAsync(ActWith("goto", new() { ["tabId"] = "200", ["url"] = "https://x" }), new CuContext());
        Assert.Equal(CuActionState.Held, item.State);        // off-pin -> held at submit
        Assert.True(b.ApproveHeld(item.ActionId).Ok);        // operator approves the excursion
        var claimed = Claim(b);
        Assert.Single(claimed);                              // delivered, NOT re-held into a loop
        Assert.Equal(CuActionState.Executing, claimed[0].State);
    }

    [Fact]
    public async Task Claim_StampsPinnedTabForNoTabIdStateChange()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("ok")));
        b.SetAttention("100");
        var item = await b.SubmitAsync(ActWith("goto", new() { ["url"] = "https://x" }), new CuContext());
        Assert.Equal(CuActionState.Approved, item.State);
        var claimed = Claim(b);
        Assert.Single(claimed);
        Assert.Equal("100", claimed[0].Action.Arg("tabId"));   // pin stamped so the executor can't divert to active
    }

    [Fact]
    public async Task Pin_TabId_CanonicalMatch_OnPin_NonInteger_Held()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("ok")));
        b.SetAttention("100");
        var onPin = await b.SubmitAsync(ActWith("goto", new() { ["tabId"] = "0100", ["url"] = "https://x" }), new CuContext());
        Assert.Equal(CuActionState.Approved, onPin.State);     // "0100" == 100 canonically -> on-pin
        var garbage = await b.SubmitAsync(ActWith("goto", new() { ["tabId"] = "0x64", ["url"] = "https://x" }), new CuContext());
        Assert.Equal(CuActionState.Held, garbage.State);       // non-integer tabId -> off-focus (conservative)
    }

    [Fact]
    public async Task TabOverride_On_OffPinWithJustification_Proceeds()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("ok"))) { AllowTabOverride = true };
        b.SetAttention("100");
        var item = await b.SubmitAsync(ActWith("goto", new() { ["tabId"] = "200", ["url"] = "https://x", ["justification"] = "checking docs, will return" }), new CuContext());
        Assert.Equal(CuActionState.Approved, item.State);
        Assert.Single(Claim(b));   // delivery re-gate honors the justified override too
    }

    [Fact]
    public async Task TabOverride_On_OffPinNoJustification_StillHeld()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("ok"))) { AllowTabOverride = true };
        b.SetAttention("100");
        var item = await b.SubmitAsync(ActWith("goto", new() { ["tabId"] = "200", ["url"] = "https://x" }), new CuContext());
        Assert.Equal(CuActionState.Held, item.State);   // justification is mandatory even with override on
    }

    [Fact]
    public async Task TabOverride_Off_OffPinWithJustification_StillHeld()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("ok")));   // override off (default)
        b.SetAttention("100");
        var item = await b.SubmitAsync(ActWith("goto", new() { ["tabId"] = "200", ["url"] = "https://x", ["justification"] = "whatever" }), new CuContext());
        Assert.Equal(CuActionState.Held, item.State);   // override off -> always held, justification or not
    }

    [Fact]
    public async Task Complete_RequiresExecutingStateExactModalityOwnerAndLease()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Hold("test", "review")));
        var item = await b.SubmitAsync(Act(), new CuContext());
        var fakeLease = new string('0', 64);

        Assert.False(b.Complete(item.ActionId, true, null, null,
            CuModality.Browser, BrowserExecutor, fakeLease).Ok); // Held cannot self-complete
        Assert.True(b.ApproveHeld(item.ActionId).Ok);
        Assert.False(b.Complete(item.ActionId, true, null, null,
            CuModality.Browser, BrowserExecutor, fakeLease).Ok); // Approved must be claimed first

        var executing = Assert.Single(Claim(b));
        Assert.False(b.Complete(item.ActionId, true, null, null,
            CuModality.Android, BrowserExecutor, executing.ExecutionToken!).Ok);
        Assert.False(b.Complete(item.ActionId, true, null, null,
            CuModality.Browser, "sibling-executor", executing.ExecutionToken!).Ok);
        Assert.False(b.Complete(item.ActionId, true, null, null,
            CuModality.Browser, BrowserExecutor, fakeLease).Ok);
        Assert.Equal(CuActionState.Executing, b.Get(item.ActionId)!.State);

        Assert.True(b.Complete(item.ActionId, true, "done", null,
            CuModality.Browser, BrowserExecutor, executing.ExecutionToken!).Ok);
        Assert.False(b.Complete(item.ActionId, true, null, null,
            CuModality.Browser, BrowserExecutor, executing.ExecutionToken!).Ok);
    }

    [Fact]
    public async Task PanicRejectsClaimedBrowserActionAndVoidsItsLease()
    {
        var halted = false;
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("test")), () => halted);
        var item = await b.SubmitAsync(Act(), new CuContext());
        var executing = Assert.Single(Claim(b));

        halted = true;
        b.OnPanicHalt();

        Assert.Equal(CuActionState.Rejected, b.Get(item.ActionId)!.State);
        Assert.False(b.ValidateExecution(item.ActionId, CuModality.Browser,
            BrowserExecutor, executing.ExecutionToken!).Ok);
        Assert.False(b.Complete(item.ActionId, true, null, null,
            CuModality.Browser, BrowserExecutor, executing.ExecutionToken!).Ok);
    }

    [Fact]
    public async Task PendingQueueHasPerHarnessAndGlobalHardCaps()
    {
        var options = new CuBrokerOptions
        {
            MaxItems = 8,
            MaxNonTerminalItems = 3,
            MaxNonTerminalPerHarness = 2,
        };
        var b = new CuBroker(new FixedAuditor(CuVerdict.Hold("test", "review")), options: options);

        Assert.Equal(CuActionState.Held, (await b.SubmitAsync(Act(byHarness: "codex"), new CuContext("codex"))).State);
        Assert.Equal(CuActionState.Held, (await b.SubmitAsync(Act(byHarness: "codex"), new CuContext("codex"))).State);
        var perHarnessOverflow = await b.SubmitAsync(Act(byHarness: "codex"), new CuContext("codex"));
        Assert.Equal(CuActionState.Blocked, perHarnessOverflow.State);
        Assert.Contains("this harness", perHarnessOverflow.Error!, StringComparison.OrdinalIgnoreCase);

        Assert.Equal(CuActionState.Held, (await b.SubmitAsync(Act(byHarness: "claude-code"), new CuContext("claude-code"))).State);
        var globalOverflow = await b.SubmitAsync(Act(byHarness: "gemini-cli"), new CuContext("gemini-cli"));
        Assert.Equal(CuActionState.Blocked, globalOverflow.State);
        Assert.Contains("queue is full", globalOverflow.Error!, StringComparison.OrdinalIgnoreCase);
        Assert.True(b.ItemCount <= options.MaxItems);
    }

    [Fact]
    public async Task StaleHeldApprovedAndExecutingActionsExpireFailClosed()
    {
        var now = new DateTimeOffset(2026, 8, 21, 0, 0, 0, TimeSpan.Zero);
        var options = new CuBrokerOptions
        {
            AuditingTtl = TimeSpan.FromMinutes(1),
            HeldTtl = TimeSpan.FromMinutes(1),
            ApprovedTtl = TimeSpan.FromMinutes(1),
            ExecutingTtl = TimeSpan.FromMinutes(1),
        };

        var heldBroker = new CuBroker(new FixedAuditor(CuVerdict.Hold("test", "review")),
            options: options, utcNow: () => now);
        var held = await heldBroker.SubmitAsync(Act(), new CuContext());
        now += TimeSpan.FromMinutes(2);
        Assert.False(heldBroker.ApproveHeld(held.ActionId).Ok);
        Assert.Equal(CuActionState.Rejected, heldBroker.Get(held.ActionId)!.State);

        var approvedBroker = new CuBroker(new FixedAuditor(CuVerdict.Allow("test")),
            options: options, utcNow: () => now);
        var approved = await approvedBroker.SubmitAsync(Act(), new CuContext());
        now += TimeSpan.FromMinutes(2);
        Assert.Empty(Claim(approvedBroker));
        Assert.Equal(CuActionState.Rejected, approvedBroker.Get(approved.ActionId)!.State);

        var executingBroker = new CuBroker(new FixedAuditor(CuVerdict.Allow("test")),
            options: options, utcNow: () => now);
        var executingAction = await executingBroker.SubmitAsync(Act(), new CuContext());
        var executing = Assert.Single(Claim(executingBroker));
        now += TimeSpan.FromMinutes(2);
        Assert.False(executingBroker.ValidateExecution(executingAction.ActionId, CuModality.Browser,
            BrowserExecutor, executing.ExecutionToken!).Ok);
        Assert.Equal(CuActionState.Rejected, executingBroker.Get(executingAction.ActionId)!.State);
    }

    [Fact]
    public async Task AdmissionSnapshotsMutableArgumentsBeforeAuditAndExecution()
    {
        var args = new Dictionary<string, string> { ["selector"] = "#approved" };
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("test")));
        var item = await b.SubmitAsync(new CuAction(CuModality.Browser, "click", args, ByHarness: "operator"),
            new CuContext());

        args["selector"] = "#attacker-swapped";

        var executing = Assert.Single(Claim(b));
        Assert.Equal("#approved", executing.Action.Arg("selector"));
        Assert.Equal("#approved", b.Get(item.ActionId)!.Action.Arg("selector"));
    }

    [Fact]
    public async Task DuplicateCallerActionIdCannotOverwriteExistingAction()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("test")));
        var first = await b.SubmitAsync(Act() with { ActionId = "same-action" }, new CuContext());
        var duplicate = await b.SubmitAsync(Act("type") with { ActionId = "same-action" }, new CuContext());

        Assert.Equal(CuActionState.Approved, first.State);
        Assert.Equal(CuActionState.Blocked, duplicate.State);
        Assert.NotEqual(first.ActionId, duplicate.ActionId);
        Assert.Equal("click", b.Get(first.ActionId)!.Action.Verb);
    }

    [Fact]
    public async Task TerminalSubmissionFloodStaysWithinHardRecordCap()
    {
        var options = new CuBrokerOptions
        {
            MaxItems = 5,
            MaxNonTerminalItems = 3,
            MaxNonTerminalPerHarness = 3,
        };
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("test")), options: options);

        for (var i = 0; i < 30; i++)
            Assert.Equal(CuActionState.Blocked,
                (await b.SubmitAsync(Act("unknown-" + i), new CuContext())).State);

        Assert.True(b.ItemCount <= options.MaxItems);
    }
}
