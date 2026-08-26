using Foreman.Core.ComputerUse;
using Foreman.Core.Settings;

namespace Foreman.Core.Tests.ComputerUse;

public sealed class CuBrokerTrustPolicyTests
{
    private const string Executor = "trust-policy-test-executor";

    private sealed class AllowAuditor : IAuditor
    {
        public Task<CuVerdict> JudgeAsync(CuAction action, CuContext context, CancellationToken ct = default) =>
            Task.FromResult(CuVerdict.Allow("test"));
    }

    private static CuAction Browser(string verb = "read") =>
        new(CuModality.Browser, verb, new Dictionary<string, string>(), ByHarness: "codex");

    private static CuBroker Broker(Func<CuAction, TrustCapabilityDecision> gate)
    {
        var broker = new CuBroker(new AllowAuditor()) { CapabilityGate = gate };
        broker.SetDriver("codex");
        return broker;
    }

    private static IReadOnlyList<CuBrokerItem> Claim(CuBroker broker, CuModality modality = CuModality.Browser) =>
        broker.Claim(1, modality, Executor);

    [Fact]
    public async Task Never_BlocksAtAdmissionBeforeAnAllowingAuditorCanGrant()
    {
        var broker = Broker(_ => TrustCapabilityPolicy.Evaluate(TrustPrivilegeMode.Never, false));

        var item = await broker.SubmitAsync(Browser(), new CuContext("codex"));

        Assert.Equal(CuActionState.Blocked, item.State);
        Assert.Empty(Claim(broker));
    }

    [Fact]
    public async Task AskEveryTime_HoldsThenExplicitOperatorApprovalCanDeliver()
    {
        var broker = Broker(_ => TrustCapabilityPolicy.Evaluate(TrustPrivilegeMode.AskEveryTime, false));

        var item = await broker.SubmitAsync(Browser(), new CuContext("codex"));

        Assert.Equal(CuActionState.Held, item.State);
        Assert.True(broker.ApproveHeld(item.ActionId).Ok);
        Assert.Single(Claim(broker));
    }

    [Fact]
    public async Task SessionLocksAfterAdmission_UnattendedUnlockedActionIsReheldAtDelivery()
    {
        var locked = false;
        var broker = Broker(_ => TrustCapabilityPolicy.Evaluate(
            TrustPrivilegeMode.UnattendedWhileUnlocked, locked));
        var item = await broker.SubmitAsync(Browser(), new CuContext("codex"));
        Assert.Equal(CuActionState.Approved, item.State);

        locked = true;

        Assert.Empty(Claim(broker));
        Assert.Equal(CuActionState.Held, broker.Get(item.ActionId)!.State);
    }

    [Fact]
    public async Task PolicyChangesToNeverAfterOperatorApproval_RevokesBeforeDelivery()
    {
        var mode = TrustPrivilegeMode.AskEveryTime;
        var broker = Broker(_ => TrustCapabilityPolicy.Evaluate(mode, false));
        var item = await broker.SubmitAsync(Browser(), new CuContext("codex"));
        Assert.True(broker.ApproveHeld(item.ActionId).Ok);

        mode = TrustPrivilegeMode.Never;

        Assert.Empty(Claim(broker));
        Assert.Equal(CuActionState.Rejected, broker.Get(item.ActionId)!.State);
    }

    [Fact]
    public async Task UnattendedAdbControl_ReplacesLegacyHardCodedHoldWhenExplicitlyConfigured()
    {
        var broker = Broker(_ => TrustCapabilityPolicy.Evaluate(
            TrustPrivilegeMode.UnattendedIncludingLocked, true));
        broker.SetAndroidDevices(["device-1"]);
        var action = new CuAction(CuModality.Android, "tap", new Dictionary<string, string>
        {
            ["serial"] = "device-1",
            ["x"] = "10",
            ["y"] = "20",
        }, ByHarness: "codex");

        var item = await broker.SubmitAsync(action, new CuContext("codex"));

        Assert.Equal(CuActionState.Approved, item.State);
        Assert.Single(Claim(broker, CuModality.Android));
    }

    [Fact]
    public async Task LegacyAskFlag_CannotBeBypassedByPermissiveUniversalProfile()
    {
        var broker = Broker(_ => TrustCapabilityPolicy.Evaluate(
            TrustPrivilegeMode.UnattendedIncludingLocked, false));
        var action = Browser() with { RequiresOperatorApproval = true };

        var item = await broker.SubmitAsync(action, new CuContext("codex"));

        Assert.Equal(CuActionState.Held, item.State);
    }
}
