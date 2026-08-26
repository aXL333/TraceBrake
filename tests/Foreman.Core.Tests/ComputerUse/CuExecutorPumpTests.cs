using Foreman.Core.ComputerUse;

namespace Foreman.Core.Tests.ComputerUse;

/// <summary>The executor pump: Claim approved desktop actions, run them via an ICuExecutor, Complete with the outcome.</summary>
public sealed class CuExecutorPumpTests
{
    private sealed class Allow : IAuditor
    {
        public Task<CuVerdict> JudgeAsync(CuAction a, CuContext c, CancellationToken ct = default)
            => Task.FromResult(CuVerdict.Allow("test"));
    }

    private sealed class FakeExecutor : ICuExecutor
    {
        public CuModality Modality => CuModality.Desktop;
        public bool IsReady { get; set; } = true;
        public List<string> Ran { get; } = new();
        public Func<CuBrokerItem, CuExecResult>? OnExec { get; set; }
        public Task<CuExecResult> ExecuteAsync(CuBrokerItem item, CancellationToken ct = default)
        {
            Ran.Add(item.ActionId);
            return Task.FromResult(OnExec?.Invoke(item) ?? new CuExecResult(true, null, null));
        }
    }

    private sealed class FakeHud : IHudAck
    {
        public bool Visible { get; set; } = true;
        public int Shown { get; private set; }
        public void EnsureShown() => Shown++;
        public bool ConfirmVisible() => Visible;
    }

    private const string Agent = LocalDriverIpc.LocalAgentHostId;
    private static CuWindowRef Win(long h) => new((IntPtr)h, 4242, "notepad", "Untitled - Notepad", 0);
    private static CuAction Desk(string verb) =>
        new(CuModality.Desktop, verb, new Dictionary<string, string>(), ByHarness: Agent);

    private static async Task<(CuBroker, CuBrokerItem)> ApprovedItem()
    {
        var b = new CuBroker(new Allow()) { DesktopAutoGrant = true };
        b.EnrollDesktopDriver(Agent);
        b.SetActiveWindow(Win(100));
        var item = await b.SubmitAsync(Desk("left_click"), new CuContext(Agent));
        Assert.Equal(CuActionState.Approved, item.State);
        return (b, item);
    }

    [Fact]
    public async Task PumpOnce_RunsApprovedItem_AndCompletes()
    {
        var (b, item) = await ApprovedItem();
        var fake = new FakeExecutor();
        var pump = new CuExecutorPump(b, fake);
        var ran = await pump.PumpOnceAsync();
        Assert.Equal(1, ran);
        Assert.Contains(item.ActionId, fake.Ran);
        Assert.Equal(CuActionState.Completed, b.Get(item.ActionId)!.State);
    }

    [Fact]
    public async Task PumpOnce_ExecutorFails_ItemFailed()
    {
        var (b, item) = await ApprovedItem();
        var fake = new FakeExecutor { OnExec = _ => new CuExecResult(false, null, "injector refused") };
        var ran = await new CuExecutorPump(b, fake).PumpOnceAsync();
        Assert.Equal(1, ran);
        Assert.Equal(CuActionState.Failed, b.Get(item.ActionId)!.State);
        Assert.Equal("injector refused", b.Get(item.ActionId)!.Error);
    }

    [Fact]
    public async Task PumpOnce_ExecutorNotReady_RunsNothing()
    {
        var (b, item) = await ApprovedItem();
        var fake = new FakeExecutor { IsReady = false };
        var ran = await new CuExecutorPump(b, fake).PumpOnceAsync();
        Assert.Equal(0, ran);
        Assert.Empty(fake.Ran);
        Assert.Equal(CuActionState.Approved, b.Get(item.ActionId)!.State);   // still pending, not consumed
    }

    [Fact]
    public async Task PumpOnce_ThrowingExecutor_ItemFailed_NeverThrows()
    {
        var (b, item) = await ApprovedItem();
        var fake = new FakeExecutor { OnExec = _ => throw new InvalidOperationException("boom") };
        var ran = await new CuExecutorPump(b, fake).PumpOnceAsync();
        Assert.Equal(1, ran);
        Assert.Equal(CuActionState.Failed, b.Get(item.ActionId)!.State);
    }

    [Fact]
    public async Task PumpOnce_HudOccluded_WithholdsAndItemWaits()
    {
        var (b, item) = await ApprovedItem();
        var fake = new FakeExecutor();
        var hud = new FakeHud { Visible = false };
        var withheld = 0;
        var ran = await new CuExecutorPump(b, fake, hud: hud, onHudWithheld: () => withheld++).PumpOnceAsync();
        Assert.Equal(0, ran);
        Assert.Empty(fake.Ran);                                            // INV-18: nothing runs behind a hidden HUD
        Assert.Equal(CuActionState.Approved, b.Get(item.ActionId)!.State); // item WAITS (not failed)
        Assert.True(hud.Shown > 0);                                        // the HUD was asked to show
        Assert.Equal(1, withheld);                                         // operator warned (piloting paused)
    }

    [Fact]
    public async Task PumpOnce_HudVisible_Executes()
    {
        var (b, item) = await ApprovedItem();
        var fake = new FakeExecutor();
        var ran = await new CuExecutorPump(b, fake, hud: new FakeHud { Visible = true }).PumpOnceAsync();
        Assert.Equal(1, ran);
        Assert.Equal(CuActionState.Completed, b.Get(item.ActionId)!.State);
    }

    [Fact]
    public async Task PumpOnce_PanicDuringFirstEffect_InvalidatesRestOfClaimedBatch()
    {
        var (b, first) = await ApprovedItem();
        var second = await b.SubmitAsync(Desk("left_click"), new CuContext(Agent));
        Assert.Equal(CuActionState.Approved, second.State);
        var fake = new FakeExecutor { OnExec = _ => { b.OnPanicHalt(); return new CuExecResult(true, null, null); } };

        var ran = await new CuExecutorPump(b, fake, batch: 4).PumpOnceAsync();

        Assert.Equal(1, ran);
        Assert.Single(fake.Ran); // second item was claimed, but its lease was voided before any effect
        Assert.Equal(CuActionState.Rejected, b.Get(first.ActionId)!.State);
        Assert.Equal(CuActionState.Rejected, b.Get(second.ActionId)!.State);
    }
}
