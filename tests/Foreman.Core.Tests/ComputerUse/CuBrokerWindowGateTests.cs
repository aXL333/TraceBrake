using Foreman.Core.ComputerUse;

namespace Foreman.Core.Tests.ComputerUse;

/// <summary>Slice 1: the desktop one-window-at-a-time gate (HWND-scoped excursion lock, parallel to the browser pin).</summary>
public sealed class CuBrokerWindowGateTests
{
    private const string DesktopExecutor = "desktop-window-test-executor";

    private sealed class Allow : IAuditor
    {
        public Task<CuVerdict> JudgeAsync(CuAction a, CuContext c, CancellationToken ct = default)
            => Task.FromResult(CuVerdict.Allow("test"));
    }

    private static CuBroker Broker() => new(new Allow());
    private static CuAction Desk(string verb, Dictionary<string, string>? args = null)
        => new(CuModality.Desktop, verb, args ?? new(), ByHarness: "operator");
    private static CuWindowRef Win(long hwnd, int pid = 4242)
        => new((IntPtr)hwnd, pid, "notepad", "Untitled - Notepad", 0);
    private static IReadOnlyList<CuBrokerItem> Claim(CuBroker broker, int limit = 10) =>
        broker.Claim(limit, CuModality.Desktop, DesktopExecutor);

    [Fact]
    public async Task NoBoundWindow_DesktopStateChange_Held()
    {
        var b = Broker();
        var item = await b.SubmitAsync(Desk("left_click"), new CuContext());
        Assert.Equal(CuActionState.Held, item.State);   // no window bound -> held until the operator binds one
    }

    [Fact]
    public async Task OnBoundWindow_Approved()
    {
        var b = Broker();
        b.SetActiveWindow(Win(100));
        var item = await b.SubmitAsync(Desk("left_click"), new CuContext());   // no explicit hwnd -> runs in the bound window
        Assert.Equal(CuActionState.Approved, item.State);
    }

    [Fact]
    public async Task OffWindow_StateChange_Held()
    {
        var b = Broker();
        b.SetActiveWindow(Win(100));
        var item = await b.SubmitAsync(Desk("left_click", new() { ["hwnd"] = "200" }), new CuContext());
        Assert.Equal(CuActionState.Held, item.State);
    }

    [Fact]
    public async Task OffWindow_CursorMove_AlsoHeld()
    {
        var b = Broker();
        b.SetActiveWindow(Win(100));
        var item = await b.SubmitAsync(Desk("move", new() { ["hwnd"] = "200" }), new CuContext());
        Assert.Equal(CuActionState.Held, item.State);   // a bare move/scroll to another window is an excursion, not free
    }

    [Fact]
    public async Task ModalityScoping_BrowserActionIgnoresWindowBind()
    {
        var b = Broker();
        b.SetActiveWindow(Win(100));                     // a desktop window is bound...
        var item = await b.SubmitAsync(
            new CuAction(CuModality.Browser, "goto", new Dictionary<string, string> { ["url"] = "https://x" }, ByHarness: "operator"), new CuContext());
        Assert.Equal(CuActionState.Approved, item.State);   // ...the browser gate (no pin set) is unaffected
    }

    [Fact]
    public async Task Claim_StampsBoundHwndAndEpoch()
    {
        var b = Broker();
        b.SetActiveWindow(Win(100));
        var item = await b.SubmitAsync(Desk("left_click"), new CuContext());
        var claimed = Claim(b);
        Assert.Single(claimed);
        Assert.Equal("100", claimed[0].Action.Arg("hwnd"));            // executor can't pick another window
        Assert.False(string.IsNullOrEmpty(claimed[0].Action.Arg("epoch")));
    }

    [Fact]
    public async Task Claim_WindowSwitchedAfterApprove_ReHeld()
    {
        var b = Broker();
        b.SetActiveWindow(Win(100));
        var item = await b.SubmitAsync(Desk("left_click"), new CuContext());
        Assert.Equal(CuActionState.Approved, item.State);
        b.SetActiveWindow(Win(300));                     // operator switches the bound window (Epoch bumps)
        Assert.Empty(Claim(b));                        // the approved action is re-held, never auto-retargeted
        Assert.Equal(CuActionState.Held, b.Get(item.ActionId)!.State);
    }

    [Fact]
    public void SetActiveWindow_RejectsOwnProcessWindow()
    {
        var b = Broker();
        var r = b.SetActiveWindow(new CuWindowRef((IntPtr)999, Environment.ProcessId, "Foreman", "Foreman", 0));
        Assert.False(r.Ok);
        Assert.Null(b.ActiveWindow);
    }

    [Fact]
    public void SetActiveWindow_FiresOnWindowSwitch()
    {
        var b = Broker();
        CuWindowRef? seen = null; var fired = false;
        b.OnWindowSwitch = (_, n) => { fired = true; seen = n; };
        b.SetActiveWindow(Win(100));
        Assert.True(fired);
        Assert.Equal((IntPtr)100, seen!.Hwnd);
    }

    [Fact]
    public async Task OnPanicHalt_RejectsDesktopQueue_AndClaimDeliversNothing()
    {
        var b = Broker();
        b.SetActiveWindow(Win(100));
        var item = await b.SubmitAsync(Desk("left_click"), new CuContext());
        Assert.Equal(CuActionState.Approved, item.State);
        b.OnPanicHalt();
        Assert.Equal(CuActionState.Rejected, b.Get(item.ActionId)!.State);   // queue invalidated on panic
        Assert.Empty(Claim(b));
    }

    [Fact]
    public async Task Complete_DoesNotOverwritePanicRejected()
    {
        var b = Broker();
        b.SetActiveWindow(Win(100));
        var item = await b.SubmitAsync(Desk("left_click"), new CuContext());
        var executing = Assert.Single(Claim(b));
        b.OnPanicHalt();                                                       // panic rejects the in-flight item
        Assert.Equal(CuActionState.Rejected, b.Get(item.ActionId)!.State);
        var (ok, _) = b.Complete(item.ActionId, ok: false, result: null, error: "killed pipe",
            CuModality.Desktop, DesktopExecutor, executing.ExecutionToken!);
        Assert.False(ok);                                                      // the pump's post-kill Complete is refused
        Assert.Equal(CuActionState.Rejected, b.Get(item.ActionId)!.State);    // audit record stays truthful
    }

    private sealed class DeadProbe : IDesktopWindowProbe
    {
        public CuWindowRef? CaptureForeground() => null;
        public bool IsAlive(CuWindowRef w) => false;          // the bound window is gone / its handle was recycled
        public IntPtr RootOwner(IntPtr hwnd) => hwnd;
    }

    [Fact]
    public async Task Claim_BoundWindowNotAlive_ReHeld()
    {
        var b = Broker();
        b.WindowProbe = new DeadProbe();
        b.SetActiveWindow(Win(100));
        var item = await b.SubmitAsync(Desk("left_click"), new CuContext());
        Assert.Equal(CuActionState.Approved, item.State);
        Assert.Empty(Claim(b));                              // probe reports the window gone -> never delivered (INV-2)
        Assert.Equal(CuActionState.Held, b.Get(item.ActionId)!.State);
    }

    [Fact]
    public void SetActiveWindow_RequiresValidBindToken_ConsumeOnce()
    {
        var b = Broker();
        var used = false;
        b.BindTokenValidator = t => { if (t == "good" && !used) { used = true; return true; } return false; };  // INV-17 + consume-once

        Assert.False(b.SetActiveWindow(Win(100), "bad").Ok);    // wrong token -> refused
        Assert.Null(b.ActiveWindow);
        Assert.False(b.SetActiveWindow(Win(100), null).Ok);     // missing token -> refused
        Assert.Null(b.ActiveWindow);

        Assert.True(b.SetActiveWindow(Win(100), "good").Ok);    // the minted token binds
        Assert.NotNull(b.ActiveWindow);
        Assert.False(b.SetActiveWindow(Win(200), "good").Ok);   // ...but only once (replay refused)
    }
}
