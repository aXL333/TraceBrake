using Foreman.Core.ComputerUse;

namespace Foreman.Core.Tests.ComputerUse;

/// <summary>L5: the broker gates a relayed desktop proposal - verb allowlist (INV-12), modality-scoped driver
/// authorization where "*" never authorizes Desktop (INV-14), and default-Held unless auto-grant is on (INV-15).</summary>
public sealed class CuBrokerDesktopDriverTests
{
    private sealed class Allow : IAuditor
    {
        public Task<CuVerdict> JudgeAsync(CuAction a, CuContext c, CancellationToken ct = default)
            => Task.FromResult(CuVerdict.Allow("test"));
    }

    private const string Agent = LocalDriverIpc.LocalAgentHostId;   // "local-agent-host"
    private static CuBroker Broker() => new(new Allow());
    private static CuWindowRef Win(long hwnd) => new((IntPtr)hwnd, 4242, "notepad", "Untitled - Notepad", 0);
    private static CuAction Desk(string verb, string by)
        => new(CuModality.Desktop, verb, new Dictionary<string, string>(), ByHarness: by);

    [Fact]
    public async Task UnknownVerb_Blocked()
    {
        var b = Broker();
        b.EnrollDesktopDriver(Agent);
        b.SetActiveWindow(Win(100));
        var item = await b.SubmitAsync(Desk("frobnicate", Agent), new CuContext(Agent));
        Assert.Equal(CuActionState.Blocked, item.State);
    }

    [Fact]
    public async Task OverLengthVerb_Blocked()
    {
        var b = Broker();
        b.EnrollDesktopDriver(Agent);
        b.SetActiveWindow(Win(100));
        var item = await b.SubmitAsync(Desk(new string('x', 500), Agent), new CuContext(Agent));
        Assert.Equal(CuActionState.Blocked, item.State);
    }

    [Fact]
    public async Task UnauthorizedDriver_Blocked()
    {
        var b = Broker();   // no driver enrolled
        b.SetActiveWindow(Win(100));
        var item = await b.SubmitAsync(Desk("left_click", "random-harness"), new CuContext("random-harness"));
        Assert.Equal(CuActionState.Blocked, item.State);
        Assert.Contains("not authorized", item.Verdict!.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Wildcard_DoesNotAuthorizeDesktop()
    {
        var b = Broker();
        b.SetDriver("*");   // browser=any...
        b.SetActiveWindow(Win(100));
        var item = await b.SubmitAsync(Desk("left_click", "random-harness"), new CuContext("random-harness"));
        Assert.Equal(CuActionState.Blocked, item.State);   // ...but "*" never authorizes Desktop (INV-14)
    }

    [Fact]
    public async Task EnrolledDriver_DefaultHeld_EvenOnAllow()
    {
        var b = Broker();
        b.EnrollDesktopDriver(Agent);
        b.SetActiveWindow(Win(100));   // bound + on-window, so the window gate would otherwise Approve
        var item = await b.SubmitAsync(Desk("left_click", Agent), new CuContext(Agent));
        Assert.Equal(CuActionState.Held, item.State);   // INV-15: auto-grant OFF -> held for the operator
    }

    [Fact]
    public async Task EnrolledDriver_AutoGrantOn_Approved()
    {
        var b = Broker();
        b.DesktopAutoGrant = true;
        b.EnrollDesktopDriver(Agent);
        b.SetActiveWindow(Win(100));
        var item = await b.SubmitAsync(Desk("left_click", Agent), new CuContext(Agent));
        Assert.Equal(CuActionState.Approved, item.State);   // opted in + on the bound window
    }

    [Fact]
    public async Task AutoGrant_BudgetExhausted_FallsBackToHeld()
    {
        var b = Broker();
        b.DesktopAutoGrant = true;
        b.AutoGrantMaxActions = 1;
        b.EnrollDesktopDriver(Agent);
        b.SetActiveWindow(Win(100));
        var first = await b.SubmitAsync(Desk("left_click", Agent), new CuContext(Agent));
        Assert.Equal(CuActionState.Approved, first.State);   // within the budget
        var second = await b.SubmitAsync(Desk("left_click", Agent), new CuContext(Agent));
        Assert.Equal(CuActionState.Held, second.State);      // INV-15: budget exhausted -> back to Held
    }

    [Fact]
    public async Task AutoGrant_OperatorIdle_FallsBackToHeld()
    {
        var b = Broker();
        b.DesktopAutoGrant = true;
        b.OperatorIdle = () => TimeSpan.FromMinutes(5);      // operator is away from the machine
        b.EnrollDesktopDriver(Agent);
        b.SetActiveWindow(Win(100));
        var item = await b.SubmitAsync(Desk("left_click", Agent), new CuContext(Agent));
        Assert.Equal(CuActionState.Held, item.State);        // INV-15: auto-grant paused while idle
    }

    [Fact]
    public void EnrollDesktopDriver_SurvivesBrowserDriverChange_ButScopesDesktop()
    {
        var b = Broker();
        b.SetDriver("*");
        b.EnrollDesktopDriver(Agent);
        Assert.Contains("*", b.Drivers);                                              // browser driver set unaffected
        Assert.DoesNotContain(Agent, b.Drivers);                                      // enrollment is NOT in the persisted set
        Assert.True(b.CanDrive("any-harness", isOperator: false));                    // browser: "*" still works
        Assert.True(b.CanDriveModality(Agent, false, CuModality.Desktop));            // desktop: enrolled id passes
        Assert.False(b.CanDriveModality("other-harness", false, CuModality.Desktop)); // desktop: "*" does NOT
        b.SetDrivers(new[] { "some-browser-harness" });                              // operator changes the BROWSER driver...
        Assert.True(b.CanDriveModality(Agent, false, CuModality.Desktop));            // ...the desktop enrollment SURVIVES
    }

    [Fact]
    public async Task ClaimModalityFilter_DesktopNeverDeliveredToBrowserClaim()
    {
        var b = Broker();
        b.DesktopAutoGrant = true;
        b.EnrollDesktopDriver(Agent);
        b.SetActiveWindow(Win(100));
        var item = await b.SubmitAsync(Desk("left_click", Agent), new CuContext(Agent));
        Assert.Equal(CuActionState.Approved, item.State);
        Assert.Empty(b.Claim(10, CuModality.Browser, "browser-test-executor"));    // the MCP poll path never sees Desktop
        Assert.Single(b.Claim(10, CuModality.Desktop, "desktop-test-executor"));   // an in-process executor can claim it
    }

    private sealed class GatedAllow : IAuditor
    {
        public readonly SemaphoreSlim Entered = new(0);
        public readonly SemaphoreSlim Release = new(0);
        public async Task<CuVerdict> JudgeAsync(CuAction a, CuContext c, CancellationToken ct = default)
        {
            Entered.Release();
            await Release.WaitAsync(ct);
            return CuVerdict.Allow("test");
        }
    }

    [Fact]
    public async Task PanicDuringAudit_DoesNotResurrectItem()
    {
        var g = new GatedAllow();
        var b = new CuBroker(g) { DesktopAutoGrant = true };   // would be Approved but for the panic
        b.EnrollDesktopDriver(Agent);
        b.SetActiveWindow(Win(100));
        var submit = b.SubmitAsync(Desk("left_click", Agent), new CuContext(Agent));
        await g.Entered.WaitAsync();   // the audit is in-flight (placeholder is in the broker)
        b.OnPanicHalt();               // panic fires MID-AUDIT: bumps the epoch + rejects the placeholder
        g.Release.Release();           // let the audit complete and try to write its verdict back
        var item = await submit;
        Assert.NotEqual(CuActionState.Approved, item.State);   // must NOT be resurrected to Approved
        Assert.Empty(b.Claim(10, CuModality.Desktop, "desktop-test-executor")); // and nothing is claimable
    }
}
