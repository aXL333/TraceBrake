using Foreman.Core.Settings;

namespace Foreman.Core.Tests.Settings;

public sealed class SettingsChangeProvenanceTests
{
    [Fact]
    public async Task Context_FlowsAcrossAwait_AndNestedScopeRestoresPrior()
    {
        var outer = SettingsChangeAttribution.Declared(
            SettingsChangeOrigin.AuthenticatedMcp, "codex", "outer");
        var inner = SettingsChangeAttribution.Declared(
            SettingsChangeOrigin.InternalRuntime, "foreman", "inner");

        using (SettingsChangeContext.Begin(outer))
        {
            await Task.Yield();
            Assert.Same(outer, SettingsChangeContext.Current);
            using (SettingsChangeContext.Begin(inner))
                Assert.Same(inner, SettingsChangeContext.Current);
            Assert.Same(outer, SettingsChangeContext.Current);
        }

        Assert.Null(SettingsChangeContext.Current);
    }

    [Fact]
    public void PhysicalInput_IsRecognisedOnlyWhileFresh()
    {
        Assert.Equal(SettingsInputProvenance.Physical,
            SettingsInputProvenancePolicy.Assess(100, 95, 0, false, 10));
        Assert.Equal(SettingsInputProvenance.Unattributed,
            SettingsInputProvenancePolicy.Assess(100, 80, 0, false, 10));
    }

    [Fact]
    public void LaterInjectedInput_WinsOverPhysicalInput()
    {
        Assert.Equal(SettingsInputProvenance.Injected,
            SettingsInputProvenancePolicy.Assess(100, 95, 99, false, 10));
    }

    [Fact]
    public void ForemanStampedInjectedInput_IsDistinguished()
    {
        Assert.Equal(SettingsInputProvenance.ForemanComputerUse,
            SettingsInputProvenancePolicy.Assess(100, 0, 99, true, 10));
    }

    [Fact]
    public void NoInput_CoversUiAutomationBypass_AsUnattributed()
    {
        Assert.Equal(SettingsInputProvenance.Unattributed,
            SettingsInputProvenancePolicy.Assess(100, 0, 0, false, 10));
    }
}
