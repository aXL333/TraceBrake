using Foreman.Core.Mcp;
using Foreman.Core.Settings;

namespace Foreman.Core.Tests.Mcp;

public sealed class HarnessCapabilityPolicyTests
{
    [Fact]
    public void Effective_UnsetHarness_AllowsBothHighRiskCapabilities()
    {
        var effective = new ForemanSettings().EffectiveCapabilityRestrictions("codex");

        Assert.Equal(HarnessCapabilityAccess.AskFirst, effective.ComputerUse);
        Assert.Equal(HarnessCapabilityAccess.AskFirst, effective.BrowserUse);
        Assert.False(HarnessCapabilityPolicy.EvaluateComputerUse(effective).Allowed);
        Assert.False(HarnessCapabilityPolicy.EvaluateBrowserUse(effective).Allowed);
        Assert.Equal(HarnessCapabilityAccess.AskFirst, effective.ComputerUse);
        Assert.Equal(HarnessCapabilityAccess.AskFirst, effective.BrowserUse);
    }

    [Fact]
    public void Effective_SetHarness_ReturnsConfiguredRestrictions()
    {
        var settings = new ForemanSettings();
        settings.HarnessCapabilityRestrictions["claude-code"] = new()
        {
            ComputerUse = HarnessCapabilityAccess.AskFirst,
            BrowserUse = HarnessCapabilityAccess.Block,
        };

        var effective = settings.EffectiveCapabilityRestrictions("CLAUDE-CODE");

        Assert.Equal(HarnessCapabilityAccess.AskFirst, effective.ComputerUse);
        Assert.Equal(HarnessCapabilityAccess.Block, effective.BrowserUse);
        Assert.False(HarnessCapabilityPolicy.EvaluateComputerUse(effective).Allowed);
        Assert.False(HarnessCapabilityPolicy.EvaluateBrowserUse(effective).Allowed);
    }
}
