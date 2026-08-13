using Foreman.Core.ComputerUse;
using Foreman.Core.Mcp;
using Foreman.Core.Settings;

namespace Foreman.Core.Tests.Settings;

public sealed class UniversalTrustSettingsTests
{
    private static CuAction Action(CuModality modality, string verb) =>
        new(modality, verb, new Dictionary<string, string>(), ByHarness: "codex");

    [Fact]
    public void Defaults_PreserveExistingBrokerAuthorityAtEveryTrustLevel()
    {
        var settings = new UniversalTrustSettings();

        foreach (var level in Enumerable.Range(1, 5))
        {
            var profile = settings.ForLevel(level);
            Assert.Equal(TrustPrivilegeMode.UnattendedIncludingLocked, profile.BrowserObservation);
            Assert.Equal(TrustPrivilegeMode.UnattendedIncludingLocked, profile.BrowserControl);
            Assert.Equal(TrustPrivilegeMode.AskEveryTime, profile.DesktopObservation);
            Assert.Equal(TrustPrivilegeMode.AskEveryTime, profile.DesktopControl);
            Assert.Equal(TrustPrivilegeMode.UnattendedIncludingLocked, profile.AdbObservation);
            Assert.Equal(TrustPrivilegeMode.AskEveryTime, profile.AdbControl);
        }
    }

    [Theory]
    [InlineData(CuModality.Browser, "read", TrustPrivilegeMode.AskEveryTime)]
    [InlineData(CuModality.Browser, "click", TrustPrivilegeMode.UnattendedIncludingLocked)]
    [InlineData(CuModality.Desktop, "screenshot", TrustPrivilegeMode.Never)]
    [InlineData(CuModality.Desktop, "left_click", TrustPrivilegeMode.UnattendedWhileUnlocked)]
    [InlineData(CuModality.Android, "ui_dump", TrustPrivilegeMode.UnattendedIncludingLocked)]
    [InlineData(CuModality.Android, "tap", TrustPrivilegeMode.AskEveryTime)]
    public void ModeFor_SeparatesObservationFromControl(
        CuModality modality, string verb, TrustPrivilegeMode expected)
    {
        var profile = new TrustCapabilityProfile
        {
            BrowserObservation = TrustPrivilegeMode.AskEveryTime,
            BrowserControl = TrustPrivilegeMode.UnattendedIncludingLocked,
            DesktopObservation = TrustPrivilegeMode.Never,
            DesktopControl = TrustPrivilegeMode.UnattendedWhileUnlocked,
            AdbObservation = TrustPrivilegeMode.UnattendedIncludingLocked,
            AdbControl = TrustPrivilegeMode.AskEveryTime,
        };

        Assert.Equal(expected, profile.ModeFor(Action(modality, verb)));
    }

    [Fact]
    public void Policy_HandlesNeverAskUnlockedAndLockedModes()
    {
        Assert.True(TrustCapabilityPolicy.Evaluate(TrustPrivilegeMode.Never, sessionLocked: false).Blocked);
        Assert.True(TrustCapabilityPolicy.Evaluate(TrustPrivilegeMode.AskEveryTime, sessionLocked: false).RequiresApproval);

        var unlocked = TrustCapabilityPolicy.Evaluate(TrustPrivilegeMode.UnattendedWhileUnlocked, sessionLocked: false);
        Assert.False(unlocked.Blocked);
        Assert.False(unlocked.RequiresApproval);

        var locked = TrustCapabilityPolicy.Evaluate(TrustPrivilegeMode.UnattendedWhileUnlocked, sessionLocked: true);
        Assert.False(locked.Blocked);
        Assert.True(locked.RequiresApproval);

        var always = TrustCapabilityPolicy.Evaluate(TrustPrivilegeMode.UnattendedIncludingLocked, sessionLocked: true);
        Assert.False(always.Blocked);
        Assert.False(always.RequiresApproval);
    }

    [Fact]
    public void LegacyCeiling_CanOnlyMakeUniversalProfileStricter()
    {
        var permissive = new TrustCapabilityProfile
        {
            BrowserObservation = TrustPrivilegeMode.UnattendedIncludingLocked,
            BrowserControl = TrustPrivilegeMode.UnattendedIncludingLocked,
            DesktopObservation = TrustPrivilegeMode.UnattendedIncludingLocked,
            DesktopControl = TrustPrivilegeMode.UnattendedIncludingLocked,
            AdbObservation = TrustPrivilegeMode.UnattendedIncludingLocked,
            AdbControl = TrustPrivilegeMode.UnattendedIncludingLocked,
        };

        var effective = permissive.ApplyLegacyRestrictions(new HarnessCapabilityRestrictions
        {
            BrowserUse = HarnessCapabilityAccess.Block,
            ComputerUse = HarnessCapabilityAccess.AskFirst,
        });

        Assert.Equal(TrustPrivilegeMode.Never, effective.BrowserObservation);
        Assert.Equal(TrustPrivilegeMode.Never, effective.BrowserControl);
        Assert.Equal(TrustPrivilegeMode.AskEveryTime, effective.DesktopObservation);
        Assert.Equal(TrustPrivilegeMode.AskEveryTime, effective.DesktopControl);
        Assert.Equal(TrustPrivilegeMode.AskEveryTime, effective.AdbObservation);
        Assert.Equal(TrustPrivilegeMode.AskEveryTime, effective.AdbControl);
    }

    [Fact]
    public void EffectiveProfile_UsesHarnessTrustLevelAndLegacyCeiling()
    {
        var settings = new ForemanSettings();
        settings.HarnessTrust["codex"] = 5;
        settings.UniversalTrust.Profiles[5].AdbControl = TrustPrivilegeMode.UnattendedIncludingLocked;
        settings.HarnessCapabilityRestrictions["codex"] = new HarnessCapabilityRestrictions
        {
            ComputerUse = HarnessCapabilityAccess.AskFirst,
        };

        Assert.Equal(TrustPrivilegeMode.AskEveryTime, settings.EffectiveTrustCapabilities("codex").AdbControl);
        Assert.Equal(TrustPrivilegeMode.AskEveryTime, settings.EffectiveTrustCapabilities("codex").DesktopControl);
    }

    [Fact]
    public void RelaxationDetection_ExaminesEverySiblingCapability()
    {
        var before = new TrustCapabilityProfile();
        var after = before.Clone();
        after.AdbObservation = TrustPrivilegeMode.UnattendedIncludingLocked;
        Assert.False(TrustCapabilityPolicy.IsRelaxation(before, after));

        after.DesktopObservation = TrustPrivilegeMode.UnattendedIncludingLocked;
        Assert.True(TrustCapabilityPolicy.IsRelaxation(before, after));
    }
}
