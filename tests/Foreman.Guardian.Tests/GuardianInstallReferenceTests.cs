using Foreman.Guardian;

namespace Foreman.Guardian.Tests;

public sealed class GuardianInstallReferenceTests
{
    [Theory]
    [InlineData("TraceBrake.exe")]
    [InlineData("tracebrake.EXE")]
    [InlineData("Foreman.exe")]
    public void SupportedLauncherNames_AcceptCurrentAndLegacyUpgradeBinaries(string fileName)
        => Assert.True(GuardianInstallReference.IsSupportedLauncherName(fileName));

    [Theory]
    [InlineData("TraceBrake.Guardian.exe")]
    [InlineData("notepad.exe")]
    [InlineData("")]
    [InlineData(null)]
    public void SupportedLauncherNames_RejectSiblingAndAttackerChosenNames(string? fileName)
        => Assert.False(GuardianInstallReference.IsSupportedLauncherName(fileName));
}
