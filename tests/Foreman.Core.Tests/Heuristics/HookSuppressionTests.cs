using Foreman.Core.Heuristics;
using Foreman.Core.Models;

namespace Foreman.Core.Tests.Heuristics;

/// <summary>
/// A harness running its OWN configured hook scripts (under .claude/hooks/) legitimately uses
/// -ExecutionPolicy Bypass / -NoProfile, so the launcher-hygiene rule (win-002) is suppressed
/// for those command lines — otherwise every hook invocation spams an alert and escalates the
/// harness. EncodedCommand remains alertable even when a hook path is present.
/// </summary>
public sealed class HookSuppressionTests : IClassFixture<PatternLibraryFixture>
{
    private readonly CommandAnalyzer _analyzer = CommandAnalyzer.Instance;

    [Theory]
    [InlineData(@"powershell -NoProfile -ExecutionPolicy Bypass -File ""C:\Users\user\.claude\hooks\log-generation.ps1""")]
    [InlineData(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonInteractive -ExecutionPolicy Bypass -Command ""& 'C:\Users\user\.claude\hooks\pre-tool.ps1'""")]
    public void HarnessOwnHookLauncher_IsSuppressed(string cmd)
    {
        Assert.Null(_analyzer.Analyze(cmd, "powershell.exe"));
    }

    [Fact]
    public void ExecutionPolicyBypass_OutsideHookDir_StillAlerts()
    {
        // Same launcher hygiene, but not a harness hook path — must NOT be suppressed.
        var match = _analyzer.Analyze(
            @"powershell -NoProfile -ExecutionPolicy Bypass -File C:\tools\deploy.ps1", "powershell.exe");
        Assert.NotNull(match);
        Assert.Equal("win-002", match.RuleId);
    }

    [Fact]   // B3 / deep-review #21: a ".claude/hooks/" substring that isn't a launched script can't forge the exemption
    public void HookMarkerNotALaunchedScript_DoesNotSuppress()
    {
        // The marker appears, but as harmless text — not as a launched .ps1 — so win-002 must still fire.
        var match = _analyzer.Analyze(
            @"powershell -NoProfile -ExecutionPolicy Bypass -Command ""echo .claude/hooks/ ; whoami""", "powershell.exe");
        Assert.NotNull(match);
        Assert.Equal("win-002", match.RuleId);
    }

    [Fact]
    public void EncodedCommand_IsNotSuppressed_EvenWithHookPathPresent()
    {
        // A base64 -EncodedCommand payload is a primary obfuscation signal. Suppression must
        // NOT be evadable by planting a ".claude\hooks\" substring in the command line.
        var cmd = @"powershell -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA= -from C:\Users\me\.claude\hooks\x";
        var match = _analyzer.Analyze(cmd, "powershell.exe");
        Assert.NotNull(match);
        Assert.Equal("win-001", match.RuleId);
    }

    [Fact]
    public void ProfileCannotSuppressHighSeverityRuleEvenWithMatchingMarker()
    {
        var profile = new Foreman.Core.Profiles.HarnessProfile();
        profile.Alerts.LauncherSuppressedRuleIds = ["attacker-high"];
        profile.Alerts.TrustedHookPathMarkers = [@"C:\trusted\hooks\"];
        var rule = new PatternRule { Id = "attacker-high", Severity = "high" };

        Assert.False(FalsePositiveFilter.IsSuppressed(
            rule, @"powershell -File C:\trusted\hooks\payload.ps1", "powershell.exe", profile));
    }
}
