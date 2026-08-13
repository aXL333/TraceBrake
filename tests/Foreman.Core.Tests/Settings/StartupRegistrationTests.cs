using Foreman.Core.Settings;

namespace Foreman.Core.Tests.Settings;

public sealed class StartupRegistrationTests
{
    private const string Exe = @"C:\Program Files\Foreman\Foreman.exe";

    [Fact] public void RunValueName_UsesPublicProductName()
        => Assert.Equal("TraceBrake", StartupRegistration.RunValueName);

    [Fact] public void LegacyRunValueName_PreservesUpgradeCompatibility()
        => Assert.Equal("Foreman", StartupRegistration.LegacyRunValueName);

    [Fact] public void LegacyRunValueNames_IncludeEveryShippedForemanAlias()
    {
        Assert.Contains("Foreman", StartupRegistration.LegacyRunValueNames);
        Assert.Contains("ForemanAgentSafety", StartupRegistration.LegacyRunValueNames);
        Assert.Contains("Foreman Agent Safety", StartupRegistration.LegacyRunValueNames);
    }

    private static Func<string, bool> Exists(params string[] paths) =>
        p => paths.Contains(p, StringComparer.OrdinalIgnoreCase);

    // ── BuildCommand ──────────────────────────────────────────────────────────
    [Fact] public void BuildCommand_QuotesThePath()
        => Assert.Equal($"\"{Exe}\"", StartupRegistration.BuildCommand(Exe));

    // ── ParseExePath ──────────────────────────────────────────────────────────
    [Fact] public void Parse_QuotedPath()
        => Assert.Equal(Exe, StartupRegistration.ParseExePath($"\"{Exe}\""));

    [Fact] public void Parse_QuotedPathWithArgs()
        => Assert.Equal(Exe, StartupRegistration.ParseExePath($"\"{Exe}\" --startup"));

    [Fact] public void Parse_BarePath()
        => Assert.Equal(@"C:\Tools\Foreman.exe", StartupRegistration.ParseExePath(@"C:\Tools\Foreman.exe"));

    [Fact] public void Parse_BarePathWithArgs_CutsAfterExe()
        => Assert.Equal(@"C:\Tools\Foreman.exe", StartupRegistration.ParseExePath(@"C:\Tools\Foreman.exe --startup"));

    [Fact] public void Parse_BarePathCaseInsensitiveExe()
        => Assert.Equal(@"C:\Tools\FOREMAN.EXE", StartupRegistration.ParseExePath(@"C:\Tools\FOREMAN.EXE -x"));

    [Fact] public void Parse_Empty_ReturnsNull()
        => Assert.Null(StartupRegistration.ParseExePath("  "));

    [Fact] public void Parse_UnterminatedQuote_ReturnsNull()
        => Assert.Null(StartupRegistration.ParseExePath("\"C:\\Tools\\Foreman.exe"));

    // ── NeedsRepair ───────────────────────────────────────────────────────────
    [Fact] public void NoValue_FeatureOff_NoRepair()
        => Assert.False(StartupRegistration.NeedsRepair(null, Exe, Exists()));

    [Fact] public void PointsAtCurrentExe_NoRepair()
        => Assert.False(StartupRegistration.NeedsRepair($"\"{Exe}\"", Exe, Exists(Exe)));

    [Fact] public void PointsAtCurrentExe_CaseInsensitive_NoRepair()
        => Assert.False(StartupRegistration.NeedsRepair($"\"{Exe.ToUpperInvariant()}\"", Exe, Exists(Exe)));

    [Fact] public void OtherExeStillExists_NoHijack()
        // e.g. a Debug-bin run must not steal the entry from a live published install
        => Assert.False(StartupRegistration.NeedsRepair(@"""C:\Published\Foreman.exe""", Exe, Exists(@"C:\Published\Foreman.exe", Exe)));

    [Fact] public void ExistingLegacyBrandedTarget_RepairsToRenamedCurrentExe()
    {
        // Rename bypass: StartupManager may already have migrated the VALUE NAME to "TraceBrake" while retaining
        // an existing Foreman.exe target. Existence alone must not make that legacy product binary authoritative.
        const string legacy = @"W:\TOOLS\Foreman\bin\Foreman.exe";
        const string current = @"C:\Users\me\AppData\Local\Programs\TraceBrake\TraceBrake.exe";

        Assert.True(StartupRegistration.NeedsRepair(
            $"\"{legacy}\"", current, Exists(legacy, current)));
    }

    [Fact] public void ExistingCurrentProductInstall_IsNotStolenByCurrentProductDebugBuild()
    {
        const string published = @"C:\Users\me\AppData\Local\Programs\TraceBrake\TraceBrake.exe";
        const string debug = @"W:\TOOLS\Foreman\bin\Debug\TraceBrake.exe";

        Assert.False(StartupRegistration.NeedsRepair(
            $"\"{published}\"", debug, Exists(published, debug)));
    }

    [Fact] public void RegisteredExeGone_Repairs()
        => Assert.True(StartupRegistration.NeedsRepair(@"""C:\OldInstall\Foreman.exe""", Exe, Exists(Exe)));

    [Fact] public void MalformedValue_Repairs()
        => Assert.True(StartupRegistration.NeedsRepair("\"C:\\Broken\\Foreman.exe", Exe, Exists(Exe)));
}
