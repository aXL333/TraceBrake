using Foreman.Core.Models;
using Foreman.Core.Profiles;

namespace Foreman.Core.Tests.Profiles;

public sealed class ProfileStoreTests : IDisposable
{
    private readonly string _profileDir = Path.Combine(Path.GetTempPath(), "foreman-profile-store-test-" + Guid.NewGuid().ToString("N"));
    private readonly List<string> _additionalDirs = [];
    private readonly ProfileStore _store;

    public ProfileStoreTests()
    {
        _store = new ProfileStore(_profileDir);
        _store.Initialize();
    }

    [Theory]
    [InlineData("t3-code", "t3-code-default")]
    [InlineData("opencode", "opencode-default")]
    public void BuiltInProfiles_AreLoadedForNewHarnesses(string harnessId, string profileName)
    {
        Assert.NotNull(KnownHarnesses.GetById(harnessId));
        Assert.Equal(profileName, HarnessIntegrationRegistry.GetDefaultProfileName(harnessId));
        Assert.NotNull(_store.Get(profileName));
    }

    [Fact]
    public void DiskProfile_CannotOverrideEmbeddedProfileOrItsSuppressionPolicy()
    {
        using var store = InitializeWith("override.json", """
            {
              "name": "codex-default",
              "description": "attacker override",
              "alerts": {
                "trustedHookPathMarkers": ["C:\\\\"],
                "launcherSuppressedRuleIds": ["cred-004"]
              }
            }
            """);

        var profile = store.Get("codex-default");
        Assert.NotNull(profile);
        Assert.NotEqual("attacker override", profile!.Description);
        Assert.DoesNotContain("cred-004", profile.Alerts.LauncherSuppressedRuleIds);
    }

    [Fact]
    public void DiskProfile_LoadsRestrictionsButStripsAlertSuppressionAuthority()
    {
        using var store = InitializeWith("custom.json", """
            {
              "name": "custom-safe",
              "fileSystem": { "deniedPaths": ["C:\\secrets"] },
              "alerts": {
                "trustedHookPathMarkers": ["C:\\\\"],
                "launcherSuppressedRuleIds": ["cred-004", "win-002"]
              }
            }
            """);

        var profile = store.Get("custom-safe");
        Assert.NotNull(profile);
        Assert.Contains(@"C:\secrets", profile!.FileSystem.DeniedPaths);
        Assert.Empty(profile.Alerts.TrustedHookPathMarkers);
        Assert.Empty(profile.Alerts.LauncherSuppressedRuleIds);
    }

    [Fact]
    public void OversizedDiskProfile_IsIgnoredBeforeJsonAllocation()
    {
        var dir = Path.Combine(Path.GetTempPath(), "foreman-profile-limit-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "huge.json"),
                "{\"name\":\"huge\"}" + new string(' ', checked((int)ProfileStore.MaxProfileBytes + 1)));
            using var store = new ProfileStore(dir);
            store.Initialize();
            Assert.DoesNotContain(store.All, p => p.Name == "huge");
        }
        finally { try { Directory.Delete(dir, recursive: true); } catch { } }
    }

    [Fact]
    public void NullNestedSections_AreNormalizedAtTheFileBoundary()
    {
        using var store = InitializeWith("nulls.json", """
            { "name": "nulls", "processMatch": null, "fileSystem": null,
              "commands": null, "processLimits": null, "claudeCodeIntegration": null, "alerts": null }
            """);

        var profile = store.Get("nulls");
        Assert.NotNull(profile);
        Assert.NotNull(profile!.ProcessMatch);
        Assert.NotNull(profile.FileSystem);
        Assert.NotNull(profile.Commands);
        Assert.NotNull(profile.ProcessLimits);
        Assert.NotNull(profile.ClaudeCodeIntegration);
        Assert.NotNull(profile.Alerts);
    }

    private ProfileStore InitializeWith(string fileName, string json)
    {
        var dir = Path.Combine(Path.GetTempPath(), "foreman-profile-policy-test-" + Guid.NewGuid().ToString("N"));
        _additionalDirs.Add(dir);
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, fileName), json);
        var store = new ProfileStore(dir);
        store.Initialize();
        return store;
    }

    public void Dispose()
    {
        _store.Dispose();
        if (Directory.Exists(_profileDir))
            Directory.Delete(_profileDir, recursive: true);
        foreach (var dir in _additionalDirs)
            try { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); } catch { }
    }
}
