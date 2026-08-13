namespace Foreman.Core.Tests;

public sealed class ProductIdentityTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"tracebrake-identity-{Guid.NewGuid():N}");

    public ProductIdentityTests() => Directory.CreateDirectory(_root);

    [Fact]
    public void PublicAndLegacyNames_AreExplicitAndDoNotCollapse()
    {
        Assert.Equal("TraceBrake", ProductIdentity.Name);
        Assert.Equal("Foreman", ProductIdentity.LegacyName);
        Assert.Equal("Foreman Agent Safety", ProductIdentity.LegacyFullName);
        Assert.NotEqual(ProductIdentity.Name, ProductIdentity.LegacyName);
    }

    [Fact]
    public void LegacyOnly_MovesWholeLineageAndSelectsTraceBrakeRoot()
    {
        var legacy = ProductIdentity.LegacyLocalDataRoot(_root);
        Directory.CreateDirectory(Path.Combine(legacy, "profiles"));
        File.WriteAllText(Path.Combine(legacy, "settings.json"), "sealed-settings");
        File.WriteAllText(Path.Combine(legacy, "vault.fvault"), "vault");
        File.WriteAllText(Path.Combine(legacy, "profiles", "codex.json"), "profile");

        var result = ProductIdentity.MigrateLegacyDataRoot(_root);

        Assert.Equal(ProductDataMigrationStatus.Migrated, result.Status);
        Assert.False(Directory.Exists(legacy));
        Assert.Equal("sealed-settings", File.ReadAllText(Path.Combine(result.ActiveDataRoot, "settings.json")));
        Assert.Equal("vault", File.ReadAllText(Path.Combine(result.ActiveDataRoot, "vault.fvault")));
        Assert.Equal("profile", File.ReadAllText(Path.Combine(result.ActiveDataRoot, "profiles", "codex.json")));
        Assert.Equal(ProductIdentity.NewLocalDataRoot(_root), ProductIdentity.ResolveLocalDataRoot(_root));
    }

    [Fact]
    public void BothRootsExist_DoesNotMergeOrOverwriteEitherLineage()
    {
        var legacy = ProductIdentity.LegacyLocalDataRoot(_root);
        var current = ProductIdentity.NewLocalDataRoot(_root);
        Directory.CreateDirectory(legacy);
        Directory.CreateDirectory(current);
        File.WriteAllText(Path.Combine(legacy, "settings.json"), "legacy");
        File.WriteAllText(Path.Combine(current, "settings.json"), "current");

        var result = ProductIdentity.MigrateLegacyDataRoot(_root);

        Assert.Equal(ProductDataMigrationStatus.Conflict, result.Status);
        Assert.Equal(current, result.ActiveDataRoot);
        Assert.Equal("legacy", File.ReadAllText(Path.Combine(legacy, "settings.json")));
        Assert.Equal("current", File.ReadAllText(Path.Combine(current, "settings.json")));
    }

    [Fact]
    public void LegacyRootWithoutMigration_RemainsTheCompatibilityFallback()
    {
        var legacy = ProductIdentity.LegacyLocalDataRoot(_root);
        Directory.CreateDirectory(legacy);

        Assert.Equal(legacy, ProductIdentity.ResolveLocalDataRoot(_root));
    }

    [Fact]
    public void NoRoots_IsAFreshTraceBrakeInstall()
    {
        var result = ProductIdentity.MigrateLegacyDataRoot(_root);

        Assert.Equal(ProductDataMigrationStatus.FreshInstall, result.Status);
        Assert.Equal(ProductIdentity.NewLocalDataRoot(_root), result.ActiveDataRoot);
        Assert.Equal(ProductIdentity.NewLocalDataRoot(_root), ProductIdentity.ResolveLocalDataRoot(_root));
    }

    [Fact]
    public void LegacyDefaultProfilesPath_IsRemappedButCustomPathIsPreserved()
    {
        var legacyProfiles = Path.Combine(ProductIdentity.LegacyLocalDataRoot(_root), "profiles");
        var custom = Path.Combine(_root, "my-shared-profiles");

        Assert.Equal(
            Path.Combine(ProductIdentity.NewLocalDataRoot(_root), "profiles"),
            ProductIdentity.RemapLegacyProfilesDirectory(legacyProfiles, _root));
        Assert.Equal(custom, ProductIdentity.RemapLegacyProfilesDirectory(custom, _root));
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }
}
