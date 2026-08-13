namespace Foreman.Core;

/// <summary>
/// Public product identity and the compatibility boundary for the Foreman -&gt; TraceBrake rename.
/// Internal assembly, service, pipe and protocol names intentionally remain stable during the migration.
/// </summary>
public static class ProductIdentity
{
    public const string Name = "TraceBrake";
    public const string LegacyName = "Foreman";
    public const string FullName = "TraceBrake";
    public const string LegacyFullName = "Foreman Agent Safety";
    public const string ExecutableName = "TraceBrake.exe";
    public const string LegacyExecutableName = "Foreman.exe";
    public const string McpServerKey = "tracebrake";
    public const string LegacyMcpServerKey = "foreman";

    public static string LocalDataRoot => ResolveLocalDataRoot(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));

    public static string NewLocalDataRoot(string localAppData) => Path.Combine(localAppData, Name);

    public static string LegacyLocalDataRoot(string localAppData) => Path.Combine(localAppData, LegacyName);

    public static string RemapLegacyProfilesDirectory(string configuredPath, string localAppData)
    {
        try
        {
            var legacyDefault = Path.GetFullPath(Path.Combine(LegacyLocalDataRoot(localAppData), "profiles"));
            return string.Equals(Path.GetFullPath(configuredPath), legacyDefault, StringComparison.OrdinalIgnoreCase)
                ? Path.Combine(NewLocalDataRoot(localAppData), "profiles")
                : configuredPath;
        }
        catch
        {
            return configuredPath;
        }
    }

    /// <summary>
    /// Prefer TraceBrake state when it exists; otherwise keep using legacy state until the desktop app can
    /// perform the guarded one-time move. This keeps non-App hosts and tests free of migration side effects.
    /// </summary>
    public static string ResolveLocalDataRoot(string localAppData)
    {
        var current = NewLocalDataRoot(localAppData);
        if (Directory.Exists(current)) return current;

        var legacy = LegacyLocalDataRoot(localAppData);
        return Directory.Exists(legacy) ? legacy : current;
    }

    /// <summary>
    /// Atomically moves the complete per-user data directory when possible. Never merges roots or overwrites
    /// either side: settings seals, vault material and hash-chain evidence must remain one coherent lineage.
    /// </summary>
    public static ProductDataMigrationResult MigrateLegacyDataRoot(string localAppData)
    {
        var legacy = LegacyLocalDataRoot(localAppData);
        var current = NewLocalDataRoot(localAppData);

        if (Directory.Exists(current))
        {
            return Directory.Exists(legacy)
                ? new(ProductDataMigrationStatus.Conflict, current,
                    $"Both '{current}' and the legacy '{legacy}' exist. TraceBrake kept both directories and is using '{current}'; no data was merged or overwritten.")
                : new(ProductDataMigrationStatus.AlreadyCurrent, current, "TraceBrake data is already in the current location.");
        }

        if (!Directory.Exists(legacy))
            return new(ProductDataMigrationStatus.FreshInstall, current, "No legacy Foreman data was present.");

        try
        {
            if ((File.GetAttributes(legacy) & FileAttributes.ReparsePoint) != 0)
            {
                return new(ProductDataMigrationStatus.UnsafeLegacyRoot, legacy,
                    $"The legacy data directory '{legacy}' is a reparse point. TraceBrake refused to move or follow it automatically.");
            }

            Directory.Move(legacy, current);
            return new(ProductDataMigrationStatus.Migrated, current,
                $"Moved the complete Foreman data lineage from '{legacy}' to '{current}'.");
        }
        catch (Exception ex)
        {
            return new(ProductDataMigrationStatus.Failed, legacy,
                $"TraceBrake could not move the legacy data directory and will continue using it for this launch: {ex.Message}");
        }
    }
}

public enum ProductDataMigrationStatus
{
    FreshInstall,
    AlreadyCurrent,
    Migrated,
    Conflict,
    UnsafeLegacyRoot,
    Failed,
}

public sealed record ProductDataMigrationResult(
    ProductDataMigrationStatus Status,
    string ActiveDataRoot,
    string Message);
