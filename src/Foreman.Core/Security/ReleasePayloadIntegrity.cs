using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Foreman.Core.Security;

public sealed record ReleasePayloadIntegrityResult(bool Applicable, bool Trusted, string Reason);

/// <summary>Runtime verification of the release manifest. Development builds have no manifest and are unaffected.</summary>
public static partial class ReleasePayloadIntegrity
{
    public const string ManifestFileName = "release-payload.manifest.json";
    private static readonly HashSet<string> AllowedDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        "sidecar", "guardian", "cu-sidecar", "cu-pilot", "extensions",
    };

    public static ReleasePayloadIntegrityResult Verify(string root)
    {
        try
        {
            root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
            var manifestPath = Path.Combine(root, ManifestFileName);
            if (!File.Exists(manifestPath))
                return new(false, true, "development layout has no release manifest.");

            var manifest = JsonSerializer.Deserialize<Manifest>(
                File.ReadAllText(manifestPath),
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (manifest?.SchemaVersion != 1 || manifest.Files is null)
                return new(true, false, "release manifest schema is invalid.");

            var declared = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in manifest.Files)
            {
                var relative = (entry.Path ?? string.Empty).Replace('/', Path.DirectorySeparatorChar);
                if (relative.Length == 0 || Path.IsPathRooted(relative) ||
                    relative.Split(Path.DirectorySeparatorChar).Contains("..") ||
                    !declared.TryAdd(relative, entry.Sha256 ?? string.Empty))
                    return new(true, false, "release manifest contains an unsafe or duplicate path.");
            }

            foreach (var entry in Directory.EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories))
                if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0)
                    return new(true, false, "installed release contains a reparse point.");

            var actualPayload = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
                .Select(path => Path.GetRelativePath(root, path))
                .Where(path => !string.Equals(path, ManifestFileName, StringComparison.OrdinalIgnoreCase) &&
                               !IsInstallerBookkeeping(path))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (!actualPayload.SetEquals(declared.Keys))
                return new(true, false, "installed release tree differs from its signed build manifest.");

            var topDirectories = Directory.EnumerateDirectories(root)
                .Select(Path.GetFileName)
                .Where(static name => name is not null)
                .Cast<string>();
            if (topDirectories.Any(directory => !AllowedDirectories.Contains(directory)))
                return new(true, false, "installed release contains an undeclared top-level directory.");

            foreach (var (relative, expectedHash) in declared)
            {
                var full = Path.GetFullPath(Path.Combine(root, relative));
                if (!full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
                    !File.Exists(full))
                    return new(true, false, $"declared release file is missing: {relative}");
                using var stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read);
                var actualHash = Convert.ToHexString(SHA256.HashData(stream));
                if (!actualHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase))
                    return new(true, false, $"release file hash mismatch: {relative}");
            }
            return new(true, true, $"installed release matches its {declared.Count}-file manifest.");
        }
        catch (Exception ex)
        {
            return new(true, false, $"release integrity verification failed: {ex.Message}");
        }
    }

    private static bool IsInstallerBookkeeping(string relative) =>
        !relative.Contains(Path.DirectorySeparatorChar) &&
        InnoUninstallerFile().IsMatch(relative);

    [GeneratedRegex(@"^unins\d{3}\.(?:exe|dat|msg)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex InnoUninstallerFile();

    private sealed class Manifest
    {
        public int SchemaVersion { get; set; }
        public List<ManifestEntry>? Files { get; set; }
    }

    private sealed class ManifestEntry
    {
        public string? Path { get; set; }
        public string? Sha256 { get; set; }
    }
}
