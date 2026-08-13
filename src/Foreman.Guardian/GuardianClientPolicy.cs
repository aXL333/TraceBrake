using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;

namespace Foreman.Guardian;

/// <summary>
/// Persistent allow-list for callers of the LocalSystem guardian pipe.
/// Signed installations pin the verified publisher, so future same-publisher releases continue to work.
/// Unsigned development installations pin one canonical TraceBrake.exe path and SHA-256 instead of trusting every
/// authenticated local user. The development posture is useful but is deliberately not described as publisher
/// authenticated: a process able to replace that user-owned binary can still assume its identity.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class GuardianClientPolicy
{
    public const int CurrentSchemaVersion = 1;
    public const string PublisherSignedMode = "publisher_signed";
    public const string PathHashPinnedMode = "path_hash_pinned";
    public const string FileName = "client-policy.json";

    public int SchemaVersion { get; set; } = CurrentSchemaVersion;
    public string Mode { get; set; } = string.Empty;
    public string ForemanPath { get; set; } = string.Empty;
    public string? Sha256 { get; set; }
    public string? PublisherThumbprint { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public bool PublisherAuthenticated =>
        string.Equals(Mode, PublisherSignedMode, StringComparison.Ordinal);

    /// <summary>
    /// Refuse a policy replacement that weakens a previously publisher-authenticated installation.
    /// The decision depends only on administrator-owned policy state and verified replacement evidence.
    /// </summary>
    public static (bool Allowed, string Reason) CanReplace(
        GuardianClientPolicy existing,
        GuardianClientPolicy replacement)
    {
        if (existing.PublisherAuthenticated && !replacement.PublisherAuthenticated)
            return (false, "a publisher-authenticated client policy cannot be downgraded to path/hash trust.");

        return (true, "replacement does not weaken the installed client-policy trust mode.");
    }

    public static GuardianClientPolicy CreateForInstall(string? foremanPath)
    {
        if (string.IsNullOrWhiteSpace(foremanPath))
            throw new InvalidOperationException("The TraceBrake executable path is required.");

        var canonical = CanonicalPath(foremanPath);
        if (!File.Exists(canonical))
            throw new FileNotFoundException("The TraceBrake executable was not found.", canonical);

        var publisher = GuardianIntegrity.VerifiedSignerThumbprint(canonical);
        return publisher is not null
            ? new GuardianClientPolicy
            {
                Mode = PublisherSignedMode,
                ForemanPath = canonical,
                PublisherThumbprint = publisher,
            }
            : new GuardianClientPolicy
            {
                Mode = PathHashPinnedMode,
                ForemanPath = canonical,
                Sha256 = GuardianIntegrity.Sha256File(canonical),
            };
    }

    public (bool Trusted, string Reason) VerifyClient(string? clientPath)
    {
        try
        {
            if (SchemaVersion != CurrentSchemaVersion)
                return (false, $"unsupported client-policy schema {SchemaVersion}.");
            if (string.IsNullOrWhiteSpace(clientPath) || !File.Exists(clientPath))
                return (false, "client image path is missing or unreadable.");

            var canonical = CanonicalPath(clientPath);
            if (string.Equals(Mode, PublisherSignedMode, StringComparison.Ordinal))
            {
                var signer = GuardianIntegrity.VerifiedSignerThumbprint(canonical);
                return Decide(Mode, ForemanPath, Sha256, PublisherThumbprint, canonical, null, signer);
            }

            if (string.Equals(Mode, PathHashPinnedMode, StringComparison.Ordinal))
            {
                if (!string.Equals(CanonicalPath(ForemanPath), canonical, StringComparison.OrdinalIgnoreCase))
                    return (false, "client path does not match the pinned development TraceBrake executable.");
                var hash = GuardianIntegrity.Sha256File(canonical);
                return Decide(Mode, ForemanPath, Sha256, PublisherThumbprint, canonical, hash, null);
            }

            return (false, $"unknown client-policy mode '{Mode}'.");
        }
        catch (Exception ex)
        {
            return (false, $"client-policy verification failed: {ex.Message}");
        }
    }

    /// <summary>Pure decision seam used by tests; caller supplies already-verified signer/hash evidence.</summary>
    public static (bool Trusted, string Reason) Decide(
        string mode,
        string pinnedPath,
        string? pinnedSha256,
        string? pinnedPublisher,
        string clientPath,
        string? clientSha256,
        string? clientPublisher)
    {
        if (string.Equals(mode, PublisherSignedMode, StringComparison.Ordinal))
        {
            if (string.IsNullOrWhiteSpace(pinnedPublisher))
                return (false, "publisher policy has no pinned publisher.");
            if (string.IsNullOrWhiteSpace(clientPublisher))
                return (false, "client is unsigned or its Authenticode signature is invalid.");
            return string.Equals(pinnedPublisher, clientPublisher, StringComparison.OrdinalIgnoreCase)
                ? (true, "client Authenticode publisher matches the installed policy.")
                : (false, "client is signed by a different publisher.");
        }

        if (string.Equals(mode, PathHashPinnedMode, StringComparison.Ordinal))
        {
            if (!string.Equals(CanonicalPath(pinnedPath), CanonicalPath(clientPath), StringComparison.OrdinalIgnoreCase))
                return (false, "client path does not match the pinned development executable.");
            if (string.IsNullOrWhiteSpace(pinnedSha256) || string.IsNullOrWhiteSpace(clientSha256))
                return (false, "development policy is missing SHA-256 evidence.");
            return string.Equals(pinnedSha256, clientSha256, StringComparison.OrdinalIgnoreCase)
                ? (true, "client path and SHA-256 match the installed development policy.")
                : (false, "client SHA-256 does not match the installed development policy.");
        }

        return (false, $"unknown client-policy mode '{mode}'.");
    }

    public static string PolicyPath(string programDataDir) => Path.Combine(programDataDir, FileName);

    public void Save(string programDataDir)
    {
        Directory.CreateDirectory(programDataDir);
        var path = PolicyPath(programDataDir);
        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(this, JsonOptions));
        File.Move(temp, path, overwrite: true);
        HardenPolicyFile(path);
    }

    internal static byte[]? CaptureRaw(string programDataDir)
    {
        var path = PolicyPath(programDataDir);
        return File.Exists(path) ? File.ReadAllBytes(path) : null;
    }

    internal static void RestoreRaw(string programDataDir, byte[]? prior, bool harden = true)
    {
        var path = PolicyPath(programDataDir);
        if (prior is null)
        {
            if (File.Exists(path)) File.Delete(path);
            return;
        }

        Directory.CreateDirectory(programDataDir);
        File.WriteAllBytes(path, prior);
        if (harden) HardenPolicyFile(path);
    }

    public static GuardianClientPolicy Load(string programDataDir)
    {
        var path = PolicyPath(programDataDir);
        var policy = JsonSerializer.Deserialize<GuardianClientPolicy>(File.ReadAllText(path), JsonOptions)
                     ?? throw new InvalidDataException("Guardian client policy is empty.");
        if (policy.SchemaVersion != CurrentSchemaVersion)
            throw new InvalidDataException($"Unsupported guardian client-policy schema {policy.SchemaVersion}.");
        if (policy.Mode is not PublisherSignedMode and not PathHashPinnedMode)
            throw new InvalidDataException($"Unknown guardian client-policy mode '{policy.Mode}'.");
        return policy;
    }

    private static string CanonicalPath(string path) =>
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));

    private static void HardenPolicyFile(string path)
    {
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(admins);
        security.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
    };
}
