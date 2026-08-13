using System.Text.Json;

namespace Foreman.Core.Security;

/// <summary>
/// Structured lease used by the elevated sidecar to remember that TraceBrake enabled the machine-wide File System
/// audit subcategory. File authorship is enforced by the sidecar's administrator/SYSTEM-only ACL; this type keeps
/// the payload versioned and rejects malformed, future-dated, or stale ownership claims.
/// </summary>
public sealed record DecoyAuditOwnershipLease(
    int Version,
    string Owner,
    string InstanceId,
    DateTimeOffset RefreshedAtUtc);

public static class DecoyAuditOwnershipLeaseCodec
{
    public const int CurrentVersion = 1;
    public const string ExpectedOwner = "Foreman.EtwSidecar";
    public static readonly TimeSpan DefaultMaxAge = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan FutureSkew = TimeSpan.FromMinutes(1);

    public static string Create(string instanceId, DateTimeOffset now)
    {
        if (!Guid.TryParseExact(instanceId, "N", out _))
            throw new ArgumentException("Instance id must be a 32-character GUID.", nameof(instanceId));

        return JsonSerializer.Serialize(new DecoyAuditOwnershipLease(
            CurrentVersion, ExpectedOwner, instanceId, now.ToUniversalTime()));
    }

    public static bool TryParse(string? json, out DecoyAuditOwnershipLease? lease)
    {
        lease = null;
        if (string.IsNullOrWhiteSpace(json)) return false;
        try
        {
            var parsed = JsonSerializer.Deserialize<DecoyAuditOwnershipLease>(json);
            if (parsed is null
                || parsed.Version != CurrentVersion
                || !string.Equals(parsed.Owner, ExpectedOwner, StringComparison.Ordinal)
                || !Guid.TryParseExact(parsed.InstanceId, "N", out _))
                return false;
            lease = parsed;
            return true;
        }
        catch { return false; }
    }

    public static bool IsFresh(
        DecoyAuditOwnershipLease lease,
        DateTimeOffset now,
        TimeSpan? maxAge = null)
    {
        var refreshed = lease.RefreshedAtUtc.ToUniversalTime();
        var current = now.ToUniversalTime();
        if (refreshed > current + FutureSkew) return false;
        return current - refreshed <= (maxAge ?? DefaultMaxAge);
    }
}
