namespace Foreman.Core.Events;

/// <summary>Outcome of an <see cref="EventLogStore.Verify"/> integrity pass.</summary>
public enum VerifyStatus
{
    /// <summary>Empty or missing file — nothing to verify.</summary>
    Empty,
    /// <summary>The file exists but could not be opened/read; absence of evidence must not be reported as empty.</summary>
    Unavailable,
    /// <summary>Chain intact (and head seal valid, if a signer expects one).</summary>
    Valid,
    /// <summary>The LAST line is torn/undeserializable — a crash mid-append, not tamper. Benign.</summary>
    UnverifiedTail,
    /// <summary>A MIDDLE line is torn/undeserializable — reorder/insertion damage.</summary>
    Corrupt,
    /// <summary>A record's PrevHash or content hash doesn't match — an edit, drop, or reorder.</summary>
    BrokenLink,
    /// <summary>A head seal was expected but is missing or doesn't authenticate under the pinned key.</summary>
    HeadUnsealed,
    /// <summary>The head seal is authentic but commits to a different count/head than the file — truncated/extended.</summary>
    HeadMismatch,
}

/// <summary>
/// Result of verifying the event log's hash chain + head seal. <see cref="Count"/> is the number of CHAINED
/// records verified (a legacy pre-chain prefix, if any, is not counted and not treated as tamper).
/// <see cref="Index"/> is the offending line (0-based) for failure statuses, else -1.
/// </summary>
public sealed record VerifyResult(VerifyStatus Status, long Count, int Index, string Message)
{
    public bool Ok => Status is VerifyStatus.Valid or VerifyStatus.Empty or VerifyStatus.UnverifiedTail;

    public static VerifyResult Empty { get; } = new(VerifyStatus.Empty, 0, -1, "empty");
    public static VerifyResult Unavailable(string why) =>
        new(VerifyStatus.Unavailable, 0, -1, $"event log could not be verified: {why}");
    public static VerifyResult Valid(long count) => new(VerifyStatus.Valid, count, -1, $"valid chain of {count}");
    public static VerifyResult UnverifiedTail(long count) =>
        new(VerifyStatus.UnverifiedTail, count, -1, "last line torn (crash mid-append), chain otherwise intact");
    public static VerifyResult Corrupt(int index) =>
        new(VerifyStatus.Corrupt, 0, index, $"undeserializable record at line {index}");
    public static VerifyResult BrokenLink(int index, string why) =>
        new(VerifyStatus.BrokenLink, 0, index, $"chain break at line {index}: {why}");
    public static VerifyResult HeadUnsealed(long count) =>
        new(VerifyStatus.HeadUnsealed, count, -1, "chain head seal missing or not authentic under the pinned key");
    public static VerifyResult HeadMismatch(long count) =>
        new(VerifyStatus.HeadMismatch, count, -1, "head seal authentic but commits to a different count/head — records dropped or added");
}
