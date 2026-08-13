using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using Foreman.Core.Models;

namespace Foreman.Core.Events;

/// <summary>
/// An EXTERNAL, out-of-band witness of the event-log chain head, committed to the OS event log (an append-only
/// store the same-user agent can't surgically revert — there is no API to delete a single Windows event entry,
/// only to clear a whole channel, which is itself elevated + conspicuous). It records the chain head that was on
/// disk the last time TraceBrake wrote a lifecycle anchor (at clean stop, and at startup).
///
/// WHY THIS EXISTS — the gap the in-file chain provably can't close: a rogue same-user agent can snapshot the
/// whole on-disk log (<c>events.log.jsonl</c> + its head seal), let TraceBrake record incriminating events, then
/// restore the snapshot. The restored state is internally consistent, so <see cref="EventLogStore.Verify"/>
/// passes — the agent rolled BOTH the chain and its head back together. The external anchor defeats exactly this:
/// on launch we check that the head we last witnessed EXTERNALLY is still present in the on-disk chain. A rollback
/// removes it (the restored snapshot predates that head) -> <see cref="AnchorVerdict.Rolledback"/>.
///
/// ANCHOR FORGE WINDOW (closed by <paramref name="Seal"/>): once the OS-log source is registered, a same-user agent
/// can WriteEntry under it (no elevation), so it can also PLANT a counterfeit anchor pointing at a rolled-back head.
/// When head-sealing is enabled the anchor carries a MAC under the chain's signing key, and only an authentically
/// sealed anchor is trusted (see <see cref="AnchorPolicy.Evaluate"/>) — a forged one the agent can't sign is rejected.
/// </summary>
/// <param name="Seal">
/// Optional authentication tag over (<paramref name="HeadHash"/>, <paramref name="Count"/>) produced by the chain's
/// <see cref="ILogHeadSigner"/>. Present only when head-sealing is enabled; null for the no-op signer / pre-seal
/// anchors (which still parse). The signed input is domain-separated (see <see cref="SealPayloadHead"/>) so it can
/// never be confused with the on-disk head-file seal.
/// </param>
public sealed record LogAnchor(string HeadHash, long Count, string? Seal = null)
{
    private static readonly Regex _parse = new(
        @"head=(?<h>[0-9A-Fa-f]+)\s+count=(?<c>\d+)(?:\s+seal=(?<s>[^\s.]+))?",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>Domain-separation prefix for the anchor MAC. It contains non-hex letters, so it can never begin a
    /// real (hex SHA-256) head hash — which is what keeps an anchor seal's signed input distinct from a head seal's.</summary>
    private const string SealDomain = "foreman-anchor-v1:";

    /// <summary>The OS-event-log message body that carries the anchor — a stable, SIEM-greppable one-liner.</summary>
    public string Format()
    {
        var sealPart = string.IsNullOrEmpty(Seal) ? string.Empty : $" seal={Seal}";
        return $"TraceBrake log-chain anchor - head={HeadHash} count={Count.ToString(CultureInfo.InvariantCulture)}{sealPart}. " +
               "External rollback witness; do not edit.";
    }

    /// <summary>Parses an anchor previously written by <see cref="Format"/>; null if the text isn't an anchor.
    /// The <c>seal=</c> field is optional, so anchors written before sealing (or by the no-op signer) still parse.</summary>
    public static LogAnchor? TryParse(string? message)
    {
        if (string.IsNullOrEmpty(message)) return null;
        var m = _parse.Match(message);
        if (!m.Success) return null;
        var seal = m.Groups["s"].Success ? m.Groups["s"].Value : null;
        return long.TryParse(m.Groups["c"].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var count)
            ? new LogAnchor(m.Groups["h"].Value, count, seal)
            : null;
    }

    /// <summary>
    /// Domain-separated head input for the anchor MAC. The chain's <see cref="ILogHeadSigner"/> signs (headInput,
    /// count); the on-disk <c>.head</c> seal signs the BARE head, so WITHOUT a tag an agent could read a <c>.head</c>
    /// file (current or an archived <c>*.archived.head</c>) and lift its genuine seal verbatim into a counterfeit
    /// anchor — and it would verify, defeating the MAC. Prefixing <see cref="SealDomain"/> (which a hex head can
    /// never contain) makes anchor seals and head-file seals cryptographically distinct domains, so a lifted head
    /// seal fails anchor verification. The tag is only ever the SIGNED input; the stored head stays plain hex.
    /// </summary>
    public string SealPayloadHead() => SealDomain + HeadHash;
}

/// <summary>Outcome of checking the on-disk chain against the last external anchor.</summary>
public enum AnchorVerdict
{
    /// <summary>No prior external anchor (first run, OS log unavailable, or the witnessed chain was empty).</summary>
    NoPriorAnchor,
    /// <summary>The externally-witnessed head is still present in the on-disk chain — clean cycle or honest forward growth.</summary>
    Match,
    /// <summary>The externally-witnessed head is GONE from the on-disk chain — the log was reverted/rewritten while TraceBrake was down.</summary>
    Rolledback,
    /// <summary>A candidate anchor carried a seal that FAILED verification under the pinned key, and no authentically
    /// sealed anchor remained — a same-user agent forged a counterfeit external witness (so a rollback may be masked).</summary>
    Forged,
}

/// <summary>
/// Pure decision for the external-anchor check. The test isn't "does the head still equal the anchor" — it's
/// "is the anchored head still PRESENT anywhere in the chain":
///  - present as the last record  -> clean stop->start cycle, nothing touched while down;
///  - present as an interior record -> this session appended past the anchor then was killed (honest forward progress);
///  - ABSENT                       -> the on-disk log no longer contains the state we externally committed to = rollback.
/// NOTE on trims: the load-time trim to the entry cap REWRITES the chain under a new genesis — every retained
/// record's hash changes, so a trim erases ALL previously-witnessed heads, not just the evicted front. That is
/// why <see cref="EventLogStore.ChainRewritten"/> exists: the host publishes a superseding anchor at rewrite
/// time (as the rotate path does), keeping the newest witness in step with the rewritten chain. Without it,
/// every session that trims and is then killed would read here as a rollback.
/// </summary>
public static class AnchorPolicy
{
    public static AnchorVerdict Check(IReadOnlyCollection<string> onDiskChainedHashes, LogAnchor? anchor)
    {
        if (!IsUsable(anchor))
            return AnchorVerdict.NoPriorAnchor;
        return onDiskChainedHashes.Contains(anchor!.HeadHash) ? AnchorVerdict.Match : AnchorVerdict.Rolledback;
    }

    /// <summary>
    /// Seal-aware anchor decision. The OS-log anchor is forgeable by a same-user agent once the source is registered
    /// (it can <c>WriteEntry</c> under our source without elevation), so when head-sealing is enabled we trust ONLY
    /// an anchor whose seal verifies under the pinned key — defeating a counterfeit witness planted to mask a rollback.
    ///
    /// <para>Selection (candidates are newest->oldest, as <c>ReadOwnRecent</c> returns them):</para>
    /// <list type="bullet">
    ///   <item>Signer expects no seal (the casual <c>NullHeadSigner</c> default): unchanged behaviour — the newest
    ///   usable anchor wins, seals ignored. Zero change for users who never enabled sealing.</item>
    ///   <item>Seal present and valid -> trusted witness; check its head against the on-disk chain (Match/Rolledback).</item>
    ///   <item>Seal present but INVALID -> a forgery attempt; skipped, flagged via <c>ForgedSealSeen</c>, keep scanning.</item>
    ///   <item>Seal ABSENT -> legacy/pre-pin/stripped; skipped quietly (a clean upgrade isn't an attack).</item>
    /// </list>
    /// If no authentically sealed anchor is found, a forged one anywhere yields <see cref="AnchorVerdict.Forged"/>;
    /// only-unsigned yields <see cref="AnchorVerdict.NoPriorAnchor"/> (migration-tolerant).
    ///
    /// <para>RESIDUAL WINDOWS (documented, not closed here):</para>
    /// <list type="bullet">
    ///   <item>REPLAY: a genuinely-old VALID anchor can be re-written as the newest — the agent rolls the on-disk
    ///   log back to a previously-anchored state and replays that authentic anchor. Its head is present in the
    ///   rolled-back chain, so it reads as Match. Closing it needs a monotonic anchor epoch sealed into each anchor.</item>
    ///   <item>MIGRATION / KEY-LESS: the first sealing launch (no sealed anchor exists yet), and any session where the
    ///   private key was unavailable (SealHead returned null -> an unsigned anchor was written), leave unsigned anchors
    ///   that are skipped as a clean upgrade. A rollback whose surviving witnesses are all unsigned reads as NoPrior.</item>
    /// </list>
    /// </summary>
    public static AnchorEvaluation Evaluate(
        IReadOnlyCollection<string> onDiskChainedHashes,
        IReadOnlyList<LogAnchor>? candidatesNewestFirst,
        ILogHeadSigner signer)
    {
        ArgumentNullException.ThrowIfNull(signer);
        candidatesNewestFirst ??= [];

        if (!signer.ExpectsSeal)
        {
            LogAnchor? newest = null;
            foreach (var a in candidatesNewestFirst)
                if (IsUsable(a)) { newest = a; break; }
            return new AnchorEvaluation(Check(onDiskChainedHashes, newest), newest, ForgedSealSeen: false);
        }

        var forgedSealSeen = false;
        foreach (var a in candidatesNewestFirst)
        {
            if (!IsUsable(a)) continue;
            if (string.IsNullOrEmpty(a.Seal)) continue;                          // unsigned: pre-pin/legacy or stripped -> not trusted
            if (signer.VerifyHead(a.SealPayloadHead(), a.Count, a.Seal))         // domain-separated input (see SealPayloadHead)
                return new AnchorEvaluation(Check(onDiskChainedHashes, a), a, forgedSealSeen);
            forgedSealSeen = true;                                                // sealed but invalid = forgery/tamper
        }

        return new AnchorEvaluation(
            forgedSealSeen ? AnchorVerdict.Forged : AnchorVerdict.NoPriorAnchor, TrustedAnchor: null, forgedSealSeen);
    }

    private static bool IsUsable(LogAnchor? a) => a is { Count: > 0 } && !string.IsNullOrEmpty(a.HeadHash);
}

/// <summary>Outcome of <see cref="AnchorPolicy.Evaluate"/>: the rollback verdict, the anchor it trusted (null if
/// none verified), and whether any candidate carried an invalid seal (a forgery attempt worth surfacing even when
/// an authentic anchor still verified).</summary>
public sealed record AnchorEvaluation(AnchorVerdict Verdict, LogAnchor? TrustedAnchor, bool ForgedSealSeen);

/// <summary>
/// Reads the on-disk event-log JSONL independently of <see cref="EventLogStore"/> (so the anchor check doesn't
/// couple to that type's internals) and returns the chained record hashes in file order. It TRUSTS the stored
/// <c>Hash</c> fields — internal chain consistency is the separate job of <see cref="EventLogStore.Verify"/>; here
/// we only need the set/sequence of committed heads to test the external anchor against.
/// </summary>
public static class LogHeadReader
{
    private static readonly JsonSerializerOptions _json = new() { WriteIndented = false };

    /// <summary>Stored hashes of every chained (Hash-bearing) record, oldest first; empty if the file is missing/unreadable.</summary>
    public static IReadOnlyList<string> ReadChainedHashes(string filePath)
    {
        var hashes = new List<string>();
        try
        {
            if (!File.Exists(filePath)) return hashes;
            foreach (var line in File.ReadLines(filePath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var e = JsonSerializer.Deserialize<ForemanEvent>(line, _json);
                    if (e is not null && !string.IsNullOrEmpty(e.Hash)) hashes.Add(e.Hash);
                }
                catch { /* torn/legacy line — skip, consistent with EventLogStore.Verify */ }
            }
        }
        catch { /* best-effort: an unreadable log is reported elsewhere by Verify */ }
        return hashes;
    }

    /// <summary>The current on-disk head (last chained hash) and the chained count; ("", 0) when none.</summary>
    public static LogAnchor CurrentAnchor(string filePath)
    {
        var hashes = ReadChainedHashes(filePath);
        return hashes.Count == 0 ? new LogAnchor(string.Empty, 0) : new LogAnchor(hashes[^1], hashes.Count);
    }
}
