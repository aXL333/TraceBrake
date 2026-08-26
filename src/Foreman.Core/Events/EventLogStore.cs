using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Foreman.Core.Models;
using Foreman.Core.Security;
using Foreman.Core.Settings;

namespace Foreman.Core.Events;

/// <summary>
/// Durable, append-only event log on disk (JSONL — one polymorphic <see cref="ForemanEvent"/> per
/// line) so the Event Log survives restarts. Append is best-effort and never throws into the publish
/// path. Append enforces entry/byte ceilings in batches; Load also trims legacy oversized logs to the
/// most recent <c>maxEntries</c>. This feeds the Log VIEW only — it is deliberately separate from the in-memory
/// EventBus history, so reloading persisted events never resurrects stale alerts as "active".
///
/// TAMPER-EVIDENCE (P1): when <see cref="LogIntegritySettings.HashChainEnabled"/> is on, each written record
/// commits to the hash of the previous on-disk record (<see cref="LogChain"/>), and the chain head is sealed
/// via <see cref="ILogHeadSigner"/> (no-op in P1; TPM-backed in P3). <see cref="Verify"/> detects any
/// edit/drop/reorder of a past record, and — once a real seal exists — truncation. The audit log is exactly
/// what a rogue same-user agent would rewrite to hide its tracks, so this is a core self-protection layer.
/// </summary>
public sealed class EventLogStore
{
    private static readonly JsonSerializerOptions _json = new() { WriteIndented = false };

    // Event fields ultimately contain data observed from agent-owned processes. Never let one hostile JSONL
    // record force StreamReader/File.ReadAllLines to materialize an attacker-sized string. This is deliberately
    // much larger than normal event payloads while still bounding the largest string any read path constructs.
    public const int MaxRecordChars = 256 * 1024;
    private const long MaxHeadFileBytes = 64 * 1024;

    private readonly string _file;
    private readonly int _maxEntries;
    private readonly long _maxBytes;
    private readonly object _lock = new();
    private readonly bool _chain;
    private readonly ILogHeadSigner _signer;
    private readonly ITemporalClock _clock;
    private readonly ILogTimeAnchor _timeAnchor;

    private string? _headHash;   // last chained record's Hash; null until seeded, then "" (genesis) or a hash
    private long _count;         // number of chained records (bound into the head seal)
    private long _recordCount;   // all persisted records, including a legacy un-chained prefix
    private long? _lastSequence;
    private DateTimeOffset? _lastRecordedAtUtc;
    private long? _lastMonotonicTicks;
    private string? _lastTemporalSessionId;
    private long _lastMonotonicFrequency;

    public EventLogStore(string? baseDir = null, int maxEntries = 5000,
                         LogIntegritySettings? integrity = null, ILogHeadSigner? signer = null,
                         ITemporalClock? clock = null, ILogTimeAnchor? timeAnchor = null,
                         long maxBytes = 32L * 1024 * 1024)
    {
        var dir = baseDir ?? ProductIdentity.LocalDataRoot;
        _file = Path.Combine(dir, "events.log.jsonl");
        _maxEntries = Math.Max(1, maxEntries);
        _maxBytes = Math.Max(4096, maxBytes);
        _chain = (integrity ?? new LogIntegritySettings()).HashChainEnabled;
        _signer = signer ?? new NullHeadSigner();
        _clock = clock ?? new SystemTemporalClock();
        _timeAnchor = timeAnchor ?? new NullTimeAnchor();
    }

    public string FilePath => _file;
    private string HeadFile => _file + ".head";

    public Exception? LastAppendError { get; private set; }

    /// <summary>
    /// Raised after the on-disk chain was REWRITTEN under a new genesis (append/load retention compaction, or the
    /// one-time canonicalization migration): every retained record's hash changed, so any external anchor
    /// witnessed before the rewrite no longer exists in the file. The subscriber must publish a SUPERSEDING
    /// external anchor (the same pattern as the rotate path) — otherwise the very next launch compares the stale
    /// witness against the rewritten chain and falsely reports a rollback. Raised while the store lock is held;
    /// subscribers must not call back into this store.
    /// </summary>
    public event Action<LogAnchor>? ChainRewritten;

    /// <summary>Appends one event. Best-effort: any IO/serialization failure is swallowed.</summary>
    public void Append(ForemanEvent evt) => TryAppend(evt, out _);

    /// <summary>Appends one event and reports whether persistence succeeded.</summary>
    public bool TryAppend(ForemanEvent evt, out string? error)
    {
        try
        {
            AppendCore(evt);
            LastAppendError = null;
            error = null;
            return true;
        }
        catch (Exception ex)
        {
            LastAppendError = ex;
            error = ex.Message;
            return false;
        }
    }

    private void AppendCore(ForemanEvent evt, bool enforceRetention = true)
    {
        // Disk is an egress boundary: mask secret-shaped text before it lands at rest.
        var redacted = SecretRedactor.RedactEvent(evt);
        lock (_lock)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_file)!);

            if (_headHash is null || _lastSequence is null)
                SeedState();   // continue chain + sequence across store instances/restarts

            if (enforceRetention) CompactBeforeAppendIfNeeded();

            var recordedAt = _clock.UtcNow;
            var monotonicTicks = _clock.MonotonicTicks;
            var sequence = (_lastSequence ?? 0) + 1;
            redacted = redacted with
            {
                TemporalSessionId = _clock.SessionId,
                Sequence = sequence,
                RecordedAtUtc = recordedAt,
                MonotonicTicks = monotonicTicks,
                MonotonicFrequency = _clock.MonotonicFrequency,
                TemporalAnomalies = DetectTemporalAnomalies(recordedAt, monotonicTicks),
            };

            var nextHeadHash = _headHash;
            var nextCount = _count;
            if (_chain)
            {
                var canonical = LogChain.Canonicalize(redacted, _json);
                var hash = LogChain.ComputeHash(_headHash, canonical);
                redacted = redacted with { PrevHash = _headHash ?? LogChain.Genesis, Hash = hash };
                nextHeadHash = hash;
                nextCount++;
            }

            File.AppendAllText(_file, SerializeBoundedRecord(redacted) + "\n");

            // Advance in-memory state only AFTER the append succeeds. Otherwise a transient write failure would
            // make the next record chain onto a hash that never reached disk, permanently breaking the log.
            _headHash = nextHeadHash;
            _count = nextCount;
            _recordCount++;
            _lastSequence = sequence;
            _lastRecordedAtUtc = recordedAt;
            _lastMonotonicTicks = monotonicTicks;
            _lastTemporalSessionId = _clock.SessionId;
            _lastMonotonicFrequency = _clock.MonotonicFrequency;

            if (_chain)
                WriteHeadSeal(_signer.SealHead(_headHash!, _count));   // no-op file under NullHeadSigner
        }
    }

    // Append-time retention is batched. Keeping 90% of the entry/byte budget means production's 5,000-entry
    // log rewrites at most once per roughly 500 new events, instead of an O(n) rewrite on every append.
    private void CompactBeforeAppendIfNeeded()
    {
        var fileBytes = File.Exists(_file) ? new FileInfo(_file).Length : 0;
        if (_recordCount < _maxEntries && fileBytes < _maxBytes) return;

        var targetEntries = Math.Max(1, _maxEntries - Math.Max(1, _maxEntries / 10));
        var targetBytes = Math.Max(1, _maxBytes - Math.Max(1, _maxBytes / 10));
        var tail = ReadTailForCompaction(targetEntries, targetBytes);
        Rewrite(tail, throwOnFailure: true);
    }

    // Stream the source instead of File.ReadAllLines: even an oversized log from an older build stays bounded in
    // memory during its first repair. A malformed line aborts compaction rather than silently erasing evidence.
    private IReadOnlyList<ForemanEvent> ReadTailForCompaction(int targetEntries, long targetBytes)
    {
        var tail = new Queue<(ForemanEvent Event, int Bytes)>();
        long bytes = 0;
        foreach (var bounded in BoundedJsonlReader.Read(_file, MaxRecordChars))
        {
            if (bounded.Oversized)
                throw new InvalidDataException($"Event log record at line {bounded.Index} exceeds the maximum size.");
            var raw = bounded.Text!;
            if (string.IsNullOrWhiteSpace(raw)) continue;
            ForemanEvent evt;
            try
            {
                evt = JsonSerializer.Deserialize<ForemanEvent>(raw, _json)
                      ?? throw new InvalidDataException("Event log contains a null record.");
            }
            catch (Exception ex) when (ex is JsonException or NotSupportedException)
            {
                throw new InvalidDataException("Event log compaction refused a malformed record.", ex);
            }

            var lineBytes = Encoding.UTF8.GetByteCount(raw) + 1;
            tail.Enqueue((evt, lineBytes));
            bytes += lineBytes;
            while (tail.Count > targetEntries || (bytes > targetBytes && tail.Count > 1))
                bytes -= tail.Dequeue().Bytes;
        }
        return tail.Select(static item => item.Event).ToArray();
    }

    /// <summary>The outcome of a rotate: where the prior chain was archived, how many records it held, and the
    /// FRESH chain's anchor (head + count) the caller must publish as a superseding external witness.</summary>
    public sealed record RotateResult(string ArchivePath, long PriorCount, LogAnchor NewAnchor);

    /// <summary>
    /// Archives the current chain (preserving the evidence) and starts a fresh, freshly-sealed one. This is the
    /// recovery for a chain whose integrity baseline must be reset — e.g. after an offline restore reverted the
    /// log, leaving a permanent BrokenLink/rollback that is real but no longer actionable. The rotation is
    /// recorded in BOTH the closing old chain (its final record, preserved in the archive) and the opening new
    /// chain (its first record), so it is indelible on either side.
    ///
    /// Returns the archive path, the prior chained count, and the NEW chain's anchor so the caller can publish a
    /// SUPERSEDING external anchor to the OS event log. Without that, the next launch would read the stale anchor
    /// and (correctly) flag the now-absent old head as a rollback — re-raising the very alert this clears.
    ///
    /// SECURITY: re-baselining the tamper witness is a weakening action. The CALLER MUST presence-gate it and log
    /// it loudly (a silent reset would let a rogue same-user agent erase tracks). This method only does the file
    /// work; it never gates or hides anything.
    /// </summary>
    public RotateResult RotateAndReseal(string reason, DateTimeOffset now)
    {
        lock (_lock)
        {
            try
            {
                // 1. Close the OLD chain with a final, in-chain record of the rotation (kept in the archive).
                AppendCore(new MonitoringNoticeEvent(now, ForemanSeverity.Medium, "Foreman.LogRotate",
                    $"Event log rotated + re-sealed: {reason}. This is the final record of the prior chain."),
                    enforceRetention: false);
                var priorCount = _count;

                // 2. Archive the JSONL + its head seal to a UNIQUE sibling (move, never delete or overwrite — the
                //    point is to preserve evidence, so two rotates in the same second must not clobber each other).
                Directory.CreateDirectory(Path.GetDirectoryName(_file)!);
                var stamp = now.ToUnixTimeSeconds();
                var archive = $"{_file}.{stamp}.archived";
                for (var n = 1; File.Exists(archive) || File.Exists(archive + ".head"); n++)
                    archive = $"{_file}.{stamp}.{n}.archived";
                if (File.Exists(_file)) File.Move(_file, archive);
                if (File.Exists(HeadFile)) File.Move(HeadFile, archive + ".head");

                // 3. Reset ALL in-memory chain state so the next append seeds a fresh genesis from the absent file.
                ResetChainState();

                // 4. Open the NEW chain with its first record (writes a fresh file + fresh head seal).
                AppendCore(new MonitoringNoticeEvent(now, ForemanSeverity.Medium, "Foreman.LogRotate",
                    $"Fresh event-log chain established (prior chain of {priorCount} record(s) archived). Baseline re-sealed."),
                    enforceRetention: false);

                return new RotateResult(archive, priorCount, new LogAnchor(_headHash ?? LogChain.Genesis, _count));
            }
            catch
            {
                // Crash-consistency: a mid-rotate failure (e.g. the .head move or the new-chain append throws on a
                // disk-full / AV lock) must NOT leave a stale in-memory head chaining onto a moved/absent file —
                // that would silently corrupt the chain into a BrokenLink on the next launch, indistinguishable
                // from real tampering. Drop chain state so the next append re-seeds from whatever is on disk now
                // (or genesis if the file was already moved) and re-anchors cleanly. The failure surfaces to the
                // caller, which records it loudly.
                ResetChainState();
                throw;
            }
        }
    }

    // Resets every in-memory chain field to the "unseeded" state so the next AppendCore re-runs SeedState against
    // the current on-disk file. Kept in one place so a rotate (or any future reset) can't leave a field stale.
    private void ResetChainState()
    {
        _headHash = null;
        _count = 0;
        _recordCount = 0;
        _lastSequence = null;
        _lastRecordedAtUtc = null;
        _lastMonotonicTicks = null;
        _lastTemporalSessionId = null;
        _lastMonotonicFrequency = 0;
    }

    /// <summary>Loads persisted events oldest-first, skipping corrupt lines and trimming to maxEntries.</summary>
    public IReadOnlyList<ForemanEvent> Load()
    {
        lock (_lock)
        {
            try
            {
                if (!File.Exists(_file)) return [];

                // An oversized legacy log must not be materialized wholesale just because the operator opened the
                // Log view before a new event triggered append-time compaction. Stream its bounded tail instead.
                if (new FileInfo(_file).Length >= _maxBytes)
                {
                    var targetBytes = Math.Max(1, _maxBytes - Math.Max(1, _maxBytes / 10));
                    var bounded = ReadTailForCompaction(_maxEntries, targetBytes);
                    Rewrite(bounded);
                    return bounded;
                }

                // Keep only the tail we can return. A hostile file with millions of tiny records therefore cannot
                // turn the Log view into an unbounded list allocation even when maxBytes was configured unusually
                // high. Oversized/corrupt individual records remain on disk as evidence and are skipped for display.
                var events = new Queue<ForemanEvent>(Math.Min(_maxEntries, 1024));
                long validRecords = 0;
                var sawUnreadableRecord = false;
                foreach (var bounded in BoundedJsonlReader.Read(_file, MaxRecordChars))
                {
                    if (bounded.Oversized) { sawUnreadableRecord = true; continue; }
                    var line = bounded.Text!;
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    try
                    {
                        if (JsonSerializer.Deserialize<ForemanEvent>(line, _json) is { } e)
                        {
                            validRecords++;
                            events.Enqueue(e);
                            if (events.Count > _maxEntries) events.Dequeue();
                        }
                    }
                    catch { sawUnreadableRecord = true; /* skip a corrupt/partial line */ }
                }

                var retained = events.ToArray();
                if (validRecords > _maxEntries && !sawUnreadableRecord)
                {
                    Rewrite(retained);   // keep the file bounded across restarts (re-anchors the chain)
                }
                else if (validRecords <= _maxEntries)
                {
                    MigrateCanonicalDriftIfNeeded(retained);
                }
                return retained;
            }
            catch { return []; }
        }
    }

    private void MigrateCanonicalDriftIfNeeded(IReadOnlyList<ForemanEvent> events)
    {
        if (!_chain || events.Count == 0) return;
        var current = Verify();
        if (current.Status != VerifyStatus.BrokenLink ||
            !current.Message.Contains("content hash mismatch", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        if (!HistoricalStoredCanonicalChainVerifies())
            return;

        Rewrite(events);
    }

    private bool HistoricalStoredCanonicalChainVerifies()
    {
        string? prevHash = null;
        long chained = 0;
        var started = false;

        foreach (var bounded in BoundedJsonlReader.Read(_file, MaxRecordChars))
        {
            if (bounded.Oversized) return false;
            var line = bounded.Text!;
            if (string.IsNullOrWhiteSpace(line)) continue;
            ForemanEvent? e;
            try { e = JsonSerializer.Deserialize<ForemanEvent>(line, _json); }
            catch { return false; }
            if (e is null) continue;

            if (!started)
            {
                if (string.IsNullOrEmpty(e.Hash)) continue;
                started = true;
                prevHash = LogChain.Genesis;
            }
            else if (string.IsNullOrEmpty(e.Hash))
            {
                return false;
            }

            var expected = LogChain.ComputeHash(prevHash, HistoricalStoredCanonicalize(line));
            if (e.PrevHash != prevHash || e.Hash != expected)
                return false;

            prevHash = e.Hash;
            chained++;
        }

        if (!started) return false;

        var head = ReadHeadSeal();
        if (head is null)
            return !_signer.ExpectsSeal && !_timeAnchor.ExpectsAnchor;
        if (_signer.ExpectsSeal && !_signer.VerifyHead(head.HeadHash, head.Count, head.Seal))
            return false;
        if (_timeAnchor.ExpectsAnchor && !_timeAnchor.VerifyAnchor(head.HeadHash, head.Count, head.Temporal, head.TimeAnchor))
            return false;
        return head.Count == chained && head.HeadHash == prevHash;
    }

    private static string HistoricalStoredCanonicalize(string line)
    {
        var node = JsonNode.Parse(line)?.AsObject()
            ?? throw new JsonException("Event log record is not a JSON object.");
        node[nameof(ForemanEvent.Hash)] = null;
        node[nameof(ForemanEvent.PrevHash)] = null;
        return node.ToJsonString(_json);
    }

    /// <summary>
    /// Verifies the on-disk hash chain + head seal. A leading run of pre-chain records (no Hash) is treated as
    /// an unverifiable LEGACY prefix (not tamper), so enabling the chain over an existing log is graceful. A
    /// torn LAST line is an "unverified tail" (crash mid-append); a torn MIDDLE line is Corrupt. Read-only.
    /// </summary>
    public VerifyResult Verify()
    {
        lock (_lock)
        {
            if (!File.Exists(_file)) return VerifyResult.Empty;

            string? prevHash = null;   // null until the chain starts (after any legacy prefix)
            long chained = 0;
            var started = false;
            long? priorSequence = null;
            string? priorTemporalSession = null;
            long? priorMonotonicTicks = null;

            try
            {
                foreach (var bounded in BoundedJsonlReader.Read(_file, MaxRecordChars))
                {
                    var i = bounded.Index;
                    if (bounded.Oversized)
                    {
                        // Only a newline-less final record can be crash debris. A newline-terminated oversized
                        // record was durably committed (or planted) and must surface as corruption, not as an OK
                        // UnverifiedTail result.
                        return bounded.Terminated
                            ? VerifyResult.Corrupt(i)
                            : VerifyResult.UnverifiedTail(chained);
                    }

                    var line = bounded.Text!;
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    ForemanEvent? e;
                    try { e = JsonSerializer.Deserialize<ForemanEvent>(line, _json); }
                    catch
                    {
                        return bounded.Terminated
                            ? VerifyResult.Corrupt(i)
                            : VerifyResult.UnverifiedTail(chained);
                    }
                    if (e is null) continue;

                    if (!started)
                    {
                        if (string.IsNullOrEmpty(e.Hash)) continue;   // legacy pre-chain prefix
                        started = true;
                        prevHash = LogChain.Genesis;
                    }

                    var expected = LogChain.ComputeHash(prevHash, LogChain.Canonicalize(e, _json));
                    if (e.PrevHash != prevHash) return VerifyResult.BrokenLink(i, "prev-hash mismatch (dropped/reordered)");
                    if (e.Hash != expected)     return VerifyResult.BrokenLink(i, "content hash mismatch (edited)");
                    if (e.Sequence is { } seq)
                    {
                        if (priorSequence is { } prior && seq <= prior)
                            return VerifyResult.BrokenLink(i, "sequence did not increase");
                        priorSequence = seq;
                    }
                    if (e.TemporalSessionId is { } session && e.MonotonicTicks is { } mono)
                    {
                        if (string.Equals(session, priorTemporalSession, StringComparison.Ordinal) &&
                            priorMonotonicTicks is { } priorMono &&
                            mono < priorMono)
                        {
                            return VerifyResult.BrokenLink(i, "monotonic clock regressed within session");
                        }
                        priorTemporalSession = session;
                        priorMonotonicTicks = mono;
                    }
                    prevHash = e.Hash;
                    chained++;
                }
            }
            catch (IOException ex) { return VerifyResult.Unavailable(ex.GetType().Name); }
            catch (UnauthorizedAccessException ex) { return VerifyResult.Unavailable(ex.GetType().Name); }

            if (!started) return VerifyResult.Valid(0);   // empty or all-legacy: nothing chained to verify

            var head = ReadHeadSeal();
            if (head is null)
                return _signer.ExpectsSeal || _timeAnchor.ExpectsAnchor
                    ? VerifyResult.HeadUnsealed(chained)
                    : VerifyResult.Valid(chained);
            if (_signer.ExpectsSeal && !_signer.VerifyHead(head.HeadHash, head.Count, head.Seal))
                return VerifyResult.HeadUnsealed(chained);                  // seal forged / wrong key
            if (_timeAnchor.ExpectsAnchor && !_timeAnchor.VerifyAnchor(head.HeadHash, head.Count, head.Temporal, head.TimeAnchor))
                return VerifyResult.HeadUnsealed(chained);                  // time anchor forged / missing
            if (head.Count != chained || head.HeadHash != prevHash)
                return VerifyResult.HeadMismatch(chained);                  // authentic seal, file truncated/extended
            return VerifyResult.Valid(chained);
        }
    }

    // Seed the in-memory head from the file so a new store instance continues the existing chain. Counts only
    // CHAINED records (those with a Hash); a legacy prefix leaves the head at genesis (a fresh chain appends
    // after it). A crash-torn tail (a newline-less final record) is REPAIRED so a later append can still proceed;
    // any malformed newline-terminated line fails closed so damage can't be turned into a hidden middle gap.
    private void SeedState()
    {
        _headHash = LogChain.Genesis;
        _count = 0;
        _recordCount = 0;
        _lastSequence = 0;
        _lastRecordedAtUtc = null;
        _lastMonotonicTicks = null;
        _lastTemporalSessionId = null;
        _lastMonotonicFrequency = 0;
        try
        {
            if (!File.Exists(_file)) return;
            RepairUncommittedTail();   // drop a crash-torn final record so this append can't merge onto it
            foreach (var bounded in BoundedJsonlReader.Read(_file, MaxRecordChars))
            {
                if (bounded.Oversized)
                    throw new InvalidDataException($"Event log record at line {bounded.Index} exceeds the maximum size.");
                var raw = bounded.Text!;
                if (string.IsNullOrWhiteSpace(raw)) continue;
                try
                {
                    var e = JsonSerializer.Deserialize<ForemanEvent>(raw, _json);
                    if (e is null) continue;
                    _recordCount++;
                    if (!string.IsNullOrEmpty(e.Hash)) { _headHash = e.Hash; _count++; }
                    if (e.Sequence is { } seq && seq > _lastSequence) _lastSequence = seq;
                    if (e.RecordedAtUtc is { } rec) _lastRecordedAtUtc = rec;
                    if (e.MonotonicTicks is { } mono) _lastMonotonicTicks = mono;
                    if (e.TemporalSessionId is { } session) _lastTemporalSessionId = session;
                    if (e.MonotonicFrequency is { } freq) _lastMonotonicFrequency = freq;
                }
                catch (Exception ex)
                {
                    throw new InvalidDataException(
                        "Cannot append to a malformed event log; refusing to hide the damaged evidence.", ex);
                }
            }
        }
        catch
        {
            ResetChainState();
            throw;
        }
    }

    // A committed record is always persisted as "<json>\n". A log that does not end in a newline therefore
    // carries a crash-torn tail — the partial bytes of an append that never finished. Those bytes were never a
    // durable chain record; left in place, the NEXT append would concatenate onto them and turn recoverable
    // crash debris into a permanent malformed MIDDLE line (which then fails closed forever, permanently stalling
    // persistence). Truncate back to the last complete record so the append path stays available after a crash.
    // Read paths (Load/Verify) already tolerate the torn tail without mutating; only the append path must
    // physically repair it. Middle corruption is deliberately NOT repaired here — the reader above still fails
    // closed on any parse error among the surviving newline-terminated lines, so this cannot mask a tampered
    // interior record (which the head seal would in any case catch as a HeadMismatch).
    private void RepairUncommittedTail()
    {
        try
        {
            using var fs = new FileStream(_file, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            if (fs.Length == 0) return;
            fs.Position = fs.Length - 1;
            if (fs.ReadByte() == '\n') return;   // last append committed cleanly — nothing to repair

            // Serialized records contain no literal newline (WriteIndented=false escapes '\n' as "\\n"), so the
            // last '\n' in the file is always the terminator of the previous complete record. Scan back to it and
            // drop everything after it. The scan is bounded by one record's length regardless of file size.
            for (var pos = fs.Length - 2; pos >= 0; pos--)
            {
                fs.Position = pos;
                if (fs.ReadByte() == '\n') { fs.SetLength(pos + 1); return; }
            }
            fs.SetLength(0);   // no complete record at all — the very first append was torn
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Could not repair (file locked, transient IO). Leave the file untouched: the reader above then fails
            // closed on the unparseable tail, surfacing the failure to the caller (and retrying on the next
            // append) rather than risking a merged, silently-corrupt line.
        }
    }

    // Trimming drops the genesis and the PrevHash links before the cut, so we RE-ANCHOR: the first retained
    // record becomes the new genesis and the chain is recomputed forward, then the head is re-sealed. A
    // re-anchored trim is byte-indistinguishable from a malicious truncate — acceptable only because re-sealing
    // requires the signer (the TPM key in P3); Verify reports a trimmed file as valid from the new anchor.
    private void Rewrite(IReadOnlyList<ForemanEvent> events, bool throwOnFailure = false)
    {
        try
        {
            var sb = new StringBuilder(events.Count * 128);
            string? prev = LogChain.Genesis;
            long n = 0;
            ForemanEvent? last = null;
            foreach (var e in events)
            {
                var rec = e;
                if (_chain)
                {
                    var canonical = LogChain.Canonicalize(e, _json);
                    var hash = LogChain.ComputeHash(prev, canonical);
                    rec = e with { PrevHash = prev, Hash = hash };
                    prev = hash;
                    n++;
                }
                sb.Append(SerializeBoundedRecord(rec)).Append('\n');
                last = rec;
            }
            var tmp = _file + ".rewrite.tmp";
            try
            {
                File.WriteAllText(tmp, sb.ToString());
                if (File.Exists(_file)) File.Replace(tmp, _file, destinationBackupFileName: null);
                else File.Move(tmp, _file);
            }
            finally
            {
                try { if (File.Exists(tmp)) File.Delete(tmp); } catch { /* best-effort temp cleanup */ }
            }
            _recordCount = events.Count;
            _lastSequence = last?.Sequence ?? events.Count;
            _lastRecordedAtUtc = last?.RecordedAtUtc;
            _lastMonotonicTicks = last?.MonotonicTicks;
            _lastTemporalSessionId = last?.TemporalSessionId;
            _lastMonotonicFrequency = last?.MonotonicFrequency ?? 0;
            if (_chain)
            {
                _headHash = prev;
                _count = n;
                WriteHeadSeal(_signer.SealHead(prev!, n));
                // The rewrite invalidated every previously-witnessed head — let the host publish a superseding
                // external anchor NOW, not at the next clean stop (a kill in between would leave the stale witness
                // to false-alarm the next launch as a rollback).
                if (n > 0) ChainRewritten?.Invoke(new LogAnchor(prev!, n));
            }
        }
        catch when (!throwOnFailure) { /* load-time repair remains best-effort */ }
    }

    // The head seal lives in a sibling events.log.head file (small JSON), written atomically, so routine
    // appends never rewrite the JSONL. Under the no-op signer (P1) SealHead returns null and no file is written.
    private void WriteHeadSeal(string? seal)
    {
        var checkpoint = BuildTemporalCheckpoint();
        var anchor = checkpoint is null ? null : _timeAnchor.AnchorHead(_headHash ?? LogChain.Genesis, _count, checkpoint);
        if (seal is null && anchor is null) return;
        try
        {
            var json = JsonSerializer.Serialize(
                new HeadSeal(_headHash ?? LogChain.Genesis, _count, seal ?? string.Empty, checkpoint, anchor),
                _json);
            var tmp = HeadFile + ".tmp";
            File.WriteAllText(tmp, json);
            if (File.Exists(HeadFile)) File.Replace(tmp, HeadFile, destinationBackupFileName: null);
            else File.Move(tmp, HeadFile);
        }
        catch { /* best-effort; a missing/failed seal surfaces at Verify */ }
    }

    private HeadSeal? ReadHeadSeal()
    {
        try
        {
            if (!File.Exists(HeadFile)) return null;
            using var stream = new FileStream(HeadFile, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length > MaxHeadFileBytes) return null;
            return JsonSerializer.Deserialize<HeadSeal>(stream, _json);
        }
        catch { return null; }
    }

    private static string SerializeBoundedRecord(ForemanEvent evt)
    {
        var serialized = JsonSerializer.Serialize(evt, _json);
        if (serialized.Length > MaxRecordChars)
            throw new InvalidDataException($"Event log record exceeds the {MaxRecordChars}-character maximum.");
        return serialized;
    }

    private string[] DetectTemporalAnomalies(DateTimeOffset recordedAt, long monotonicTicks)
    {
        var anomalies = new List<string>();
        if (_lastRecordedAtUtc is { } lastWall && recordedAt < lastWall)
            anomalies.Add("wall-clock-moved-backward");
        if (_lastMonotonicTicks is { } lastMono && monotonicTicks < lastMono)
            anomalies.Add("monotonic-clock-regressed");

        if (_lastRecordedAtUtc is { } prevWall &&
            _lastMonotonicTicks is { } prevMono &&
            _lastMonotonicFrequency > 0 &&
            monotonicTicks >= prevMono)
        {
            var wallDeltaMs = (recordedAt - prevWall).TotalMilliseconds;
            var monoDeltaMs = (monotonicTicks - prevMono) * 1000.0 / _lastMonotonicFrequency;
            if (Math.Abs(wallDeltaMs - monoDeltaMs) > TimeSpan.FromMinutes(5).TotalMilliseconds)
                anomalies.Add("wall-monotonic-divergence");
        }

        return anomalies.ToArray();
    }

    private TemporalCheckpoint? BuildTemporalCheckpoint()
    {
        return _lastTemporalSessionId is null ||
               _lastSequence is null ||
               _lastRecordedAtUtc is null ||
               _lastMonotonicTicks is null ||
               _lastMonotonicFrequency <= 0
            ? null
            : new TemporalCheckpoint(
                _lastTemporalSessionId,
                _lastSequence.Value,
                _lastRecordedAtUtc.Value,
                _lastMonotonicTicks.Value,
                _lastMonotonicFrequency);
    }

}

internal readonly record struct BoundedJsonlLine(int Index, string? Text, bool Oversized, bool Terminated);

/// <summary>
/// Fixed-buffer JSONL reader. StreamReader.ReadLine/File.ReadLines allocate a string proportional to an
/// attacker-controlled line before the caller can reject it; this reader stops retaining characters at the cap
/// and drains the remainder of that line with constant memory.
/// </summary>
internal static class BoundedJsonlReader
{
    public static IEnumerable<BoundedJsonlLine> Read(string path, int maxLineChars)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxLineChars);

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true,
            bufferSize: 4096, leaveOpen: false);
        var buffer = new char[4096];
        var line = new StringBuilder(Math.Min(maxLineChars, buffer.Length));
        var oversized = false;
        var index = 0;
        int read;
        while ((read = reader.Read(buffer, 0, buffer.Length)) > 0)
        {
            for (var i = 0; i < read; i++)
            {
                var ch = buffer[i];
                if (ch == '\n')
                {
                    if (!oversized && line.Length > 0 && line[^1] == '\r') line.Length--;
                    yield return new BoundedJsonlLine(index++, oversized ? null : line.ToString(), oversized, Terminated: true);
                    line.Clear();
                    oversized = false;
                    continue;
                }

                if (oversized) continue;
                if (line.Length >= maxLineChars)
                {
                    line.Clear();
                    oversized = true;
                    continue;
                }
                line.Append(ch);
            }
        }

        if (oversized || line.Length > 0)
            yield return new BoundedJsonlLine(index, oversized ? null : line.ToString(), oversized, Terminated: false);
    }
}
