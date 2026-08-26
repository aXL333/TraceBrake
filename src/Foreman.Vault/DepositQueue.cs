using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Foreman.Vault;

/// <summary>
/// A clear, append-only file of ECIES-encrypted deposits (one JSON <see cref="DepositCrypto.Envelope"/> per line). An
/// agent self-signup while the vault is LOCKED appends here (encrypt-only, public key); on unlock the operator drains,
/// reviews, and commits. The file is never secret-bearing in the clear - each line is ciphertext to the vault's deposit
/// key, decryptable only with the private key sealed inside the vault. Locked-safe (enqueue + count need no key).
///
/// The clear public key means ANY same-user process can append a valid (forged) envelope, so this layer enforces a hard
/// size CAP (anti-flood) and a per-line RESILIENT drain (one junk line can't deny the operator the real deposits);
/// authenticity rests entirely on the operator reviewing + committing each drained deposit (see VaultService / the
/// review UI). Nothing here auto-commits.
/// </summary>
public sealed class DepositQueue(string path)
{
    private readonly string _path = path;
    private readonly object _gate = new();

    /// <summary>Hard cap on queued deposits: a flood of forged appends can't grow the file without bound while locked
    /// (which would pressure the operator into bulk-accepting on unlock). Persists across relaunch, unlike the in-memory
    /// signup rate window. Hitting it is itself an abuse signal the caller should surface.</summary>
    public const int MaxQueued = 50;
    public const long MaxQueueBytes = 4L * 1024 * 1024;
    public const int MaxLineChars = 128 * 1024;
    public const int MaxClaimChars = 4096;
    private const int MaxLinesToInspect = MaxQueued * 4;
    private static readonly JsonSerializerOptions JsonOptions = new() { MaxDepth = 16 };

    /// <summary>The cleartext deposit an agent created while the vault was locked, surfaced to the operator on unlock.
    /// Origin/ByHarness/CreatedAtUtc are the (unauthenticated) caller's CLAIMS - the review UI must present them as such.</summary>
    public sealed record PendingDeposit(string Origin, string? Username, string Password, string ByHarness, string CreatedAtUtc);

    /// <summary>A drain result: the deposits that decrypted cleanly, plus a count of lines that did NOT (wrong key /
    /// tamper / corruption), so the operator can be warned the queue is suspect without losing the readable deposits.</summary>
    public sealed record DrainResult(IReadOnlyList<PendingDeposit> Deposits, int Failed);

    /// <summary>Number of queued deposits (line count) - readable while locked, without the private key.</summary>
    public int Count { get { lock (_gate) return CountLocked(); } }

    private int CountLocked()
    {
        if (!File.Exists(_path)) return 0;
        if (new FileInfo(_path).Length > MaxQueueBytes) return MaxQueued;
        var count = 0;
        foreach (var line in ReadBoundedLinesLocked())
        {
            if (line.Oversized || !string.IsNullOrWhiteSpace(line.Text)) count++;
            if (count >= MaxQueued) return MaxQueued;
        }
        return count;
    }

    /// <summary>Encrypt <paramref name="deposit"/> to the deposit public key and append it. Locked-safe (public key
    /// only). Returns false (appending nothing) if the queue is already at <see cref="MaxQueued"/> - the caller should
    /// treat a full queue as an abuse/flood signal and alert, not retry.</summary>
    public bool Enqueue(byte[] publicSpki, PendingDeposit deposit)
    {
        if (!IsBounded(deposit.Origin) || !IsBoundedNullable(deposit.Username) || !IsBounded(deposit.Password) ||
            !IsBounded(deposit.ByHarness) || !IsBounded(deposit.CreatedAtUtc))
            return false;
        var plaintext = JsonSerializer.Serialize(deposit, JsonOptions);
        if (Encoding.UTF8.GetByteCount(plaintext) > DepositCrypto.MaxPlaintextBytes) return false;
        var line = JsonSerializer.Serialize(DepositCrypto.Encrypt(publicSpki, plaintext), JsonOptions);
        if (line.Length > MaxLineChars) return false;
        lock (_gate)
        {
            if (CountLocked() >= MaxQueued) return false;
            var dir = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.AppendAllText(_path, line + Environment.NewLine);
            return true;
        }
    }

    /// <summary>Decrypt every queued deposit with the vault's private key (unlock-time). Per-line RESILIENT: a line that
    /// fails to parse / decrypt / authenticate is COUNTED (<see cref="DrainResult.Failed"/>) and skipped, never throwing
    /// away the good deposits in the same file - a single junk line must not DoS the operator's real pending credentials.
    /// Bad lines are left in place (Clear is a separate, post-review step) for forensics.</summary>
    public DrainResult Drain(byte[] privatePkcs8)
    {
        lock (_gate)
        {
            if (!File.Exists(_path)) return new DrainResult([], 0);
            var deposits = new List<PendingDeposit>();
            var failed = 0;
            var inspected = 0;
            foreach (var bounded in ReadBoundedLinesLocked())
            {
                if (++inspected > MaxLinesToInspect) { failed++; break; }
                if (bounded.Oversized) { failed++; continue; }
                var line = bounded.Text;
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var env = JsonSerializer.Deserialize<DepositCrypto.Envelope>(line, JsonOptions)
                              ?? throw new FormatException("corrupt deposit queue line");
                    var json = DepositCrypto.Decrypt(privatePkcs8, env);   // throws on wrong key / tamper
                    var deposit = JsonSerializer.Deserialize<PendingDeposit>(json, JsonOptions)
                                  ?? throw new FormatException("corrupt deposit record");
                    if (!IsBounded(deposit.Origin) || !IsBoundedNullable(deposit.Username) || !IsBounded(deposit.Password) ||
                        !IsBounded(deposit.ByHarness) || !IsBounded(deposit.CreatedAtUtc))
                        throw new FormatException("deposit claim exceeds field limits");
                    deposits.Add(deposit);
                }
                catch (Exception ex) when (ex is CryptographicException or FormatException or JsonException or ArgumentException or NotSupportedException)
                {
                    failed++;   // suspect line: surfaced via the count, never poisons the readable deposits
                }
            }
            return new DrainResult(deposits, failed);
        }
    }

    private static bool IsBounded(string? value) => value is not null && value.Length <= MaxClaimChars;
    private static bool IsBoundedNullable(string? value) => value is null || value.Length <= MaxClaimChars;

    private sealed record BoundedLine(string? Text, bool Oversized);

    // File.ReadAllLines/ReadLine allocate in proportion to an attacker-controlled line. This fixed-buffer reader
    // caps both the whole file and each materialized line before JSON/base64 processing.
    private IEnumerable<BoundedLine> ReadBoundedLinesLocked()
    {
        using var stream = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > MaxQueueBytes)
        {
            yield return new BoundedLine(null, true);
            yield break;
        }

        using var reader = new StreamReader(stream);
        var buffer = new char[4096];
        var line = new StringBuilder(Math.Min(MaxLineChars, 4096));
        var oversized = false;
        int read;
        while ((read = reader.Read(buffer, 0, buffer.Length)) > 0)
        {
            for (var i = 0; i < read; i++)
            {
                var ch = buffer[i];
                if (ch == '\n')
                {
                    if (line.Length > 0 && line[^1] == '\r') line.Length--;
                    yield return new BoundedLine(oversized ? null : line.ToString(), oversized);
                    line.Clear();
                    oversized = false;
                    continue;
                }
                if (oversized) continue;
                if (line.Length >= MaxLineChars)
                {
                    line.Clear();
                    oversized = true;
                    continue;
                }
                line.Append(ch);
            }
        }

        if (oversized || line.Length > 0)
            yield return new BoundedLine(oversized ? null : line.ToString(), oversized);
    }

    /// <summary>Remove the queue file (only AFTER the operator has reviewed + committed/rejected the drained deposits).</summary>
    public void Clear()
    {
        lock (_gate) { if (File.Exists(_path)) File.Delete(_path); }
    }
}
