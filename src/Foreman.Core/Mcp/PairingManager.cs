using System.Security.Cryptography;
using System.Text;

namespace Foreman.Core.Mcp;

public sealed record PairingResult(bool Ok, string? Origin, string Reason)
{
    public static PairingResult Fail(string reason) => new(false, null, reason);
    public static PairingResult Success(string origin) => new(true, origin, "paired");
}

/// <summary>
/// Server-side state machine for pairing a TraceBrake browser extension over loopback WITHOUT the pairing code
/// ever crossing the wire. Flow: the operator clicks "Pair" in TraceBrake's GUI → <see cref="Begin"/> mints a
/// short, human-typeable code shown on screen → the user types it into the extension → the extension proves it
/// holds the code via a <see cref="ChallengeResponse"/> (the code is the HMAC key; only a fresh nonce + the
/// response transit the link) → on success the extension's <c>chrome-extension://</c> origin is returned to add
/// to the allow-list. Single pending pairing, short TTL, single-use: a local process that didn't get the
/// on-screen code can't pair, a stale challenge can't be replayed, and DNS-rebinding is moot (the loopback
/// Host check guards the endpoint and the rebinding page never sees the code).
/// </summary>
public sealed class PairingManager
{
    private readonly object _gate = new();
    private readonly Func<DateTimeOffset> _now;
    private readonly TimeSpan _ttl;
    private string? _code;          // on-screen pairing secret (HMAC key) — never sent over the wire
    private string? _challenge;     // current nonce
    private DateTimeOffset _expires;

    public PairingManager(Func<DateTimeOffset>? now = null, TimeSpan? ttl = null)
    {
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _ttl = ttl ?? TimeSpan.FromMinutes(2);
    }

    public bool IsPending
    {
        get { lock (_gate) { return _code is not null && _now() < _expires; } }
    }

    /// <summary>Begin pairing: mint the on-screen code and arm the window. Returns the code to display.</summary>
    public string Begin()
    {
        lock (_gate)
        {
            _code = NewCode();
            _challenge = null;
            _expires = _now() + _ttl;
            return _code;
        }
    }

    /// <summary>Issue a fresh challenge nonce for the extension to answer; null if no pairing is armed.</summary>
    public string? IssueChallenge()
    {
        lock (_gate)
        {
            if (_code is null || _now() >= _expires) return null;
            _challenge = ChallengeResponse.NewChallenge();
            return _challenge;
        }
    }

    /// <summary>Verify the extension's response against the armed code + current challenge and that the origin
    /// is a browser extension. Single-use: a success or an expired window clears the pairing.</summary>
    public PairingResult Complete(string? origin, string? response)
    {
        lock (_gate)
        {
            if (_code is null || _now() >= _expires) { Clear(); return PairingResult.Fail("No active pairing window."); }
            if (_challenge is null) return PairingResult.Fail("Request a challenge first.");
            if (!IsExtensionOrigin(origin)) return PairingResult.Fail("Origin is not a browser extension.");
            if (!ChallengeResponse.Verify(_code, _challenge, response))
            {
                _challenge = null;   // burn the nonce; the operator can retry within the window
                return PairingResult.Fail("Pairing code did not match.");
            }
            var paired = origin!.TrimEnd('/');
            Clear();
            return PairingResult.Success(paired);
        }
    }

    /// <summary>
    /// Auto-pair WITHOUT the on-screen code: succeeds if a pairing window is currently armed and the origin is a
    /// browser extension. The operator's act of arming the window (clicking "Pair") is the consent — no code is
    /// verified, so this is strictly weaker than <see cref="Complete"/> and the caller should only use it under an
    /// explicit opt-in. Single-use: consumes the armed window like a successful Complete.
    /// </summary>
    public PairingResult AutoComplete(string? origin)
    {
        lock (_gate)
        {
            if (_code is null || _now() >= _expires) { Clear(); return PairingResult.Fail("No active pairing window."); }
            if (!IsExtensionOrigin(origin)) return PairingResult.Fail("Origin is not a browser extension.");
            var paired = origin!.TrimEnd('/');
            Clear();
            return PairingResult.Success(paired);
        }
    }

    public void Cancel() { lock (_gate) { Clear(); } }

    private void Clear() { _code = null; _challenge = null; _expires = default; }

    /// <summary>True when <paramref name="origin"/> is a first-party browser extension scheme.</summary>
    public static bool IsExtensionOrigin(string? origin) =>
        !string.IsNullOrWhiteSpace(origin)
        && (origin.StartsWith("chrome-extension://", StringComparison.OrdinalIgnoreCase)
            || origin.StartsWith("moz-extension://", StringComparison.OrdinalIgnoreCase));

    // Short, human-typeable, no-confusable-character code (~50 bits) — ample for a single-use, 2-minute,
    // rate-limited, loopback-only window. Shown as e.g. "ABCDE-FGHJK".
    private static string NewCode()
    {
        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";   // no 0/O/1/I
        var bytes = RandomNumberGenerator.GetBytes(10);
        var sb = new StringBuilder(11);
        for (var i = 0; i < bytes.Length; i++)
        {
            if (i == 5) sb.Append('-');
            sb.Append(alphabet[bytes[i] % alphabet.Length]);
        }
        return sb.ToString();
    }
}
