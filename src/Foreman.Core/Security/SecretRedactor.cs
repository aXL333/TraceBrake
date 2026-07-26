using System.Text.RegularExpressions;
using Foreman.Core.Models;

namespace Foreman.Core.Security;

/// <summary>
/// Masks secret-shaped substrings in strings that LEAVE Foreman — disk persistence (events.log.jsonl),
/// MCP tool output, CSV export, clipboard/audit prompts, and client notifications.
///
/// This is deliberately an EGRESS transform, never a construction-time one. The raw command line stays
/// intact on the live <see cref="ProcessRecord"/> and inside <see cref="CommandAnalyzer"/> so detection
/// and the kill path keep working; only the copies that leave the process are masked. Redacting at
/// construction would blind the detector (a token-bearing <c>curl … | bash</c> might stop matching).
///
/// Best-effort hygiene, not a guarantee: it targets well-known credential SHAPES and key/flag/header/URL
/// forms. It deliberately does NOT do generic high-entropy detection — that false-positives on hashes,
/// git SHAs, GUIDs, and ordinary base64 — so a novel secret format can still slip through.
/// </summary>
public static class SecretRedactor
{
    public const string Mask = "[REDACTED]";

    private const RegexOptions Opts =
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    // Ordered: structured forms first (they keep a visible prefix so the reader sees WHAT was masked),
    // then standalone token shapes (whole-match replace). All are anchored/length-bounded to limit
    // false positives. Mask contains no secret-shaped substring, so Redact is idempotent.
    private static readonly (Regex Rx, string Replacement)[] Rules =
    [
        // Authorization headers: "Authorization: Bearer <token>" / Basic / token / digest
        (new Regex(@"(authorization:\s*(?:bearer|basic|token|digest)?\s*)\S+", Opts), "$1" + Mask),

        // Credentials embedded in a URL userinfo: scheme://user:pass@host  (mask the password)
        (new Regex(@"([a-z][a-z0-9+.\-]*://[^/\s:@]+:)[^/\s:@]+(@)", Opts), "$1" + Mask + "$2"),

        // --password / --token / --api-key / --secret <value>  (space- or =-separated)
        (new Regex(@"(--?(?:password|passwd|pwd|token|api[-_]?key|secret|access[-_]?key|client[-_]?secret|auth[-_]?token)[ =]+)\S+", Opts), "$1" + Mask),

        // KEY=value / KEY: value where KEY names a secret — incl. env style (GITHUB_TOKEN, MY_API_KEY, DB_PASSWORD)
        (new Regex(@"\b([a-z0-9_]*(?:password|passwd|pwd|secret|api[-_]?key|apikey|token|access[-_]?key|credential)[a-z0-9_]*\s*[=:]\s*)[^\s;,""']+", Opts), "$1" + Mask),

        // Standalone token shapes
        (new Regex(@"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", Opts), Mask),  // JWT
        (new Regex(@"\bgh[pousr]_[A-Za-z0-9]{30,}", Opts), Mask),                                 // GitHub PAT
        (new Regex(@"\bxox[baprs]-[A-Za-z0-9\-]{10,}", Opts), Mask),                              // Slack token
        (new Regex(@"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}", Opts), Mask),                      // OpenAI / Anthropic
        (new Regex(@"\bAIza[0-9A-Za-z_\-]{35,}", Opts), Mask),                                    // Google API key (>=35 body)
        (new Regex(@"\bAKIA[0-9A-Z]{16}\b", Opts), Mask),                                          // AWS access key id
        (new Regex(@"\bsk_(?:live|test)_[A-Za-z0-9]{20,}", Opts), Mask),                            // Stripe secret key
        (new Regex(@"\brk_(?:live|test)_[A-Za-z0-9]{20,}", Opts), Mask),                            // Stripe restricted key
        (new Regex(@"\bgithub_pat_[A-Za-z0-9_]{30,}", Opts), Mask),                                 // GitHub fine-grained PAT
        (new Regex(@"\bglpat-[A-Za-z0-9_\-]{20,}", Opts), Mask),                                    // GitLab PAT
        (new Regex(@"\bnpm_[A-Za-z0-9]{36}\b", Opts), Mask),                                        // npm automation token
        (new Regex(@"\bhf_[A-Za-z0-9]{30,}", Opts), Mask),                                          // Hugging Face token
        (new Regex(@"\bxai-[A-Za-z0-9]{20,}", Opts), Mask),                                         // xAI key
        (new Regex(@"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}", Opts), Mask),                 // SendGrid key
        // PEM private-key block (RSA/EC/OPENSSH/PGP). Singleline so '.' spans the base64 body across newlines.
        (new Regex(@"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----",
                   Opts | RegexOptions.Singleline), Mask),
    ];

    private static readonly Regex PaymentCardCandidate = new(
        @"(?<!\d)(?:\d[ -]?){11,18}\d(?!\d)", Opts, TimeSpan.FromMilliseconds(50));

    private static readonly Regex NamedCardValue = new(
        @"(\b(?:card\s*(?:number|no\.?|#|security\s*code|expiry)|payment\s*card|credit\s*card|debit\s*card|pan|cvv|cvc|expiration)\s*[=:]\s*)[^\s;,""']+",
        Opts, TimeSpan.FromMilliseconds(50));

    /// <summary>Returns <paramref name="input"/> with secret-shaped substrings masked. Idempotent.</summary>
    public static string Redact(string? input)
    {
        if (string.IsNullOrEmpty(input)) return input ?? string.Empty;
        var s = input;
        foreach (var (rx, replacement) in Rules)
            s = rx.Replace(s, replacement);
        s = NamedCardValue.Replace(s, "$1" + Mask);
        s = PaymentCardCandidate.Replace(s, static match =>
            PaymentCardDetection.PassesLuhn(match.Value) ? Mask : match.Value);
        return s;
    }

    /// <summary>
    /// Returns a redacted copy of an event for egress (persistence, MCP, notifications). Preserves Id,
    /// Acknowledged, type, and all other fields; only the secret-bearing text is masked. The original
    /// event in the in-memory EventBus history is untouched, so the local operator's live view stays raw.
    /// </summary>
    public static ForemanEvent RedactEvent(ForemanEvent evt) => evt switch
    {
        CommandAlertEvent c => c with { CommandLine = Redact(c.CommandLine), Message = Redact(c.Message) },
        // PermissionViolationEvent carries the offending path/command in Detail, which is persisted — mask it too.
        PermissionViolationEvent p => p with { Message = Redact(p.Message), Detail = Redact(p.Detail) },
        _                   => evt with { Message = Redact(evt.Message) },
    };
}
