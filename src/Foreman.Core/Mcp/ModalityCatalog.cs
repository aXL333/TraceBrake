namespace Foreman.Core.Mcp;

/// <summary>The fixed set of basic modalities the closed loop supports. Deliberately small + structured so a
/// tiny, heavily-quantised on-device model can execute them reliably (see the closed-loop spec).</summary>
public enum ModalityKind { LogReport, SelfCheck, Triage, Extract, Redact }

/// <summary>Who runs a modality: an <see cref="Agent"/>-facing house-rule delivered to the harness over MCP,
/// or a Foreman-<see cref="Internal"/> micro-task the tiered inference runs on data.</summary>
public enum ModalityAudience { Agent, Internal }

public enum ModalityStatus { Valid, Escalate }

/// <summary>Outcome of validating a model/agent output against a modality's constrained contract. Anything
/// not cleanly valid — garbage, ambiguity, or an "unsure" — returns <see cref="ModalityStatus.Escalate"/>:
/// the "validate, never trust garbage; bump a tier instead" rule that makes weak models safe to use.</summary>
public sealed record ModalityCheck(ModalityStatus Status, string Normalized)
{
    public bool ShouldEscalate => Status == ModalityStatus.Escalate;
    public static ModalityCheck Valid(string normalized) => new(ModalityStatus.Valid, normalized);
    public static readonly ModalityCheck Escalate = new(ModalityStatus.Escalate, "");
}

public sealed record Modality(string Id, string Title, ModalityKind Kind, ModalityAudience Audience, string Instruction);

/// <summary>
/// The closed loop's modality set + their validate-or-escalate contracts. Pure + unit-tested. The actual
/// model invocation (Nano → LM Studio → cloud → heuristics) is the runtime's job; this defines WHAT the
/// modalities are, how their output is constrained, and when to escalate a tier.
/// </summary>
public static class ModalityCatalog
{
    public static IReadOnlyList<Modality> All { get; } =
    [
        new("log-report", "Log report", ModalityKind.LogReport, ModalityAudience.Agent,
            "In 8 short lines or fewer, report what you've done this session: tasks, files changed, commands run. " +
            "Plain list, no prose padding."),
        new("self-check", "Self-check vs Foreman", ModalityKind.SelfCheck, ModalityAudience.Agent,
            "Ask TraceBrake what it sees about you (get_behavior_metrics, get_my_permissions, list_recent_events). " +
            "If nothing is flagged, reply exactly 'clean'. If something is flagged, fix your own mess and explain " +
            "it in one short line per item. Don't pad."),
        new("triage", "Alert triage", ModalityKind.Triage, ModalityAudience.Internal,
            "Classify the alert as exactly one word: benign, suspicious, or unsure."),
        new("extract", "Field extraction", ModalityKind.Extract, ModalityAudience.Internal,
            "Extract the single requested field. Output only the value, nothing else."),
        new("redact", "Secret redaction", ModalityKind.Redact, ModalityAudience.Internal,
            "Return the text with any secret, credential, token, key, or PII replaced by [REDACTED]. " +
            "Change nothing else."),
    ];

    public static Modality? Get(string id) =>
        All.FirstOrDefault(m => string.Equals(m.Id, id, StringComparison.OrdinalIgnoreCase));

    public static IEnumerable<Modality> ForAudience(ModalityAudience audience) =>
        All.Where(m => m.Audience == audience);

    /// <summary>The Agent-facing modality ids — the default "house rules" a harness honours when none are set.</summary>
    public static IReadOnlyList<string> DefaultAgentModalities { get; } =
        ForAudience(ModalityAudience.Agent).Select(m => m.Id).ToArray();

    private const int LogReportMaxLines = 8;
    private const int ExtractMaxChars = 200;

    /// <summary>Validate a candidate output against the modality's constrained contract.</summary>
    public static ModalityCheck Validate(ModalityKind kind, string? output)
    {
        if (string.IsNullOrWhiteSpace(output)) return ModalityCheck.Escalate;
        var trimmed = output.Trim();

        switch (kind)
        {
            case ModalityKind.Triage:
            {
                var token = FirstWord(trimmed);
                return token switch
                {
                    "benign"     => ModalityCheck.Valid("benign"),
                    "suspicious" => ModalityCheck.Valid("suspicious"),
                    _            => ModalityCheck.Escalate,   // "unsure", rambling, or garbage → bump a tier
                };
            }

            case ModalityKind.SelfCheck:
            {
                var l = trimmed.ToLowerInvariant();
                if (l.Contains("flag")) return ModalityCheck.Valid("flagged");
                if (l.Contains("clean")) return ModalityCheck.Valid("clean");
                return ModalityCheck.Escalate;
            }

            case ModalityKind.LogReport:
            {
                var lines = trimmed.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (lines.Length == 0) return ModalityCheck.Escalate;
                return ModalityCheck.Valid(string.Join("\n", lines.Take(LogReportMaxLines)));
            }

            case ModalityKind.Extract:
            {
                // A clean single-value extraction: one line, not a paragraph.
                if (trimmed.Length > ExtractMaxChars) return ModalityCheck.Escalate;
                if (trimmed.Contains('\n')) return ModalityCheck.Escalate;
                return ModalityCheck.Valid(trimmed);
            }

            case ModalityKind.Redact:
                // Weak validation by design (can't recompute the source here); the runtime re-scans for
                // residual secret patterns. Non-empty output passes; emptiness escalates.
                return ModalityCheck.Valid(trimmed);

            default:
                return ModalityCheck.Escalate;
        }
    }

    private static string FirstWord(string s)
    {
        var i = 0;
        while (i < s.Length && !char.IsLetter(s[i])) i++;
        var start = i;
        while (i < s.Length && char.IsLetter(s[i])) i++;
        return s[start..i].ToLowerInvariant();
    }
}
