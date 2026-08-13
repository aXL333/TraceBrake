namespace Foreman.Core.Models;

/// <summary>
/// An agent's self-reported context/token budget. TraceBrake can't observe a model's context window from the
/// outside, so the harness reports it via the <c>report_usage</c> MCP tool. Every field is optional — a harness
/// reports whatever it knows (a percentage, or used/budget tokens, or just a note).
/// </summary>
public sealed record HarnessContextUsage(
    double? PercentRemaining,
    long? TokensUsed,
    long? TokensBudget,
    string? Note,
    DateTimeOffset ReportedAtUtc)
{
    /// <summary>The remaining-context percentage, taken directly or derived from used/budget tokens; null if unknown.</summary>
    public double? RemainingPercent =>
        PercentRemaining is { } p ? Math.Clamp(p, 0, 100)
        : (TokensUsed is { } u && TokensBudget is { } b && b > 0) ? Math.Clamp(100.0 * (b - u) / b, 0, 100)
        : null;

    /// <summary>A short "ctx 42% left" label for cards, or null if no percentage can be computed.</summary>
    public string? ShortLabel => RemainingPercent is { } p ? $"ctx {p:0}% left" : null;
}
