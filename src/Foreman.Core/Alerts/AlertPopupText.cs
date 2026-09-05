using Foreman.Core.Models;
using Foreman.Core.Security;

namespace Foreman.Core.Alerts;

/// <summary>
/// Builds short, priority-ordered text for tray popups. Popups are an egress surface:
/// redact secrets, flatten control whitespace, and apply a hard length cap here rather
/// than relying on the notification host to truncate the important part arbitrarily.
/// </summary>
public static class AlertPopupText
{
    public const int MaxBodyLength = 240;
    public const int MaxDetailLength = 150;
    private const string ClickHint = "\nClick for details";

    public static string BuildBody(ForemanEvent evt)
    {
        ArgumentNullException.ThrowIfNull(evt);

        var content = evt switch
        {
            EscalationEvent esc => Join(
                RuleLead(esc.TriggerRuleId, esc.TriggerRuleName),
                DetailLine(esc.TriggerDetail),
                $"{Clean(esc.HarnessDisplayName)} · {esc.TotalAlerts} alerts · {esc.UniqueRules} rules"),

            CommandAlertEvent cmd => Join(
                RuleLead(cmd.RuleId, cmd.RuleName),
                DetailLine(cmd.CommandLine)),

            PermissionViolationEvent permission => Join(
                Truncate($"VIOLATION — {Clean(permission.ViolationType)}", 100),
                DetailLine(permission.Detail)),

            _ => Truncate(Clean(evt.Message), MaxBodyLength - ClickHint.Length),
        };

        return Truncate(content, MaxBodyLength - ClickHint.Length) + ClickHint;
    }

    /// <summary>A redacted, single-line evidence excerpt for an expanded popup.</summary>
    public static string DetailExcerpt(string? value, int maxLength = MaxDetailLength)
    {
        if (maxLength < 1) throw new ArgumentOutOfRangeException(nameof(maxLength));
        return Truncate(Clean(value), maxLength);
    }

    private static string RuleLead(string? ruleId, string? ruleName)
    {
        var id = Clean(ruleId);
        var name = Clean(ruleName);
        var label = (id, name) switch
        {
            ("", "") => "Trigger rule unavailable",
            (_, "") => $"TRIGGER RULE — [{id}]",
            ("", _) => $"TRIGGER RULE — {name}",
            _ => $"TRIGGER RULE — [{id}] {name}",
        };
        return Truncate(label, 110);
    }

    private static string DetailLine(string? detail)
    {
        var excerpt = DetailExcerpt(detail);
        return excerpt.Length == 0 ? string.Empty : $"Observed: {excerpt}";
    }

    private static string Join(params string[] lines) =>
        string.Join('\n', lines.Where(line => !string.IsNullOrWhiteSpace(line)));

    private static string Clean(string? value)
    {
        var redacted = SecretRedactor.Redact(value);
        if (redacted.Length == 0) return string.Empty;

        return string.Join(' ', redacted
            .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }

    private static string Truncate(string value, int maxLength)
    {
        if (value.Length <= maxLength) return value;
        if (maxLength == 1) return "…";

        var take = maxLength - 1;
        if (take > 0 && char.IsHighSurrogate(value[take - 1])) take--;
        return value[..take].TrimEnd() + "…";
    }
}
