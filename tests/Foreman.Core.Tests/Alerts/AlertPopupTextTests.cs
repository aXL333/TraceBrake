using Foreman.Core.Alerts;
using Foreman.Core.Behavior;
using Foreman.Core.Models;

namespace Foreman.Core.Tests.Alerts;

public sealed class AlertPopupTextTests
{
    private static readonly DateTimeOffset T = DateTimeOffset.UnixEpoch;

    [Fact]
    public void Emergency_LeadsWithTriggerRule_ThenBoundedEvidence()
    {
        var evt = new EscalationEvent(
            T, EscalationLevel.Emergency, EscalationLevel.Alarm,
            "claude-code", "Claude Code", "reason", 10, 2, 1, ["win"],
            "win-002", "PowerShell execution policy bypass",
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\work\\very-long-script.ps1 " + new string('x', 300));

        var body = AlertPopupText.BuildBody(evt);

        Assert.StartsWith("TRIGGER RULE — [win-002] PowerShell execution policy bypass\nObserved:", body);
        Assert.Contains('…', body);
        Assert.EndsWith("Click for details", body);
        Assert.True(body.Length <= AlertPopupText.MaxBodyLength);
    }

    [Fact]
    public void CriticalCommand_RedactsSecrets_AndKeepsRuleAheadOfCommand()
    {
        var evt = new CommandAlertEvent(
            T, ForemanSeverity.Critical, "powershell.exe (pid 42)", "message",
            "powershell -ExecutionPolicy Bypass --api-key abcdef1234567890",
            "win-002", "PowerShell execution policy bypass", "description", "guidance", 42);

        var body = AlertPopupText.BuildBody(evt);

        Assert.StartsWith("TRIGGER RULE — [win-002]", body);
        Assert.Contains("Observed: powershell", body);
        Assert.Contains("[REDACTED]", body);
        Assert.DoesNotContain("abcdef1234567890", body);
    }

    [Fact]
    public void MissingTrigger_UsesExplicitFallback_AndNormalizesWhitespace()
    {
        var evt = new EscalationEvent(
            T, EscalationLevel.Alarm, EscalationLevel.Alert,
            "codex", "Codex", "reason", 3, 2, 1, ["win"], "", "", "line one\r\nline two");

        var body = AlertPopupText.BuildBody(evt);

        Assert.StartsWith("Trigger rule unavailable\nObserved: line one line two", body);
    }
}
