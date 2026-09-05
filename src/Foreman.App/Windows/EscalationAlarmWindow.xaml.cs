using Foreman.Core.Behavior;
using Foreman.Core.Alerts;
using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.Core.Settings;
using Foreman.Monitor;
using System.Windows;

namespace Foreman.App.Windows;

public partial class EscalationAlarmWindow : Window
{
    private readonly EscalationEvent _event;
    private readonly Func<string, HarnessTerminationResult> _killHarness;
    private readonly Func<string, (bool Ok, string Message)> _disableHarness;
    private readonly Action<EscalationEvent>? _auditHarness;

    public static Action? OpenLogRequested { get; set; }

    private EscalationAlarmWindow(
        EscalationEvent evt,
        Func<string, HarnessTerminationResult> killHarness,
        Func<string, (bool Ok, string Message)> disableHarness,
        Action<EscalationEvent>? auditHarness)
    {
        _event          = evt;
        _killHarness    = killHarness;
        _disableHarness = disableHarness;
        _auditHarness   = auditHarness;

        InitializeComponent();
        DataContext = new EscalationAlarmVm(evt);

        // "Audit Harness" only makes sense when an auditor route is wired AND the offender is an interrogable agent
        // (an OS process - "proc:..." - has no agent to audit; matches App.IsUninterrogableProcess).
        AuditButton.Visibility =
            _auditHarness is not null && !evt.HarnessId.StartsWith("proc:", StringComparison.Ordinal)
                ? Visibility.Visible
                : Visibility.Collapsed;
    }

    public static void ShowFor(
        EscalationEvent evt,
        Func<string, HarnessTerminationResult> killHarness,
        Func<string, (bool Ok, string Message)> disableHarness,
        Action<EscalationEvent>? auditHarness = null)
    {
        var w = new EscalationAlarmWindow(evt, killHarness, disableHarness, auditHarness);
        // Surface, not bare Activate: from a tray app, Activate() loses to foreground-lock
        // and the EMERGENCY window can open silently *behind* the user's editor.
        WindowActivation.Surface(w);
    }

    private void AuditClick(object sender, RoutedEventArgs e)
    {
        if (_auditHarness is null) return;

        EventBus.Instance.Publish(new InfoEvent(
            DateTimeOffset.UtcNow,
            "Foreman.Behavior",
            $"Operator requested an independent audit of '{_event.HarnessDisplayName}' from the Emergency alert."));

        _auditHarness(_event);

        // Immediate feedback; the routing outcome (which auditor, or skipped) lands in the event log. The window stays
        // open so the operator can still kill / pause / acknowledge after sending the audit.
        if (sender is System.Windows.Controls.Button b)
        {
            b.Content   = "Audit requested";
            b.IsEnabled = false;
        }
    }

    private void KillClick(object sender, RoutedEventArgs e)
    {
        var r = MessageBox.Show(
            $"Immediately kill all running '{_event.HarnessDisplayName}' processes?\n\n" +
            "This cannot be undone. Any unsaved work by the harness will be lost.",
            "TraceBrake — Confirm Emergency Kill",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (r != MessageBoxResult.Yes) return;

        var result = _killHarness(_event.HarnessId);

        EventBus.Instance.Publish(new InfoEvent(
            DateTimeOffset.UtcNow,
            "Foreman.Behavior",
            $"Operator used Emergency termination for '{_event.HarnessDisplayName}'. {result.OperatorMessage}"));

        if (result.Complete)
        {
            Close();
            return;
        }

        MessageBox.Show(
            result.OperatorMessage,
            "TraceBrake — Emergency Kill Incomplete",
            MessageBoxButton.OK,
            MessageBoxImage.Warning);
    }

    private async void DisableClick(object sender, RoutedEventArgs e)
    {
        if (!await Foreman.App.Security.PresenceGuard.AuthorizeAsync(
                Foreman.Core.Security.WeakeningAction.DisableMonitoring, $"disable monitoring for '{_event.HarnessDisplayName}'"))
            return;
        var result = _disableHarness(_event.HarnessId);
        if (!result.Ok)
        {
            MessageBox.Show(
                result.Message,
                "TraceBrake — Monitoring Still Enabled",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        EventBus.Instance.Publish(new InfoEvent(
            DateTimeOffset.UtcNow,
            "Foreman.Behavior",
            $"User disabled monitoring for '{_event.HarnessDisplayName}'. Re-enable in Harnesses window."));

        Close();
    }

    private void AcknowledgeClick(object sender, RoutedEventArgs e)
    {
        _event.Acknowledged = true;
        EventBus.Instance.Publish(new InfoEvent(
            DateTimeOffset.UtcNow,
            "Foreman.Behavior",
            $"Emergency acknowledged for '{_event.HarnessDisplayName}' — continuing to monitor."));
        Close();
    }

    private void OpenLogClick(object sender, RoutedEventArgs e)
    {
        OpenLogRequested?.Invoke();
        Close();
    }
}

// ─── ViewModel ─────────────────────────────────────────────────────────────────

public sealed class EscalationAlarmVm
{
    public string SubTitle          { get; }
    public string HarnessDisplayName { get; }
    public string TriggerRuleId     { get; }
    public string TriggerRuleName   { get; }
    public string TriggerDetail     { get; }
    public int    TotalAlerts       { get; }
    public int    UniqueRules       { get; }
    public string CategoriesLabel   { get; }
    public string SessionDuration   { get; } = "—";
    public string Reason            { get; }
    public string Explanation       { get; }

    public EscalationAlarmVm(EscalationEvent evt)
    {
        HarnessDisplayName = evt.HarnessDisplayName;
        TriggerRuleId      = evt.TriggerRuleId;
        TriggerRuleName    = evt.TriggerRuleName;
        var triggerExcerpt = AlertPopupText.DetailExcerpt(evt.TriggerDetail, 220);
        TriggerDetail      = triggerExcerpt.Length > 0
            ? $"Observed: {triggerExcerpt}"
            : "No triggering command excerpt was captured; open the Event Log for the contributing events.";
        TotalAlerts        = evt.TotalAlerts;
        UniqueRules        = evt.UniqueRules;
        CategoriesLabel    = evt.CategoryList.Length > 0
            ? string.Join(", ", evt.CategoryList).ToUpperInvariant()
            : "none";
        Reason = evt.Reason;

        SubTitle = $"Escalated from {evt.OldLevel} to {evt.NewLevel} · {evt.Timestamp.LocalDateTime:HH:mm:ss}";

        Explanation = BuildExplanation(evt);
    }

    private static string BuildExplanation(EscalationEvent evt)
    {
        var cats = evt.CategoryList.Select(c => c.ToLowerInvariant()).ToHashSet();
        var ruleId = evt.TriggerRuleId ?? "";

        // Emergency via specific rule — ordered most severe first
        if (ruleId.StartsWith("cred-004") || ruleId.StartsWith("cred-005"))
            return "The harness executed a known credential dumping tool (mimikatz or LSASS dump). " +
                   "All credentials cached in Windows memory — including plaintext passwords, NTLM hashes, " +
                   "and Kerberos tickets — may be compromised. This is almost never a legitimate coding task. " +
                   "Terminate the harness immediately and rotate all Windows account passwords.";

        if (ruleId.StartsWith("win-009") || ruleId.StartsWith("priv-003"))
            return "The harness deleted Volume Shadow Copies (Windows VSS backups). This is the primary " +
                   "technique used by ransomware before encrypting files — it eliminates all recovery points. " +
                   "Check your files for unexpected encryption immediately. If files are encrypted, " +
                   "restore from external backups and do NOT pay any ransom demands.";

        if (ruleId.StartsWith("cred-018") || ruleId.StartsWith("cred-019"))
            return "The harness executed Active Directory attack tools (DCSync, Kerberoasting, or lateral " +
                   "movement via CrackMapExec/Impacket). These tools are exclusively used by attackers " +
                   "to move across a network using stolen credentials. Disconnect from the network " +
                   "and report to your security team immediately.";

        if (ruleId.StartsWith("net-001") || ruleId.StartsWith("net-002"))
            return "The harness fetched a remote script and executed it directly without inspection " +
                   "(curl | bash or PowerShell IEX-from-web). This is the most common drive-by attack delivery " +
                   "mechanism — the downloaded script ran with your full user privileges before anyone could " +
                   "review it. Check for new scheduled tasks, services, registry Run keys, and user accounts " +
                   "that the script may have created.";

        if (ruleId.StartsWith("net-005") || ruleId.StartsWith("net-008") || ruleId.StartsWith("net-009"))
            return "The harness established or attempted to establish a remote code execution channel " +
                   "(reverse shell, mshta remote HTA, or Squiblydoo regsvr32 technique). Someone at a " +
                   "remote IP address may now have an interactive session on your machine. Check active " +
                   "network connections with 'netstat -an | findstr ESTABLISHED' and kill any unexpected " +
                   "outbound connections immediately.";

        if (ruleId.StartsWith("priv-002"))
            return "The harness added a user account to the local Administrators group — granting full " +
                   "system control to that account. Run 'net localgroup administrators' to see current " +
                   "members. Remove any account you did not explicitly add. This is almost never a " +
                   "legitimate coding task and is a classic backdoor technique.";

        if (ruleId.StartsWith("priv-004") || ruleId.StartsWith("win-008"))
            return "The harness disabled Windows Defender or the Windows Firewall. This removes your " +
                   "primary malware defense, allowing subsequent malicious activity to go undetected. " +
                   "Re-enable Defender via Windows Security settings immediately, then run a full scan. " +
                   "Review what actions the harness took while defenses were disabled.";

        if (ruleId.StartsWith("priv-008") || ruleId.StartsWith("win-010"))
            return "The harness exploited a UAC bypass technique (fodhelper.exe or eventvwr.exe registry " +
                   "hijacking) to execute code at elevated integrity without showing a UAC prompt. " +
                   "Check HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command in Registry Editor " +
                   "and remove any unexpected entries. Review what elevated code ran without your approval.";

        if (ruleId.StartsWith("priv-010"))
            return "The harness modified /etc/sudoers to grant passwordless root access (NOPASSWD). " +
                   "This creates a permanent root backdoor — any process running as that user can now " +
                   "execute arbitrary commands as root without a password. Run 'sudo visudo' to review " +
                   "and remove any NOPASSWD entries you did not add yourself.";

        // Emergency via combined categories

        // Emergency via combined categories
        if (cats.Contains("cred") && cats.Contains("priv") && cats.Contains("net"))
            return "This harness has touched all three major attack categories simultaneously: " +
                   "credential theft (cred), privilege escalation (priv), and network exfiltration (net). " +
                   "This pattern is consistent with a fully autonomous attack chain — stealing credentials, " +
                   "escalating permissions, then exfiltrating data. Review everything the harness has done " +
                   "in this session and treat the system as potentially compromised.";

        // Emergency via volume. The closing advice is reader-aware: a "proc:" offender is an unrecognized OS
        // process, not a connected agent — flatly telling the user to "terminate it" is dangerous when that
        // process is a Windows component (e.g. SearchProtocolHost.exe, the Search indexer, reading a home-root
        // decoy during routine file indexing — a known benign false positive).
        var closing = evt.HarnessId.StartsWith("proc:", StringComparison.Ordinal)
            ? "This offender is an OS/system process, not a connected agent. If it is a Windows component — " +
              "e.g. SearchProtocolHost.exe (the Search indexer) reading a credential decoy during routine file " +
              "indexing — this is very likely a FALSE POSITIVE, not harvesting. Review its reads in the event log " +
              "and verify what it is before terminating anything; do not kill a core Windows process."
            : "Review its recent actions in the event log and terminate it if the behavior was not expected.";
        return $"This harness has triggered {evt.TotalAlerts} suspicious command alerts across " +
               $"{evt.UniqueRules} different security rules and {evt.CategoryList.Length} threat categories " +
               $"({CategoriesString(evt.CategoryList)}). The volume and diversity of alerts indicates " +
               "the harness is systematically probing multiple security boundaries. " + closing;
    }

    private static string CategoriesString(string[] cats) =>
        string.Join(", ", cats.Select(c => c switch
        {
            "cred" => "credential theft",
            "priv" => "privilege escalation",
            "net"  => "network exfiltration",
            "win"  => "Windows-specific attacks",
            "del"  => "destructive deletion",
            "cmd"  => "destructive commands",   // legacy alias
            _      => c,
        }));
}
