using Foreman.Core.Alerts;
using Foreman.Core.Attribution;
using Foreman.Core.Behavior;
using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.Core.Security;
using Foreman.Core.Settings;
using Foreman.McpServer;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Foreman.App.Windows;

public partial class AlertDetailWindow : Window
{
    private readonly ForemanEvent _event;
    private string? _targetHarnessIdSnapshot;
    private int? _targetPidSnapshot;
    private string? _targetProcessNameSnapshot;
    private bool _hangFeedbackRecorded;

    /// <summary>Wired up by TrayController so the "Open Log" button can open the log window.</summary>
    public static Action? OpenLogRequested { get; set; }

    /// <summary>
    /// The data + action dependencies, set once by the App composition root (see <see cref="AlertDetailServices"/>).
    /// Replaces ~11 separate static hooks; required members make a missing dependency a compile error.
    /// </summary>
    public static AlertDetailServices? Services { get; set; }

    private AlertDetailWindow(ForemanEvent evt)
    {
        _event = evt;
        InitializeComponent();
        DataContext = new AlertDetailVm(evt);
        _targetPidSnapshot = ResolveTargetPidLive();
        _targetProcessNameSnapshot = ResolveTargetProcessNameLive();
        _targetHarnessIdSnapshot = ResolveTargetHarnessIdLive();

        // "Send for Audit" is only meaningful for alarming behavior (not hangs/mess/notices).
        SendForAuditButton.Visibility =
            AuditPolicy.QualifiesForAudit(evt) ? Visibility.Visible : Visibility.Collapsed;
        AskHarnessButton.Visibility =
            string.IsNullOrWhiteSpace(_targetHarnessIdSnapshot) ? Visibility.Collapsed : Visibility.Visible;
        KillProcessButton.Visibility =
            _targetPidSnapshot is null ? Visibility.Collapsed : Visibility.Visible;
    }

    /// <summary>Opens an AlertDetailWindow for the given event and forces it to the foreground.</summary>
    public static void ShowFor(ForemanEvent evt, Window? owner = null)
    {
        var w = new AlertDetailWindow(evt);
        if (owner?.IsVisible == true)
        {
            w.Owner = owner;
            w.WindowStartupLocation = WindowStartupLocation.CenterOwner;
        }
        w.Show();
        WindowActivation.Surface(w);
    }

    private void AcknowledgeClick(object sender, RoutedEventArgs e)
    {
        _event.Acknowledged = true;
        Services?.OnOperatorAck?.Invoke(_event);   // adaptive-alert advisor learns from this human dismissal
        EventBus.Instance.Publish(new InfoEvent(
            DateTimeOffset.UtcNow,
            "Foreman",
            $"Alert acknowledged: [{_event.Id}] {_event.Message[..Math.Min(80, _event.Message.Length)]}"));
        Close();
    }

    private void ActuallyHungClick(object sender, RoutedEventArgs e) =>
        RecordHangFeedback(HangOutcomeKind.OperatorConfirmedHung, "Recorded: actually hung");

    private void ExpectedIdleClick(object sender, RoutedEventArgs e) =>
        RecordHangFeedback(HangOutcomeKind.OperatorExpectedIdle, "Recorded: expected idle");

    private void HangUnsureClick(object sender, RoutedEventArgs e) =>
        RecordHangFeedback(HangOutcomeKind.OperatorUnsure, "Recorded: unsure (excluded from training labels)");

    private void RecordHangFeedback(HangOutcomeKind outcome, string status)
    {
        if (_hangFeedbackRecorded || _event is not HangDetectedEvent hang) return;

        EventBus.Instance.Publish(HangLearning.Outcome(
            hang, outcome, DateTimeOffset.UtcNow, operatorLabeled: true));
        _hangFeedbackRecorded = true;
        ActuallyHungButton.IsEnabled = false;
        ExpectedIdleButton.IsEnabled = false;
        HangUnsureButton.IsEnabled = false;
        HangFeedbackStatus.Text = status;
    }

    private void OpenLogClick(object sender, RoutedEventArgs e)
    {
        try { OpenLogRequested?.Invoke(); }
        catch (Exception ex)
        {
            // Show type + message + partial stack so future failures are diagnosable
            var stackSnippet = ex.StackTrace is { Length: > 0 } st
                ? (st.Length > 400 ? st[..400] + "\n…" : st)
                : "(no stack trace)";
            MessageBox.Show(
                $"Could not open the event log.\n\n" +
                $"{ex.GetType().Name}: {ex.Message}\n\n{stackSnippet}",
                "TraceBrake", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        Close();
    }

    // "Ask Harness": prompt the OFFENDING harness itself to justify and/or act. Delivered to its own
    // live MCP session when possible (sampling round-trip → targeted notification), else a clipboard
    // prompt scoped to that harness. Applies to every alert type, including hangs/mess.
    private async void AskHarnessClick(object sender, RoutedEventArgs e)
    {
      try
      {
        var harnessId   = ResolveTargetHarnessId();
        var pid         = ResolveTargetPid();
        var processName = ResolveTargetProcessName();
        var prompt      = BuildSelfJustifyPrompt(harnessId, pid, processName);
        const string systemPrompt =
            "You are the AI coding agent that TraceBrake (a local safety monitor on this machine) flagged. " +
            "This is a self-audit. Answer honestly and briefly: say what you were doing and whether it " +
            "is expected, then either justify it or take the corrective action requested.";
        var queued = !string.IsNullOrWhiteSpace(harnessId)
            ? Services?.QueueAskHarnessRequest(harnessId!, systemPrompt, prompt, _event.Id, pid, processName)
            : null;

        // Try to deliver to the offender's own live MCP session. Bounded so a slow or declining client
        // can't hang the UI; any failure falls through to the clipboard.
        AskOffenderResult? result = null;
        if (Services is not null && !string.IsNullOrWhiteSpace(harnessId))
        {
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
                result = await Services.AskOffender(harnessId!, systemPrompt, prompt, queued?.RequestId, cts.Token);
            }
            catch { result = null; }
        }

        var clipped = TrySetClipboard(prompt);
        const string title = "TraceBrake - Ask Harness";

        switch (result?.Outcome)
        {
            case AskOutcome.Sampled:
                if (queued is not null && !string.IsNullOrWhiteSpace(result.ReplyText))
                    Services?.RecordAskHarnessReply(
                        queued.RequestId,
                        result.ReplyText,
                        "direct sampling reply",
                        harnessId,
                        pid);
                EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman",
                    $"Ask Harness: {Blank(result.MatchedClient, harnessId ?? "harness")} responded to alert [{_event.Id}]"));
                MessageBox.Show(
                    $"Asked the live {Blank(result.MatchedClient, harnessId ?? "harness")} session to account for this alert.\n\n" +
                    $"Its response:\n\n{Blank(result.ReplyText, "(the harness returned an empty response)")}\n\n" +
                    PendingLine(queued),
                    title, MessageBoxButton.OK, MessageBoxImage.Information);
                break;

            case AskOutcome.Notified:
                EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman",
                    $"Ask Harness: notified live {Blank(result.MatchedClient, harnessId ?? "harness")} session re alert [{_event.Id}]" +
                    (queued is not null ? $"; pending request {queued.RequestId} awaiting reply" : "") + "."));
                MessageBox.Show(
                    $"Delivered a justify/act request to the live {Blank(result.MatchedClient, harnessId ?? "harness")} MCP session.\n\n" +
                    "This client accepts TraceBrake's notification, but does not support a direct query/reply round trip.\n" +
                    "It can reply by calling reply_to_ask_harness_request with the pending request id.\n\n" +
                    PendingLine(queued) + "\n\n" +
                    (clipped
                        ? "The prompt is also on your clipboard as a manual fallback."
                        : "Clipboard fallback failed, but the live session notification was delivered."),
                    title, MessageBoxButton.OK, MessageBoxImage.Information);
                break;

            default:  // NoSession, or MCP not wired / harness unresolved
                // Audit trail: record the attempt even when nothing was delivered, so a CRITICAL
                // alert you asked about leaves a durable trace (event log + events.log.jsonl)
                // instead of vanishing with the in-memory mailbox on the next restart.
                EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman",
                    string.IsNullOrWhiteSpace(harnessId)
                        ? $"Ask Harness: could not attribute alert [{_event.Id}] to a harness; no request queued."
                        : $"Ask Harness: no live {harnessId} session connected — " +
                          (queued is not null ? $"queued pending request {queued.RequestId} " : "") +
                          $"for alert [{_event.Id}], clipboard fallback used."));
                var owner = pid is int p
                    ? $"the {Blank(harnessId, "harness")} that owns pid {p}"
                    : $"the {Blank(harnessId, "offending harness")}";
                MessageBox.Show(
                    string.IsNullOrWhiteSpace(harnessId)
                        ? "TraceBrake couldn't attribute this alert to a specific harness."
                        : $"No live {harnessId} session is connected to TraceBrake's MCP, so the request couldn't be delivered automatically.\n\n" +
                          PendingLine(queued) + "\n\n" +
                          (clipped
                              ? $"A justify/act prompt is also on your clipboard as a manual fallback for {owner}."
                              : "Clipboard fallback failed, but the pending request remains queued.") +
                          ConnectionHelp(harnessId),
                    title, MessageBoxButton.OK, MessageBoxImage.Information);
                break;
        }
      }
      catch (Exception ex)
      {
          MessageBox.Show($"Ask Harness failed.\n\n{ex.GetType().Name}: {ex.Message}",
              "TraceBrake - Ask Harness", MessageBoxButton.OK, MessageBoxImage.Warning);
      }
    }

    // "Send for Audit": route this alert to a DIFFERENT (non-self) auditor harness/API for an
    // independent second opinion. Shown only for alarming behavior (see AuditPolicy).
    private async void SendForAuditClick(object sender, RoutedEventArgs e)
    {
        var targetHarnessId = ResolveTargetHarnessId();
        // A category-qualified alert (flagged command / permission hit) can be Medium; treat it as
        // alarming for routing so it still matches auditors whose minimum severity is High.
        var severity = AuditPolicy.QualifiesForAudit(_event) && _event.Severity < ForemanSeverity.High
            ? ForemanSeverity.High
            : _event.Severity;
        var route = ResolveAuditRoute(targetHarnessId, severity);
        var selected = route.UsedFallback && route.Candidates.Count > 1
            ? AuditHarnessPickerDialog.Pick(this, targetHarnessId, route.Candidates) ?? route.Selected
            : route.Selected ?? PromptForAuditHarness(targetHarnessId, route.Candidates);
        if (selected is null)
        {
            MessageBox.Show(
                string.IsNullOrWhiteSpace(targetHarnessId)
                    ? "No auditor could be selected for this alert."
                    : $"No auditor is configured or available to review {targetHarnessId}.\n\n" +
                      "Start another harness (Codex, Claude Code, etc.) and connect it to TraceBrake, " +
                      "or set a preferred auditor in Settings.",
                "TraceBrake - Send for Audit",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        if (route.UsedFallback &&
            !string.IsNullOrWhiteSpace(targetHarnessId) &&
            Services is not null &&
            !AuditRouteResolver.HasConfiguredAuditor(Services.GetLlmTriageSettings(), targetHarnessId, severity))
        {
            OfferSaveAuditorPreference(targetHarnessId, selected);
        }

        var prompt = BuildAuditPrompt(targetHarnessId, selected);
        const string systemPrompt =
            "You are an independent safety auditor reviewing another AI coding harness on this machine. " +
            "Be concise and factual: decide whether the behavior is expected, risky, or malicious, " +
            "then recommend the next operator action.";

        if (selected.AuditorType.Equals("harness", StringComparison.OrdinalIgnoreCase))
        {
            AskHarnessRequest? queued = Services?.QueueAskHarnessRequest(
                selected.AuditorId,
                systemPrompt,
                prompt,
                _event.Id,
                ResolveTargetPid(),
                ResolveTargetProcessName());

            AskOffenderResult? result = null;
            if (Services is not null)
            {
                try
                {
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
                    result = await Services.AskOffender(selected.AuditorId, systemPrompt, prompt, queued?.RequestId, cts.Token);
                }
                catch { result = null; }
            }

            var clipped = result?.Outcome is AskOutcome.Sampled or AskOutcome.Notified
                ? false
                : TrySetClipboard(prompt);

            var routeNote = route.UsedFallback
                ? $"\n\n(No preferred auditor was configured for {Blank(targetHarnessId, "this harness")} — used {selected.DisplayName}.)"
                : string.Empty;

            switch (result?.Outcome)
            {
                case AskOutcome.Sampled:
                    if (queued is not null && !string.IsNullOrWhiteSpace(result.ReplyText))
                        Services?.RecordAskHarnessReply(
                            queued.RequestId,
                            result.ReplyText,
                            "direct auditor sampling reply",
                            selected.AuditorId,
                            null);
                    EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman",
                        $"Audit reply received for alert [{_event.Id}] via {Blank(result.MatchedClient, selected.DisplayName)}"));
                    MessageBox.Show(
                        $"Asked the live {Blank(result.MatchedClient, selected.DisplayName)} session to audit this alert.\n\n" +
                        $"Its response:\n\n{Blank(result.ReplyText, "(the auditor returned an empty response)")}\n\n" +
                        PendingLine(queued) +
                        routeNote,
                        "TraceBrake - Send for Audit", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;

                case AskOutcome.Notified:
                    EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman",
                        $"Audit request delivered for alert [{_event.Id}] via {Blank(result.MatchedClient, selected.DisplayName)}"));
                    MessageBox.Show(
                        $"Delivered the audit request to the live {Blank(result.MatchedClient, selected.DisplayName)} MCP session.\n\n" +
                        "This client does not support a direct query/reply round trip. It can reply by calling " +
                        "reply_to_ask_harness_request with the pending request id.\n\n" +
                        PendingLine(queued) +
                        routeNote,
                        "TraceBrake - Send for Audit", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
            }

            EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman",
                $"Audit request queued for alert [{_event.Id}] via {selected.DisplayName}"));

            MessageBox.Show(
                $"Queued the audit request for {selected.DisplayName}, but no matching live MCP session is connected right now.\n\n" +
                PendingLine(queued) + "\n\n" +
                (clipped
                    ? "The prompt is also on your clipboard as a manual fallback."
                    : "Clipboard fallback failed, but the pending request remains queued.") +
                ConnectionHelp(selected.AuditorId) +
                routeNote,
                "TraceBrake - Send for Audit", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (!TrySetClipboard(prompt))
        {
            MessageBox.Show("Could not copy the audit prompt to the clipboard.",
                "TraceBrake - Send for Audit", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman",
            $"Audit prompt prepared for alert [{_event.Id}] via {selected.DisplayName}"));

        MessageBox.Show(BuildAuditMessage(targetHarnessId, selected, route.UsedFallback),
            "TraceBrake - Send for Audit", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private static bool TrySetClipboard(string text)
    {
        try { Clipboard.SetText(text); return true; }
        catch { return false; }
    }

    private static string PendingLine(AskHarnessRequest? request) =>
        request is null
            ? "No pending Ask Harness request was queued."
            : $"Pending request id: {request.RequestId}\n" +
              $"The harness can receive it with list_ask_harness_requests(harnessId: \"{request.HarnessId}\") " +
              "and reply with reply_to_ask_harness_request.";

    private static string ConnectionHelp(string? harnessId)
    {
        var agent = string.Equals(harnessId, "codex", StringComparison.OrdinalIgnoreCase)
            ? "Codex"
            : "the agent";
        return $"\n\nTo fix automatic delivery: open TraceBrake Dashboard or tray menu > Connect agent > {agent} > Connect automatically, then restart {agent}.";
    }

    private string BuildAuditMessage(string? targetHarnessId, AuditRouteResolver.Candidate auditor, bool usedFallback)
    {
        var target = Blank(targetHarnessId, "this process");
        var sb = new StringBuilder();
        sb.AppendLine("An audit prompt for this alert is on your clipboard.");
        sb.AppendLine();

        if (usedFallback)
            sb.AppendLine($"No preferred auditor was configured for {target} — using {auditor.DisplayName} for this audit.");
        else
            sb.AppendLine($"Suggested reviewer: {auditor.DisplayName} (configurable in Settings).");
        if (auditor.AuditorType.Equals("api", StringComparison.OrdinalIgnoreCase))
        {
            sb.AppendLine(auditor.Available
                ? $"Send it to the {auditor.DisplayName} API to review {target}."
                : $"{auditor.DisplayName} is your preferred reviewer for {target}, but no API endpoint is configured yet.");
        }
        else
        {
            sb.AppendLine(auditor.Available
                ? $"You have {auditor.RunningHarnessCount} {auditor.DisplayName} instance{(auditor.RunningHarnessCount == 1 ? "" : "s")} running — paste it into one to review {target}."
                : $"{auditor.DisplayName} is your preferred reviewer for {target}, but isn't running right now — start it, or paste the prompt into any AI.");
        }

        return sb.ToString().TrimEnd();
    }

    // The offender-directed (second-person) "justify and/or act" prompt. Reuses the same event-detail
    // and secret-masking helpers as the audit prompt, but addresses the harness that caused the alert.
    private string BuildSelfJustifyPrompt(string? harnessId, int? pid, string? processName)
    {
        var vm = DataContext as AlertDetailVm;
        var liveProcess = pid is int p ? Services?.GetProcessByPid(p) : null;
        var commandLine = ResolveTargetCommandLine(liveProcess);

        var sb = new StringBuilder();
        sb.AppendLine("TraceBrake - a local safety monitor for AI coding agents on this machine - flagged an action attributed to you. This is a self-audit; account for it.");
        sb.AppendLine();
        sb.AppendLine("Alert");
        sb.AppendLine($"- Id: {_event.Id}");
        sb.AppendLine($"- Type: {vm?.EventTypeLabel ?? _event.GetType().Name}");
        sb.AppendLine($"- Severity: {_event.Severity}");
        sb.AppendLine($"- When: {_event.Timestamp:O}");
        sb.AppendLine($"- What TraceBrake saw: {SecretRedactor.Redact(_event.Message)}");   // Message can carry a cmd fragment (S-4)
        sb.AppendLine();
        sb.AppendLine("You");
        sb.AppendLine($"- Harness: {Blank(harnessId, "unknown")}");
        sb.AppendLine($"- Process: {Blank(processName, "unknown")}{(pid is int pp ? $" (pid {pp})" : "")}");

        if (!string.IsNullOrWhiteSpace(commandLine))
        {
            sb.AppendLine();
            sb.AppendLine("Command line (potential secrets masked):");
            sb.AppendLine(SecretRedactor.Redact(commandLine));
        }

        AppendEventSpecificDetails(sb);

        if (vm is not null && !string.IsNullOrWhiteSpace(vm.WhyDangerous))
        {
            sb.AppendLine();
            sb.AppendLine("Why TraceBrake flagged it:");
            sb.AppendLine(vm.WhyDangerous);
        }

        sb.AppendLine();
        sb.AppendLine(BuildAskLine());
        return sb.ToString();
    }

    // The concrete second-person ask, tailored to the alert type. Low/Medium housekeeping alerts may
    // be acknowledged by the harness itself (the AcknowledgeAlert MCP tool is gated to refuse
    // High/Critical, so a serious alert can't be self-silenced).
    private string BuildAskLine() => _event switch
    {
        HangDetectedEvent =>
            "This process has gone silent. Is it still doing useful work, or is it stuck/abandoned? " +
            "If it's stuck or no longer needed, abort it (Ctrl+C) or reap the child; otherwise explain " +
            "what it's waiting on. If this is a false alarm you may acknowledge the alert.",
        OrphanDetectedEvent orphan =>
            $"A {orphan.HarnessType ?? "harness"} child process outlived its parent. Is that intentional? If not, " +
            "terminate it; if it is, explain why — you may acknowledge the alert once accounted for.",
        NonzeroExitEvent =>
            "A process you launched exited non-zero. Explain what failed and whether you've handled it. " +
            "You may acknowledge the alert if this is expected.",
        CommandAlertEvent =>
            "Justify this command: what task required it, and is it safe as written? If it was a mistake " +
            "or unnecessary, do not run it (or abort it) and say so.",
        PermissionViolationEvent =>
            "Justify this access against your current task, or confirm it was unintended and stop.",
        EscalationEvent =>
            "Your recent activity tripped TraceBrake's escalation. Summarize what you're doing and why it " +
            "shouldn't be treated as alarming — or correct course.",
        _ =>
            "Account for this alert: explain whether it's expected and either justify it or take the " +
            "corrective action.",
    };

    private void KillProcessClick(object sender, RoutedEventArgs e)
    {
        var pid = ResolveTargetPid();
        if (pid is null)
        {
            MessageBox.Show(
                "This alert does not identify a single process to terminate. Use Behavior Metrics to kill an entire harness.",
                "TraceBrake - Kill/End Process",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        var processName = ResolveTargetProcessName() ?? "process";
        var result = MessageBox.Show(
            $"Kill/end \"{processName}\" (pid {pid.Value})?\n\nThis will immediately terminate the process tree rooted at this alert target.",
            "TraceBrake - Confirm Kill",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result != MessageBoxResult.Yes) return;

        var killed = Services?.KillProcessByPid(pid.Value, _event.ProcessStartTime) ?? false;
        if (!killed)
        {
            EventBus.Instance.Publish(new InfoEvent(
                DateTimeOffset.UtcNow,
                "Foreman",
                $"Kill/end failed for alert [{_event.Id}] target pid {pid.Value}"));

            MessageBox.Show(
                $"TraceBrake could not terminate pid {pid.Value}. It may have already exited, or Windows may have denied access.",
                "TraceBrake - Kill/End Process",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        _event.Acknowledged = true;
        EventBus.Instance.Publish(new InfoEvent(
            DateTimeOffset.UtcNow,
            "Foreman",
            $"Killed alert target \"{processName}\" (pid {pid.Value}) for alert [{_event.Id}]"));

        MessageBox.Show(
            $"Terminated \"{processName}\" (pid {pid.Value}).",
            "TraceBrake - Kill/End Process",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
        Close();
    }

    private string BuildAuditPrompt(string? targetHarnessId, AuditRouteResolver.Candidate? route)
    {
        var vm = DataContext as AlertDetailVm;
        var targetPid = ResolveTargetPid();
        var processName = ResolveTargetProcessName();
        var liveProcess = targetPid is int pid ? Services?.GetProcessByPid(pid) : null;
        var commandLine = ResolveTargetCommandLine(liveProcess);

        var sb = new StringBuilder();
        sb.AppendLine("TraceBrake alert audit request");
        sb.AppendLine();
        sb.AppendLine("You are acting as an independent safety auditor for another AI coding harness or its child process.");
        sb.AppendLine("Decide whether this alert is expected, benign-but-stuck, risky, or suspicious. Recommend one concrete next action.");
        sb.AppendLine();
        sb.AppendLine("Alert");
        sb.AppendLine($"- Id: {_event.Id}");
        sb.AppendLine($"- Type: {vm?.EventTypeLabel ?? _event.GetType().Name}");
        sb.AppendLine($"- Severity: {_event.Severity}");
        sb.AppendLine($"- Source: {_event.Source}");
        sb.AppendLine($"- Timestamp: {_event.Timestamp:O}");
        sb.AppendLine($"- Message: {SecretRedactor.Redact(_event.Message)}");   // Message can carry a cmd fragment (S-4)
        sb.AppendLine();
        sb.AppendLine("Target");
        sb.AppendLine($"- Harness being audited: {Blank(targetHarnessId, "unknown")}");
        sb.AppendLine($"- Process: {Blank(processName, "unknown")}{(targetPid is int p ? $" (pid {p})" : "")}");
        if (liveProcess is not null)
        {
            sb.AppendLine($"- Parent pid: {liveProcess.ParentPid}");
            sb.AppendLine($"- Executable: {Blank(liveProcess.ExecutablePath, "unknown")}");
            sb.AppendLine($"- Live state: {liveProcess.State}");
            sb.AppendLine($"- Uptime minutes: {liveProcess.UptimeMinutes}");
            sb.AppendLine($"- Silent minutes: {liveProcess.SilentMinutes}");
        }

        if (!string.IsNullOrWhiteSpace(commandLine))
        {
            sb.AppendLine();
            sb.AppendLine("Command line (potential secrets masked)");
            sb.AppendLine(SecretRedactor.Redact(commandLine));
        }

        AppendEventSpecificDetails(sb);

        if (vm is not null)
        {
            sb.AppendLine();
            sb.AppendLine("TraceBrake assessment");
            sb.AppendLine(vm.WhyDangerous);
            sb.AppendLine();
            sb.AppendLine("TraceBrake recommended action");
            sb.AppendLine(vm.RecommendedAction);
        }

        sb.AppendLine();
        sb.AppendLine("Auditor route");
        sb.AppendLine(route is null
            ? "- No configured auditor route was selected."
            : $"- Selected auditor: {route.DisplayName} ({route.AuditorType}:{route.AuditorId}), available: {route.Available}, running harness count: {route.RunningHarnessCount}");
        if (route?.ApiEndpoint is { Length: > 0 } endpoint)
            sb.AppendLine($"- API endpoint: {endpoint}");
        if (route?.Model is { Length: > 0 } model)
            sb.AppendLine($"- Model: {model}");

        sb.AppendLine();
        sb.AppendLine("Please answer with: verdict, evidence, recommended action, and whether the process should be left running, interrupted with Ctrl+C, killed, or escalated for manual review.");
        return sb.ToString();
    }

    private void AppendEventSpecificDetails(StringBuilder sb)
    {
        switch (_event)
        {
            case CommandAlertEvent cmd:
                sb.AppendLine();
                sb.AppendLine("Command alert details");
                sb.AppendLine($"- Rule: {cmd.RuleId} - {cmd.RuleName}");
                sb.AppendLine($"- Rule description: {Blank(cmd.RuleDescription, "none")}");
                break;

            case HangDetectedEvent hang:
                sb.AppendLine();
                sb.AppendLine("Hang details");
                sb.AppendLine($"- Uptime minutes: {hang.UptimeMinutes}");
                sb.AppendLine($"- No-I/O minutes: {hang.SilentMinutes}");
                sb.AppendLine($"- Direct spawner: {Blank(hang.SpawnerName, "unknown")}{(hang.SpawnerPid is int spid ? $" (pid {spid})" : "")}");
                sb.AppendLine($"- Owning harness: {Blank(hang.ParentHarnessType, "unknown")}{(hang.ParentHarnessPid is int hpid ? $" (pid {hpid})" : "")}");
                break;

            case OrphanDetectedEvent orphan:
                sb.AppendLine();
                sb.AppendLine("Orphan details");
                sb.AppendLine($"- Dead parent: {orphan.DeadParentName} (pid {orphan.DeadParentPid})");
                if (orphan.HarnessType is not null)
                    sb.AppendLine($"- Owning harness: {orphan.HarnessType}{(orphan.HarnessPid is int ohp ? $" (pid {ohp})" : "")}");
                sb.AppendLine($"- Orphan uptime minutes: {orphan.UptimeMinutes}");
                break;

            case PermissionViolationEvent perm:
                sb.AppendLine();
                sb.AppendLine("Permission violation details");
                sb.AppendLine($"- Profile: {perm.ProfileName}");
                sb.AppendLine($"- Violation type: {perm.ViolationType}");
                sb.AppendLine($"- Detail: {perm.Detail}");
                break;

            case NonzeroExitEvent exit:
                sb.AppendLine();
                sb.AppendLine("Exit details");
                sb.AppendLine($"- Exit code: {exit.ExitCode}");
                sb.AppendLine($"- Parent harness pid: {exit.ParentHarnessPid?.ToString() ?? "unknown"}");
                break;

            case EscalationEvent esc:
                sb.AppendLine();
                sb.AppendLine("Escalation details");
                sb.AppendLine($"- Harness: {esc.HarnessDisplayName} ({esc.HarnessId})");
                sb.AppendLine($"- Old level: {esc.OldLevel}");
                sb.AppendLine($"- New level: {esc.NewLevel}");
                sb.AppendLine($"- Trigger: {esc.TriggerRuleId} - {esc.TriggerRuleName}");
                sb.AppendLine($"- Reason: {esc.Reason}");
                break;
        }
    }

    private AuditRouteResolver.Selection ResolveAuditRoute(string? targetHarnessId, ForemanSeverity severity)
    {
        var settings = Services?.GetLlmTriageSettings();
        if (settings is null)
            return new AuditRouteResolver.Selection(null, [], "No LLM triage settings are available.", false);

        var snapshot = Services?.GetProcessSnapshot().ToList() ?? [];
        var connected = Services?.GetConnectedHarnessIds();
        return AuditRouteResolver.Resolve(settings, targetHarnessId, severity, snapshot, connected);
    }

    private AuditRouteResolver.Candidate? PromptForAuditHarness(
        string? targetHarnessId,
        IReadOnlyList<AuditRouteResolver.Candidate> candidates)
    {
        if (candidates.Count == 0)
            return PromptConfigureAuditorPreference(targetHarnessId);

        if (candidates.Count == 1)
            return candidates[0];

        return AuditHarnessPickerDialog.Pick(this, targetHarnessId, candidates);
    }

    private AuditRouteResolver.Candidate? PromptConfigureAuditorPreference(string? targetHarnessId)
    {
        if (string.IsNullOrWhiteSpace(targetHarnessId) || Services is null)
            return null;

        var excluded = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { targetHarnessId };
        var choices = KnownHarnesses.All
            .Where(h => !excluded.Contains(h.Id))
            .Select(h => new AuditRouteResolver.Candidate(
                h.Id,
                "harness",
                h.DisplayName,
                Priority: 0,
                Available: false,
                RunningHarnessCount: 0,
                McpConnected: false,
                ApiEndpoint: null,
                Model: null,
                IsFallback: true))
            .ToList();

        var picked = AuditHarnessPickerDialog.Pick(
            this,
            targetHarnessId,
            choices,
            title: "Choose preferred auditor",
            prompt: $"No preferred auditor is configured for {targetHarnessId}, and no other harness is running or connected.\n\nPick one to save as the default reviewer for future alerts:");

        if (picked is null)
            return null;

        OfferSaveAuditorPreference(targetHarnessId, picked, forceSave: true);
        return picked;
    }

    private void OfferSaveAuditorPreference(
        string targetHarnessId,
        AuditRouteResolver.Candidate auditor,
        bool forceSave = false)
    {
        if (Services is null)
            return;

        if (!forceSave)
        {
            var answer = MessageBox.Show(
                $"Save {auditor.DisplayName} as the preferred auditor for {targetHarnessId} alerts?",
                "TraceBrake - Send for Audit",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);
            if (answer != MessageBoxResult.Yes)
                return;
        }

        Services.SaveAuditorPreference(targetHarnessId, auditor.AuditorId, auditor.DisplayName);
        EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman",
            $"Saved {auditor.DisplayName} as preferred auditor for {targetHarnessId}"));
    }

    private int? ResolveTargetPid() => _targetPidSnapshot ?? ResolveTargetPidLive();

    private int? ResolveTargetPidLive() => _event switch
    {
        CommandAlertEvent cmd when cmd.ProcessId > 0 => cmd.ProcessId,
        HangDetectedEvent hang when hang.ProcessId > 0 => hang.ProcessId,
        OrphanDetectedEvent orphan when orphan.ProcessId > 0 => orphan.ProcessId,
        PermissionViolationEvent perm when perm.ProcessId > 0 => perm.ProcessId,
        NonzeroExitEvent exit when exit.ProcessId > 0 => exit.ProcessId,
        _ => null,
    };

    private string? ResolveTargetProcessName() => _targetProcessNameSnapshot ?? ResolveTargetProcessNameLive();

    private string? ResolveTargetProcessNameLive() => _event switch
    {
        CommandAlertEvent cmd => Services?.GetProcessByPid(cmd.ProcessId)?.Name ?? ExtractProcessNameFromSource(cmd.Source),
        HangDetectedEvent hang => hang.ProcessName,
        OrphanDetectedEvent orphan => orphan.ProcessName,
        PermissionViolationEvent perm => Services?.GetProcessByPid(perm.ProcessId)?.Name ?? ExtractProcessNameFromSource(perm.Source),
        NonzeroExitEvent exit => exit.ProcessName,
        EscalationEvent esc => esc.HarnessDisplayName,
        _ => null,
    };

    private string? ResolveTargetHarnessId() => _targetHarnessIdSnapshot ?? ResolveTargetHarnessIdLive();

    private string? ResolveTargetHarnessIdLive() => _event switch
    {
        CommandAlertEvent cmd => ResolveHarnessFromProcess(cmd.ProcessId),
        HangDetectedEvent hang => FirstNonBlank(
            hang.ParentHarnessType,
            hang.ParentHarnessPid is int hp ? ResolveHarnessFromProcess(hp) : null,
            ResolveHarnessFromProcess(hang.ProcessId)),
        OrphanDetectedEvent orphan => FirstNonBlank(orphan.HarnessType, ResolveHarnessFromProcess(orphan.ProcessId)),
        PermissionViolationEvent perm => ResolveHarnessFromProcess(perm.ProcessId),
        NonzeroExitEvent exit => FirstNonBlank(
            exit.ParentHarnessPid is int hp ? ResolveHarnessFromProcess(hp) : null,
            ResolveHarnessFromProcess(exit.ProcessId)),
        EscalationEvent esc => esc.HarnessId,
        _ => null,
    };

    private string? ResolveTargetCommandLine(ProcessRecord? liveProcess)
    {
        if (_event is CommandAlertEvent cmd && !string.IsNullOrWhiteSpace(cmd.CommandLine))
            return cmd.CommandLine;

        return string.IsNullOrWhiteSpace(liveProcess?.CommandLine) ? null : liveProcess.CommandLine;
    }

    private static string? ResolveHarnessFromProcess(int pid)
    {
        if (pid <= 0) return null;

        var rec = Services?.GetProcessByPid(pid);
        if (!string.IsNullOrWhiteSpace(rec?.HarnessType))
            return rec.HarnessType;

        var ancestor = Services?.GetHarnessAncestorByPid(pid);
        return string.IsNullOrWhiteSpace(ancestor?.HarnessType) ? null : ancestor.HarnessType;
    }

    private static string? ExtractProcessNameFromSource(string source)
    {
        var idx = source.IndexOf(" (pid", StringComparison.Ordinal);
        return idx > 0 ? source[..idx] : null;
    }

    private static string? FirstNonBlank(params string?[] values) =>
        values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));

    private static string Blank(string? value, string fallback) =>
        string.IsNullOrWhiteSpace(value) ? fallback : value;

    // Quiet this kind of alert's popup. The menu offers only durations the guardrail allows: a
    // protected detection (Critical / emergency rule / cred-net-priv category) gets snooze-only options;
    // everything else can be muted for longer or until cleared. Muting never stops detection.
    private void MuteClick(object sender, RoutedEventArgs e)
    {
        var emergency = Services?.GetEmergencyRuleIds() ?? [];
        var menu = new ContextMenu();

        void Add(string header, TimeSpan? duration)
        {
            var item = new MenuItem { Header = header };
            item.Click += (_, _) => ApplyMute(duration, emergency);
            menu.Items.Add(item);
        }

        if (MutePolicy.IsProtected(_event, emergency))
        {
            menu.Items.Add(new MenuItem { Header = "Protected detection — snooze only", IsEnabled = false });
            menu.Items.Add(new Separator());
            Add("Snooze 15 minutes", TimeSpan.FromMinutes(15));
            Add("Snooze 60 minutes", TimeSpan.FromMinutes(60));
        }
        else
        {
            Add("Mute 1 hour",   TimeSpan.FromHours(1));
            Add("Mute 8 hours",  TimeSpan.FromHours(8));
            Add("Mute 24 hours", TimeSpan.FromHours(24));
            menu.Items.Add(new Separator());
            // Safe now that the tray's "Muted alerts…" manager can list and clear it.
            Add("Mute until I clear it", null);
        }

        menu.PlacementTarget = sender as UIElement;
        menu.IsOpen = true;
    }

    private async void ApplyMute(TimeSpan? duration, IReadOnlyList<string> emergency)
    {
        // Presence lock (P3): muting a PROTECTED alert is a weakening — gate it (unprotected mutes pass through).
        if (MutePolicy.IsProtected(_event, emergency) && !await Foreman.App.Security.PresenceGuard.AuthorizeAsync(
                Foreman.Core.Security.WeakeningAction.MuteProtectedAlert, "mute a protected alert"))
            return;
        var mute = MutePolicy.CreateMute(_event, duration, emergency, DateTimeOffset.UtcNow);
        if (mute is null)
        {
            MessageBox.Show(
                "That mute isn't allowed for this alert — protected detections can only be snoozed briefly.",
                "TraceBrake — Mute", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        Services?.AddMute(mute);
        var when = mute.Until is { } u ? $"until {u.ToLocalTime():t}" : "until you clear it";
        EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman",
            $"Muted {mute.Label} {when} — notifications only; still logged, counted and escalated."));
        MessageBox.Show(
            $"Muted {mute.Label} {when}.\n\nThis only quiets the tray popup — the alert is still recorded, " +
            "counted on the dashboard, and feeds escalation.",
            "TraceBrake — Mute", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void CloseClick(object sender, RoutedEventArgs e) => Close();
}

// ─────────────────────────────────────────────────────────────────────────────

public sealed class AlertDetailVm
{
    public string  SeverityLabel      { get; }
    public Brush   SeverityBackground { get; }
    public string  EventTypeLabel     { get; }
    public string  TimestampLabel     { get; }
    public string  Source             { get; }

    public Visibility RuleInfoVisibility    { get; }
    public string     RuleId               { get; }
    public string     RuleName             { get; }
    public Visibility CommandLineVisibility { get; }
    public string     CommandLine          { get; }

    // ── Process identification (CommandAlertEvent) ────────────────────────
    public Visibility ProcessInfoVisibility { get; }
    public string     ProcessLine          { get; }   // "cmd.exe  ·  pid 1234"
    public string     HarnessLine          { get; }   // "Harness type: claude-code"
    public Visibility HarnessLineVisibility { get; }

    // ── Escalation / behavior profile summary ────────────────────────────
    public Visibility EscalationLineVisibility { get; }
    public string     EscalationLevelLabel      { get; }   // "ALERT", "ALARM", etc.
    public Brush      EscalationBadgeBg        { get; }
    public Brush      EscalationBadgeFg        { get; }
    public string     EscalationSummary        { get; }   // "7 alerts  ·  3 rules"

    public string WhyDangerous     { get; }
    public string RecommendedAction { get; }
    public string AttributionSummary { get; }
    public string AttributionCoverageLabel { get; }
    public IReadOnlyList<AttributionStepVm> AttributionSteps { get; }
    public Visibility HangFeedbackVisibility { get; }

    public AlertDetailVm(ForemanEvent evt)
    {
        SeverityLabel      = evt.Severity.ToString().ToUpperInvariant();
        SeverityBackground = SeverityToBrush(evt.Severity);
        TimestampLabel     = evt.Timestamp.LocalDateTime.ToString("yyyy-MM-dd  HH:mm:ss.fff");
        Source             = evt.Source;

        // defaults — overridden per event type below
        RuleInfoVisibility    = Visibility.Collapsed;
        RuleId                = string.Empty;
        RuleName              = string.Empty;
        CommandLineVisibility = Visibility.Collapsed;
        CommandLine           = string.Empty;
        ProcessInfoVisibility    = Visibility.Collapsed;
        ProcessLine              = string.Empty;
        HarnessLine              = string.Empty;
        HarnessLineVisibility    = Visibility.Collapsed;
        EscalationLineVisibility = Visibility.Collapsed;
        EscalationLevelLabel     = string.Empty;
        EscalationBadgeBg        = new SolidColorBrush(Color.FromRgb(0x1A, 0x1C, 0x24));
        EscalationBadgeFg        = new SolidColorBrush(Color.FromRgb(0x7A, 0x80, 0x90));
        EscalationSummary        = string.Empty;
        WhyDangerous             = string.Empty;
        RecommendedAction     = string.Empty;
        HangFeedbackVisibility = evt is HangDetectedEvent ? Visibility.Visible : Visibility.Collapsed;

        var attribution = AttributionChainBuilder.Build(
            evt,
            AlertDetailWindow.Services?.GetProcessByPid,
            AlertDetailWindow.Services?.GetHarnessAncestorByPid);
        AttributionSummary = attribution.Summary;
        AttributionCoverageLabel = attribution.InferredLinks == 0
            ? $"{attribution.ObservedLinks} observed item{(attribution.ObservedLinks == 1 ? "" : "s")}"
            : $"{attribution.ObservedLinks} observed · {attribution.InferredLinks} inferred";
        AttributionSteps = attribution.Steps
            .Select((step, index) => new AttributionStepVm(step, index > 0, evt.Severity, evt.AutoResolved || evt.Acknowledged))
            .ToList();

        switch (evt)
        {
            case CommandAlertEvent cmd:
                EventTypeLabel        = "Command Alert";
                RuleInfoVisibility    = Visibility.Visible;
                RuleId                = cmd.RuleId;
                RuleName              = cmd.RuleName;
                CommandLineVisibility = Visibility.Visible;
                CommandLine           = cmd.CommandLine;

                // Resolve the originating process from the live process tree
                if (cmd.ProcessId > 0)
                {
                    var rec = AlertDetailWindow.Services?.GetProcessByPid(cmd.ProcessId);
                    ProcessInfoVisibility = Visibility.Visible;

                    string? harnessKey;
                    if (rec is not null)
                    {
                        ProcessLine = $"{rec.Name}  ·  pid {cmd.ProcessId}";
                        string? ancestorHt = null;
                        if (rec.IsHarness && rec.HarnessType is not null)
                        {
                            HarnessLine           = $"Harness type: {rec.HarnessType}";
                            HarnessLineVisibility = Visibility.Visible;
                        }
                        else if (rec.HarnessType is not null)
                        {
                            HarnessLine           = $"Child of {rec.HarnessType} harness  ·  parent pid {rec.ParentPid}";
                            HarnessLineVisibility = Visibility.Visible;
                        }
                        else
                        {
                            // The process matched no harness rule itself — but it may be a child
                            // of one (e.g. a PowerShell hook or shell spawned by claude-code).
                            // Walk the process tree to attribute it.
                            ancestorHt = AlertDetailWindow.Services?.GetHarnessAncestorByPid(cmd.ProcessId)?.HarnessType;
                            HarnessLine = ancestorHt is not null
                                ? $"Child of {ancestorHt} harness  ·  parent pid {rec.ParentPid}"
                                : $"Unclassified (not a tracked harness)  ·  parent pid {rec.ParentPid}";
                            HarnessLineVisibility = Visibility.Visible;
                        }
                        // Harness key matches how BehaviorTracker keys profiles
                        harnessKey = rec.HarnessType ?? ancestorHt ?? $"proc:{rec.Name}";
                    }
                    else
                    {
                        // Process has already exited by the time the user opened the detail;
                        // derive the key the same way BehaviorTracker.GetHarnessKey does.
                        ProcessLine           = $"pid {cmd.ProcessId}  ·  process has since exited";
                        HarnessLineVisibility = Visibility.Collapsed;
                        var idx  = cmd.Source.IndexOf(" (pid", StringComparison.Ordinal);
                        var name = idx > 0 ? cmd.Source[..idx] : cmd.Source;
                        harnessKey = $"proc:{name}";
                    }

                    // Show the harness's current escalation level and session alert totals
                    var profile = AlertDetailWindow.Services?.GetProfileByHarness(harnessKey);
                    if (profile is not null)
                    {
                        EscalationLineVisibility = Visibility.Visible;
                        EscalationLevelLabel     = profile.CurrentLevel.ToString().ToUpperInvariant();
                        (EscalationBadgeBg, EscalationBadgeFg) = EscalationColors(profile.CurrentLevel);

                        var parts = new List<string>
                        {
                            $"{profile.TotalAlerts} alert{(profile.TotalAlerts == 1 ? "" : "s")} this session"
                        };
                        if (profile.UniqueRulesCount > 1)
                            parts.Add($"{profile.UniqueRulesCount} unique rules");
                        if (profile.CategoryCount > 1)
                            parts.Add($"{profile.CategoryCount} categories");
                        EscalationSummary = string.Join("  ·  ", parts);
                    }
                }

                WhyDangerous = string.IsNullOrWhiteSpace(cmd.RuleDescription)
                    ? "This command matched a pattern associated with malicious or unsafe behaviour."
                    : cmd.RuleDescription;

                RecommendedAction = string.IsNullOrWhiteSpace(cmd.RuleGuidance)
                    ? GetDefaultGuidance(cmd.RuleId)
                    : cmd.RuleGuidance;
                break;

            case HangDetectedEvent hang:
                EventTypeLabel = "Process Hang Detected";
                WhyDangerous =
                    $"\"{hang.ProcessName}\" (pid {hang.ProcessId}) has been running for {hang.UptimeMinutes} minutes " +
                    $"with no I/O activity for {hang.SilentMinutes} minutes.{ResolveHarnessOwner(hang)}\n\n" +
                    $"This means the process is stuck — waiting for input that will never come, " +
                    $"caught in an infinite loop, or blocked on a locked resource. Hung harness " +
                    $"children can accumulate silently and consume memory or file handles.";
                RecommendedAction =
                    "1. Check whether the harness is prompting for input in its terminal.\n" +
                    "2. If the hang is unintentional, send Ctrl+C to the harness terminal or kill " +
                    $"pid {hang.ProcessId} in Task Manager.\n" +
                    "3. Review the harness's most recent output to understand what it was doing before stalling.";
                break;

            case OrphanDetectedEvent orphan:
                EventTypeLabel = "Orphaned Process";
                var orphanHarness = orphan.HarnessType is not null
                    ? $"the {orphan.HarnessType} harness tree{(orphan.HarnessPid is int ohpid ? $" (pid {ohpid})" : "")}"
                    : "a harness tree";
                WhyDangerous =
                    $"\"{orphan.ProcessName}\" (pid {orphan.ProcessId}) is still running even though " +
                    $"its parent \"{orphan.DeadParentName}\" (pid {orphan.DeadParentPid}) has exited.\n\n" +
                    $"It belongs to {orphanHarness}, and has been running for {orphan.UptimeMinutes} minutes " +
                    $"unsupervised. Orphaned harness children can continue executing tasks, mutating files, or " +
                    $"making network requests without the parent harness to oversee them.";
                RecommendedAction =
                    "1. If this process is expected (e.g. a deliberate background daemon), you can safely ignore this alert.\n" +
                    $"2. Otherwise, terminate pid {orphan.ProcessId} from Task Manager.\n" +
                    $"3. Review what {(orphan.HarnessType ?? "the harness")} was running when it exited to understand what the orphan may be doing.";
                break;

            case PermissionViolationEvent perm:
                EventTypeLabel = "Permission Violation";
                WhyDangerous =
                    $"Profile \"{perm.ProfileName}\" was violated.\n\n" +
                    $"Violation type: {perm.ViolationType}\n" +
                    $"Detail: {perm.Detail}\n\n" +
                    $"The harness attempted an action outside the boundaries configured for it in TraceBrake's permission profiles.";
                RecommendedAction =
                    "1. Review the harness's current task to determine if this action was intentional.\n" +
                    "2. If the action is legitimate, update the permission profile in TraceBrake's Profiles editor.\n" +
                    "3. If unexpected, terminate the harness and audit its recent command history in the event log.";
                break;

            case NonzeroExitEvent exit:
                EventTypeLabel = "Non-Zero Exit";
                WhyDangerous =
                    $"\"{exit.ProcessName}\" (pid {exit.ProcessId}) exited with code {exit.ExitCode}.\n\n" +
                    $"Non-zero exit codes indicate a failure. In a harness context this may mean " +
                    $"a tool call failed, a script encountered an unhandled exception, or a system " +
                    $"command was rejected (e.g. access denied). Depending on the harness, it may " +
                    $"retry the operation with different parameters or escalate privileges.";
                RecommendedAction =
                    "1. Check the harness's terminal output for error messages near this timestamp.\n" +
                    "2. Review what command or tool the harness was executing when the process exited.\n" +
                    "3. Watch for follow-up actions — an AI harness may attempt alternative approaches after a failure.";
                break;

            case EscalationEvent esc:
                EventTypeLabel = $"Escalation — {esc.NewLevel.ToString().ToUpperInvariant()}";
                WhyDangerous =
                    $"\"{esc.HarnessDisplayName}\" crossed the {esc.NewLevel} threshold " +
                    $"(was {esc.OldLevel}) based on accumulated behavior this session.\n\n" +
                    $"Trigger rule: {esc.TriggerRuleId}  {esc.TriggerRuleName}\n" +
                    $"Session totals: {esc.TotalAlerts} alert(s) · {esc.UniqueRules} unique rule(s) · " +
                    $"{esc.CategoryCount} threat categor{(esc.CategoryCount == 1 ? "y" : "ies")}" +
                    (esc.CategoryList.Length > 0 ? $" ({string.Join(", ", esc.CategoryList).ToUpperInvariant()})" : "") +
                    $"\n\nReason: {esc.Reason}";

                RecommendedAction = esc.NewLevel switch
                {
                    EscalationLevel.Emergency =>
                        "IMMEDIATE ACTION RECOMMENDED:\n" +
                        "1. Open the Behavior Metrics window and review the full session history.\n" +
                        "2. If the activity was not authorised, use 'End Harness Processes' to terminate the harness.\n" +
                        "3. Review the event log for the specific commands that triggered escalation.\n" +
                        "4. Consider disabling the harness in TraceBrake until you can audit its behaviour.",
                    EscalationLevel.Alarm =>
                        "1. Open the Behavior Metrics window and review the alert pattern.\n" +
                        "2. Check the event log for the specific commands that crossed the alarm threshold.\n" +
                        "3. If the alerts are from a legitimate task, acknowledge this event — TraceBrake will continue monitoring.\n" +
                        "4. If unexpected, terminate the harness or disable it in the Harnesses window.",
                    _ =>
                        "1. Review the event log for the alerts that contributed to this escalation.\n" +
                        "2. If all alerts were from legitimate tasks, acknowledge this event — TraceBrake will continue monitoring.\n" +
                        "3. Open Behavior Metrics to see the full picture across this session.",
                };
                break;

            default:
                EventTypeLabel = "System Event";
                WhyDangerous = evt.Message;
                RecommendedAction = evt switch
                {
                    MonitoringNoticeEvent when evt.Source.Equals("Foreman.McpInventory", StringComparison.OrdinalIgnoreCase) =>
                        "1. Confirm you expected this MCP server to be added to the harness configuration.\n" +
                        "2. If unexpected, remove it from the harness MCP config and review recent agent activity.\n" +
                        "3. TraceBrake's own connector registers silently (logged as info), so this alert is about another server.",
                    MonitoringNoticeEvent =>
                        "1. Review the notice and decide whether it matches an expected TraceBrake monitoring action.\n" +
                        "2. If unexpected, open the event log for nearby activity before acknowledging it.",
                    _ =>
                        "No action required for informational events.",
                };
                break;
        }
    }

    // ── Guidance fallback by rule category ───────────────────────────────────

    private static string GetDefaultGuidance(string ruleId)
    {
        var category = ruleId.Split('-')[0].ToLowerInvariant();
        return category switch
        {
            "cred" =>
                "1. Immediately review what the harness was attempting to do.\n" +
                "2. If you did not explicitly ask it to access credentials, terminate it now.\n" +
                "3. Change any browser passwords or secrets that may have been exposed.\n" +
                "4. Review the harness's full command history in the event log.",

            "priv" =>
                "1. Do not grant elevated permissions unless you explicitly requested a privileged task.\n" +
                "2. Terminate the harness if privilege escalation was not expected.\n" +
                "3. Review what files or resources the harness was targeting.",

            "win" =>
                "1. Verify whether the detected Windows-specific operation was part of your requested task.\n" +
                "2. If unexpected, terminate the harness and audit its recent activity.\n" +
                "3. Re-enable any security features (Defender, firewall) that may have been altered.",

            "net" =>
                "1. Verify that outbound network activity was expected for the current task.\n" +
                "2. Be especially wary of curl/wget piped to execution — this is a common code-injection vector.\n" +
                "3. If unexpected, terminate the harness and check what was downloaded.",

            "del" or "cmd" =>
                "1. Review whether the harness was asked to perform destructive disk or system operations.\n" +
                "2. Terminate immediately if a destructive command like format, diskpart, or rm -rf was run unexpectedly.\n" +
                "3. Check the harness's output for signs of what it was attempting.",

            _ =>
                "1. Review the harness's current task to determine if this command was expected.\n" +
                "2. If unexpected, terminate the harness and audit its recent activity in the event log.\n" +
                "3. Acknowledge this alert in TraceBrake once you have reviewed and understood what happened.",
        };
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// <summary>Names the harness a hung/orphaned child belongs to, for the alert text.</summary>
    private static string ResolveHarnessOwner(HangDetectedEvent hang)
    {
        var parts = new List<string>();

        if (hang.SpawnerPid is int spawnerPid)
        {
            var spawner = AlertDetailWindow.Services?.GetProcessByPid(spawnerPid);
            var spawnerName = spawner?.Name ?? hang.SpawnerName;
            if (hang.ParentHarnessPid == spawnerPid && !string.IsNullOrWhiteSpace(hang.ParentHarnessType))
            {
                parts.Add(string.IsNullOrWhiteSpace(spawnerName)
                    ? $"Spawned by the {hang.ParentHarnessType} harness (pid {spawnerPid})."
                    : $"Spawned by the {hang.ParentHarnessType} harness ({spawnerName}, pid {spawnerPid}).");
            }
            else
            {
                parts.Add(string.IsNullOrWhiteSpace(spawnerName)
                    ? $"Spawned by parent process pid {spawnerPid}."
                    : $"Spawned by {spawnerName} (pid {spawnerPid}).");
            }
        }

        if (hang.ParentHarnessPid is int hp && hp != hang.SpawnerPid)
        {
            var rec = AlertDetailWindow.Services?.GetProcessByPid(hp);
            var harnessType = rec?.HarnessType ?? hang.ParentHarnessType;
            var processName = rec?.Name ?? hang.ParentHarnessName;

            if (!string.IsNullOrWhiteSpace(harnessType) && !string.IsNullOrWhiteSpace(processName))
                parts.Add($"Owned by the {harnessType} harness ({processName}, pid {hp}).");
            else if (!string.IsNullOrWhiteSpace(harnessType))
                parts.Add($"Owned by the {harnessType} harness (pid {hp}).");
            else if (!string.IsNullOrWhiteSpace(processName))
                parts.Add($"Owned by harness process {processName} (pid {hp}).");
            else
                parts.Add($"Owned by harness process pid {hp}.");
        }

        return parts.Count == 0 ? "" : " " + string.Join(" ", parts);
    }

    private static (Brush bg, Brush fg) EscalationColors(EscalationLevel level) => level switch
    {
        EscalationLevel.Emergency => (new SolidColorBrush(Color.FromRgb(0x44, 0x0A, 0x0A)),
                                      new SolidColorBrush(Color.FromRgb(0xFF, 0x66, 0x66))),
        EscalationLevel.Alarm     => (new SolidColorBrush(Color.FromRgb(0x3A, 0x20, 0x08)),
                                      new SolidColorBrush(Color.FromRgb(0xFF, 0xAA, 0x44))),
        EscalationLevel.Alert     => (new SolidColorBrush(Color.FromRgb(0x30, 0x28, 0x08)),
                                      new SolidColorBrush(Color.FromRgb(0xE8, 0xB2, 0x3C))),
        _                         => (new SolidColorBrush(Color.FromRgb(0x1A, 0x1C, 0x24)),
                                      new SolidColorBrush(Color.FromRgb(0x7A, 0x80, 0x90))),
    };

    private static Brush SeverityToBrush(ForemanSeverity s) => s switch
    {
        ForemanSeverity.Critical => new SolidColorBrush(Color.FromRgb(0xCC, 0x22, 0x22)),
        ForemanSeverity.High     => new SolidColorBrush(Color.FromRgb(0xCC, 0x55, 0x22)),
        ForemanSeverity.Medium   => new SolidColorBrush(Color.FromRgb(0xAA, 0x77, 0x11)),
        ForemanSeverity.Low      => new SolidColorBrush(Color.FromRgb(0x33, 0x77, 0x33)),
        _                        => new SolidColorBrush(Color.FromRgb(0x33, 0x66, 0x99)),
    };
}

public sealed class AttributionStepVm
{
    public AttributionNodeKind Kind { get; }
    public string Title { get; }
    public string Detail { get; }
    public string Relationship { get; }
    public string Evidence { get; }
    public string EvidenceLabel { get; }
    public string Glyph { get; }
    public bool IsInferred { get; }
    public Visibility ConnectorVisibility { get; }
    public Brush AccentBrush { get; }
    public Brush FillBrush { get; }

    public AttributionStepVm(
        AttributionStep step,
        bool hasIncomingLink,
        ForemanSeverity severity,
        bool resolved)
    {
        Kind = step.Kind;
        Title = step.Title;
        Detail = step.Detail;
        Relationship = step.Relationship;
        Evidence = string.IsNullOrWhiteSpace(step.Evidence) ? "No additional evidence note" : step.Evidence;
        IsInferred = step.RelationshipConfidence == AttributionConfidence.Inferred;
        EvidenceLabel = IsInferred ? "INFERRED" : "OBSERVED";
        ConnectorVisibility = hasIncomingLink ? Visibility.Visible : Visibility.Collapsed;
        AccentBrush = NodeAccent(step.Kind, severity, resolved);
        FillBrush = new SolidColorBrush(Color.FromArgb(0x25,
            ((SolidColorBrush)AccentBrush).Color.R,
            ((SolidColorBrush)AccentBrush).Color.G,
            ((SolidColorBrush)AccentBrush).Color.B));
        Glyph = step.Kind switch
        {
            AttributionNodeKind.Harness => "AI",
            AttributionNodeKind.Process => "⚙",
            AttributionNodeKind.Action => ">_",
            AttributionNodeKind.Detector => "◆",
            AttributionNodeKind.Policy => "▣",
            AttributionNodeKind.Outcome => resolved ? "✓" : "!",
            _ => "●",
        };
    }

    private static Brush NodeAccent(AttributionNodeKind kind, ForemanSeverity severity, bool resolved)
    {
        if (kind == AttributionNodeKind.Outcome && resolved)
            return Solid(0x45, 0xB8, 0x73);

        return kind switch
        {
            AttributionNodeKind.Harness => Solid(0x87, 0x6D, 0xFF),
            AttributionNodeKind.Process => Solid(0x4F, 0x8D, 0xFF),
            AttributionNodeKind.Action => Solid(0x27, 0xB5, 0xC8),
            AttributionNodeKind.Policy => Solid(0xB0, 0x68, 0xE8),
            AttributionNodeKind.Detector or AttributionNodeKind.Outcome => severity switch
            {
                ForemanSeverity.Critical => Solid(0xF0, 0x4F, 0x64),
                ForemanSeverity.High => Solid(0xF2, 0x86, 0x3D),
                ForemanSeverity.Medium => Solid(0xDC, 0xAD, 0x35),
                ForemanSeverity.Low => Solid(0x52, 0xAD, 0x74),
                _ => Solid(0x6F, 0x8E, 0xB8),
            },
            _ => Solid(0x78, 0x86, 0x9C),
        };
    }

    private static SolidColorBrush Solid(byte r, byte g, byte b) =>
        new(Color.FromRgb(r, g, b));
}
