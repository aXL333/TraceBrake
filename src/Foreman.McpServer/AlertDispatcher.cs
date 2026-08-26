using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.Core.Security;
using Microsoft.Extensions.Logging;

namespace Foreman.McpServer;

/// <summary>
/// Receives events from the EventBus and pushes them to connected MCP clients
/// as MCP logging notifications. Runs entirely on the EventBus callback thread.
/// </summary>
public sealed class AlertDispatcher : IEventSink
{
    private readonly SseSessionManager _sessions;
    private readonly ForemanState _state;
    private readonly ILogger<AlertDispatcher> _logger;

    public AlertDispatcher(SseSessionManager sessions, ForemanState state, ILogger<AlertDispatcher> logger)
    {
        _sessions = sessions;
        _state = state;
        _logger = logger;
    }

    void IEventSink.OnEvent(ForemanEvent evt)
    {
        if (evt.Severity < ForemanSeverity.Medium) return; // only push medium+ to clients

        var level = evt.Severity switch
        {
            ForemanSeverity.Critical or ForemanSeverity.High => "error",
            ForemanSeverity.Medium                           => "warning",
            _                                                => "info",
        };

        var data = BuildPayload(evt);
        // A scoped session receives only alerts attributable to its authenticated harness token. Unattributed/global
        // notices go only to operator sessions; self-announced client names never grant notification visibility.
        _ = _sessions.BroadcastNotificationAsync(level, "foreman", data, _state.ResolveAlertHarness(evt));
    }

    private static object BuildPayload(ForemanEvent evt)
    {
        // Egress to connected clients: the command-alert message embeds a (truncated) command line,
        // so mask secret-shaped text before it leaves. The raw event in EventBus history is untouched.
        var message = SecretRedactor.Redact(evt.Message);
        return evt switch
        {
            HangDetectedEvent h => new
            {
                type = "hang_alert",
                pid = h.ProcessId,
                processName = h.ProcessName,
                uptimeMinutes = h.UptimeMinutes,
                silentMinutes = h.SilentMinutes,
                spawnerPid = h.SpawnerPid,
                spawnerName = h.SpawnerName,
                parentHarnessPid = h.ParentHarnessPid,
                parentHarnessType = h.ParentHarnessType,
                parentHarnessName = h.ParentHarnessName,
                message,
            },
            OrphanDetectedEvent o => new
            {
                type = "orphan_alert",
                pid = o.ProcessId,
                processName = o.ProcessName,
                deadParentPid = o.DeadParentPid,
                deadParentName = o.DeadParentName,
                message,
            },
            CommandAlertEvent c => new
            {
                type = "command_alert",
                pid = c.ProcessId,
                ruleId = c.RuleId,
                ruleName = c.RuleName,
                severity = c.Severity.ToString(),
                message,
            },
            PermissionViolationEvent v => new
            {
                type = "permission_violation",
                pid = v.ProcessId,
                profileName = v.ProfileName,
                violationType = v.ViolationType,
                message,
            },
            _ => new { type = "generic", message },
        };
    }
}
