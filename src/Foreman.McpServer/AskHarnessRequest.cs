namespace Foreman.McpServer;

/// <summary>
/// Durable hand-off for "Ask Harness" prompts. Server-initiated MCP delivery is best-effort, so
/// harnesses can also poll TraceBrake for pending prompts and reply through MCP tools.
/// </summary>
public sealed record AskHarnessRequest(
    string RequestId,
    DateTimeOffset CreatedAt,
    string AlertId,
    string HarnessId,
    int? ProcessId,
    string? ProcessName,
    string SystemPrompt,
    string Prompt,
    string Status,
    DateTimeOffset? RepliedAt = null,
    string? ReplyText = null,
    string? ActionTaken = null,
    string? SenderHarnessId = null,
    string RequestKind = "ask_harness");

/// <summary>
/// The lifecycle states of <see cref="AskHarnessRequest.Status"/>. A request is born <see cref="Pending"/>;
/// a harness reply moves it to <see cref="Answered"/>; if no reply arrives within the configured timeout the
/// reaper ages it to <see cref="Expired"/> — distinct from "answered" (we asked, nobody answered in time) and
/// logged, never silently dropped. A late reply to an expired request is still accepted and recorded (the
/// agent may have reconnected after the timeout).
/// </summary>
public static class AskHarnessStatus
{
    public const string Pending  = "pending";
    public const string Answered = "answered";
    public const string Expired  = "expired";

    /// <summary>Terminal (resolved) states — evicted under the count cap before any still-open pending request.</summary>
    public static bool IsTerminal(string status) => status is Answered or Expired;
}
