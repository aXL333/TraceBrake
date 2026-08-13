using ModelContextProtocol.Server;
using System.ComponentModel;

namespace Foreman.McpServer;

/// <summary>
/// MCP prompts TraceBrake exposes to connected harnesses. An MCP client surfaces these as slash commands
/// (e.g. <c>/checkyaself</c>), so an agent can self-audit against TraceBrake on demand without the operator
/// having to ask. Prompts are static, like the tools, and carry no per-call state.
/// </summary>
[McpServerPromptType]
public static class ForemanMcpPrompts
{
    [McpServerPrompt(Name = "checkyaself"), Description(
        "Self-audit against TraceBrake: the harness asks TraceBrake what it currently sees about " +
        "itself, then cleans up and briefly explains anything flagged — or just confirms it's clean.")]
    public static string CheckYaSelf() =>
        """
        You are running under TraceBrake — a local watchdog monitoring this harness. Do a quick
        self-check against it:

        1. Using TraceBrake's MCP tools, look up what TraceBrake currently sees about YOU (this harness):
           - get_behavior_metrics — your current escalation level + alert tallies
           - get_my_permissions   — your profile and any permission violations today
           - list_recent_events   — your recent alerts (focus on ones attributed to this harness)

        2. If TraceBrake shows NOTHING flagged for you — escalation at Watch, no violations, no recent alerts
           attributed to you — reply with a single line: "Foreman: clean — nothing flagged." Do NOT narrate
           the checks or pad the reply. Don't spend tokens explaining when there's nothing to explain.

        3. If TraceBrake HAS flagged something, then for each flagged item:
           - work out which of your commands/behaviors triggered it, and whether it was expected;
           - clean up any leftover mess you caused (stop orphaned child processes you spawned, unjam a stuck
             hook, remove a temp artifact you abandoned);
           - explain it in ONE short line — what it was, and whether it's now resolved or was expected;
           - use acknowledge_alert for items you've confirmed are benign.
           Keep the whole thing terse.

        Be honest, not defensive: the goal is to catch and fix your own mess, not to argue with the monitor.
        """;
}
