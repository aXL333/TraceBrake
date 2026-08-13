namespace Foreman.Core.Models;

/// <summary>
/// Pure decision logic for "Idle Harness self-cleanup": when a harness process tree looks
/// abandoned, TraceBrake asks the harness over MCP to pack up cleanly (checkpoint work, stop
/// leftover children, release resources) instead of silently burning CPU/tokens. The
/// orchestration (timer, mailbox, MCP push) lives in Foreman.Monitor/App; everything here
/// is side-effect-free and unit-testable.
///
/// This is a housekeeping nudge, not an enforcement action: the harness decides what to do,
/// and an unanswered request only escalates to a visible notice suggesting the operator act.
/// </summary>
public static class IdleCleanupPolicy
{
    /// <summary>
    /// True when the harness tree looks abandoned: every judgeable (readable-counters,
    /// not-terminated) process has been I/O-silent for at least <paramref name="idleAfterMinutes"/>,
    /// AND nothing in the tree was spawned more recently than that (a fresh child is activity),
    /// AND at least one process is judgeable at all. Records with unavailable I/O counters
    /// (elevated children) can't veto idleness, but their spawn time still counts as activity.
    /// </summary>
    public static bool IsTreeIdle(IReadOnlyList<ProcessRecord> tree, int idleAfterMinutes, DateTimeOffset now)
    {
        var threshold = TimeSpan.FromMinutes(Math.Max(1, idleAfterMinutes));
        var live = tree.Where(r => r.State != ProcessState.Terminated).ToList();
        if (live.Count == 0) return false;

        var judgeable = live.Where(r => !r.IoCountersUnavailable).ToList();
        if (judgeable.Count == 0) return false;                       // can't tell — never nag blind

        if (live.Any(r => now - r.StartTime < threshold)) return false;          // recent spawn = activity
        return judgeable.All(r => now - r.LastIoChangeTime >= threshold);
    }

    /// <summary>Minutes since the tree last did anything — min silent time across judgeable processes.</summary>
    public static int TreeIdleMinutes(IReadOnlyList<ProcessRecord> tree, DateTimeOffset now)
    {
        var judgeable = tree
            .Where(r => r.State != ProcessState.Terminated && !r.IoCountersUnavailable)
            .ToList();
        if (judgeable.Count == 0) return 0;
        return (int)judgeable.Min(r => (now - r.LastIoChangeTime).TotalMinutes);
    }

    /// <summary>Whether an automatic request may fire — once per harness per cooldown window.</summary>
    public static bool ShouldAutoRequest(DateTimeOffset? lastRequestAt, int cooldownMinutes, DateTimeOffset now)
        => lastRequestAt is null
        || now - lastRequestAt.Value >= TimeSpan.FromMinutes(Math.Max(1, cooldownMinutes));

    /// <summary>
    /// Whether an unanswered cleanup request should escalate to a visible notice. Fires at most
    /// once per request, only while the request is still pending AND the tree is still idle —
    /// if the harness woke up or replied, there is nothing to escalate.
    /// </summary>
    public static bool ShouldEscalate(
        DateTimeOffset requestedAt, bool stillPending, bool stillIdle, bool alreadyEscalated,
        int graceMinutes, DateTimeOffset now)
        => !alreadyEscalated
        && stillPending
        && stillIdle
        && now - requestedAt >= TimeSpan.FromMinutes(Math.Max(1, graceMinutes));

    /// <summary>
    /// Builds the system/user prompts delivered to the harness (via the Ask-Harness mailbox and,
    /// when a session is live, the sampling/notification push). The request id is not embedded —
    /// agents see it alongside the prompt in ListAskHarnessRequests, and pushes carry it separately.
    /// </summary>
    public static (string System, string User) BuildPrompts(
        string harnessId, int idleMinutes, IReadOnlyList<string> childNames, bool manual)
    {
        var system =
            $"You are the '{harnessId}' coding agent. TraceBrake, the local watchdog on this machine, " +
            "is asking you to wrap up an apparently idle session. This is routine housekeeping, not an accusation — " +
            "if you are mid-task or waiting on the user, just say so.";

        var trigger = manual
            ? "The operator asked TraceBrake to request a session cleanup from you."
            : $"Your process tree has shown no I/O activity for about {idleMinutes} minute(s) and looks abandoned.";

        var children = childNames.Count > 0
            ? $" Your tracked child processes: {string.Join(", ", childNames.Distinct(StringComparer.OrdinalIgnoreCase).Take(8))}."
            : "";

        var user =
            $"{trigger}{children}\n" +
            "Please pack up cleanly:\n" +
            "1. Finish or checkpoint your current work (save files; commit only if your own instructions allow it).\n" +
            "2. Stop any leftover child processes you spawned (builds, dev servers, file watchers, shells).\n" +
            "3. Release file locks and clean up temp resources you own.\n" +
            $"4. Reply via reply_to_ask_harness_request(requestId, response, actionTaken, harnessId: \"{harnessId}\") " +
            "— the requestId is shown by list_ask_harness_requests.\n" +
            "5. If this session is still needed (mid-task, waiting for the user), reply saying so and TraceBrake will leave you alone.";

        return (system, user);
    }

    /// <summary>
    /// "Prep for update" disposition for one harness tree: <see cref="UpdatePrepDisposition.Reap"/> an already-idle /
    /// abandoned tree (safe to kill — a cooperative ask would go unanswered), <see cref="UpdatePrepDisposition.Checkpoint"/>
    /// an active one (cooperative request, never killed), or <see cref="UpdatePrepDisposition.Skip"/> (local-model host /
    /// nothing live). Pure so the reap-vs-nudge decision is unit-tested away from the real kill path.
    /// </summary>
    public static UpdatePrepDisposition ClassifyForUpdatePrep(
        string harnessType, IReadOnlyList<ProcessRecord> tree, bool isLocalModelHost,
        int idleAfterMinutes, DateTimeOffset now)
    {
        // Never reap or nag a local-model host (LM Studio / Ollama) — idling between prompts is its normal state.
        if (isLocalModelHost) return UpdatePrepDisposition.Skip;
        var live = tree.Where(r => r.State != ProcessState.Terminated).ToList();
        if (live.Count == 0) return UpdatePrepDisposition.Skip;
        return IsTreeIdle(live, idleAfterMinutes, now)
            ? UpdatePrepDisposition.Reap          // abandoned → clean it up
            : UpdatePrepDisposition.Checkpoint;   // active → ask it to save/commit before the restart; never kill it
    }

    /// <summary>
    /// Prompts for the "prep for update" cooperative request: like the idle nudge, but framed as an imminent
    /// update/restart rather than abandonment, so an ACTIVE agent checkpoints instead of being told it looks idle.
    /// </summary>
    public static (string System, string User) BuildUpdatePrepPrompts(string harnessId, IReadOnlyList<string> childNames)
    {
        var system =
            $"You are the '{harnessId}' coding agent. TraceBrake, the local watchdog on this machine, is " +
            "preparing for an imminent update or restart that may interrupt you. This is routine — checkpoint so nothing is lost.";

        var children = childNames.Count > 0
            ? $" Your tracked child processes: {string.Join(", ", childNames.Distinct(StringComparer.OrdinalIgnoreCase).Take(8))}."
            : "";

        var user =
            $"An update or restart is imminent and may interrupt this session.{children}\n" +
            "Please get to a safe-to-interrupt state now:\n" +
            "1. Save and checkpoint your work; commit it ONLY if your own instructions allow committing.\n" +
            "2. Stop any leftover child processes you spawned (builds, dev servers, file watchers, shells).\n" +
            "3. Release file locks and clean up temp resources you own.\n" +
            $"4. Reply via reply_to_ask_harness_request(requestId, response, actionTaken, harnessId: \"{harnessId}\") " +
            "with whether you are safe to interrupt — the requestId is shown by list_ask_harness_requests.";

        return (system, user);
    }
}

/// <summary>What "prep for update" should do with one harness tree. See <see cref="IdleCleanupPolicy.ClassifyForUpdatePrep"/>.</summary>
public enum UpdatePrepDisposition { Skip, Checkpoint, Reap }
