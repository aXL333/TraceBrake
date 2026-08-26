using System.Collections.Concurrent;
using System.Text.Json;

namespace Foreman.McpServer;

public enum LiveWeaveCommandStatus
{
    Pending,
    Delivered,
    TimedOut,
    Completed,
    Failed,
}

public sealed record LiveWeaveCommand(
    string CommandId,
    string Action,
    IReadOnlyDictionary<string, object?> Parameters,
    DateTimeOffset CreatedAt,
    LiveWeaveCommandStatus Status,
    object? Result = null,
    string? Error = null,
    DateTimeOffset? CompletedAt = null,
    string? ByHarness = null);   // delivery gate only; opaque command IDs intentionally support driver handoff

public sealed class LiveWeavePresence
{
    public DateTimeOffset LastSeen { get; set; }
    public object? TabInfo { get; set; }
    public string? NanoStatus { get; set; }
}

/// <summary>
/// Command queue between TraceBrake MCP (agents) and the LiveWeave Chrome extension.
/// Agents enqueue; the extension polls and completes.
/// </summary>
public sealed class LiveWeaveBroker
{
    private readonly ConcurrentDictionary<string, LiveWeaveCommand> _commands = new();
    private readonly ConcurrentQueue<string> _pending = new();
    private readonly object _admissionLock = new();
    private readonly object _presenceLock = new();
    private readonly object _driverLock = new();
    private LiveWeavePresence _presence = new();
    private const int MaxCommands = 100;
    private const int MaxNonTerminalCommands = 80;  // leave receipt capacity while hard-capping live work globally
    private const int MaxNonTerminalPerHarness = 30;
    private const int MaxParameterFields = 64;
    private const int MaxParamsChars = 256 * 1024;  // cap inbound command payload (parity with resultJson/tabInfo caps)
    // A command that is never picked up (extension not open/paired/reachable) or never completed (extension crashed
    // mid-command) is failed after this window, so the agent's liveweave_command_result poll gets a terminal status
    // instead of hanging forever. LiveWeave commands are near-instant, and a connected extension polls at least every
    // ~30s, so 2 min comfortably distinguishes "busy" from "gone".
    private static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan HardExpiryAfter = TimeSpan.FromMinutes(10);
    private volatile string? _driver;   // null = operator only; "*" = any harness; otherwise chosen harness id
    private readonly Func<DateTimeOffset> _now;

    /// <summary>Default clock is wall time; tests inject one to exercise stale-expiry without waiting.</summary>
    public LiveWeaveBroker(Func<DateTimeOffset>? clock = null) => _now = clock ?? (() => DateTimeOffset.UtcNow);

    /// <summary>"operator" marker recorded for commands enqueued by the unscoped install token — always allowed.</summary>
    private const string OperatorMarker = "operator";

    /// <summary>The harness the operator chose to let drive the builder; null = operator only, "*" = any harness.</summary>
    public string? Driver => _driver;

    /// <summary>Set by the LiveWeave extension to the harness it accepts commands from. Empty means operator only;
    /// "any" is the explicit broad mode.</summary>
    public void SetDriver(string? harnessId)
    {
        lock (_driverLock)
        {
            if (string.IsNullOrWhiteSpace(harnessId))
            {
                _driver = null;
                return;
            }

            var normalized = harnessId.Trim().ToLowerInvariant();
            _driver = string.Equals(normalized, "any", StringComparison.OrdinalIgnoreCase) ? "*" : normalized;
        }
    }

    /// <summary>May commands from <paramref name="harnessId"/> drive LiveWeave? The operator always may; an
    /// operator-enqueued command always may; a harness only when it is the chosen driver, or when "any" was
    /// explicitly selected.</summary>
    public bool CanDrive(string? harnessId, bool isOperator)
    {
        if (isOperator || string.Equals(harnessId, OperatorMarker, StringComparison.OrdinalIgnoreCase)) return true;
        var d = _driver;
        if (string.IsNullOrEmpty(d)) return false;
        if (string.Equals(d, "*", StringComparison.Ordinal)) return true;
        return harnessId is not null && string.Equals(harnessId, d, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Resolve stale commands without pretending a delivered command is safe to retry. A never-delivered Pending
    /// command can fail terminally. A Delivered command becomes TimedOut (outcome uncertain) and remains eligible
    /// for a late completion, preventing an expiry/completion race from encouraging an agent-side double apply.
    /// </summary>
    private void ExpireStale()
    {
        var now = _now();
        var cutoff = now - StaleAfter;
        foreach (var (id, cmd) in _commands)
        {
            if (cmd.Status == LiveWeaveCommandStatus.TimedOut && cmd.CreatedAt <= now - HardExpiryAfter)
            {
                _commands.TryUpdate(id, cmd with
                {
                    Status = LiveWeaveCommandStatus.Failed,
                    Error = $"LiveWeave completion never arrived after {(int)HardExpiryAfter.TotalMinutes} min. " +
                            "The execution outcome remains uncertain; inspect the canvas before retrying.",
                    CompletedAt = now,
                }, cmd);
                continue;
            }
            if (cmd.Status is not (LiveWeaveCommandStatus.Pending or LiveWeaveCommandStatus.Delivered)) continue;
            if (cmd.CreatedAt > cutoff) continue;
            var wasDelivered = cmd.Status == LiveWeaveCommandStatus.Delivered;
            _commands.TryUpdate(id, cmd with
            {
                Status = wasDelivered ? LiveWeaveCommandStatus.TimedOut : LiveWeaveCommandStatus.Failed,
                Error = wasDelivered
                    ? $"LiveWeave completion is overdue after {(int)StaleAfter.TotalMinutes} min. The outcome is " +
                      "uncertain: do not resubmit this edit automatically; keep polling or inspect the canvas."
                    : $"LiveWeave command timed out after {(int)StaleAfter.TotalMinutes} min — the LiveWeave " +
                      "extension never accepted it. Is it open in Chrome and paired with Foreman?",
                CompletedAt = wasDelivered ? null : now,
            }, cmd);
        }
    }

    public string Enqueue(string action, IReadOnlyDictionary<string, object?>? parameters = null, string? byHarness = null)
    {
        lock (_admissionLock)
        {
            ExpireStale();
            var id = Guid.NewGuid().ToString("N");
            var harness = string.IsNullOrWhiteSpace(byHarness) ? null : byHarness.Trim().ToLowerInvariant();
            var parameterReject = TrySnapshotParameters(parameters, out var snapshot);
            var reject = parameterReject ?? RejectCapacityReason(harness);
            var normalizedAction = (action ?? string.Empty).Trim().ToLowerInvariant();
            if (normalizedAction.Length is < 1 or > 64
                || normalizedAction.Any(ch => !char.IsAsciiLetterLower(ch) && ch != '_'))
                reject ??= "LiveWeave action must be a bounded lowercase action id.";
            var now = _now();
            var cmd = new LiveWeaveCommand(
                id,
                normalizedAction,
                snapshot,
                now,
                reject is null ? LiveWeaveCommandStatus.Pending : LiveWeaveCommandStatus.Failed,
                Error: reject,
                CompletedAt: reject is null ? null : now,
                ByHarness: harness);

            _commands[id] = cmd;
            if (reject is null) _pending.Enqueue(id);
            Prune();
            return id;
        }
    }

    // Reason to reject an enqueue (surfaced as the command's terminal error so the agent's result-poll sees it),
    // or null to accept.
    private string? RejectCapacityReason(string? harness)
    {
        var live = _commands.Values.Count(IsNonTerminal);
        if (live >= MaxNonTerminalCommands)
            return $"Too many live LiveWeave commands ({live}); let them complete or expire first.";
        if (harness is not null)
        {
            var pending = _commands.Values.Count(c =>
                IsNonTerminal(c) &&
                string.Equals(c.ByHarness, harness, StringComparison.OrdinalIgnoreCase));
            if (pending >= MaxNonTerminalPerHarness)
                return $"Too many live LiveWeave commands for '{harness}' ({pending}); let them complete or expire first.";
        }
        return null;
    }

    private static string? TrySnapshotParameters(
        IReadOnlyDictionary<string, object?>? parameters,
        out IReadOnlyDictionary<string, object?> snapshot)
    {
        snapshot = new Dictionary<string, object?>();
        if (parameters is null or { Count: 0 }) return null;
        if (parameters.Count > MaxParameterFields)
            return $"LiveWeave command parameters have too many fields (cap {MaxParameterFields}).";
        if (parameters.Keys.Any(static key => string.IsNullOrWhiteSpace(key) || key.Length > 64))
            return "LiveWeave parameter names must be 1-64 characters.";

        try
        {
            var options = new JsonSerializerOptions { MaxDepth = 32 };
            var json = JsonSerializer.Serialize(parameters, options);
            if (json.Length > MaxParamsChars)
                return $"LiveWeave command parameters too large ({json.Length} chars; cap {MaxParamsChars}).";
            var parsed = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json, options)
                         ?? new Dictionary<string, JsonElement>();
            snapshot = parsed.ToDictionary(
                static pair => pair.Key,
                static pair => (object?)pair.Value.Clone(),
                StringComparer.OrdinalIgnoreCase);
            return null;
        }
        catch
        {
            return "LiveWeave command parameters could not be serialized.";
        }
    }

    public IReadOnlyList<LiveWeaveCommand> Poll(int limit)
    {
        ExpireStale();
        var n = Math.Clamp(limit, 1, 10);
        var batch = new List<LiveWeaveCommand>(n);
        while (batch.Count < n && _pending.TryDequeue(out var id))
        {
            if (!_commands.TryGetValue(id, out var cmd)) continue;
            if (cmd.Status != LiveWeaveCommandStatus.Pending) continue;
            // Driver decision + Pending transition share the driver lock with SetDriver, and the state update is CAS.
            // Thus a concurrent expiry/completion cannot be overwritten and a driver switch cannot race this claim.
            lock (_driverLock)
            {
                if (!_commands.TryGetValue(id, out cmd) || cmd.Status != LiveWeaveCommandStatus.Pending) continue;
                if (!CanDrive(cmd.ByHarness, isOperator: false))
                {
                    var d = _driver;
                    _commands.TryUpdate(id, cmd with
                    {
                        Status = LiveWeaveCommandStatus.Failed,
                        Error = string.IsNullOrEmpty(d)
                            ? $"Rejected: LiveWeave has no harness driver selected; '{cmd.ByHarness ?? "unknown"}' cannot drive it."
                            : $"Rejected: LiveWeave is set to accept commands only from '{DriverLabel(d)}', not '{cmd.ByHarness ?? "unknown"}'.",
                        CompletedAt = _now(),
                    }, cmd);
                    continue;
                }
                var delivered = cmd with { Status = LiveWeaveCommandStatus.Delivered };
                if (_commands.TryUpdate(id, delivered, cmd)) batch.Add(delivered);
            }
        }
        TouchPresence();
        return batch;
    }

    public (bool Ok, string Reason) Complete(string commandId, bool ok, object? result, string? error)
    {
        // Compare-and-swap so two concurrent completions of one id can't both pass the terminal-status guard and
        // last-writer-win (silently dropping one result while both report success). Mirrors ExpireStale's CAS.
        while (true)
        {
            if (!_commands.TryGetValue(commandId, out var cmd))
                return (false, "Unknown command id.");

            if (cmd.Status is LiveWeaveCommandStatus.Completed or LiveWeaveCommandStatus.Failed)
                return (false, "Command already completed.");
            if (cmd.Status == LiveWeaveCommandStatus.Pending)
                return (false, "Command has not been delivered to the LiveWeave extension.");

            var done = cmd with
            {
                Status = ok ? LiveWeaveCommandStatus.Completed : LiveWeaveCommandStatus.Failed,
                Result = result,
                Error = string.IsNullOrWhiteSpace(error) ? null : error.Trim(),
                CompletedAt = _now(),
            };
            if (_commands.TryUpdate(commandId, done, cmd))
            {
                TouchPresence();
                return (true, ok ? "Completed." : "Failed.");
            }
            // lost the race with a concurrent Complete/ExpireStale — re-read and re-check.
        }
    }

    public LiveWeaveCommand? GetCommand(string commandId)
    {
        ExpireStale();   // so the agent's result-poll sees a timed-out command as Failed, not perpetually Pending
        return _commands.TryGetValue(commandId, out var c) ? c : null;
    }

    public void UpdatePresence(object? tabInfo, string? nanoStatus)
    {
        lock (_presenceLock)
        {
            _presence.LastSeen = DateTimeOffset.UtcNow;
            if (tabInfo is not null) _presence.TabInfo = tabInfo;
            if (!string.IsNullOrWhiteSpace(nanoStatus)) _presence.NanoStatus = nanoStatus;
        }
    }

    /// <summary>
    /// True when the LiveWeave extension has polled/checked in within the last 30 seconds — the same
    /// presence window <see cref="DescribeStatus"/> reports. Lets the Connect-Agent UI show live link state
    /// without depending on MCP session bookkeeping (the extension polls, it holds no persistent session).
    /// </summary>
    public bool IsConnected
    {
        get
        {
            lock (_presenceLock)
                return DateTimeOffset.UtcNow - _presence.LastSeen < TimeSpan.FromSeconds(30);
        }
    }

    public object DescribeStatus()
    {
        ExpireStale();   // so pendingCommands/inFlightCommands reflect timed-out commands, not zombies
        lock (_presenceLock)
        {
            var age = DateTimeOffset.UtcNow - _presence.LastSeen;
            var connected = age < TimeSpan.FromSeconds(30);
            var pending = _commands.Values.Count(c => c.Status == LiveWeaveCommandStatus.Pending);
            var delivered = _commands.Values.Count(c => c.Status == LiveWeaveCommandStatus.Delivered);
            var timedOut = _commands.Values.Count(c => c.Status == LiveWeaveCommandStatus.TimedOut);
            var d = _driver;   // snapshot once so driverMode and driverHarness can't disagree if SetDriver races
            var driverMode = string.IsNullOrEmpty(d)
                ? "operator_only"
                : string.Equals(d, "*", StringComparison.Ordinal)
                    ? "any_harness"
                    : "selected_harness";

            return new
            {
                connected,
                lastSeenSecondsAgo = connected ? (int)age.TotalSeconds : (int?)null,
                nanoStatus = _presence.NanoStatus,
                tab = _presence.TabInfo,
                pendingCommands = pending,
                inFlightCommands = delivered + timedOut,
                uncertainCommands = timedOut,
                driverHarness = DriverLabel(d),
                driverMode,
                hint = connected
                    ? (driverMode == "operator_only"
                        ? "LiveWeave extension is linked, but no harness driver is selected. Operator token only."
                        : "LiveWeave extension is linked. The selected driver may use liveweave_command.")
                    : "LiveWeave extension not connected — open LiveWeave in Chrome and pair with TraceBrake (Connect agent → Pair browser extension, choose LiveWeave harness).",
            };
        }
    }

    private static string? DriverLabel(string? driver) =>
        string.Equals(driver, "*", StringComparison.Ordinal) ? "any" : driver;

    private void TouchPresence() => UpdatePresence(null, null);

    private void Prune()
    {
        if (_commands.Count <= MaxCommands) return;
        var victims = _commands.Values
            .Where(c => c.Status is LiveWeaveCommandStatus.Completed or LiveWeaveCommandStatus.Failed)
            .OrderBy(c => c.CompletedAt ?? c.CreatedAt)
            .Take(_commands.Count - MaxCommands)
            .Select(c => c.CommandId)
            .ToList();
        foreach (var id in victims) _commands.TryRemove(id, out _);
    }

    private static bool IsNonTerminal(LiveWeaveCommand command) =>
        command.Status is LiveWeaveCommandStatus.Pending
            or LiveWeaveCommandStatus.Delivered
            or LiveWeaveCommandStatus.TimedOut;

    internal int CommandCount => _commands.Count;
    internal int NonTerminalCount => _commands.Values.Count(IsNonTerminal);
}
