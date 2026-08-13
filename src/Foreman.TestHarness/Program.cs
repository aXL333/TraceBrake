using System.Text.Json.Nodes;
using Foreman.McpServer;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace Foreman.TestHarness;

/// <summary>
/// A standalone MCP client that impersonates a harness and drives TraceBrake's Ask Harness loop end to end,
/// so you can exercise the round-trip without a real Claude/Codex/Cursor session attached.
///
/// Each tick it prints a SITREP (foreman_status + this harness's behaviour metrics) and, unless --no-ack is
/// passed, ACKs every pending Ask Harness / audit request addressed to it (reply_to_ask_harness_request).
/// Leave it running, then trigger an alert/Ask Harness/audit in the tray and watch the harness side answer.
///
/// It connects with a real per-harness scoped token (minted via the same McpAuthToken the app uses), so it
/// exercises the per-harness identity + caller-scoping path, not just the operator token.
/// </summary>
internal static class Program
{
    private static async Task<int> Main(string[] rawArgs)
    {
        var args = ParseArgs(rawArgs);
        if (args.ContainsKey("help") || args.ContainsKey("h"))
        {
            PrintUsage();
            return 0;
        }

        var harness  = Arg(args, "harness", "claude-code").Trim().ToLowerInvariant();
        var port     = int.TryParse(Arg(args, "port", "54321"), out var p) ? p : 54321;
        var interval = int.TryParse(Arg(args, "interval", "15"), out var iv) ? Math.Max(2, iv) : 15;
        var limit    = int.TryParse(Arg(args, "limit", "10"), out var lim) ? lim : 10;
        var once     = args.ContainsKey("once");
        var probe    = args.ContainsKey("probe");
        var ack      = !args.ContainsKey("no-ack");
        var name     = Arg(args, "name", FriendlyName(harness));

        if (probe)
            return await ProbeAsync(harness, port, limit, Arg(args, "token", ""), ct: default);

        if (args.ContainsKey("cu"))
            return await RunCuAsync(args, port, ct: default);

        // Token: an explicit --token wins; otherwise mint a scoped per-harness token from the install secret.
        string token; string scope;
        var explicitToken = Arg(args, "token", "");
        if (!string.IsNullOrWhiteSpace(explicitToken))
        {
            token = explicitToken.Trim();
            scope = token.StartsWith("fmh1.", StringComparison.Ordinal) ? "per-harness (supplied)" : "operator (supplied)";
        }
        else
        {
            var auth = new McpAuthToken();
            token = auth.MintHarnessToken(harness);
            scope = "per-harness (minted)";
        }

        var url = $"http://localhost:{port}/mcp";
        Banner(harness, name, url, scope, token, interval, ack, once);

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); Log("", "Ctrl+C — shutting down…"); };
        var ct = cts.Token;

        var transport = new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint          = new Uri(url),
            Name              = name,
            ConnectionTimeout = TimeSpan.FromSeconds(10),
            AdditionalHeaders = new Dictionary<string, string> { ["Authorization"] = $"Bearer {token}" },
        }, null);

        var options = new McpClientOptions
        {
            ClientInfo = new Implementation { Name = name, Version = "test", Title = name },
        };

        McpClient client;
        try
        {
            client = await McpClient.CreateAsync(transport, options, null, ct);
        }
        catch (OperationCanceledException) { return 0; }
        catch (Exception ex)
        {
            Log("ERR", $"Couldn't connect to TraceBrake at {url}.");
            Log("ERR", $"  {ex.Message}");
            Log("ERR", "  Is the TraceBrake tray app running? Is the port right? Is the token valid?");
            return 1;
        }

        await using (client)
        {
            int toolCount;
            try { toolCount = (await client.ListToolsAsync(options: null, cancellationToken: ct)).Count; }
            catch { toolCount = -1; }
            Log("OK", $"Connected as \"{name}\" — {(toolCount < 0 ? "tools unavailable" : $"{toolCount} TraceBrake tools visible")}.");

            // Announce a task boundary so this shows up as an active harness in Foreman.
            await Call(client, "report_task_start",
                new() { ["taskDescription"] = "TraceBrake MCP test harness online (ack/sitrep loop)" }, ct);

            int tick = 0;
            while (!ct.IsCancellationRequested)
            {
                tick++;
                await Sitrep(client, harness, ct);
                await PollAndAck(client, harness, ack, limit, ct);

                if (once) break;
                try { await Task.Delay(TimeSpan.FromSeconds(interval), ct); }
                catch (OperationCanceledException) { break; }
            }
        }

        Log("", "Disconnected.");
        return 0;
    }

    /// <summary>
    /// Cheap inbox probe for schedulers / loop watchers. One MCP round-trip, no logging spam.
    /// Exit 0 = idle, 1 = pending Ask Harness mail, 2 = TraceBrake unreachable.
    /// </summary>
    private static async Task<int> ProbeAsync(string harness, int port, int limit, string explicitToken, CancellationToken ct)
    {
        string token;
        if (!string.IsNullOrWhiteSpace(explicitToken))
            token = explicitToken.Trim();
        else
            token = new McpAuthToken().MintHarnessToken(harness);

        var url = $"http://localhost:{port}/mcp";
        var transport = new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint          = new Uri(url),
            Name              = FriendlyName(harness),
            ConnectionTimeout = TimeSpan.FromSeconds(8),
            AdditionalHeaders = new Dictionary<string, string> { ["Authorization"] = $"Bearer {token}" },
        }, null);

        try
        {
            await using var client = await McpClient.CreateAsync(transport, new McpClientOptions
            {
                ClientInfo = new Implementation { Name = FriendlyName(harness), Version = "probe", Title = FriendlyName(harness) },
            }, null, ct);

            var result = await Call(client, "list_ask_harness_requests",
                new() { ["harnessId"] = harness, ["includeAnswered"] = false, ["limit"] = limit }, ct);
            var requests = result?["requests"] as JsonArray ?? [];
            var pending = requests.Count(r => string.Equals(Str(r, "status"), "pending", StringComparison.OrdinalIgnoreCase));

            var payload = new JsonObject
            {
                ["status"] = pending > 0 ? "pending" : "idle",
                ["pendingCount"] = pending,
                ["harness"] = harness,
            };
            Console.WriteLine(payload.ToJsonString());
            return pending > 0 ? 1 : 0;
        }
        catch (OperationCanceledException) { return 2; }
        catch
        {
            Console.WriteLine(new JsonObject
            {
                ["status"] = "unreachable",
                ["pendingCount"] = 0,
                ["harness"] = harness,
            }.ToJsonString());
            return 2;
        }
    }

    /// <summary>
    /// Drives the mediated computer-use broker end to end: submits ONE cu_* action as the OPERATOR (the only
    /// scope allowed to drive until a CU-driver-set path exists), then polls cu_action_status until the action
    /// reaches a terminal state. The paired browser extension claims + executes APPROVED browser actions on its
    /// own ~5s poll, so an approved navigate opens a real tab. Authenticates with the install (operator) token,
    /// read internally from mcp.token — never handled by the caller.
    /// Flags: --cu &lt;verb&gt; (navigate|read|click|type|…), --modality browser|desktop (default browser),
    /// plus verb args via --url / --text / --selector / --key / --value.
    /// </summary>
    private static async Task<int> RunCuAsync(Dictionary<string, string> args, int port, CancellationToken ct)
    {
        var verb = Arg(args, "cu", "navigate").Trim().ToLowerInvariant();
        var modality = Arg(args, "modality", "browser").Trim().ToLowerInvariant();

        var argObj = new JsonObject();
        foreach (var k in new[] { "url", "text", "selector", "key", "value", "tabId", "justification" })
        {
            var v = Arg(args, k, "");
            if (!string.IsNullOrEmpty(v)) argObj[k] = v;
        }
        var argsJson = argObj.ToJsonString();

        // Scope: mint a per-harness token for --harness (default "claude-code") from the install secret, read
        // internally from mcp.token so the caller never handles a token. cu_submit's driver gate admits the
        // operator OR the harness the operator authorized as the driver (via cu_set_driver / the Browser-use
        // driver picker). The operator token is peer-bound to its first user and gets 401'd from a separate
        // process, so a per-harness token is what a driver must present from here.
        var harness = Arg(args, "harness", "claude-code").Trim().ToLowerInvariant();
        // An explicit --token wins (e.g. a token TraceBrake minted for this harness via Connect Agent, which the
        // running instance honors even when its live secret has diverged from the on-disk mcp.token). Otherwise
        // mint a per-harness token from the install secret on disk.
        var explicitToken = Arg(args, "token", "").Trim();
        var token = explicitToken.Length > 0 ? explicitToken : new McpAuthToken().MintHarnessToken(harness);
        var url = $"http://localhost:{port}/mcp";
        var transport = new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint = new Uri(url),
            Name = harness,
            ConnectionTimeout = TimeSpan.FromSeconds(10),
            AdditionalHeaders = new Dictionary<string, string> { ["Authorization"] = $"Bearer {token}" },
        }, null);

        McpClient client;
        try { client = await McpClient.CreateAsync(transport, new McpClientOptions { ClientInfo = new Implementation { Name = harness, Version = "test", Title = $"CU driver ({harness})" } }, null, ct); }
        catch (Exception ex) { Log("ERR", $"Couldn't connect to TraceBrake at {url}: {ex.Message}"); return 1; }

        await using (client)
        {
            // Report the current CU driver first, so a "no driver selected" refusal is self-explanatory.
            var cuStatus = await Call(client, "cu_status", new(), ct);
            if (cuStatus is not null) Log("CU", $"cu_status -> {cuStatus.ToJsonString()}  (connected as '{harness}')");

            Log("CU", $"cu_submit  modality={modality}  verb={verb}  args={argsJson}");
            var sub = await Call(client, "cu_submit", new() { ["modality"] = modality, ["verb"] = verb, ["argsJson"] = argsJson }, ct);
            if (sub is null) { Log("CU", "no response from cu_submit (is cu_* present — i.e. the new build?)"); return 1; }

            var actionId = Str(sub, "actionId");
            Log("CU", $"  -> state={Str(sub, "state")}  decision={Str(sub, "decision")}  actionId={actionId}");
            if (Str(sub, "reason") is { Length: > 0 } why) Log("CU", $"     reason: {why}");
            if (string.IsNullOrEmpty(actionId)) return 0;

            for (int i = 0; i < 15; i++)
            {
                await Task.Delay(TimeSpan.FromSeconds(1), ct);
                var st = await Call(client, "cu_action_status", new() { ["actionId"] = actionId }, ct);
                var s = Str(st, "state") ?? "?";
                var extra = "";
                if (Str(st, "error") is { Length: > 0 } err) extra += $"  error={err}";
                if (st?["result"] is { } r) extra += $"  result={r.ToJsonString()}";
                Log("CU", $"  status[{i + 1}] {s}{extra}");
                if (s is "completed" or "failed" or "rejected" or "blocked") break;
            }
        }
        return 0;
    }

    // ---- the loop ----------------------------------------------------------

    private static async Task Sitrep(McpClient client, string harness, CancellationToken ct)
    {
        var status = await Call(client, "foreman_status", new(), ct);
        if (status is null) { Log("SITREP", "(no response from foreman_status)"); return; }

        var color   = Str(status, "status") ?? "?";
        var alerts  = Num(status, "activeAlerts");
        var procs   = Num(status, "monitoredProcesses");
        var pending = Num(status, "pendingAskHarnessRequests");
        var uptime  = Num(status, "uptimeSeconds");
        var version = Str(status, "version") ?? "?";

        Log("SITREP", $"status={color.ToUpperInvariant()}  alerts={alerts}  procs={procs}  " +
                      $"pending-ask={pending}  uptime={Friendly(uptime)}  v{version}");

        // This harness's own escalation state, when the scoped token can see it.
        var metrics = await Call(client, "get_behavior_metrics", new(), ct);
        var profiles = metrics?["profiles"] as JsonArray ?? metrics?["harnesses"] as JsonArray;
        if (profiles is { Count: > 0 })
        {
            foreach (var m in profiles)
            {
                var hid = Str(m, "harnessId") ?? harness;
                var lvl = Str(m, "escalationLevel") ?? Str(m, "level") ?? "?";
                var score = Num(m, "riskScore");
                Log("BEHAV", $"{hid}: level={lvl} risk={score}");
            }
        }
    }

    private static async Task PollAndAck(McpClient client, string harness, bool ack, int limit, CancellationToken ct)
    {
        var result = await Call(client, "list_ask_harness_requests",
            new() { ["harnessId"] = harness, ["includeAnswered"] = false, ["limit"] = limit }, ct);
        if (result is null) return;

        var requests = result["requests"] as JsonArray ?? [];
        var pending = requests.Where(r => string.Equals(Str(r, "status"), "pending", StringComparison.OrdinalIgnoreCase)).ToList();
        if (pending.Count == 0) { Log("MAILBOX", "no pending requests."); return; }

        Log("MAILBOX", $"{pending.Count} pending request(s) for '{harness}':");
        foreach (var r in pending)
        {
            var id     = Str(r, "requestId") ?? "?";
            var alert  = Str(r, "alertId") ?? "?";
            var pname  = Str(r, "processName") ?? "?";
            var prompt = Str(r, "prompt") ?? "(no prompt)";
            Log("ASK", $"[{id}] alert={alert} proc={pname}");
            Log("ASK", $"   ▸ {OneLine(prompt, 200)}");

            if (!ack) { Log("ASK", "   (ack disabled — not replying)"); continue; }

            var reply = await Call(client, "reply_to_ask_harness_request", new()
            {
                ["requestId"]   = id,
                ["response"]    = "ACK from the TraceBrake test harness: this event was generated/observed during " +
                                  "loop testing of the Ask Harness round-trip. No corrective action required.",
                ["actionTaken"] = "acknowledged by test harness (loop)",
                ["harnessId"]   = harness,
            }, ct);

            var accepted = reply is not null && (Bool(reply, "accepted") ?? false);
            Log("ACK", accepted ? $"   ✓ replied to [{id}]" : $"   ✗ reply rejected: {Str(reply, "reason") ?? "unknown"}");
        }
    }

    // ---- MCP call + JSON helpers ------------------------------------------

    /// <summary>Calls a tool and returns its structured result as a JsonObject (null on error/empty).</summary>
    private static async Task<JsonObject?> Call(
        McpClient client, string tool, Dictionary<string, object?> args, CancellationToken ct)
    {
        try
        {
            var res = await client.CallToolAsync(tool, args, cancellationToken: ct);

            // Prefer the structured result; fall back to parsing the first text content block.
            if (res.StructuredContent is { } structured && structured.ValueKind == System.Text.Json.JsonValueKind.Object
                && JsonNode.Parse(structured.GetRawText()) is JsonObject so) return so;

            var text = res.Content.OfType<TextContentBlock>().FirstOrDefault()?.Text;
            if (!string.IsNullOrWhiteSpace(text) && JsonNode.Parse(text) is JsonObject parsed) return parsed;
            return null;
        }
        catch (OperationCanceledException) { return null; }
        catch (Exception ex)
        {
            Log("ERR", $"{tool} failed: {ex.Message}");
            return null;
        }
    }

    // Case-insensitive property access so we don't care whether the server serialized PascalCase or camelCase.
    private static JsonNode? Get(JsonNode? node, string name)
    {
        if (node is not JsonObject o) return null;
        if (o.TryGetPropertyValue(name, out var exact)) return exact;
        foreach (var kv in o)
            if (string.Equals(kv.Key, name, StringComparison.OrdinalIgnoreCase)) return kv.Value;
        return null;
    }

    private static string? Str(JsonNode? n, string name) => Get(n, name)?.GetValue<object?>()?.ToString();
    private static long Num(JsonNode? n, string name) => long.TryParse(Str(n, name), out var v) ? v : 0;
    private static bool? Bool(JsonNode? n, string name) => bool.TryParse(Str(n, name), out var v) ? v : null;

    // ---- presentation ------------------------------------------------------

    private static void Log(string tag, string msg)
    {
        var stamp = DateTimeOffset.Now.ToString("HH:mm:ss");
        Console.WriteLine(string.IsNullOrEmpty(tag) ? $"[{stamp}] {msg}" : $"[{stamp}] {tag,-8} {msg}");
    }

    private static void Banner(string harness, string name, string url, string scope, string token,
                               int interval, bool ack, bool once)
    {
        Console.WriteLine("TraceBrake test harness — MCP ack/sitrep loop");
        Console.WriteLine($"  harness  : {harness}  (announces as \"{name}\")");
        Console.WriteLine($"  endpoint : {url}");
        Console.WriteLine($"  token    : {Mask(token)}  [{scope}]");
        Console.WriteLine($"  cadence  : {(once ? "single pass" : interval + "s")},  auto-ack: {(ack ? "on" : "off")}");
        Console.WriteLine(new string('-', 60));
    }

    private static void PrintUsage()
    {
        Console.WriteLine("""
        TraceBrake test harness — drives TraceBrake's MCP Ask Harness loop (ack/sitrep).

        Usage: foreman-harness [options]

          --harness <id>     Harness identity to impersonate (default: claude-code).
                             e.g. codex, cursor, opencode, or any custom id.
          --port <n>         TraceBrake MCP port (default: 54321).
          --token <tok>      Use this bearer token verbatim instead of minting one.
                             (Default: mint a scoped per-harness token from mcp.token.)
          --name <text>      Client name announced to TraceBrake (default: derived from --harness).
          --interval <secs>  Seconds between ticks (default: 15, min 2).
          --limit <n>        Max Ask Harness requests to pull per tick (default: 10).
          --once             Run a single SITREP + ACK pass and exit.
          --probe            One-line JSON probe; exit 0 idle, 1 pending mail, 2 unreachable.
          --no-ack           Print pending requests but do NOT reply to them.
          --help             Show this help.

        Examples:
          foreman-harness                          # claude-code, every 15s, auto-ack
          foreman-harness --harness codex --once    # one pass as codex
          foreman-harness --no-ack --interval 5     # observe only, fast
        """);
    }

    // ---- small utils -------------------------------------------------------

    private static Dictionary<string, string> ParseArgs(string[] a)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < a.Length; i++)
        {
            if (!a[i].StartsWith("--", StringComparison.Ordinal) && !a[i].StartsWith('-')) continue;
            var key = a[i].TrimStart('-');
            if (i + 1 < a.Length && !a[i + 1].StartsWith('-')) { d[key] = a[++i]; }
            else d[key] = "true";
        }
        return d;
    }

    private static string Arg(Dictionary<string, string> a, string key, string fallback) =>
        a.TryGetValue(key, out var v) && v != "true" ? v : (a.ContainsKey(key) && fallback == "" ? "true" : fallback);

    private static string FriendlyName(string harness) => harness switch
    {
        "claude-code" => "Claude Code (test harness)",
        "codex"       => "Codex (test harness)",
        "cursor"      => "Cursor (test harness)",
        "opencode"    => "OpenCode (test harness)",
        _             => $"{harness} (test harness)",
    };

    private static string Mask(string token) =>
        token.Length <= 14 ? "••••" : token[..12] + "…(" + token.Length + " chars)";

    private static string Friendly(long seconds)
    {
        if (seconds < 60) return $"{seconds}s";
        if (seconds < 3600) return $"{seconds / 60}m{seconds % 60:00}s";
        return $"{seconds / 3600}h{(seconds % 3600) / 60:00}m";
    }

    private static string OneLine(string s, int max)
    {
        s = s.Replace("\r", " ").Replace("\n", " ").Trim();
        while (s.Contains("  ")) s = s.Replace("  ", " ");
        return s.Length <= max ? s : s[..max] + "…";
    }
}
