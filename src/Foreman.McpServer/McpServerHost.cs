#pragma warning disable MCPEXP002 // RunSessionHandler is experimental but stable enough for our use
// Alias avoids Foreman.McpServer namespace shadowing ModelContextProtocol.Server.McpServer
using McpServerType = global::ModelContextProtocol.Server.McpServer;
using Foreman.Core.Events;
using Foreman.Core.Mcp;
using Foreman.Core.Models;
using Foreman.Core.Settings;
using System.Collections.Concurrent;
using System.Net.Sockets;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.AspNetCore;

namespace Foreman.McpServer;

/// <summary>
/// Hosts an embedded Kestrel MCP HTTP+SSE server.
/// Call StartAsync() from App startup, DisposeAsync() on shutdown.
/// </summary>
public sealed class McpServerHost : IAsyncDisposable
{
    private readonly ForemanSettings _settings;
    private readonly EventBus _bus;
    private readonly McpAuthToken _authToken = new();
    private readonly PairingManager _pairing = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _peerMismatchSeen = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _staleTokenSeen = new();
    private WebApplication? _app;

    public ForemanState State { get; } = new();
    public SseSessionManager Sessions { get; } = new();

    /// <summary>Path of the MCP bearer-token file, so the (Windows) app shell can ACL-restrict it.</summary>
    public string TokenFilePath => _authToken.TokenFilePath;

    /// <summary>The per-install bearer token, so the app shell can build connect instructions/config.</summary>
    public string McpToken => _authToken.Value;

    /// <summary>Mints a scoped per-harness bearer token for the Connect-Agent flow to write into a config.</summary>
    public string MintHarnessToken(string harnessId) => _authToken.MintHarnessToken(harnessId);

    /// <summary>Begin extension pairing: mint a short on-screen code for the user to type into the Foreman
    /// browser extension. The code is the challenge/response key and never crosses the wire. (Closed-loop spec.)</summary>
    public string BeginExtensionPairing() => _pairing.Begin();

    public McpServerHost(ForemanSettings settings, EventBus bus)
    {
        _settings = settings;
        _bus = bus;
        State.McpPort = settings.McpPort;
        State.LlmTriage = settings.LlmTriage;
        State.HarnessModalities = settings.HarnessModalities;
        State.HarnessCapabilityRestrictions = settings.HarnessCapabilityRestrictions;
        State.GetMcpSessionCount = () => Sessions.Count;
        State.GetMcpClients = () => Sessions.DescribeSessions();
    }

    public async Task StartAsync(CancellationToken ct = default)
    {
        // inject shared state into the static tool type
        ForemanMcpTools.SetState(State);

        // subscribe state to the event bus
        _bus.Subscribe(State);

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseKestrel(opts =>
        {
            // Loopback-only by design: ListenLocalhost binds 127.0.0.1 and [::1] *only*, never a routable
            // interface — the MCP/health server is never remotely reachable. This is a deliberate trust
            // boundary (see SECURITY.md), and it also keeps TraceBrake off the AV radar (a localhost listener
            // needs no firewall rule and raises no inbound prompt). Do not switch to ListenAnyIP.
            opts.ListenLocalhost(_settings.McpPort);
        });

        builder.Logging.SetMinimumLevel(LogLevel.Warning); // suppress Kestrel noise from tray

        builder.Services.AddHttpContextAccessor();   // lets tools read the auth-gate's resolved CallerScope
        builder.Services
            .AddSingleton(Sessions)
            .AddSingleton<AlertDispatcher>()
            .AddMcpServer()
            .WithHttpTransport(options =>
            {
                // Register/unregister each SSE session so AlertDispatcher can push
                // notifications/message proactively without the client polling.
                options.RunSessionHandler = async (Microsoft.AspNetCore.Http.HttpContext httpCtx, McpServerType server, CancellationToken sessionCt) =>
                {
                    var id = Sessions.Register(server);
                    try
                    {
                        await server.RunAsync(sessionCt).ConfigureAwait(false);
                    }
                    finally
                    {
                        Sessions.Unregister(id);
                    }
                };
            })
            .WithToolsFromAssembly(typeof(ForemanMcpTools).Assembly)
            .WithPromptsFromAssembly(typeof(ForemanMcpTools).Assembly);   // /checkyaself etc.

        _app = builder.Build();

        // Register the alert dispatcher as an event sink
        var dispatcher = _app.Services.GetRequiredService<AlertDispatcher>();
        _bus.Subscribe(dispatcher);

        // ── MCP auth gate ────────────────────────────────────────────────────────
        // localhost is not an authorization boundary on a shared box. Require the bearer
        // token (and reject cross-origin/browser requests) on /mcp so a random local process
        // or a drive-by browser POST cannot drive TraceBrake's tools. /health stays open.
        _authToken.WriteSetupFile(_settings.McpPort);
        _app.Use(async (ctx, next) =>
        {
            var isMcpRequest = ctx.Request.Path.StartsWithSegments("/mcp");
            try
            {
                if (isMcpRequest)
                {
                    // Host must be loopback (DNS-rebinding defence) — checked before anything else.
                    if (!LoopbackRequestPolicy.IsLoopbackHost(ctx.Request.Host.Value))
                    {
                        await Deny(ctx, StatusCodes.Status403Forbidden,
                            "Request Host is not a loopback address (possible DNS rebinding).").ConfigureAwait(false);
                        return;
                    }

                    var origin = ctx.Request.Headers.Origin.ToString();
                    var presented = ExtractToken(ctx.Request);
                    var auth = _authToken.Authenticate(presented);

                    // Self-heal paired extension origins: the extension keeps its minted harness token in
                    // chrome.storage across restarts, but PairedExtensionOrigins may be empty on disk (save
                    // failed, fresh settings, etc.). A valid liveweave/browser-extension token plus a real
                    // extension Origin re-adds the origin before the transport gate runs.
                    if (auth.Ok && IsExtensionHarness(auth.HarnessId) && PairingManager.IsExtensionOrigin(origin))
                        RememberPairedExtensionOrigin(origin.TrimEnd('/'));

                    // Origin, when present, must be loopback or a paired extension. See LoopbackRequestPolicy.
                    var verdict = LoopbackRequestPolicy.Evaluate(
                        ctx.Request.Host.Value,
                        origin,
                        _settings.PairedExtensionOrigins);
                    if (!verdict.Allowed)
                    {
                        await Deny(ctx, StatusCodes.Status403Forbidden, verdict.Reason).ConfigureAwait(false);
                        return;
                    }
                    if (!auth.Ok)
                    {
                        MaybeReportStaleToken(presented);   // surface "your saved token went stale — reconnect"
                        ctx.Response.Headers.WWWAuthenticate = "Bearer";
                        await Deny(ctx, StatusCodes.Status401Unauthorized,
                            "A valid TraceBrake MCP token is required. See mcp-setup.txt in %LocalAppData%\\TraceBrake.").ConfigureAwait(false);
                        return;
                    }
                    // Peer-PID binding (second factor): a per-harness token must be presented BY that harness's
                    // own process. Bind the token's claimed identity to the loopback peer the OS says opened the
                    // socket. A different process replaying a harness's token is token theft — never legitimate.
                    // (Match / unattributed always pass; the alert is raised inside CheckPeerBinding.)
                    var peerVerdict = auth.HarnessId is { Length: > 0 } claimedHarness
                        ? CheckPeerBinding(ctx, claimedHarness)
                        : PeerBindingVerdict.Unattributed;   // operator token is not peer-bound

                    // Carry the proven identity to the tools (read via IHttpContextAccessor). A per-harness token
                    // scopes tools to that harness; the raw install token authenticates as operator. PeerMismatch
                    // lets the MUTATING tools fail closed on token theft even when enforcement is off.
                    ctx.Items[CallerScope.HttpItemKey] = new CallerScope(
                        auth.HarnessId, auth.IsOperator, PeerMismatch: peerVerdict == PeerBindingVerdict.Mismatch);

                    // When enforcement is on, a mismatch blocks the whole request (reads included).
                    if (peerVerdict == PeerBindingVerdict.Mismatch && _settings.McpPeerBindingEnforce)
                    {
                        await Deny(ctx, StatusCodes.Status403Forbidden,
                            "Token/identity mismatch: this per-harness token belongs to a different harness than the calling process.").ConfigureAwait(false);
                        return;
                    }

                    // Sticky "connected" signal for the dashboard: an authenticated, allowed request from a
                    // per-harness token marks that harness recently-active. (Operator token has no harness id and
                    // isn't tracked.) These clients hold no persistent session, so the live count alone reads ~0.
                    Sessions.MarkSeen(auth.HarnessId);
                }
                await next().ConfigureAwait(false);
            }
            catch (System.Text.Json.JsonException ex) when (isMcpRequest && !ctx.Response.HasStarted)
            {
                LogMcpException(ex);
                await Deny(ctx, StatusCodes.Status400BadRequest, "Invalid JSON-RPC request body.").ConfigureAwait(false);
            }
            catch (Exception ex) when (isMcpRequest)
            {
                LogMcpException(ex);
                throw;
            }
        });

        _app.MapMcp("/mcp");
        // Liveness only — no session count: /health is unauthenticated, so it shouldn't
        // tell a local prober how many agents are connected.
        _app.MapGet("/health", () => new { status = "ok", port = _settings.McpPort });

        // Extension pairing (loopback-only; no bearer — the extension has none yet. The on-screen code
        // authenticates via challenge/response, so the code never crosses the wire). Host must be loopback.
        _app.MapGet("/pair/challenge", (HttpContext c) =>
        {
            if (!LoopbackRequestPolicy.IsLoopbackHost(c.Request.Host.Value))
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            var challenge = _pairing.IssueChallenge();
            return challenge is null
                ? Results.StatusCode(StatusCodes.Status409Conflict)   // no pairing window armed
                : Results.Json(new { challenge });
        });
        _app.MapPost("/pair/complete", async (HttpContext c) =>
        {
            if (!LoopbackRequestPolicy.IsLoopbackHost(c.Request.Host.Value))
                return Results.StatusCode(StatusCodes.Status403Forbidden);

            string? response = null, originBody = null, harnessIdBody = null;
            try
            {
                using var reader = new System.IO.StreamReader(c.Request.Body);
                using var doc = System.Text.Json.JsonDocument.Parse(await reader.ReadToEndAsync().ConfigureAwait(false));
                if (doc.RootElement.TryGetProperty("response", out var r)) response = r.GetString();
                if (doc.RootElement.TryGetProperty("origin", out var o)) originBody = o.GetString();
                if (doc.RootElement.TryGetProperty("harnessId", out var h)) harnessIdBody = h.GetString();
            }
            catch { /* malformed body — Complete fails below */ }

            // Prefer the browser-set Origin header (unspoofable by page JS); fall back to the body if absent.
            var origin = c.Request.Headers.Origin.ToString();
            if (string.IsNullOrEmpty(origin)) origin = originBody ?? "";

            var result = _pairing.Complete(origin, response);
            if (!result.Ok)
                return Results.Json(new { ok = false, reason = result.Reason }, statusCode: StatusCodes.Status403Forbidden);

            // Pairing both allow-lists the origin AND issues a scoped token — /mcp still requires a bearer, and
            // the extension has none until now. Default harness is browser-extension; LiveWeave sends harnessId=liveweave.
            var harnessId = string.IsNullOrWhiteSpace(harnessIdBody) ? "browser-extension" : harnessIdBody.Trim();
            if (!string.Equals(harnessId, "browser-extension", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(harnessId, "liveweave", StringComparison.OrdinalIgnoreCase))
            {
                return Results.Json(new { ok = false, reason = "Unsupported harnessId for extension pairing." },
                    statusCode: StatusCodes.Status403Forbidden);
            }
            if (!_settings.PairedExtensionOrigins.Contains(result.Origin!, StringComparer.OrdinalIgnoreCase))
            {
                _settings.PairedExtensionOrigins.Add(result.Origin!);
                using var provenance = SettingsChangeContext.Begin(SettingsChangeAttribution.Declared(
                    SettingsChangeOrigin.AuthenticatedMcp, harnessId, "complete-extension-pairing"));
                try { SettingsStore.Save(_settings); } catch { /* in-memory allow-list still applies this session */ }
            }
            var token = _authToken.MintHarnessToken(harnessId);
            return Results.Json(new { ok = true, origin = result.Origin, token, harnessId });
        });

        // Auto-pair (opt-in, default on): a first-party extension links itself DURING an operator-armed window
        // without the on-screen code. The operator's "Pair" click is the consent; the token is scoped. Strictly
        // weaker than the code path (any loopback extension origin can grab a scoped token in that short window),
        // so every auto-pair is announced (Medium) for visibility. Disable via settings.AllowAutoExtensionPairing.
        _app.MapPost("/pair/auto", async (HttpContext c) =>
        {
            if (!LoopbackRequestPolicy.IsLoopbackHost(c.Request.Host.Value))
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            if (!_settings.AllowAutoExtensionPairing)
                return Results.Json(new { ok = false, reason = "Auto-pairing is disabled — use the on-screen code." },
                    statusCode: StatusCodes.Status403Forbidden);

            string? originBody = null, harnessIdBody = null;
            try
            {
                using var reader = new System.IO.StreamReader(c.Request.Body);
                using var doc = System.Text.Json.JsonDocument.Parse(await reader.ReadToEndAsync().ConfigureAwait(false));
                if (doc.RootElement.TryGetProperty("origin", out var o)) originBody = o.GetString();
                if (doc.RootElement.TryGetProperty("harnessId", out var h)) harnessIdBody = h.GetString();
            }
            catch { /* malformed → AutoComplete fails below */ }

            var origin = c.Request.Headers.Origin.ToString();
            if (string.IsNullOrEmpty(origin)) origin = originBody ?? "";

            var result = _pairing.AutoComplete(origin);   // armed window + extension origin; no code; single-use
            if (!result.Ok)
                return Results.Json(new { ok = false, reason = result.Reason }, statusCode: StatusCodes.Status403Forbidden);

            var harnessId = string.IsNullOrWhiteSpace(harnessIdBody) ? "browser-extension" : harnessIdBody.Trim();
            if (!string.Equals(harnessId, "browser-extension", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(harnessId, "liveweave", StringComparison.OrdinalIgnoreCase))
                return Results.Json(new { ok = false, reason = "Unsupported harnessId for extension pairing." },
                    statusCode: StatusCodes.Status403Forbidden);

            if (!_settings.PairedExtensionOrigins.Contains(result.Origin!, StringComparer.OrdinalIgnoreCase))
            {
                _settings.PairedExtensionOrigins.Add(result.Origin!);
                using var provenance = SettingsChangeContext.Begin(SettingsChangeAttribution.Declared(
                    SettingsChangeOrigin.AuthenticatedMcp, harnessId, "auto-pair-extension"));
                try { SettingsStore.Save(_settings); } catch { /* in-memory allow-list still applies this session */ }
            }
            var token = _authToken.MintHarnessToken(harnessId);
            _bus.Publish(new MonitoringNoticeEvent(DateTimeOffset.UtcNow, ForemanSeverity.Medium, "Foreman.Pairing",
                $"Browser extension auto-paired as '{harnessId}' ({result.Origin}) during the pairing window. " +
                "If you didn't initiate this, remove it from paired origins and disable auto-pairing in settings."));
            return Results.Json(new { ok = true, origin = result.Origin, token, harnessId });
        });

        await _app.StartAsync(ct).ConfigureAwait(false);
    }

    // Binds a per-harness token's claimed identity to the loopback peer process that presented it: look up the
    // owning PID of the client socket (OS truth), classify it to a harness (itself or a harness ancestor), and
    // compare. A Mismatch is logged Critical (de-duped). Any lookup failure → Unattributed (fail-open: a
    // transient race must never brick a real session, and is never reported as an attack).
    private PeerBindingVerdict CheckPeerBinding(HttpContext ctx, string claimedHarness)
    {
        string? attributed = null;
        int? peerPid = null;
        try
        {
            var ipv6 = ctx.Connection.RemoteIpAddress?.AddressFamily == AddressFamily.InterNetworkV6;
            peerPid = LoopbackPeer.FindOwningPid(ctx.Connection.RemotePort, ctx.Connection.LocalPort, ipv6);
            if (peerPid is int pid)
                attributed = State.FindHarnessAncestorByPid?.Invoke(pid)?.HarnessType;
        }
        catch { return PeerBindingVerdict.Unattributed; }

        var verdict = PeerIdentityPolicy.Evaluate(claimedHarness, attributed);
        if (verdict == PeerBindingVerdict.Mismatch)
            RaisePeerMismatch(claimedHarness, attributed, peerPid);
        return verdict;
    }

    private void RaisePeerMismatch(string claimed, string? attributed, int? pid)
    {
        // De-dupe so a chatty connection can't spam Critical alerts: one per (claimed→attributed, pid) / 5 min.
        var key = $"{claimed}->{attributed ?? "?"}|{pid?.ToString() ?? "?"}";
        var now = DateTimeOffset.UtcNow;
        if (_peerMismatchSeen.TryGetValue(key, out var last) && now - last < TimeSpan.FromMinutes(5)) return;
        _peerMismatchSeen[key] = now;

        _bus.Publish(new MonitoringNoticeEvent(now, ForemanSeverity.Critical, "Foreman.McpAuth",
            $"MCP token impersonation: a process attributed to '{attributed ?? "unknown"}' (pid {(pid?.ToString() ?? "?")}) " +
            $"presented '{claimed}'s per-harness token on a loopback connection — a harness token replayed by a different " +
            "process, i.e. possible token theft." +
            (_settings.McpPeerBindingEnforce ? " Request blocked." : " (Alert-only; binding enforcement is off.)")));
    }

    // A previously-minted per-harness token that no longer validates is usually STALE: the harness's saved
    // token was minted under a different install secret, so it 401s silently with no hint to reconnect.
    // Surface a throttled, operator-facing notice (via the bus, so it lands in the hash-chained event log,
    // the OS event log, and the tray) pointing at the one-click fix. We attribute it to a recent secret
    // rotation ONLY when the token file was actually (re)written recently (LoadOrCreate regenerates it only
    // when missing/empty); otherwise we stay neutral about the cause. The id is the token's UNVERIFIED claim
    // (bounded by McpAuthToken.LooksLikeStaleHarnessToken); we never act on it.
    internal void MaybeReportStaleToken(string? presented)
    {
        if (!_authToken.LooksLikeStaleHarnessToken(presented, out var id)) return;
        var now = DateTimeOffset.UtcNow;
        // De-dupe per claimed id for this app run. A stale saved token is a persistent repair-needed state; if a
        // polling connector retries every few seconds, repeating the same tray warning every few minutes is noise.
        // The first notice remains visible/logged/OS-forwarded; reconnecting the agent is still the operator fix.
        if (_staleTokenSeen.ContainsKey(id)) return;
        if (_staleTokenSeen.Count > 64 && !_staleTokenSeen.ContainsKey(id)) return;
        if (!_staleTokenSeen.TryAdd(id, now)) return;

        _bus.Publish(new MonitoringNoticeEvent(now, ForemanSeverity.Medium, "Foreman.McpAuth",
            BuildStaleTokenNotice(id, _authToken.RecentlyRegenerated())));
    }

    // Operator-facing text for a per-harness token this server can't validate. The install secret is
    // regenerated ONLY when mcp.token is missing/empty (see McpAuthToken.LoadOrCreate), so claim "rotated"
    // ONLY when the token file was actually written recently; otherwise stay neutral about the cause (the
    // secret usually was NOT rotated). Either way keep the reconnect fix and the forged-token possibility.
    public static string BuildStaleTokenNotice(string id, bool secretRecentlyRotated) =>
        secretRecentlyRotated
            ? $"Harness '{id}' presented a TraceBrake MCP token this server can't validate. TraceBrake's token secret " +
              $"was rotated recently, so '{id}'s saved token is stale. Open Connect Agent and reconnect '{id}' to " +
              "re-issue its token. If you didn't expect this, it could be a forged token from another local process."
            : $"TraceBrake can't validate '{id}'s saved token. Open Connect Agent and reconnect '{id}' to re-issue it. " +
              "If you didn't expect this, it could be a forged token from another local process.";

    private static bool IsExtensionHarness(string? harnessId) =>
        string.Equals(harnessId, "liveweave", StringComparison.OrdinalIgnoreCase)
        || string.Equals(harnessId, "browser-extension", StringComparison.OrdinalIgnoreCase);

    private void RememberPairedExtensionOrigin(string origin)
    {
        if (string.IsNullOrWhiteSpace(origin)) return;
        if (_settings.PairedExtensionOrigins.Contains(origin, StringComparer.OrdinalIgnoreCase)) return;
        _settings.PairedExtensionOrigins.Add(origin);
        using var provenance = SettingsChangeContext.Begin(SettingsChangeAttribution.Declared(
            SettingsChangeOrigin.AuthenticatedMcp, "browser-extension", "remember-paired-origin"));
        try { SettingsStore.Save(_settings); } catch { /* in-memory allow-list still applies this session */ }
    }

    private static string? ExtractToken(HttpRequest req)
    {
        var auth = req.Headers.Authorization.ToString();
        if (auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return auth["Bearer ".Length..].Trim();
        var x = req.Headers["X-Foreman-Token"].ToString();
        return string.IsNullOrEmpty(x) ? null : x;
    }

    private static async Task Deny(HttpContext ctx, int status, string message)
    {
        ctx.Response.StatusCode = status;
        await ctx.Response.WriteAsJsonAsync(new { error = message }).ConfigureAwait(false);
    }

    private static void LogMcpException(Exception ex)
    {
        try
        {
            var dir = Foreman.Core.ProductIdentity.LocalDataRoot;
            Directory.CreateDirectory(dir);
            // Redact before persisting. This is the lone disk sink that handled an agent-influenced exception
            // (a JSON-RPC body / tool arg can ride into ex.Message/inner exceptions); every other egress sink
            // already routes through SecretRedactor, so close the gap rather than write the raw ToString().
            File.AppendAllText(
                Path.Combine(dir, "mcp-errors.log"),
                Foreman.Core.Security.SecretRedactor.Redact($"[{DateTimeOffset.UtcNow:O}] {ex}") + "\n\n");
        }
        catch { /* best-effort diagnostics only */ }
    }

    public async ValueTask DisposeAsync()
    {
        if (_app is not null)
            await _app.DisposeAsync().ConfigureAwait(false);
    }
}
