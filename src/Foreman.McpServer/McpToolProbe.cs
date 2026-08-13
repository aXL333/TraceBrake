using System.Net;
using System.Net.Http;
using System.Text;
using Foreman.Core.Mcp;
using ModelContextProtocol.Client;

namespace Foreman.McpServer;

/// <summary>
/// Tier-1 (opt-in) MCP client probe. Connects to an HTTP/SSE MCP server the user's harness is
/// configured to use, lists its tools, and runs <see cref="McpToolScanner"/> over the names +
/// descriptions to surface prompt-injection / exfil text smuggled into tool docs.
///
/// Deliberately does NOT launch stdio servers — spawning the very process you are suspicious of is
/// worse than not scanning it, so stdio entries are skipped by the caller. No credentials are sent
/// to third-party servers (TraceBrake has none for them); servers that require their own auth simply
/// fail to enumerate and are reported as "unreachable".
/// </summary>
public sealed class McpToolProbe
{
    // Pre-flight uses a shared client; timeout is driven per-call via a linked CTS, not HttpClient.Timeout.
    private static readonly HttpClient PreflightHttp = new() { Timeout = Timeout.InfiniteTimeSpan };

    /// <summary>
    /// Connects to one HTTP/SSE server and returns any scanner findings.
    /// Throws on connect/enumerate failure (caller decides how to surface it).
    /// </summary>
    public async Task<IReadOnlyList<McpToolFinding>> ProbeAsync(
        McpServerEntry server, TimeSpan timeout, CancellationToken ct = default)
    {
        if (!Uri.TryCreate(server.Target, UriKind.Absolute, out var endpoint))
            throw new ArgumentException($"Server '{server.Name}' has no usable URL: {server.Target}");

        // Pre-flight reachability/auth check with a FULLY-AWAITED request BEFORE creating the MCP client.
        // McpClient.CreateAsync spins a background receive loop; when an endpoint rejects the handshake with
        // 401/403 (its own auth — TraceBrake holds no third-party credentials) or 405, that loop faults and,
        // because nothing awaits it, the fault surfaces later as an UNOBSERVED task exception (crash.log + a
        // spurious High OS-event). Such a server can't be scanned anyway, so detect it here and throw — the
        // caller already treats a throw as "unreachable" — without ever spinning the SDK's loop.
        await PreflightAsync(endpoint, timeout, ct).ConfigureAwait(false);

        var transport = new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint          = endpoint,
            Name              = $"TraceBrake scan: {server.Name}",
            ConnectionTimeout = timeout,
        }, null);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);

        await using var client = await McpClient.CreateAsync(transport, null, null, cts.Token);
        var tools = await client.ListToolsAsync(options: null, cancellationToken: cts.Token);

        return McpToolScanner.Scan(
            server.Name,
            tools.Select(t => (t.Name, (string?)t.Description)));
    }

    // The MCP streamable-HTTP handshake: POST a JSON-RPC initialize. We don't negotiate a session here — we
    // only read the status to decide whether the full SDK probe is worth attempting. 401/403 = the server's
    // own auth (unprobeable, and the case that leaks an unobserved fault); 405 = wrong method/not a streamable
    // endpoint (also faults the loop). Anything else (200, 400, 404, 5xx, redirects) falls through to the real
    // probe, which fails cleanly if it can't enumerate. ResponseHeadersRead + dispose avoids hanging on an SSE
    // body. This request is fully awaited, so it never leaves an unobserved task.
    private const string InitializeBody =
        "{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\"," +
        "\"capabilities\":{},\"clientInfo\":{\"name\":\"foreman-scan-preflight\",\"version\":\"1\"}}}";

    private static async Task PreflightAsync(Uri endpoint, TimeSpan timeout, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);

        using var req = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new StringContent(InitializeBody, Encoding.UTF8, "application/json"),
        };
        req.Headers.Accept.ParseAdd("application/json, text/event-stream");

        HttpResponseMessage resp;
        try
        {
            resp = await PreflightHttp.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;   // caller's cancellation — propagate as-is
        }
        catch (Exception ex)   // connection refused / DNS / TLS / per-server timeout
        {
            throw new InvalidOperationException($"MCP endpoint unreachable: {ex.Message}", ex);
        }

        using (resp)
        {
            if (resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden
                or HttpStatusCode.MethodNotAllowed)
            {
                throw new InvalidOperationException(
                    $"MCP endpoint not scannable (HTTP {(int)resp.StatusCode}): requires its own auth or is not a " +
                    "streamable-HTTP MCP endpoint. TraceBrake holds no third-party credentials, so it is skipped.");
            }
        }
    }
}
