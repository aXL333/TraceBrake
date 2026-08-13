using System.Net;

namespace Foreman.Core.Mcp;

/// <summary>Result of a transport-policy check on an inbound request.</summary>
public sealed record RequestVerdict(bool Allowed, string Reason)
{
    public static readonly RequestVerdict Ok = new(true, "ok");
    public static RequestVerdict Deny(string reason) => new(false, reason);
}

/// <summary>
/// Pure transport-layer gate for TraceBrake's loopback MCP server, evaluated BEFORE the bearer-token check.
/// Defends the local endpoint against the browser-reachable attacks the whitepaper describes:
///
///  - <b>Host header must be loopback.</b> The canonical DNS-rebinding defence: a malicious public page can
///    rebind a hostname to 127.0.0.1 and make the victim's browser reach the local server, but the request's
///    Host header still carries the attacker's rebound hostname — so rejecting a non-loopback Host blocks it.
///  - <b>Origin, when present, must be loopback or an explicitly paired extension</b>
///    (<c>chrome-extension://&lt;id&gt;</c>). An absent Origin is allowed: non-browser MCP clients omit it, and
///    the bearer token is the backstop there. A browser page from a foreign site DOES send its Origin, so a
///    drive-by cross-origin POST is rejected here.
///
/// This is defence-in-depth layered on top of the token, never instead of it. Pure + unit-tested so the gate's
/// logic is verified without standing up the ASP.NET host.
/// </summary>
public static class LoopbackRequestPolicy
{
    public static RequestVerdict Evaluate(string? host, string? origin, IReadOnlyCollection<string> allowedExtensionOrigins)
    {
        if (!IsLoopbackHost(host))
            return RequestVerdict.Deny("Request Host is not a loopback address (possible DNS rebinding).");

        if (!string.IsNullOrEmpty(origin) && !IsAllowedOrigin(origin, allowedExtensionOrigins))
            return RequestVerdict.Deny("Origin is neither loopback nor a paired extension.");

        return RequestVerdict.Ok;
    }

    /// <summary>True if the Host header (with optional :port, incl. bracketed IPv6) resolves to a loopback
    /// address — localhost, 127.0.0.0/8, or ::1.</summary>
    public static bool IsLoopbackHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return false;   // HTTP/1.1 always sends Host; absence is suspicious
        var h = host.Trim();

        string name;
        if (h.StartsWith('['))                               // [::1] or [::1]:port
        {
            var end = h.IndexOf(']');
            if (end < 1) return false;
            name = h[1..end];
        }
        else
        {
            var colon = h.IndexOf(':');                      // host or host:port (no bracket = at most one colon)
            name = colon >= 0 ? h[..colon] : h;
        }

        if (name.Equals("localhost", StringComparison.OrdinalIgnoreCase)) return true;
        return IPAddress.TryParse(name, out var ip) && IPAddress.IsLoopback(ip);
    }

    private static bool IsAllowedOrigin(string origin, IReadOnlyCollection<string> allowedExtensionOrigins)
    {
        if (IsLoopbackOrigin(origin)) return true;
        foreach (var allowed in allowedExtensionOrigins)
            if (!string.IsNullOrWhiteSpace(allowed)
                && string.Equals(origin.TrimEnd('/'), allowed.TrimEnd('/'), StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    /// <summary>True if the Origin is a loopback http(s) origin.</summary>
    public static bool IsLoopbackOrigin(string origin) =>
        Uri.TryCreate(origin, UriKind.Absolute, out var u)
        && (u.IsLoopback || u.Host is "localhost" or "127.0.0.1" or "::1");
}
