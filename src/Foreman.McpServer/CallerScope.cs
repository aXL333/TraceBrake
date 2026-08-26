using Microsoft.AspNetCore.Http;

namespace Foreman.McpServer;

/// <summary>
/// The authenticated identity of an MCP caller, resolved from its bearer token by the auth gate and
/// carried in <c>HttpContext.Items</c> so static tool methods can scope by it (via an injected
/// <see cref="IHttpContextAccessor"/>). The raw install token authenticates as the unscoped OPERATOR;
/// a per-harness token scopes the caller to its own harness so it can't read or act on another's data.
/// </summary>
public sealed record CallerScope(
    string? HarnessId,
    bool IsOperator,
    bool PeerMismatch = false,
    bool IsAuthenticated = true)
{
    public const string HttpItemKey = "foreman.caller";
    private const string UnauthenticatedHarnessId = "$unauthenticated$";

    /// <summary>
    /// Explicit non-HTTP / in-process calls are trusted as operator calls. A real HTTP accessor whose
    /// context or auth-gate item is missing is different: it fails closed as <see cref="Unauthenticated"/>.
    /// This keeps unit/in-process callers deliberate without turning middleware/DI regressions into operator
    /// authority.
    /// </summary>
    public static readonly CallerScope OperatorDefault = new(null, true);

    /// <summary>Fail-closed identity for a real HTTP execution that lacks an auth-gate projection.</summary>
    public static readonly CallerScope Unauthenticated =
        new(UnauthenticatedHarnessId, IsOperator: false, PeerMismatch: true, IsAuthenticated: false);

    public static CallerScope From(IHttpContextAccessor? http)
    {
        if (http is null) return OperatorDefault;
        return http.HttpContext?.Items.TryGetValue(HttpItemKey, out var v) == true
               && v is CallerScope { IsAuthenticated: true } caller
            ? caller
            : Unauthenticated;
    }

    /// <summary>
    /// Resolve identity for a state-changing MCP tool. Unlike <see cref="From"/>, a missing accessor is never
    /// interpreted as an in-process operator: real SDK/DI injection failures must fail closed. Trusted in-process
    /// callers should pass an explicit operator context if they intentionally invoke a mutating tool.
    /// </summary>
    public static CallerScope FromAuthenticated(IHttpContextAccessor? http)
        => http is null ? Unauthenticated : From(http);

    /// <summary>True if this caller may see/act on <paramref name="harnessId"/>. Operator: anything. Harness: only itself; unattributable (null) is denied.</summary>
    public bool CanAccess(string? harnessId)
        => IsAuthenticated && (IsOperator
            || (harnessId is not null && string.Equals(harnessId, HarnessId, StringComparison.OrdinalIgnoreCase)));

    /// <summary>The harness a non-operator caller is locked to (its own); null for operator (unscoped).</summary>
    public string? ScopeHarness => IsOperator ? null : HarnessId ?? UnauthenticatedHarnessId;

    /// <summary>
    /// May this caller invoke STATE-MUTATING tools (acknowledge / reset-metrics / reply-to-ask)? An operator
    /// always may. A per-harness caller may NOT when its token was presented by a DIFFERENT process than the
    /// harness it claims (<see cref="PeerMismatch"/>) — that is token theft, so it must not be able to
    /// self-exonerate (ack its alerts, wipe its escalation, forge an Ask reply) even when peer-binding
    /// ENFORCEMENT is off. Reads remain governed by <see cref="CanAccess"/>.
    /// </summary>
    public bool CanMutate => IsAuthenticated
        && (IsOperator || (HarnessId is not null && !PeerMismatch));
}
