namespace Foreman.Core.Security;

/// <summary>
/// Process-global "computer use is HALTED" flag — the safety floor for TraceBrake-mediated computer/browser use.
/// Set by the panic kill (global hotkey or the tray STOP item), checked by every CU executor before each action,
/// and cleared ONLY by an operator + presence tap (never by an agent and never over MCP). Lives in Core so the
/// McpServer tools, the App UI, and the future CU sidecar all read one source of truth.
///
/// Halting is the SAFE direction and is unguarded (anyone/anything that can reach this may stop computer use).
/// Resuming is the dangerous direction: callers MUST gate <see cref="Resume"/> behind operator presence — an agent
/// must never be able to un-halt itself. The flag is the base case of the audit chain: it needs no auditor, only
/// the human.
/// </summary>
public sealed class CuPanicState
{
    private volatile bool _halted;

    /// <summary>True while all TraceBrake-mediated computer/browser use is halted.</summary>
    public bool IsHalted => _halted;

    /// <summary>Best-effort notification that the halt flag flipped (arg = now-halted). For the tray/overlay/log to react.</summary>
    public event Action<bool>? Changed;

    /// <summary>Halt all computer use (the safe direction, unguarded). Idempotent; returns true only if this call changed the state.</summary>
    public bool Halt() => Set(true);

    /// <summary>Clear the halt. DANGEROUS: callers MUST presence-gate this (operator only). Returns true only if this call changed the state.</summary>
    public bool Resume() => Set(false);

    private bool Set(bool halted)
    {
        if (_halted == halted) return false;
        _halted = halted;
        try { Changed?.Invoke(halted); } catch { /* a bad subscriber must never wedge the panic path */ }
        return true;
    }
}
