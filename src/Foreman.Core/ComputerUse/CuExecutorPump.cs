using System;
using System.Threading;
using System.Threading.Tasks;

namespace Foreman.Core.ComputerUse;

/// <summary>
/// Drives APPROVED computer-use actions to an <see cref="ICuExecutor"/> for one modality: it Claims the broker's
/// approved queue (which re-gates driver-auth, panic epoch, and one-window confinement at delivery), runs each via the
/// executor, and reports the outcome back with <see cref="CuBroker.Complete"/>. The broker owns audit/confinement/panic;
/// the pump only moves cleared work and records results. Nothing here can approve or un-halt anything.
/// </summary>
public sealed class CuExecutorPump
{
    private readonly CuBroker _broker;
    private readonly ICuExecutor _executor;
    private readonly int _batch;
    private readonly string _executionOwner;
    private readonly IHudAck? _hud;
    private readonly Action? _onHudWithheld;
    private DateTimeOffset _lastHudWarn = DateTimeOffset.MinValue;

    public CuExecutorPump(CuBroker broker, ICuExecutor executor, int batch = 4,
        IHudAck? hud = null, Action? onHudWithheld = null)
    {
        _broker = broker;
        _executor = executor;
        _batch = Math.Clamp(batch, 1, 10);
        _executionOwner = $"inproc:{executor.Modality.ToString().ToLowerInvariant()}:{Guid.NewGuid():N}";
        _hud = hud;
        _onHudWithheld = onHudWithheld;
    }

    /// <summary>Claim + execute one batch of Approved actions for this executor's modality. Returns the count run. Never
    /// throws: a failed/throwing action is Completed with its error so it never wedges the queue. Claim returns nothing
    /// while halted, so panic naturally drains the pump.</summary>
    public async Task<int> PumpOnceAsync(CancellationToken ct = default)
    {
        if (!_executor.IsReady) return 0;

        // INV-18: before delivering ANY desktop input, the operator HUD must be confirmed VISIBLE right now (topmost +
        // un-cloaked + un-occluded). Peek FIRST so we only raise/test the HUD when there is approved work, then fail
        // CLOSED if it can't be confirmed: we don't even Claim, so the Approved items simply WAIT (never execute behind a
        // hidden HUD, never terminally fail) and resume the instant the HUD is visible again.
        if (_hud is not null)
        {
            if (!_broker.HasApprovedFor(_executor.Modality)) return 0;
            _hud.EnsureShown();
            if (!_hud.ConfirmVisible())
            {
                if (DateTimeOffset.UtcNow - _lastHudWarn > TimeSpan.FromSeconds(5))
                {
                    _lastHudWarn = DateTimeOffset.UtcNow;
                    try { _onHudWithheld?.Invoke(); } catch { /* warning is best-effort */ }
                }
                return 0;
            }
        }

        var batch = _broker.Claim(_batch, _executor.Modality, _executionOwner);
        var ran = 0;
        foreach (var item in batch)
        {
            if (ct.IsCancellationRequested) break;
            // Claim may return a batch, then panic/revocation/expiry can invalidate a later item while an earlier one
            // runs. Re-check the exact owner-bound lease immediately before every physical effect.
            var live = _broker.ValidateExecution(item.ActionId, _executor.Modality, _executionOwner,
                item.ExecutionToken ?? string.Empty);
            if (!live.Ok) continue;
            CuExecResult r;
            try { r = await _executor.ExecuteAsync(live.Item!, ct).ConfigureAwait(false); }
            catch (Exception ex) { r = new CuExecResult(false, null, ex.Message); }
            _broker.Complete(item.ActionId, r.Ok, r.Result, r.Error, _executor.Modality,
                _executionOwner, item.ExecutionToken ?? string.Empty);
            ran++;
        }
        return ran;
    }

    /// <summary>Run <see cref="PumpOnceAsync"/> on an interval until cancelled (the App fire-and-forgets this).</summary>
    public async Task RunAsync(TimeSpan interval, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await PumpOnceAsync(ct).ConfigureAwait(false); } catch { /* keep pumping */ }
            try { await Task.Delay(interval, ct).ConfigureAwait(false); } catch { break; }
        }
    }
}
