using System.Linq;
using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.Core.Security;
using Foreman.Core.Settings;

namespace Foreman.Monitor;

/// <summary>
/// Dead-man's switch (task #62): a periodic human tap-in. When the operator has been away (no keyboard/mouse
/// input) past the configured window WHILE one or more agents keep running, TraceBrake is operating unattended — it
/// raises a single heads-up notice per absence episode and re-arms once the operator returns. Opt-in. Reads only
/// idle DURATION (no keylogging), via the same <see cref="IUserInputProvider"/> the hang-threshold scaling uses.
///
/// All decisions live in <see cref="DeadMansSwitchPolicy"/> (pure, tested); this is the 60s timer + bus wiring.
/// </summary>
public sealed class DeadMansSwitch : IDisposable
{
    private readonly EventBus _bus;
    private readonly ForemanSettings _settings;
    private readonly ProcessTreeTracker _tree;
    private readonly IUserInputProvider _operator;
    private readonly CancellationTokenSource _cts = new();
    private bool _fired;
    private Task? _task;

    public DeadMansSwitch(EventBus bus, ForemanSettings settings, ProcessTreeTracker tree, IUserInputProvider operatorActivity)
    {
        _bus = bus;
        _settings = settings;
        _tree = tree;
        _operator = operatorActivity;
    }

    public void Start() => _task = RunAsync(_cts.Token);

    private async Task RunAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(60));
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            try { CheckNow(); }
            catch { /* a single bad tick must not kill the loop */ }
        }
    }

    /// <summary>One check. Public so tests can drive it.</summary>
    public void CheckNow()
    {
        var s = _settings.DeadMansSwitch;
        if (!s.Enabled) { _fired = false; return; }   // off → keep disarmed

        var absence = _operator.MinutesSinceLastInput;
        if (DeadMansSwitchPolicy.ShouldRearm(absence, s)) { _fired = false; return; }   // operator is back

        var active = _tree.GetAll().Count(r => r.IsHarness && r.State != ProcessState.Terminated);
        if (!DeadMansSwitchPolicy.ShouldFire(absence, active, _fired, s)) return;

        _fired = true;
        var span = absence >= 120 ? $"~{absence / 60}h" : $"{absence}m";
        _bus.Publish(new MonitoringNoticeEvent(
            DateTimeOffset.UtcNow, ForemanSeverity.Medium, "Foreman.DeadMansSwitch",
            $"No operator activity for {span} while {active} agent process(es) keep running — TraceBrake is operating " +
            "UNATTENDED. If you didn't intend to leave agents running, review what they've done and consider pausing them."));
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _task?.GetAwaiter().GetResult(); }
        catch (OperationCanceledException) { /* normal shutdown */ }
        _cts.Dispose();
    }
}
