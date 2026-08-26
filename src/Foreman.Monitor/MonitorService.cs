using Foreman.Core.Behavior;
using Foreman.Core.Events;
using Foreman.Core.Profiles;
using Foreman.Core.Settings;
using Foreman.Core.Termination;
using Foreman.Monitor.Wmi;

namespace Foreman.Monitor;

/// <summary>
/// Top-level composition root for all monitoring components.
/// Call Start() once at app startup, Dispose() on exit.
/// </summary>
public sealed class MonitorService : IDisposable
{
    private readonly WmiProcessWatcher _watcher;
    private readonly IoPoller _poller;
    private readonly ProfileStore _profileStore;
    private readonly DeadMansSwitch _deadMansSwitch;
    private readonly HarnessAppModelFailureMonitor _appModelFailures;
    private bool _started;

    public ProcessTreeTracker Tree     { get; }
    public BehaviorTracker    Behavior { get; }
    public ProfileMatcher     Profiles { get; }
    public McpInventoryMonitor McpInventory { get; }
    public IdleHarnessDetector IdleCleanup { get; }

    /// <summary>Connects broker/UI termination producers to both live and reconciliation exit consumers.</summary>
    public ExpectedTerminationLedger? ExpectedTerminations
    {
        set
        {
            _watcher.ExpectedTerminations = value;
            _poller.ExpectedTerminations = value;
            IdleCleanup.ExpectedTerminations = value;
        }
    }

    public MonitorService(ForemanSettings settings, EventBus bus)
    {
        McpInventory = new McpInventoryMonitor(bus, settings.McpPort);
        Tree = new ProcessTreeTracker();
        _profileStore = new ProfileStore(settings.ProfilesDirectory);
        _profileStore.Initialize();
        Profiles = new ProfileMatcher(_profileStore);
        var violationDetector = new ViolationDetector(
            Profiles,
            bus,
            pid => Tree.FindProfileAncestor(pid));
        var hangDetector = new HangDetector(bus, settings, Tree, new Win32UserInputProvider());
        _watcher  = new WmiProcessWatcher(Tree, bus, settings, Profiles, violationDetector);
        _poller   = new IoPoller(Tree, hangDetector, settings, bus);
        Behavior  = new BehaviorTracker(
            settings, bus,
            pid => Tree.GetByPid(pid),
            pid => Tree.FindHarnessTypeAncestor(pid),
            settings.EffectiveThresholds);   // per-harness Trust thresholds (level 3 == global baseline)
        IdleCleanup = new IdleHarnessDetector(bus, settings, Tree);
        _deadMansSwitch = new DeadMansSwitch(bus, settings, Tree, new Win32UserInputProvider());
        _appModelFailures = new HarnessAppModelFailureMonitor(bus);
    }

    public void Start()
    {
        if (_started) return;
        _started = true;
        _watcher.Start();
        _poller.Start();
        McpInventory.Start();
        IdleCleanup.Start();
        _deadMansSwitch.Start();
        _appModelFailures.Start();
    }

    public void Dispose()
    {
        _poller.Dispose();
        _watcher.Dispose();
        _profileStore.Dispose();
        McpInventory.Dispose();
        IdleCleanup.Dispose();
        _deadMansSwitch.Dispose();
        _appModelFailures.Dispose();
    }
}
