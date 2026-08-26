using Foreman.Core.Events;
using Foreman.Core.Heuristics;
using Foreman.Core.Models;
using Foreman.Core.Profiles;
using Foreman.Core.Security;
using Foreman.Core.Settings;
using Foreman.Core.Termination;
using System.Collections.Generic;
using System.Globalization;
using System.Management;

namespace Foreman.Monitor.Wmi;

/// <summary>
/// Listens for process creation and termination via WMI event subscriptions.
/// Fires at medium IL (no admin required). ~1s latency vs. ETW, acceptable for Phase 1.
/// </summary>
public sealed class WmiProcessWatcher : IDisposable
{
    private readonly ProcessTreeTracker _tree;
    private readonly EventBus _bus;
    private readonly ForemanSettings _settings;
    private readonly ProfileMatcher? _profileMatcher;
    private readonly ViolationDetector? _violationDetector;
    private readonly CredentialSweepAggregator _credSweep;
    private ManagementEventWatcher? _createWatcher;
    private ManagementEventWatcher? _deleteWatcher;
    private bool _started;

    /// <summary>Shared broker ledger used to suppress only exits TraceBrake itself actually initiated.</summary>
    public ExpectedTerminationLedger? ExpectedTerminations { get; set; }

    private readonly object _armLock = new();
    private volatile bool _healthy;
    private bool _degraded;          // have we already announced degradation? (guards notice spam)
    private Timer? _watchdog;
    private volatile bool _disposed;

    public WmiProcessWatcher(
        ProcessTreeTracker tree,
        EventBus bus,
        ForemanSettings settings,
        ProfileMatcher? profileMatcher = null,
        ViolationDetector? violationDetector = null)
    {
        _tree = tree;
        _bus = bus;
        _settings = settings;
        _profileMatcher = profileMatcher;
        _violationDetector = violationDetector;
        _credSweep = new CredentialSweepAggregator(
            settings.CredentialSweepDistinctThreshold, settings.CredentialSweepWindowSeconds);
    }

    public void Start()
    {
        if (_started) return;
        _started = true;

        // initial snapshot — detect already-running harnesses before WMI watchers start
        Task.Run(RunInitialScan);

        ArmWatchers();

        // Watchdog: a WMI event sink can die silently (WMI service restart, COM fault) — which used to
        // end process monitoring with no signal. Re-arm any stopped watcher so detection recovers instead
        // of going quietly dark. Cheap: only does work when a watcher is known-unhealthy.
        _watchdog = new Timer(_ => Watchdog(), null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    /// <summary>Creates (or recreates) and starts both WMI watchers. Safe to call repeatedly.</summary>
    private void ArmWatchers()
    {
        lock (_armLock)
        {
            if (_disposed) return;
            try
            {
                TeardownWatchers();   // detach + dispose any previous instances first

                // process creation — WITHIN 1 means polling every 1 second
                _createWatcher = new ManagementEventWatcher(
                    new WqlEventQuery("SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"));
                _createWatcher.EventArrived += OnProcessCreated;
                _createWatcher.Stopped += OnWatcherStopped;
                _createWatcher.Start();

                // process termination — 2s is fine since we track final state
                _deleteWatcher = new ManagementEventWatcher(
                    new WqlEventQuery("SELECT * FROM __InstanceDeletionEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_Process'"));
                _deleteWatcher.EventArrived += OnProcessDeleted;
                _deleteWatcher.Stopped += OnWatcherStopped;
                _deleteWatcher.Start();

                _healthy = true;
                if (_degraded)   // recovered from a previous failure
                {
                    _degraded = false;
                    _bus.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman.Monitor",
                        "Process monitoring recovered — WMI watchers restarted."));
                }
            }
            catch (Exception ex)
            {
                _healthy = false;
                TeardownWatchers();   // don't leave a half-armed state
                if (!_degraded)
                {
                    _degraded = true;
                    _bus.Publish(new MonitoringNoticeEvent(DateTimeOffset.UtcNow, ForemanSeverity.High, "Foreman.Monitor",
                        $"Process monitoring is DEGRADED — WMI watchers failed to start ({ex.Message}). " +
                        "Hang/orphan/command detection is paused; TraceBrake will keep retrying every 30s."));
                }
            }
        }
    }

    private void TeardownWatchers()
    {
        // Detach BEFORE Stop()/Dispose() so our own intentional teardown never trips OnWatcherStopped.
        if (_createWatcher is not null)
        {
            _createWatcher.EventArrived -= OnProcessCreated;
            _createWatcher.Stopped -= OnWatcherStopped;
            try { _createWatcher.Stop(); } catch { }
            _createWatcher.Dispose();
            _createWatcher = null;
        }
        if (_deleteWatcher is not null)
        {
            _deleteWatcher.EventArrived -= OnProcessDeleted;
            _deleteWatcher.Stopped -= OnWatcherStopped;
            try { _deleteWatcher.Stop(); } catch { }
            _deleteWatcher.Dispose();
            _deleteWatcher = null;
        }
    }

    // Fires on unexpected stops (we detach before our own teardown, so this is always involuntary).
    // Mark unhealthy; the watchdog re-arms on its next tick.
    private void OnWatcherStopped(object sender, StoppedEventArgs e)
    {
        if (!_disposed) _healthy = false;
    }

    private void Watchdog()
    {
        if (_disposed || _healthy) return;
        ArmWatchers();
    }

    private void RunInitialScan()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath, CreationDate " +
                "FROM Win32_Process");

            var harnessesFound = new List<string>();

            foreach (ManagementObject proc in searcher.Get())
            {
                try
                {
                    using var _ = proc;
                    var record = BuildRecord(proc);
                    _tree.OnProcessCreated(record);

                    if (record.HarnessType is not null)
                        harnessesFound.Add($"{record.HarnessType} (pid {record.Pid})");
                }
                catch { /* process may have exited mid-scan */ }
            }

            var msg = harnessesFound.Count > 0
                ? $"Initial scan — {harnessesFound.Count} harness process(es) already running: {string.Join(", ", harnessesFound)}"
                : "Initial scan complete — no harnesses currently running";

            _bus.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman.Monitor", msg));
        }
        catch (Exception ex)
        {
            _bus.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman.Monitor",
                $"Initial process scan failed: {ex.Message}"));
        }
    }

    // A process NAMED like TraceBrake but running from a DIFFERENT path than the real TraceBrake is a strong IOC: an
    // agent impersonating the watchdog (e.g. to inherit a self-exemption or fool the operator). TraceBrake's own
    // process is excluded by path. Best-effort — an elevated impostor's path may be unreadable (the rarer case).
    private static readonly HashSet<string> _foremanProcessNames = new(StringComparer.OrdinalIgnoreCase)
        { "TraceBrake.exe", "TraceBrake", "Foreman.exe", "Foreman.App.exe", "Foreman", "Foreman.App" };

    private void CheckForemanImpersonation(ProcessRecord record)
    {
        if (!_foremanProcessNames.Contains(record.Name)) return;
        var realPath = Environment.ProcessPath;
        if (string.IsNullOrEmpty(record.ExecutablePath) || string.IsNullOrEmpty(realPath)) return;
        if (string.Equals(record.ExecutablePath, realPath, StringComparison.OrdinalIgnoreCase)) return;

        _bus.Publish(new MonitoringNoticeEvent(
            DateTimeOffset.UtcNow, ForemanSeverity.High, "Foreman.Integrity",
            $"A process named '{record.Name}' (pid {record.Pid}) is running from '{record.ExecutablePath}', not " +
            "TraceBrake's own install location — a process impersonating the watchdog. Investigate and stop it."));
    }

    private void OnProcessCreated(object sender, EventArrivedEventArgs e)
    {
        try
        {
            using var proc = (ManagementBaseObject)e.NewEvent["TargetInstance"];
            var record = BuildRecord(proc);
            _tree.OnProcessCreated(record);
            ApplyProfileInheritance(record);
            CheckForemanImpersonation(record);

            // heuristic analysis on the thread pool — don't block the WMI callback
            if (!string.IsNullOrWhiteSpace(record.CommandLine))
            {
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    var profile = ResolveProfile(record);
                    var match = CommandAnalyzer.Instance.Analyze(record.CommandLine, record.Name, profile);
                    _violationDetector?.CheckCommandLine(record, match);
                    if (match is null) return;

                    var now = DateTimeOffset.UtcNow;
                    var severity = match.Severity;
                    var message = $"[{match.RuleId}] {match.RuleName}: {TruncateCmdLine(record.CommandLine)}";

                    // #44 Layer B — a credential/network rule firing INSIDE a package-install subtree of a
                    // harness is almost never legitimate (the Miasma / Phantom-Gyp install-time detonation):
                    // escalate one severity and annotate. No new alert surface — it only sharpens this one.
                    if (match.Category is "cred" or "net"
                        && _tree.FindInstallAncestor(record.Pid) is { } install
                        && _tree.FindHarnessTypeAncestor(record.Pid) is { } harnessOwner)
                    {
                        severity = Severities.EscalateOneLevel(match.Severity);
                        message = $"[{match.RuleId}] {match.RuleName} during a package install " +
                                  $"({TruncateCmdLine(install.CommandLine)}) under {harnessOwner.HarnessType}: " +
                                  TruncateCmdLine(record.CommandLine);
                    }

                    _bus.Publish(new CommandAlertEvent(
                        now, severity, $"{record.Name} (pid {record.Pid})", message,
                        record.CommandLine, match.RuleId, match.RuleName, match.Description, match.Guidance,
                        record.Pid) { ProcessStartTime = record.StartTime });

                    // #43 burst aggregator — several DISTINCT credential stores read by one harness tree in a
                    // short window is the Miasma harvester fingerprint; fire a single Critical sweep alert.
                    if (match.Category == "cred")
                    {
                        var owner = _tree.FindHarnessTypeAncestor(record.Pid);
                        var treeKey = (owner ?? record).Key;
                        // A downgraded harness env-snapshot ("cred-013-harness") is still an env-store read — feed
                        // the sweep its CANONICAL store id so the downgrade can't shrink the distinct-store count.
                        var sweepRuleId = match.RuleId == "cred-013-harness" ? "cred-013" : match.RuleId;
                        if (_credSweep.Observe(treeKey, sweepRuleId, now) is { } swept)
                        {
                            var who = owner?.HarnessType ?? record.Name;
                            _bus.Publish(new CommandAlertEvent(
                                now, ForemanSeverity.Critical, $"{who} (pid {record.Pid})",
                                $"Credential-store sweep: {swept.Count} distinct credential stores read by {who} " +
                                $"within {_settings.CredentialSweepWindowSeconds}s ({string.Join(", ", swept)}) — " +
                                "the behaviour of an automated credential harvester, not normal development.",
                                record.CommandLine, "cred-sweep", "Credential-store sweep",
                                "A single harness tree read several different credential stores in quick succession. " +
                                "Each read may look benign alone, but the burst is the signature of a credential-stealing payload.",
                                "Treat as an active credential-theft incident: identify and stop the process, then rotate " +
                                "every credential it could have read (cloud keys, SSH/GPG keys, tokens).",
                                record.Pid) { ProcessStartTime = record.StartTime });
                        }
                    }
                });
            }
        }
        catch (ManagementException) { /* process died before we could read it */ }
        catch (Exception) { /* never crash the watcher thread */ }
    }

    private void OnProcessDeleted(object sender, EventArrivedEventArgs e)
    {
        try
        {
            using var proc = (ManagementBaseObject)e.NewEvent["TargetInstance"];
            var pid = Convert.ToInt32(proc["ProcessId"]);
            var name = proc["Name"]?.ToString() ?? string.Empty;
            var exitCode = proc["ExitCode"] is uint code ? (int)code : 0;
            var startTime = ParseDmtfDate(proc["CreationDate"]?.ToString());
            var expected = ExpectedTerminations?.WasExpected(pid, startTime, out _) == true;

            var orphans = _tree.OnProcessDeleted(pid, startTime, out var deleted);

            // A local-model host (LM Studio, Ollama, …) exiting commonly leaves its inference server lingering for
            // a moment — that's normal teardown, not an abandoned orphan. Skip orphan events for its children.
            var deadParentIsLocalModelHost = KnownHarnesses.IsLocalModelHost(deleted?.HarnessType);

            // publish orphan events for any children that survived — but ONLY for orphans that belong to a harness
            // tree. A re-parented Windows process (e.g. SIHClient.exe when its upfc.exe launcher exits) has no
            // harness lineage and is OS churn, not an "orphaned harness child"; attributing it would be a false
            // positive. When a harness IS found, name it on the alert.
            foreach (var orphan in orphans)
            {
                if (expected) continue;
                if (deadParentIsLocalModelHost) continue;
                var harness = _tree.AttributeOrphanHarness(orphan, deleted);
                if (harness is null) continue;   // not part of a harness tree — ignore (Windows process churn)
                _bus.Publish(new OrphanDetectedEvent(
                    DateTimeOffset.UtcNow,
                    "Foreman.Monitor",
                    $"{orphan.Name} (pid {orphan.Pid}) is orphaned — parent {name} (pid {pid}) exited " +
                    $"[harness: {harness.HarnessType ?? harness.Name}]",
                    orphan.Pid,
                    orphan.Name,
                    pid,
                    name,
                    orphan.UptimeMinutes,
                    harness.Pid,
                    harness.HarnessType,
                    harness.Name
                ) { ProcessStartTime = orphan.StartTime });
            }

            // flag nonzero exits from harness-classified processes
            if (!expected && exitCode != 0 && deleted?.IsHarness == true)
            {
                _bus.Publish(new NonzeroExitEvent(
                    DateTimeOffset.UtcNow,
                    "Foreman.Monitor",
                    $"{name} (pid {pid}) exited with code {exitCode}",
                    pid, name, exitCode, null
                ));
            }
        }
        catch { }
    }

    private ProcessRecord BuildRecord(ManagementBaseObject proc)
    {
        var pid = Convert.ToInt32(proc["ProcessId"]);
        var parentPid = Convert.ToInt32(proc["ParentProcessId"]);
        var name = proc["Name"]?.ToString() ?? string.Empty;
        var cmdLine = proc["CommandLine"]?.ToString() ?? string.Empty;
        var exePath = proc["ExecutablePath"]?.ToString() ?? string.Empty;

        // WMI CreationDate is a DMTF datetime string
        var startTime = ParseDmtfDate(proc["CreationDate"]?.ToString());

        var record = new ProcessRecord
        {
            Pid = pid,
            ParentPid = parentPid,
            Name = name,
            CommandLine = cmdLine,
            ExecutablePath = exePath,
            StartTime = startTime,
            LastIoChangeTime = DateTimeOffset.UtcNow,
        };

        HarnessClassifier.Classify(record, _settings.DisabledHarnesses, _settings.CustomHarnessExes);
        ApplyDirectProfile(record);
        return record;
    }

    private static DateTimeOffset ParseDmtfDate(string? dmtf)
    {
        if (string.IsNullOrEmpty(dmtf))
            return DateTimeOffset.UtcNow;

        if (TryParseDmtfDateTimeOffset(dmtf, out var parsed))
            return parsed;

        try
        {
            var local = ManagementDateTimeConverter.ToDateTime(dmtf);
            if (local.Kind == DateTimeKind.Unspecified)
                local = DateTime.SpecifyKind(local, DateTimeKind.Local);
            return new DateTimeOffset(local);
        }
        catch
        {
            return DateTimeOffset.UtcNow;
        }
    }

    private static bool TryParseDmtfDateTimeOffset(string dmtf, out DateTimeOffset value)
    {
        value = default;
        if (dmtf.Length < 25 || dmtf[14] != '.')
            return false;

        var sign = dmtf[21];
        if (sign is not ('+' or '-'))
            return false;

        try
        {
            var year = ParseInt(dmtf, 0, 4);
            var month = ParseInt(dmtf, 4, 2);
            var day = ParseInt(dmtf, 6, 2);
            var hour = ParseInt(dmtf, 8, 2);
            var minute = ParseInt(dmtf, 10, 2);
            var second = ParseInt(dmtf, 12, 2);
            var microsecond = ParseInt(dmtf, 15, 6);
            var offsetMinutes = ParseInt(dmtf, 22, 3);
            if (sign == '-') offsetMinutes = -offsetMinutes;

            value = new DateTimeOffset(
                year, month, day, hour, minute, second,
                TimeSpan.FromMinutes(offsetMinutes)).AddTicks(microsecond * 10L);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static int ParseInt(string value, int start, int length) =>
        int.Parse(value.AsSpan(start, length), NumberStyles.None, CultureInfo.InvariantCulture);

    private void ApplyDirectProfile(ProcessRecord record)
    {
        if (_profileMatcher?.Match(record) is { } profile)
            record.ProfileName = profile.Name;
    }

    private void ApplyProfileInheritance(ProcessRecord record)
    {
        if (record.ProfileName is not null) return;
        if (_tree.FindProfileAncestor(record.Pid)?.ProfileName is { } profileName)
            record.ProfileName = profileName;
    }

    private HarnessProfile? ResolveProfile(ProcessRecord record)
    {
        if (record.ProfileName is not null && _profileMatcher?.Get(record.ProfileName) is { } byName)
            return byName;
        ApplyDirectProfile(record);
        ApplyProfileInheritance(record);
        return record.ProfileName is not null
            ? _profileMatcher?.Get(record.ProfileName)
            : null;
    }

    private static string TruncateCmdLine(string cmd, int max = 120) =>
        cmd.Length <= max ? cmd : cmd[..max] + "…";

    public void Dispose()
    {
        _disposed = true;
        _watchdog?.Dispose();
        lock (_armLock)
            TeardownWatchers();
    }
}
