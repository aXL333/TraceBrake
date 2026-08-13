using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Foreman.Core.Events;
using Foreman.Core.Ipc;
using Foreman.Core.Models;
using Foreman.Core.Power;

namespace Foreman.App;

/// <summary>
/// Launches and supervises the elevated ETW network sidecar and exposes the per-PID network rates
/// it streams. The sidecar is the ONLY elevated component — this controller and the rest of the app
/// (including the MCP server and the kill UI) stay at medium integrity.
///
/// Transport: the app hosts a current-user-only named pipe; the elevated sidecar connects to it and
/// proves itself with a one-time nonce before any data is accepted. The sidecar exits on its own when
/// the pipe breaks or the app exits, so nothing privileged lingers.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ElevatedSidecarController : IDisposable
{
    private static SidecarPayloadPin? _activePayloadPin;
    private readonly object _gate = new();
    private CancellationTokenSource? _cts;
    private volatile Dictionary<int, double> _rates = new();
    private volatile WakeRequestSnapshot _wakeRequests = WakeRequestSnapshot.Unavailable("Elevated sidecar is not connected.");
    private volatile bool _connected;
    private volatile bool _launchFailed;   // last launch attempt failed to START (declined UAC / missing / untrusted)
    private volatile bool _launchInProgress;
    private int _processStartInProgress;   // Process.Start(runas) cannot be cancelled while UAC is open
    private bool _captureNet = true;
    private bool _captureWakeRequests = true;
    private IReadOnlyList<string> _decoyPaths = [];
    private string? _decoyPathsFile;
    private int _decoyExpected;
    private int _decoyArmed;

    /// <summary>
    /// Sets what the next launch does: per-PID network capture and/or SACL read-auditing of the given decoy
    /// paths. Call before <see cref="Start"/> / <see cref="Restart"/>.
    /// </summary>
    public void Configure(bool captureNet, IReadOnlyList<string>? decoyPaths, bool captureWakeRequests = true)
    {
        _captureNet = captureNet;
        _captureWakeRequests = captureWakeRequests;
        _decoyPaths = decoyPaths ?? [];
        _decoyExpected = _decoyPaths.Count;
        _decoyArmed = 0;
    }

    /// <summary>Stop and start with the current configuration (re-prompts UAC if elevated).</summary>
    public void Restart() { Stop(); Start(); }

    public bool IsRunning { get; private set; }
    public bool IsConnected => _connected;
    public int DecoyAuditExpected => _decoyExpected;
    public int DecoyAuditArmed => _decoyArmed;

    /// <summary>
    /// True when the most recent launch attempt failed to START — the user declined the UAC prompt, or the helper
    /// was missing / failed integrity. Distinguishes a declined (re-)elevation from a genuine post-connect crash so
    /// a supervisor can auto-recover the latter without re-prompting UAC on a loop for the former. Cleared when a
    /// new launch begins or the sidecar connects.
    /// </summary>
    public bool LaunchFailed => _launchFailed;

    /// <summary>
    /// True while Windows is displaying the UAC prompt or the accepted helper is still connecting. Supervisors
    /// must not interpret this interval as a crash and launch another elevation prompt.
    /// </summary>
    public bool LaunchInProgress => _launchInProgress;

    /// <summary>Raised when the elevated sidecar reports a SACL-audited read of a decoy credential file.</summary>
    public Action<DecoyReadMessage>? OnDecoyRead { get; set; }

    /// <summary>Latest network bytes/sec for a PID, or null when the sidecar isn't feeding it.</summary>
    public double? GetRate(int pid) =>
        _connected && _rates.TryGetValue(pid, out var rate) ? rate : null;

    public WakeRequestSnapshot GetWakeRequests() =>
        _connected ? _wakeRequests : WakeRequestSnapshot.Unavailable("Elevated sidecar is not connected.");

    public void Start()
    {
        lock (_gate)
        {
            if (IsRunning) return;
            IsRunning = true;
            _launchFailed = false;   // a fresh attempt is starting; clear the prior verdict
            _launchInProgress = true;
            _cts = new CancellationTokenSource();
            var cts = _cts;
            _ = Task.Run(() => RunAsync(cts));
        }
    }

    public void Stop()
    {
        lock (_gate)
        {
            if (!IsRunning) return;
            IsRunning = false;
            _connected = false;
            _launchInProgress = false;
            _cts?.Cancel();
            _rates = new();
            _wakeRequests = WakeRequestSnapshot.Unavailable("Elevated sidecar is not connected.");
        }
    }

    private async Task RunAsync(CancellationTokenSource cts)
    {
        var ct = cts.Token;
        var pipeName = "foreman-etw-" + Guid.NewGuid().ToString("N");
        var nonce    = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

        try
        {
            using var server = CreateOwnerOnlyPipe(pipeName);
            if (!LaunchSidecar(pipeName, nonce)) { _launchFailed = true; return; }   // exe missing or UAC declined

            using var connectionCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectionCts.CancelAfter(TimeSpan.FromSeconds(60));
            try
            {
                await server.WaitForConnectionAsync(connectionCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                EventBus.Instance.Publish(new MonitoringNoticeEvent(
                    DateTimeOffset.UtcNow, ForemanSeverity.High, "Foreman.Sidecar",
                    "The elevated helper launched but did not complete its authenticated connection within 60 " +
                    "seconds. The launch was cleared so supervision can recover cleanly."));
                return;
            }

            // Reject a non-elevated racer: the cmdline nonce is readable by same-user processes, so a medium-IL
            // agent could scrape it and connect first. The genuine sidecar runs elevated — anything that isn't is
            // an impersonator, dropped before any frame is trusted (the nonce check below is the second factor).
            if (PipeClientGuard.ConnectedClientIsNotElevated(server.SafePipeHandle, out var notElevatedReason))
            {
                EventBus.Instance.Publish(new MonitoringNoticeEvent(
                    DateTimeOffset.UtcNow, ForemanSeverity.High, "Foreman.Sidecar",
                    $"Rejected a process impersonating the elevated sidecar over its pipe ({notElevatedReason})."));
                return;
            }

            using var reader = new StreamReader(server, new UTF8Encoding(false));

            // Handshake: the first line must be our nonce, else it isn't the sidecar we launched.
            var presented = await reader.ReadLineAsync(connectionCts.Token).ConfigureAwait(false);
            if (!string.Equals(presented, nonce, StringComparison.Ordinal)) return;

            _connected = true;
            _launchInProgress = false;
            _launchFailed = false;   // launched and handshook — a later drop is a crash, not a failed launch
            while (!ct.IsCancellationRequested)
            {
                var line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
                if (line is null) break;   // sidecar closed the pipe
                try { HandleFrame(line); }
                catch { /* skip one malformed frame */ }
            }
        }
        catch (OperationCanceledException) { }
        catch { /* pipe/launch failure — features simply stay n/a */ }
        finally
        {
            _connected = false;
            CleanupDecoyPathsFile();
            // Clear IsRunning so a later Start() can relaunch a dead/failed sidecar — but only if a newer
            // Start() hasn't already replaced our CTS (else we'd stomp the live run's flag).
            lock (_gate)
            {
                if (ReferenceEquals(_cts, cts))
                {
                    IsRunning = false;
                    _launchInProgress = false;
                }
            }
        }
    }

    // Each pipe line is self-describing via a "Kind" field; route net frames to the rate table and
    // decoy-read frames to the callback. A line without Kind is a legacy net frame.
    private void HandleFrame(string line)
    {
        using var doc = JsonDocument.Parse(line);
        var kind = doc.RootElement.TryGetProperty("Kind", out var k) ? k.GetString() : SidecarFrame.Net;
        if (kind == SidecarFrame.DecoyRead)
        {
            if (JsonSerializer.Deserialize<DecoyReadMessage>(line) is { } d) OnDecoyRead?.Invoke(d);
        }
        else if (kind == SidecarFrame.DecoyAuditStatus)
        {
            if (JsonSerializer.Deserialize<DecoyAuditStatusMessage>(line) is { } status)
            {
                _decoyExpected = status.ExpectedCount;
                _decoyArmed = status.ArmedCount;
            }
        }
        else if (kind == SidecarFrame.WakeRequests)
        {
            if (JsonSerializer.Deserialize<WakeRequestsMessage>(line) is { } msg)
                _wakeRequests = new WakeRequestSnapshot(msg.Available, msg.Requests, msg.Error);
        }
        else if (JsonSerializer.Deserialize<NetworkRatesMessage>(line) is { } msg)
        {
            _rates = msg.Rates;
        }
    }

    private static NamedPipeServerStream CreateOwnerOnlyPipe(string name)
    {
        var me = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("No current Windows user SID.");
        var security = new PipeSecurity();
        security.SetOwner(me);
        security.AddAccessRule(new PipeAccessRule(me, PipeAccessRights.FullControl, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(
            name, PipeDirection.In, maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous,
            inBufferSize: 0, outBufferSize: 0, security);
    }

    /// <summary>The staged elevated ETW sidecar path.</summary>
    public static string SidecarPath() => Path.Combine(AppContext.BaseDirectory, "sidecar", "Foreman.EtwSidecar.exe");

    /// <summary>
    /// Hold write/delete-denying handles on the elevated sidecar's ENTIRE staged payload for the App's whole lifetime.
    /// Framework-dependent development builds load managed code from neighbouring DLLs, so pinning only the apphost EXE
    /// leaves the actual payload replaceable. Release builds are independently required to contain one self-contained
    /// EXE, but this directory-wide lease keeps local builds safe as well. Call once at startup and retain until exit.
    /// </summary>
    public static IDisposable? PinBinaryAtRest()
    {
        _activePayloadPin?.Dispose();
        _activePayloadPin = SidecarPayloadPin.TryAcquire(Path.GetDirectoryName(SidecarPath())!);
        return _activePayloadPin;
    }

    private bool LaunchSidecar(string pipeName, string nonce)
    {
        if (Volatile.Read(ref _processStartInProgress) != 0) return false;
        var exe = SidecarPath();
        if (!File.Exists(exe)) return false;

        if (_activePayloadPin?.ValidateSnapshot() != true)
        {
            EventBus.Instance.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow, ForemanSeverity.High, "Foreman.Sidecar",
                "Refused to launch the elevated sidecar because its complete payload could not be held and verified " +
                "unchanged. Reinstall TraceBrake or restart after any development build finishes."));
            return false;
        }

        // Never launch an UNTRUSTED binary with administrator rights. The sidecar sits in a same-user-writable
        // dir and forces requireAdministrator, so an overwritten sidecar would turn TraceBrake's branded UAC prompt
        // into a privilege-escalation primitive. Require it to carry the same Authenticode signature as Foreman.
        var (trusted, reason) = SidecarIntegrity.Verify(exe);
        if (!trusted)
        {
            EventBus.Instance.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow, ForemanSeverity.High, "Foreman.Sidecar",
                $"Refused to launch the elevated sidecar — {reason} This can mean the sidecar binary was tampered " +
                "with to hijack TraceBrake's administrator prompt. Reinstall TraceBrake from a trusted source."));
            return false;
        }

        var args = $"--pipe {pipeName} --nonce {nonce} --parent {Environment.ProcessId}";
        if (_captureNet) args += " --capture-net";
        if (_captureWakeRequests) args += " --wake-requests";

        _decoyPathsFile = null;
        if (_decoyPaths.Count > 0)
        {
            try
            {
                // The decoy paths (not secret) are passed via a temp file rather than a long arg list.
                _decoyPathsFile = Path.Combine(Path.GetTempPath(), "foreman-decoys-" + Guid.NewGuid().ToString("N") + ".txt");
                File.WriteAllLines(_decoyPathsFile, _decoyPaths);
                args += $" --audit-decoys \"{_decoyPathsFile}\"";
            }
            catch { _decoyPathsFile = null; }
        }

        try
        {
            // UseShellExecute=true is required for the sidecar's requireAdministrator manifest to
            // raise the UAC prompt. If the user declines, Process.Start throws (1223) — features stay n/a.
            // A watchdog expiry may request recovery while the original ShellExecute is still blocked on UAC.
            // Refuse another Process.Start until it returns, so bounded recovery cannot stack elevation prompts.
            if (Interlocked.CompareExchange(ref _processStartInProgress, 1, 0) != 0)
                return false;
            try
            {
                Process.Start(new ProcessStartInfo(exe) { Arguments = args, UseShellExecute = true });
                return true;
            }
            finally
            {
                Interlocked.Exchange(ref _processStartInProgress, 0);
            }
        }
        catch { return false; }
    }

    private sealed class SidecarPayloadPin : IDisposable
    {
        private readonly string _root;
        private readonly Dictionary<string, FileStream> _files;
        private bool _disposed;

        private SidecarPayloadPin(string root, Dictionary<string, FileStream> files)
        {
            _root = root;
            _files = files;
        }

        public static SidecarPayloadPin? TryAcquire(string root)
        {
            var held = new Dictionary<string, FileStream>(StringComparer.OrdinalIgnoreCase);
            try
            {
                if (!Directory.Exists(root)) return null;
                foreach (var path in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                {
                    var canonical = Path.GetFullPath(path);
                    held.Add(canonical, new FileStream(
                        canonical, FileMode.Open, FileAccess.Read, FileShare.Read));
                }

                return held.Count > 0 ? new SidecarPayloadPin(Path.GetFullPath(root), held) : null;
            }
            catch
            {
                foreach (var stream in held.Values) stream.Dispose();
                return null;
            }
        }

        public bool ValidateSnapshot()
        {
            if (_disposed) return false;
            try
            {
                var current = Directory.EnumerateFiles(_root, "*", SearchOption.AllDirectories)
                    .Select(Path.GetFullPath)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);
                return current.SetEquals(_files.Keys)
                    && _files.Values.All(static stream => stream.CanRead);
            }
            catch { return false; }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            foreach (var stream in _files.Values) stream.Dispose();
            _files.Clear();
        }
    }

    private void CleanupDecoyPathsFile()
    {
        if (_decoyPathsFile is null) return;
        try { if (File.Exists(_decoyPathsFile)) File.Delete(_decoyPathsFile); } catch { }
        _decoyPathsFile = null;
    }

    public void Dispose() => Stop();
}
