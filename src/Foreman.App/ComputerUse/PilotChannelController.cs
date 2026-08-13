using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Foreman.Core.ComputerUse;
using Foreman.Core.Events;
using Foreman.Core.Models;

namespace Foreman.App.ComputerUse;

/// <summary>
/// Launches and supervises the Local Agent Host PILOT shim (<c>Foreman.CuPilot.exe</c>) over HOP A - the duplex
/// owner-only control pipe to the broker-reaching shim. This is the SAME launch-bound trust spine as
/// <see cref="DesktopCuController"/> (the spec chose to reuse it verbatim): the shim is TraceBrake's OWN signed binary,
/// launched by Foreman, so the connecting client must clear the integrity + identity + knowledge gates before any
/// frame is trusted - a same-user attacker cannot be the launched, signed, PID-pinned process. L3 is relay-free /
/// capture-free / input-free (the shim only does Hello/Heartbeat); the agent channel (HOP B) + DriverSubmit relay
/// land in L4. Off by default behind <c>CuDriverHostEnabled</c>.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PilotChannelController : IDisposable
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(5);

    private readonly object _gate = new();
    private CancellationTokenSource? _cts;
    private NamedPipeServerStream? _pipe;
    private StreamReader? _reader;
    private StreamWriter? _writer;
    private readonly SemaphoreSlim _io = new(1, 1);
    private volatile bool _connected;
    private volatile Process? _child;
    private string _nonce = string.Empty;

    public bool IsRunning { get; private set; }
    public bool IsConnected => _connected;

    public Action<ForemanSeverity, string>? OnSecurityNotice { get; set; }

    /// <summary>The operator-configured local agent the shim launches for HOP B, or null to run HOP A only. App-set
    /// (never agent-supplied); arming the host is presence-gated upstream (INV-16).</summary>
    public StartAgentArgs? AgentSpec { get; set; }

    /// <summary>Raised for each relayed agent proposal, already rebuilt as a TRUSTED CuAction (App-set Desktop +
    /// local-agent-host id, reserved/auditor-descriptor keys stripped per INV-12). The App audits + submits it
    /// in-process (the broker submit is wired in L5); in L4 the App just surfaces it.</summary>
    public Action<CuAction>? OnDriverSubmit { get; set; }

    /// <summary>The staged pilot shim path (under the app dir, beside TraceBrake's own binaries).</summary>
    public static string PilotPath() => Path.Combine(AppContext.BaseDirectory, "cu-pilot", "Foreman.CuPilot.exe");

    /// <summary>Hold a write/delete-denying handle on the staged shim for the App's whole lifetime so a same-user
    /// process cannot swap it AT REST (same safeguard as the injector sidecar; primary integrity anchor on unsigned
    /// dev builds). The App calls this once at startup regardless of CuDriverHostEnabled. Null if not installed.</summary>
    public static FileStream? PinBinaryAtRest()
    {
        try
        {
            var exe = PilotPath();
            return File.Exists(exe) ? new FileStream(exe, FileMode.Open, FileAccess.Read, FileShare.Read) : null;
        }
        catch { return null; }
    }

    public void Start()
    {
        lock (_gate)
        {
            if (IsRunning) return;
            IsRunning = true;
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
            _cts?.Cancel();
            try { _pipe?.Dispose(); } catch { }
            _pipe = null;
        }
    }

    /// <summary>Hard-kill the live shim IMMEDIATELY (the panic floor's KillPilotNow step - drops HOP B with it),
    /// independent of the normal teardown path. Returns true if a live shim was killed. Never throws.</summary>
    public bool KillPilotNow()
    {
        _connected = false;
        var child = _child;
        var killed = false;
        try { if (child is { HasExited: false }) { child.Kill(); killed = true; } } catch { }
        try { _cts?.Cancel(); } catch { }
        return killed;
    }

    private async Task RunAsync(CancellationTokenSource cts)
    {
        var ct = cts.Token;
        var pipeName = "foreman-pilot-" + Guid.NewGuid().ToString("N");
        _nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

        FileStream? exeLock = null;
        Process? child = null;
        try
        {
            var exe = PilotPath();
            if (!File.Exists(exe)) { Notice(ForemanSeverity.Low, "Local Agent Host pilot shim is not installed."); return; }

            try { exeLock = new FileStream(exe, FileMode.Open, FileAccess.Read, FileShare.Read); }
            catch { Notice(ForemanSeverity.High, "Could not lock the pilot shim for launch (in use?)."); return; }

            var (trusted, reason) = SidecarIntegrity.Verify(exe);
            if (!trusted)
            {
                Notice(ForemanSeverity.High,
                    $"Refused to launch the pilot shim - {reason} The binary may have been tampered with.");
                return;
            }
            if (!SidecarIntegrity.SelfIsSigned())
                Notice(ForemanSeverity.Low,
                    "Pilot shim Authenticode is NOT enforced on this unsigned (dev) build - the at-rest binary lock " +
                    "is the active integrity safeguard. Use a signed build for the full guarantee.");

            using var server = CreateOwnerOnlyDuplexPipe(pipeName);
            _pipe = server;

            child = LaunchPilot(exe, pipeName, _nonce);
            if (child is null) { Notice(ForemanSeverity.Low, "Pilot shim failed to start."); return; }
            _child = child;

            using (var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                connectCts.CancelAfter(ConnectTimeout);
                try { await server.WaitForConnectionAsync(connectCts.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    Notice(ForemanSeverity.Low, "Pilot shim did not connect in time - abandoning launch.");
                    return;
                }
            }

            if (!VerifyClientIdentity(server, child, exe, out var idReason))
            {
                Notice(ForemanSeverity.High, $"Rejected a process impersonating the pilot shim ({idReason}).");
                return;
            }

            var reader = new StreamReader(server, new UTF8Encoding(false));
            var writer = new StreamWriter(server, new UTF8Encoding(false)) { AutoFlush = true };

            var challenge = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            using (var hsCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                hsCts.CancelAfter(RequestTimeout);
                try
                {
                    await writer.WriteLineAsync(challenge.AsMemory(), hsCts.Token).ConfigureAwait(false);
                    var presented = await reader.ReadLineAsync(hsCts.Token).ConfigureAwait(false);
                    if (!CuHandshake.Verify(_nonce, CuHandshake.HandshakeMessage(challenge), presented))
                    {
                        Notice(ForemanSeverity.High, "Pilot shim failed the nonce challenge-response - dropped.");
                        return;
                    }
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    Notice(ForemanSeverity.Low, "Pilot shim did not complete the handshake in time - dropped.");
                    return;
                }
            }

            _reader = reader;
            _writer = writer;
            _connected = true;

            var hello = await SendAsync(new DesktopCuRequest(NewId(), DesktopCuKind.Hello), ct).ConfigureAwait(false);
            if (hello is not { Ok: true })
                Notice(ForemanSeverity.Low, "Pilot shim connected but did not acknowledge Hello.");

            // L4: have the shim launch the operator-configured local agent for HOP B (the agent connects to the shim,
            // never to the App; we only POLL the shim for the agent's relayed proposals over HOP A).
            if (AgentSpec is { } spec)
            {
                var started = await SendAsync(new DesktopCuRequest(NewId(), DesktopCuKind.StartAgent,
                    B64(JsonSerializer.Serialize(spec, CuJson.Options))), ct).ConfigureAwait(false);
                if (started is not { Ok: true })
                    Notice(ForemanSeverity.Low, $"Pilot shim could not start the local agent: {started?.Error ?? "no response"}.");
            }

            var ticks = 0;
            while (!ct.IsCancellationRequested && server.IsConnected)
            {
                await Task.Delay(400, ct).ConfigureAwait(false);

                // Poll the agent's proposals; rebuild each as a TRUSTED CuAction (INV-12) and hand it to the App.
                var poll = await SendAsync(new DesktopCuRequest(NewId(), DesktopCuKind.PollDriverSubmits), ct).ConfigureAwait(false);
                if (poll is not { Ok: true }) break;
                if (poll.PayloadB64 is { } pb && OnDriverSubmit is { } sink)
                {
                    try
                    {
                        var batch = JsonSerializer.Deserialize<DriverSubmitBatch>(
                            Encoding.UTF8.GetString(Convert.FromBase64String(pb)), CuJson.Options);
                        if (batch?.Items is { Count: > 0 } items)
                            foreach (var sub in items) { try { sink(LocalDriverIpc.BuildAction(sub)); } catch { } }
                    }
                    catch { /* a malformed batch is not fatal - the channel stays up */ }
                }

                if (++ticks % 5 == 0)   // ~ every 2s: liveness heartbeat
                {
                    var beat = await SendAsync(new DesktopCuRequest(NewId(), DesktopCuKind.Heartbeat), ct).ConfigureAwait(false);
                    if (beat is not { Ok: true }) break;
                }
            }
        }
        catch (OperationCanceledException) { }
        catch { /* pipe/launch failure -> the agent host simply stays unavailable */ }
        finally
        {
            _connected = false;
            _child = null;
            try { if (child is { HasExited: false }) child.Kill(); } catch { }
            try { child?.Dispose(); } catch { }
            try { exeLock?.Dispose(); } catch { }
            lock (_gate) { if (ReferenceEquals(_cts, cts)) IsRunning = false; }
        }
    }

    /// <summary>Send one request and return the shim's authenticated response (null on any failure or timeout).</summary>
    public async Task<DesktopCuResponse?> SendAsync(DesktopCuRequest req, CancellationToken ct = default)
    {
        var reader = _reader;
        var writer = _writer;
        if (reader is null || writer is null) return null;

        await _io.WaitAsync(ct).ConfigureAwait(false);
        using var opCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        opCts.CancelAfter(RequestTimeout);
        try
        {
            await writer.WriteLineAsync(JsonSerializer.Serialize(req, CuJson.Options).AsMemory(), opCts.Token).ConfigureAwait(false);
            var line = await reader.ReadLineAsync(opCts.Token).ConfigureAwait(false);
            if (line is null) { _connected = false; return null; }

            var resp = JsonSerializer.Deserialize<DesktopCuResponse>(line, CuJson.Options);
            if (resp is null) { _connected = false; return null; }

            var expectMac = CuJson.ResponseMac(resp.Kind, resp.RequestId, resp.Ok, resp.Error, resp.PayloadB64);
            if (resp.RequestId != req.RequestId || !CuHandshake.Verify(_nonce, expectMac, resp.Hmac))
            {
                Notice(ForemanSeverity.High, "Discarded an unauthenticated pilot shim response frame.");
                _connected = false;
                return null;
            }
            return resp;
        }
        catch { _connected = false; return null; }
        finally { _io.Release(); }
    }

    // Identity gate (INV-6/INV-13 HOP A): the connected client must BE the child we launched, parented to Foreman,
    // from our signed exe. Identical to DesktopCuController.VerifyClientIdentity.
    private bool VerifyClientIdentity(NamedPipeServerStream server, Process child, string exe, out string reason)
    {
        reason = string.Empty;
        if (!GetNamedPipeClientProcessId(server.SafePipeHandle.DangerousGetHandle(), out var clientPid) || clientPid == 0)
        { reason = "no client PID"; return false; }

        if ((int)clientPid != child.Id) { reason = $"client PID {clientPid} != launched {child.Id}"; return false; }

        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, clientPid);
        if (h == IntPtr.Zero) { reason = "could not open client process"; return false; }
        try
        {
            var img = QueryImagePath(h);
            if (string.IsNullOrEmpty(img) ||
                !string.Equals(Path.GetFullPath(img), Path.GetFullPath(exe), StringComparison.OrdinalIgnoreCase))
            { reason = "client image is not the verified pilot shim"; return false; }

            if (!TryGetParentPid(h, out var ppid) || ppid != Environment.ProcessId)
            { reason = $"client parent {ppid} != TraceBrake {Environment.ProcessId}"; return false; }

            var (trusted, why) = SidecarIntegrity.Verify(img);
            if (!trusted) { reason = $"connected image failed integrity: {why}"; return false; }
        }
        catch (Exception ex) { reason = "could not inspect client image: " + ex.Message; return false; }
        finally { CloseHandle(h); }

        return true;
    }

    private static NamedPipeServerStream CreateOwnerOnlyDuplexPipe(string name)
    {
        var me = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("No current Windows user SID.");
        var security = new PipeSecurity();
        security.SetOwner(me);
        security.AddAccessRule(new PipeAccessRule(me, PipeAccessRights.FullControl, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(
            name, PipeDirection.InOut, maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous,
            inBufferSize: 0, outBufferSize: 0, security);
    }

    private Process? LaunchPilot(string exe, string pipeName, string nonce)
    {
        try
        {
            var psi = new ProcessStartInfo(exe)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(exe) ?? AppContext.BaseDirectory,
            };
            psi.ArgumentList.Add("--pipe");   psi.ArgumentList.Add(pipeName);
            psi.ArgumentList.Add("--nonce");  psi.ArgumentList.Add(nonce);
            psi.ArgumentList.Add("--parent"); psi.ArgumentList.Add(Environment.ProcessId.ToString());
            return Process.Start(psi);
        }
        catch { return null; }
    }

    private void Notice(ForemanSeverity sev, string message)
    {
        try { OnSecurityNotice?.Invoke(sev, message); } catch { }
        try { EventBus.Instance.Publish(new MonitoringNoticeEvent(DateTimeOffset.UtcNow, sev, "Foreman.CuPilot", message)); }
        catch { }
    }

    private static string NewId() => Guid.NewGuid().ToString("N");

    private static string B64(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s));

    private static string? QueryImagePath(IntPtr hProcess)
    {
        var sb = new StringBuilder(1024);
        var size = sb.Capacity;
        return QueryFullProcessImageName(hProcess, 0, sb, ref size) ? sb.ToString() : null;
    }

    private static bool TryGetParentPid(IntPtr hProcess, out int parentPid)
    {
        parentPid = 0;
        var pbi = default(PROCESS_BASIC_INFORMATION);
        if (NtQueryInformationProcess(hProcess, 0, ref pbi, Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _) != 0)
            return false;
        parentPid = (int)pbi.InheritedFromUniqueProcessId.ToUInt64();
        return true;
    }

    private const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, int flags, StringBuilder exeName, ref int size);

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public UIntPtr UniqueProcessId;
        public UIntPtr InheritedFromUniqueProcessId;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr handle, int infoClass, ref PROCESS_BASIC_INFORMATION pbi, int size, out int returnLength);

    public void Dispose() { Stop(); _io.Dispose(); }
}
