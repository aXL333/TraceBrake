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
/// Launches and supervises the medium-IL desktop computer-use sidecar (<c>Foreman.CuSidecar.exe</c>) and owns the
/// duplex control pipe to it. Unlike the elevated ETW sidecar, this one runs at the SAME integrity as TraceBrake - CU
/// needs isolation (one auditable input source), never elevation.
///
/// Trust rebuild (spec INV-6): because the sidecar is same-user / same-IL, the elevation test that guards the ETW
/// pipe does not apply. Instead the connecting client must clear THREE gates before any frame is trusted:
///   1. Integrity:   the exe carries TraceBrake's Authenticode signature, verified under a write/delete-denying handle
///                   held across verify -> launch, and re-verified against the connected image. On UNSIGNED dev
///                   builds the signer match is waived (no trust anchor exists), so the binary is additionally held
///                   write/delete-locked AT REST for the whole app lifetime (<see cref="PinBinaryAtRest"/>) to stop a
///                   same-user swap while the (off-by-default) feature is disabled.
///   2. Identity:    the pipe's client PID equals the PID we launched, its parent is Foreman, and its kernel image
///                   path (QueryFullProcessImageName, not the flaky module list) is that exe.
///   3. Knowledge:   challenge-response - we send a random challenge, it returns HMAC(nonce, handshake-tagged
///                   challenge). A nonce scraped from our command line is useless on a new connection because gate 2
///                   pins the PID.
/// Off by default; the App starts it only when <c>CuDesktopEnabled</c> is set. Slice 3 is capture-free / input-free.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DesktopCuController : IDisposable
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
    private volatile Process? _child;   // the live sidecar, exposed for the panic floor's hard kill
    private string _nonce = string.Empty;

    public bool IsRunning { get; private set; }
    public bool IsConnected => _connected;

    /// <summary>Raised High when a process tried to impersonate the sidecar or the integrity check failed.</summary>
    public Action<ForemanSeverity, string>? OnSecurityNotice { get; set; }

    /// <summary>The shared panic/bind map the App owns and the sidecar reads (read-only). REQUIRED to run desktop CU -
    /// the App hands the sidecar a read-only duplicated handle to it after the handshake. Set by the App at wiring.</summary>
    public CuSharedPanicFlag? PanicFlag { get; set; }

    /// <summary>Raised when an ExecuteAction result FAILED independent verification (INV-5) - the App should escalate to
    /// a full panic halt. The controller already hard-kills the offending sidecar locally before raising this.</summary>
    public Action? OnVerificationFailure { get; set; }

    /// <summary>The staged sidecar path (under the app dir, beside TraceBrake's own binaries).</summary>
    public static string SidecarPath() => Path.Combine(AppContext.BaseDirectory, "cu-sidecar", "Foreman.CuSidecar.exe");

    /// <summary>
    /// Hold a write/delete-denying handle on the staged sidecar for the App's WHOLE lifetime so a same-user process
    /// cannot swap it AT REST. This is the primary integrity safeguard on unsigned/dev builds (where
    /// <see cref="SidecarIntegrity"/> waives the signer match): without it the sidecar exe sits unlocked whenever the
    /// off-by-default feature is disabled, and a swapped-in binary would be launched and pass all three handshake
    /// gates (it would be the PID we launched, parented to us, and the nonce rides its own argv). On signed builds it
    /// is defense-in-depth. The App calls this ONCE at startup regardless of CuDesktopEnabled and holds the handle
    /// until exit. Returns null if the sidecar is not installed (or already locked by a prior instance).
    /// </summary>
    public static FileStream? PinBinaryAtRest()
    {
        try
        {
            var exe = SidecarPath();
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

    /// <summary>Hard-kill the live sidecar IMMEDIATELY (the panic floor's INV-3 TerminateProcess step) - independent of
    /// the normal cancel/teardown path, so a halt does not wait on the pipe or the heartbeat loop. Marks the channel
    /// dead and cancels the run so it does not relaunch. Returns true if a live sidecar was killed. Never throws.</summary>
    public bool KillSidecarNow()
    {
        _connected = false;
        var child = _child;
        var killed = false;
        try { if (child is { HasExited: false }) { child.Kill(); killed = true; } } catch { }
        try { _cts?.Cancel(); } catch { }   // stop the run loop; finally reaps/disposes
        return killed;
    }

    private async Task RunAsync(CancellationTokenSource cts)
    {
        var ct = cts.Token;
        var pipeName = "foreman-cu-" + Guid.NewGuid().ToString("N");
        _nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

        // A short-lived write/delete lock across verify -> launch (the at-rest lock the App also holds for life is the
        // primary defense; this one closes the verify->launch window precisely).
        FileStream? exeLock = null;
        Process? child = null;
        try
        {
            var exe = SidecarPath();
            if (!File.Exists(exe)) { Notice(ForemanSeverity.Low, "Desktop CU sidecar is not installed."); return; }

            try { exeLock = new FileStream(exe, FileMode.Open, FileAccess.Read, FileShare.Read); }
            catch { Notice(ForemanSeverity.High, "Could not lock the desktop CU sidecar for launch (in use?)."); return; }

            var (trusted, reason) = SidecarIntegrity.Verify(exe);
            if (!trusted)
            {
                Notice(ForemanSeverity.High,
                    $"Refused to launch the desktop CU sidecar - {reason} The binary may have been tampered with.");
                return;
            }
            if (!SidecarIntegrity.SelfIsSigned())
                Notice(ForemanSeverity.Low,
                    "Desktop CU sidecar Authenticode is NOT enforced on this unsigned (dev) build - the at-rest binary " +
                    "lock is the active integrity safeguard. Use a signed build for the full guarantee.");

            using var server = CreateOwnerOnlyDuplexPipe(pipeName);
            _pipe = server;

            child = LaunchSidecar(exe, pipeName, _nonce);
            if (child is null) { Notice(ForemanSeverity.Low, "Desktop CU sidecar failed to start."); return; }
            _child = child;   // publish for the panic floor's hard kill

            // Bound the wait: a sidecar launched then immediately SUSPENDED by a hostile same-user process must not
            // wedge us forever holding exeLock + the sole pipe instance.
            using (var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                connectCts.CancelAfter(ConnectTimeout);
                try { await server.WaitForConnectionAsync(connectCts.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    Notice(ForemanSeverity.Low, "Desktop CU sidecar did not connect in time - abandoning launch.");
                    return;
                }
            }

            if (!VerifyClientIdentity(server, child, exe, out var idReason))
            {
                Notice(ForemanSeverity.High, $"Rejected a process impersonating the desktop CU sidecar ({idReason}).");
                return;
            }

            var reader = new StreamReader(server, new UTF8Encoding(false));
            var writer = new StreamWriter(server, new UTF8Encoding(false)) { AutoFlush = true };

            // Challenge-response: prove the client holds the nonce without it ever crossing the wire (domain-tagged),
            // under a deadline so a suspended peer can't stall the handshake forever.
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
                        Notice(ForemanSeverity.High, "Desktop CU sidecar failed the nonce challenge-response - dropped.");
                        return;
                    }
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    Notice(ForemanSeverity.Low, "Desktop CU sidecar did not complete the handshake in time - dropped.");
                    return;
                }
            }

            _reader = reader;
            _writer = writer;
            _connected = true;

            // Hand the sidecar a READ-ONLY duplicated handle to the shared panic/bind map (INV-2/INV-3): it reads
            // panic/boundHwnd itself before every input (Slice 4b). The map is unnamed, so ONLY this duplicated
            // read-only handle can reach it - no same-user process can open it, and the sidecar cannot write it.
            if (PanicFlag is null)
            { Notice(ForemanSeverity.High, "No shared panic map wired - refusing to run desktop CU."); return; }

            long panicHandle;
            try { panicHandle = PanicFlag.DuplicateReadOnlyHandleInto(child.Handle); } catch { panicHandle = 0; }
            if (panicHandle == 0)
            { Notice(ForemanSeverity.High, "Could not hand the sidecar its read-only panic map - dropping the channel."); return; }

            var helloPayload = B64(JsonSerializer.Serialize(new HelloArgs(panicHandle, PanicFlag.MapCapacity), CuJson.Options));
            var hello = await SendAsync(new DesktopCuRequest(NewId(), DesktopCuKind.Hello, helloPayload), ct).ConfigureAwait(false);
            if (hello is not { Ok: true })
            { Notice(ForemanSeverity.High, "Desktop CU sidecar could not map the shared panic view - dropping the channel."); return; }
            CrossCheckSnapshot(hello, "hello");   // confirm it reads what we wrote (INV-5 substrate)

            while (!ct.IsCancellationRequested && server.IsConnected)
            {
                await Task.Delay(2000, ct).ConfigureAwait(false);
                var beat = await SendAsync(new DesktopCuRequest(NewId(), DesktopCuKind.Heartbeat), ct).ConfigureAwait(false);
                if (beat is not { Ok: true }) break;   // sidecar gone / unauthenticated / timed out

                // Tamper canary: the App's own panic byte must never change except when the App writes it.
                if (PanicFlag.DetectTamper())
                {
                    Notice(ForemanSeverity.Critical,
                        "Shared panic map tampered (the App's own byte changed by another writer) - killing the desktop CU sidecar.");
                    break;
                }
                CrossCheckSnapshot(beat, "heartbeat");
            }
        }
        catch (OperationCanceledException) { }
        catch { /* pipe/launch failure -> desktop CU simply stays unavailable */ }
        finally
        {
            _connected = false;
            _child = null;
            // Reap the child on ANY exit (cancel, timeout, reject, pipe break, normal stop). Its parent (the App) is
            // still alive, so it would NOT self-exit on parent death - it would orphan as a stranded medium-IL process.
            try { if (child is { HasExited: false }) child.Kill(); } catch { }
            try { child?.Dispose(); } catch { }
            try { exeLock?.Dispose(); } catch { }
            lock (_gate) { if (ReferenceEquals(_cts, cts)) IsRunning = false; }
        }
    }

    /// <summary>Send one request and return the sidecar's authenticated response (null on any failure or timeout).</summary>
    public async Task<DesktopCuResponse?> SendAsync(DesktopCuRequest req, CancellationToken ct = default)
    {
        var reader = _reader;
        var writer = _writer;
        if (reader is null || writer is null) return null;

        await _io.WaitAsync(ct).ConfigureAwait(false);
        // Per-request deadline so a wedged/suspended peer cannot pin the single _io permit (and every later control
        // frame) forever. On any failure we mark the channel dead so IsConnected stops lying.
        using var opCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        opCts.CancelAfter(RequestTimeout);
        try
        {
            await writer.WriteLineAsync(JsonSerializer.Serialize(req, CuJson.Options).AsMemory(), opCts.Token).ConfigureAwait(false);
            var line = await reader.ReadLineAsync(opCts.Token).ConfigureAwait(false);
            if (line is null) { _connected = false; return null; }

            var resp = JsonSerializer.Deserialize<DesktopCuResponse>(line, CuJson.Options);
            if (resp is null) { _connected = false; return null; }

            // INV-5: authenticate the return channel - a frame whose HMAC does not verify (over id+kind+Ok+Error+
            // payload) is not from our sidecar.
            var expectMac = CuJson.ResponseMac(resp.Kind, resp.RequestId, resp.Ok, resp.Error, resp.PayloadB64);
            if (resp.RequestId != req.RequestId || !CuHandshake.Verify(_nonce, expectMac, resp.Hmac))
            {
                Notice(ForemanSeverity.High, "Discarded an unauthenticated desktop CU response frame.");
                _connected = false;
                return null;
            }
            return resp;
        }
        catch { _connected = false; return null; }   // timeout / pipe break / cancel -> the channel is dead
        finally { _io.Release(); }
    }

    private const int CursorTolerance = 8;   // px slack for the cursor cross-check (operator may nudge it mid round-trip)

    /// <summary>Execute one desktop gesture through the sidecar and INDEPENDENTLY verify the result (INV-5). The App
    /// re-reads GetForegroundWindow itself: the sidecar's self-reported FinalHwnd must match what the App observes, or
    /// the input did not land where the sidecar claims (or the foreground changed) - either way the result is rejected,
    /// the offending sidecar is hard-killed, and OnVerificationFailure fires so the App escalates to a full halt. The
    /// cursor position is cross-checked with tolerance (soft). Returns null if desktop CU is unavailable.</summary>
    public async Task<ExecuteActionResult?> ExecuteAsync(ExecuteActionArgs args, CancellationToken ct = default)
    {
        if (!_connected) return null;
        var bound = PanicFlag?.BoundHwnd ?? 0;
        // INV-2: the action must target the window it was APPROVED against. If the operator re-bound the CU window
        // between approval/Claim and now, args.BoundHwnd (the approved-against window) no longer matches the live bound
        // window - refuse rather than redirect the action into the freshly-bound window. (The injector's per-input
        // snap.BoundHwnd != args.BoundHwnd check is the mid-gesture backstop; this catches the pre-injection window.)
        if (bound == 0 || args.BoundHwnd != bound)
        {
            Notice(ForemanSeverity.High,
                $"Desktop CU action's bound window changed since approval (action={args.BoundHwnd}, bound now={bound}) - refusing (INV-2).");
            return new ExecuteActionResult(false, "bound window changed since approval (INV-2)");
        }
        var payload = B64(JsonSerializer.Serialize(args, CuJson.Options));
        var resp = await SendAsync(new DesktopCuRequest(NewId(), DesktopCuKind.ExecuteAction, payload), ct).ConfigureAwait(false);

        // A null result means the App stopped waiting (timeout / dead channel) while the sidecar may STILL be injecting
        // the rest of the gesture - exactly when the hard floor must fire. Do not silently leave a live injector.
        if (resp is null)
        {
            Notice(ForemanSeverity.High, "Desktop CU action did not return in time - hard-killing the sidecar and halting (INV-5).");
            KillSidecarNow();
            try { OnVerificationFailure?.Invoke(); } catch { }
            return null;
        }

        // INV-19: re-check the tamper canary on EVERY round-trip, not just the 2s heartbeat - the App's own panic/bind
        // bytes must never have changed except when the App wrote them. A divergence mid-action means another writer
        // (PROCESS_VM_WRITE / handle-dup residual) touched the map: kill + halt before trusting any result.
        if (PanicFlag is { } pf && pf.DetectTamper())
        {
            Notice(ForemanSeverity.Critical,
                "Shared panic map tampered during a desktop CU action - hard-killing the sidecar and halting (INV-19).");
            KillSidecarNow();
            try { OnVerificationFailure?.Invoke(); } catch { }
            return new ExecuteActionResult(false, "panic map tampered mid-action (INV-19)");
        }

        ExecuteActionResult? result;
        try
        {
            result = resp.PayloadB64 is null ? null
                : JsonSerializer.Deserialize<ExecuteActionResult>(
                    Encoding.UTF8.GetString(Convert.FromBase64String(resp.PayloadB64)), CuJson.Options);
        }
        catch { result = null; }
        if (result is null) return new ExecuteActionResult(false, "no ExecuteAction result payload");

        // INV-5: independently verify against the AUTHORITATIVE bound window - never the sidecar's self-reported value,
        // and never merely "whatever the foreground happens to be". On a claimed success the foreground the App reads
        // ITSELF must be the bound window AND the sidecar's FinalHwnd must agree. (A legit refusal, Ok=false, is left as
        // a refusal - it has not landed harmful input; the compromised-injector inject-then-Ok=false case is closed by
        // the floor + the 4b-3 foreground-lock, not by killing every refusal.)
        if (result.Ok)
        {
            var fg = GetForegroundWindow().ToInt64();
            GetCursorPos(out var pt);
            if (bound == 0 || fg != bound || result.FinalHwnd != bound)
            {
                Notice(ForemanSeverity.High,
                    $"Desktop CU result FAILED independent verification (bound={bound}, sidecar FinalHwnd={result.FinalHwnd}, " +
                    $"App foreground={fg}) - hard-killing the sidecar and halting (INV-5).");
                KillSidecarNow();
                try { OnVerificationFailure?.Invoke(); } catch { }
                return new ExecuteActionResult(false, "result failed independent verification (INV-5)");
            }
            if (Math.Abs(result.CursorX - pt.X) > CursorTolerance || Math.Abs(result.CursorY - pt.Y) > CursorTolerance)
                Notice(ForemanSeverity.Medium,
                    $"Desktop CU cursor self-report ({result.CursorX},{result.CursorY}) drifted from observed ({pt.X},{pt.Y}).");
        }
        else if (result.HaltedMidStream)
        {
            Notice(ForemanSeverity.Low, "Desktop CU action aborted mid-stream by panic (sidecar honored the halt).");
        }
        return result;
    }

    // Identity gate (INV-6 #2): the connected client must BE the child we launched, parented to Foreman, from our exe.
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
            // Image path from the kernel (QueryFullProcessImageName) - NOT Process.MainModule, which can throw/return
            // null across bitness, during fast startup, or under AV contention and would fail-close a genuine sidecar.
            var img = QueryImagePath(h);
            if (string.IsNullOrEmpty(img) ||
                !string.Equals(Path.GetFullPath(img), Path.GetFullPath(exe), StringComparison.OrdinalIgnoreCase))
            { reason = "client image is not the verified sidecar"; return false; }

            // Parent must be TraceBrake (spec INV-6) - defense in depth behind the PID pin.
            if (!TryGetParentPid(h, out var ppid) || ppid != Environment.ProcessId)
            { reason = $"client parent {ppid} != TraceBrake {Environment.ProcessId}"; return false; }

            // Re-verify the running image's backing file (belt-and-suspenders against a swap between launch and connect).
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

    private Process? LaunchSidecar(string exe, string pipeName, string nonce)
    {
        try
        {
            // asInvoker manifest -> UseShellExecute=false (no UAC), and we get the real PID for the identity pin.
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
        try
        {
            EventBus.Instance.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow, sev, "Foreman.CuSidecar", message));
        }
        catch { }
    }

    private static string NewId() => Guid.NewGuid().ToString("N");

    private static string B64(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s));

    // INV-5 substrate check: confirm the sidecar reads the SAME panic byte the App wrote through the read-only map.
    // In Slice 4a this is informational (no input to stop yet, and a single-frame skew can be read timing); Slice 4b
    // enforces it with panic-epoch reasoning. A persistent "App halted but sidecar still sees running" is the case to
    // watch. DetectTamper (the App's own byte changing) is the hard, unambiguous failure and is handled by the caller.
    private void CrossCheckSnapshot(DesktopCuResponse resp, string phase)
    {
        try
        {
            if (resp.PayloadB64 is null) return;
            var snap = JsonSerializer.Deserialize<PanicSnapshot>(
                Encoding.UTF8.GetString(Convert.FromBase64String(resp.PayloadB64)), CuJson.Options);
            if (snap is null || PanicFlag is null) return;
            var app = PanicFlag.Snapshot();   // one consistent App tuple (no self-tear across three getters)
            if (snap.Panic != app.Panic || snap.BoundHwnd != app.BoundHwnd || snap.Epoch != app.Epoch)
                Notice(ForemanSeverity.Low,
                    $"Desktop CU sidecar {phase} snapshot (panic={snap.Panic},hwnd={snap.BoundHwnd},epoch={snap.Epoch}) " +
                    $"differs from the App's (panic={app.Panic},hwnd={app.BoundHwnd},epoch={app.Epoch}) - may be read timing. " +
                    "Note: this self-report is NOT trusted as verification; Slice 4b verifies independently (INV-5) + enforces with epochs.");
        }
        catch { /* a bad snapshot frame is not itself a security event in Slice 4a */ }
    }

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

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetCursorPos(out POINT pt);

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT { public int X, Y; }

    public void Dispose() { Stop(); _io.Dispose(); }
}
