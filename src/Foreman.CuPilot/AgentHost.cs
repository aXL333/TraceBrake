using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Foreman.Core.ComputerUse;

/// <summary>
/// HOP B host (L4) inside the Pilot shim. TraceBrake tells the shim to start the operator's agent; the shim LAUNCHES it
/// inside a kill-on-close Job Object (so it dies with the shim even on a hard TerminateProcess), hands it the HOP B
/// pipe name + a per-session secret via the agent's STDIN (an inherited handle - never argv/file), hosts an owner-only
/// duplex pipe, and accepts the agent only if it is the LAUNCHED PID AND answers the secret challenge - RE-LOOPING on
/// any failed accept so a same-user racer cannot consume the single-instance slot. It then queues the agent's
/// DriverSubmit PROPOSALS (bounded) for the App to poll over HOP A. The agent can only PROPOSE.
/// </summary>
internal static class AgentHost
{
    private const int MaxQueue = 512;        // bound the proposal backlog (a flooding agent cannot OOM the shim)
    private const int MaxFrameChars = 65536; // bound a single proposal frame (no giant-line OOM)
    private static readonly TimeSpan AcceptDeadline = TimeSpan.FromSeconds(15);

    private static readonly ConcurrentQueue<DriverSubmit> _queue = new();
    private static readonly object _lock = new();
    private static Process? _agent;
    private static IntPtr _job = IntPtr.Zero;
    private static bool _started;

    /// <summary>Launch the agent (in a kill-on-close Job Object) + host HOP B. Idempotent while running. Never throws.</summary>
    public static bool Start(StartAgentArgs args, out string error)
    {
        error = string.Empty;
        lock (_lock)
        {
            if (_started) { error = "agent already started"; return false; }
            if (string.IsNullOrWhiteSpace(args.Command)) { error = "no agent command configured"; return false; }

            var pipeName = "foreman-agent-" + Guid.NewGuid().ToString("N");
            var secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

            NamedPipeServerStream server;
            try { server = CreateOwnerOnlyDuplexPipe(pipeName); }
            catch (Exception ex) { error = "could not host HOP B pipe: " + ex.Message; return false; }

            // Job Object FIRST, so the agent is in it before it can spawn anything: KILL_ON_JOB_CLOSE means when the
            // shim dies (even via TerminateProcess on panic, which skips managed finally) the kernel reaps the whole
            // agent tree - the untrusted agent can never survive a panic.
            EnsureJob();

            Process agent;
            try
            {
                var psi = new ProcessStartInfo(args.Command)
                {
                    Arguments = args.Arguments ?? string.Empty,
                    WorkingDirectory = string.IsNullOrWhiteSpace(args.WorkingDir) ? string.Empty : args.WorkingDir!,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardInput = true,
                };
                agent = Process.Start(psi) ?? throw new InvalidOperationException("Process.Start returned null");
            }
            catch (Exception ex) { try { server.Dispose(); } catch { } error = "could not launch agent: " + ex.Message; return false; }

            try { if (_job != IntPtr.Zero) AssignProcessToJobObject(_job, agent.Handle); } catch { }

            // Hand the agent its HOP B pipe name + the session secret via STDIN (an inherited handle), then close.
            try
            {
                agent.StandardInput.WriteLine(pipeName);
                agent.StandardInput.WriteLine(secret);
                agent.StandardInput.Flush();
                agent.StandardInput.Close();
            }
            catch { /* if the agent never reads it, accept/verify below fails closed */ }

            _agent = agent;
            _started = true;
            var agentPid = agent.Id;

            var t = new Thread(() => ServeAgent(server, agentPid, secret)) { IsBackground = true, Name = "cu-agent-hopb" };
            t.Start();
            return true;
        }
    }

    private static void ServeAgent(NamedPipeServerStream server, int agentPid, string secret)
    {
        var deadline = DateTimeOffset.UtcNow + AcceptDeadline;
        try
        {
            using (server)
            {
                while (DateTimeOffset.UtcNow < deadline)
                {
                    var remaining = deadline - DateTimeOffset.UtcNow;
                    if (remaining <= TimeSpan.Zero) break;
                    using (var acceptCts = new CancellationTokenSource(remaining))
                    {
                        try { server.WaitForConnectionAsync(acceptCts.Token).GetAwaiter().GetResult(); }
                        catch { break; }   // deadline reached with no valid connection -> give up
                    }

                    if (TryServeConnection(server, agentPid, secret))
                        return;   // the launch-pinned + secret-verified agent connected and was served to completion

                    // A racer / wrong process consumed the accept - DISCONNECT it and RE-LOOP so the real agent still
                    // gets the single-instance slot (a connect race cannot DoS the agent).
                    try { if (server.IsConnected) server.Disconnect(); } catch { }
                }
            }
        }
        catch { /* HOP B failure just means no proposals flow; HOP A + the App stay healthy */ }
        finally
        {
            // Allow a future StartAgent to relaunch once this agent/host is done (closes the one-shot wedge).
            lock (_lock) { _started = false; _agent = null; }
        }
    }

    // Returns true only if the genuine agent (launched PID + correct secret) connected; false => caller re-loops.
    private static bool TryServeConnection(NamedPipeServerStream server, int agentPid, string secret)
    {
        // launch-PID-pin: the connecting client MUST be the agent we launched.
        if (!GetNamedPipeClientProcessId(server.SafePipeHandle.DangerousGetHandle(), out var pid) || (int)pid != agentPid)
            return false;

        // leaveOpen: true so disposing these does NOT close the server (we may need to re-loop on a secret failure).
        using var reader = new StreamReader(server, new UTF8Encoding(false), false, 1024, leaveOpen: true);
        using var writer = new StreamWriter(server, new UTF8Encoding(false), 1024, leaveOpen: true) { AutoFlush = true };

        // Secret challenge-response: the agent proves it read the stdin secret without it crossing the pipe.
        var challenge = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        try { writer.WriteLine(challenge); } catch { return false; }
        string? presented;
        try { presented = ReadBoundedLine(reader); } catch { return false; }
        if (!CuHandshake.Verify(secret, CuHandshake.HandshakeMessage(challenge), presented)) return false;

        // Verified: queue the agent's proposals until it/the pipe closes. Bounded so a flood cannot OOM the shim.
        while (server.IsConnected)
        {
            string? line;
            try { line = ReadBoundedLine(reader); }
            catch { break; }
            if (line is null) break;   // EOF or an over-length (abusive) frame
            DriverSubmit? sub;
            try { sub = JsonSerializer.Deserialize<DriverSubmit>(line, CuJson.Options); }
            catch { continue; }
            if (sub is not null && _queue.Count < MaxQueue) _queue.Enqueue(sub);   // drop beyond the cap (bounded)
        }
        return true;
    }

    // Read one line, bounded to MaxFrameChars; null on EOF OR an over-length frame (treated as abusive -> stop).
    private static string? ReadBoundedLine(StreamReader r)
    {
        var sb = new StringBuilder();
        int ch;
        while ((ch = r.Read()) >= 0)
        {
            if (ch == '\n') return sb.ToString().TrimEnd('\r');
            sb.Append((char)ch);
            if (sb.Length > MaxFrameChars) return null;
        }
        return sb.Length > 0 ? sb.ToString().TrimEnd('\r') : null;
    }

    /// <summary>Drain the queued agent proposals for the App's poll.</summary>
    public static DriverSubmitBatch Drain()
    {
        var list = new List<DriverSubmit>();
        while (_queue.TryDequeue(out var s)) list.Add(s);
        return new DriverSubmitBatch(list);
    }

    /// <summary>Kill the agent (on shim shutdown / parent death). The Job Object is the hard guarantee; this is the
    /// prompt graceful path. Never throws.</summary>
    public static void Stop()
    {
        lock (_lock)
        {
            try { if (_agent is { HasExited: false }) _agent.Kill(entireProcessTree: true); } catch { }
            _started = false; _agent = null;
        }
    }

    private static void EnsureJob()
    {
        if (_job != IntPtr.Zero) return;
        try
        {
            var job = CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero) return;
            var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            var len = Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
            var p = Marshal.AllocHGlobal(len);
            try
            {
                Marshal.StructureToPtr(info, p, false);
                if (SetInformationJobObject(job, JobObjectExtendedLimitInformation, p, (uint)len)) _job = job;
                else CloseHandle(job);
            }
            finally { Marshal.FreeHGlobal(p); }
        }
        catch { /* no job -> Stop()'s explicit kill-tree is the fallback */ }
    }

    private static NamedPipeServerStream CreateOwnerOnlyDuplexPipe(string name)
    {
        var me = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("No current Windows user SID.");
        var security = new PipeSecurity();
        security.SetOwner(me);
        security.AddAccessRule(new PipeAccessRule(me, PipeAccessRights.FullControl, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(
            name, PipeDirection.InOut, maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, inBufferSize: 0, outBufferSize: 0, security);
    }

    // ── Win32 ────────────────────────────────────────────────────────────────────────────────────────
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000;
    private const int JobObjectExtendedLimitInformation = 9;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(IntPtr hJob, int infoClass, IntPtr lpInfo, uint cbInfo);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr h);

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
        public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }
}
