using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Foreman.Core.Ipc;
using Foreman.Core.Notifications;
using Foreman.EtwSidecar;
using Microsoft.Diagnostics.Tracing.Session;

// TraceBrake elevated sidecar (capture-only). The ONLY elevated component.
//   Usage: Foreman.EtwSidecar --pipe <name> --nonce <token> --parent <pid>
//          [--capture-net] [--audit-decoys <pathsFile>] [--wake-requests]
// It connects to the app's local pipe, proves itself with the nonce, then streams self-describing JSON
// frames: per-PID network byte rates (--capture-net) and/or decoy-credential read alerts (--audit-decoys).
// It exits when the pipe breaks or the parent exits, and on the way out reverts every SACL / audit-policy
// change it made — so nothing privileged (and no system change) lingers.

return Run(args);

static int Run(string[] args)
{
    string? pipeName = null, nonce = null, decoyFile = null;
    var parentPid = 0;
    var captureNet = false;
    var wakeRequests = false;
    for (var i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "--pipe":         pipeName = Next(args, ref i); break;
            case "--nonce":        nonce = Next(args, ref i); break;
            case "--parent":       _ = int.TryParse(Next(args, ref i), out parentPid); break;
            case "--audit-decoys": decoyFile = Next(args, ref i); break;
            case "--capture-net":  captureNet = true; break;
            case "--wake-requests": wakeRequests = true; break;
        }
    }

    if (string.IsNullOrEmpty(pipeName) || string.IsNullOrEmpty(nonce)) return 2;   // bad args
    if (TraceEventSession.IsElevated() != true) return 3;                          // must be admin

    // We're elevated — register TraceBrake's Windows Event Log source (one-time, admin-only) so the non-elevated
    // main app can emit its blackbox-handoff entries. Best-effort: never let this break the sidecar's real job.
    TryRegisterEventSource();

    NetworkCapture? capture = null;
    DecoyAudit? decoyAudit = null;
    try
    {
        if (captureNet)
        {
            capture = new NetworkCapture();
            capture.Start();
        }

        if (!string.IsNullOrEmpty(decoyFile) && File.Exists(decoyFile))
        {
            var paths = File.ReadAllLines(decoyFile)
                .Select(l => l.Trim()).Where(l => l.Length > 0).ToArray();
            decoyAudit = new DecoyAudit(paths, [parentPid, Environment.ProcessId]);
            _ = decoyAudit.Start();   // armed count is reported after handshake, including partial/failed arming
        }

        if (capture is null && decoyAudit is null && !wakeRequests) return 6;   // nothing to do

        using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.Out);
        try { pipe.Connect(5000); }
        catch { return 4; }

        using var writer = new StreamWriter(pipe, new UTF8Encoding(false)) { AutoFlush = true };
        try { writer.WriteLine(nonce); }   // handshake
        catch { return 5; }

        if (decoyAudit is not null && !TryWrite(writer, new DecoyAuditStatusMessage
        {
            TimestampUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            ExpectedCount = decoyAudit.ExpectedCount,
            ArmedCount = decoyAudit.ArmedCount,
        })) return 5;

        var parent = SafeGetProcess(parentPid);
        var clock = Stopwatch.StartNew();
        var interval = TimeSpan.FromMilliseconds(1000);
        var nextWakeRead = DateTimeOffset.MinValue;

        while (pipe.IsConnected)
        {
            Thread.Sleep(interval);
            if (parent is { HasExited: true }) break;

            // Decoy reads first (latency-sensitive).
            if (decoyAudit is not null)
            {
                var stop = false;
                foreach (var hit in decoyAudit.Drain())
                    if (!TryWrite(writer, hit)) { stop = true; break; }
                if (stop) break;
            }

            // Network rates.
            if (capture is not null)
            {
                var elapsed = clock.Elapsed.TotalSeconds;
                clock.Restart();
                if (elapsed <= 0.1) continue;

                var drained = capture.DrainAndReset();
                var msg = new NetworkRatesMessage { TimestampUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() };
                foreach (var (pid, bytes) in drained)
                    msg.Rates[pid] = bytes / elapsed;
                if (!TryWrite(writer, msg)) break;
            }

            if (wakeRequests && DateTimeOffset.UtcNow >= nextWakeRead)
            {
                nextWakeRead = DateTimeOffset.UtcNow.AddSeconds(5);
                var snapshot = WakeRequestProbe.Read();
                var msg = new WakeRequestsMessage
                {
                    TimestampUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    Available = snapshot.Available,
                    Error = snapshot.Error,
                    Requests = snapshot.Requests.ToList(),
                };
                if (!TryWrite(writer, msg)) break;
            }
        }

        return 0;
    }
    finally
    {
        decoyAudit?.Dispose();   // removes SACLs + reverts auditpol
        capture?.Dispose();
    }
}

static bool TryWrite<T>(StreamWriter writer, T message)
{
    try { writer.WriteLine(JsonSerializer.Serialize(message)); return true; }
    catch { return false; }   // pipe gone — app exited
}

static string? Next(string[] args, ref int i) => i + 1 < args.Length ? args[++i] : null;

// One-time registration of TraceBrake's Windows Event Log source (needs admin — which we are). Harmless if it
// already exists; swallowed on any failure so the sidecar's capture/audit duties are never affected.
static void TryRegisterEventSource()
{
    try
    {
        if (!EventLog.SourceExists(OsEventLogNames.SourceName))
            EventLog.CreateEventSource(new EventSourceCreationData(OsEventLogNames.SourceName, OsEventLogNames.LogName));
    }
    catch { /* event-source registration is best-effort, never fatal */ }
}

static Process? SafeGetProcess(int pid)
{
    if (pid <= 0) return null;
    try { return Process.GetProcessById(pid); }
    catch { return null; }
}
