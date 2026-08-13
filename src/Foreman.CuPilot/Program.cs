using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Foreman.Core.ComputerUse;

// TraceBrake Local Agent Host PILOT shim (HOP A; L3: handshake + idle only - relay-free, capture-free, input-free).
//   Usage: Foreman.CuPilot --pipe <name> --nonce <secret> --parent <pid>
// TraceBrake LAUNCHES this signed shim and pins its identity (PID == launched, parent == Foreman, signed image) exactly
// like the injector sidecar, so a same-user process cannot impersonate it on the broker-reaching hop. It connects to
// the App's duplex owner-only control pipe, proves it holds the launch nonce via challenge-response (HMAC over the
// handshake-tagged challenge; the nonce never crosses the wire), and services Hello/Heartbeat. In L4 it will host a
// SECOND owner-only pipe the operator's Foreman-LAUNCHED agent connects to and relay that agent's DriverSubmit
// proposals to the App over this hop - it never reaches the broker any other way. Exits on parent death / pipe break.

return Run(args);

static int Run(string[] args)
{
    string? pipeName = null, nonce = null;
    var parentPid = 0;
    for (var i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "--pipe":   pipeName = Next(args, ref i); break;
            case "--nonce":  nonce = Next(args, ref i); break;
            case "--parent": _ = int.TryParse(Next(args, ref i), out parentPid); break;
        }
    }
    if (string.IsNullOrEmpty(pipeName) || string.IsNullOrEmpty(nonce)) return 2;   // bad args

    try
    {
        using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut);
        try { pipe.Connect(5000); }
        catch { return 4; }

        using var reader = new StreamReader(pipe, new UTF8Encoding(false));
        using var writer = new StreamWriter(pipe, new UTF8Encoding(false)) { AutoFlush = true };

        // Handshake: return HMAC(nonce, handshake-tagged challenge). Never echo the nonce.
        var challenge = reader.ReadLine();
        if (string.IsNullOrEmpty(challenge)) return 5;
        try { writer.WriteLine(CuHandshake.Hmac(nonce, CuHandshake.HandshakeMessage(challenge))); }
        catch { return 5; }

        var parent = SafeGetProcess(parentPid);
        while (true)
        {
            if (parent is { HasExited: true }) break;

            string? line;
            try { line = reader.ReadLine(); }
            catch { break; }
            if (line is null) break;   // App closed the pipe

            DesktopCuRequest? req;
            try { req = JsonSerializer.Deserialize<DesktopCuRequest>(line, CuJson.Options); }
            catch { continue; }
            if (req is null) continue;

            DesktopCuResponse resp;
            switch (req.Kind)
            {
                case DesktopCuKind.Hello:
                    resp = new DesktopCuResponse(req.RequestId, req.Kind, Ok: true, PayloadB64: B64("pilot-ready"));
                    break;
                case DesktopCuKind.Heartbeat:
                    resp = new DesktopCuResponse(req.RequestId, req.Kind, Ok: true);
                    break;
                case DesktopCuKind.StartAgent:
                {
                    // HOP B (L4): launch the operator's agent + host the second owner-only pipe (AgentHost).
                    var sa = FromB64<StartAgentArgs>(req.PayloadB64);
                    if (sa is null) { resp = new DesktopCuResponse(req.RequestId, req.Kind, Ok: false, Error: "bad StartAgent payload"); break; }
                    var ok = AgentHost.Start(sa, out var err);
                    resp = new DesktopCuResponse(req.RequestId, req.Kind, ok, Error: ok ? null : err);
                    break;
                }
                case DesktopCuKind.PollDriverSubmits:
                    // Return the agent's queued proposals for the App to rebuild + audit (the agent only proposes).
                    resp = new DesktopCuResponse(req.RequestId, req.Kind, Ok: true, PayloadB64: ToB64(AgentHost.Drain()));
                    break;
                default:
                    resp = new DesktopCuResponse(req.RequestId, req.Kind, Ok: false, Error: "Unsupported pilot request kind.");
                    break;
            }

            try { writer.WriteLine(JsonSerializer.Serialize(Sign(resp, nonce), CuJson.Options)); }
            catch { break; }
        }

        return 0;
    }
    catch { return 1; }
    finally { AgentHost.Stop(); }   // never leave the launched agent running past the shim
}

// Authenticate every reply with the session nonce so the App can reject any frame it did not get from us.
static DesktopCuResponse Sign(DesktopCuResponse r, string nonce) =>
    r with { Hmac = CuHandshake.Hmac(nonce, CuJson.ResponseMac(r.Kind, r.RequestId, r.Ok, r.Error, r.PayloadB64)) };

static string B64(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s));

static T? FromB64<T>(string? b64)
{
    if (string.IsNullOrEmpty(b64)) return default;
    try { return JsonSerializer.Deserialize<T>(Encoding.UTF8.GetString(Convert.FromBase64String(b64)), CuJson.Options); }
    catch { return default; }
}

static string ToB64<T>(T value) =>
    Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value, CuJson.Options)));

static Process? SafeGetProcess(int pid)
{
    if (pid <= 0) return null;
    try { return Process.GetProcessById(pid); }
    catch { return null; }
}

static string? Next(string[] a, ref int i) => i + 1 < a.Length ? a[++i] : null;
