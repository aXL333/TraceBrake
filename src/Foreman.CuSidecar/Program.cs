using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Foreman.Core.ComputerUse;

// TraceBrake desktop computer-use sidecar (Slice 4a: handshake + shared-panic READER - still capture-free, input-free).
//   Usage: Foreman.CuSidecar --pipe <name> --nonce <secret> --parent <pid>
// It connects to the App's duplex owner-only control pipe, proves it holds the launch nonce via challenge-response
// (HMAC(nonce, handshake-tagged challenge); the nonce never crosses the wire and the App pins our PID), then on Hello
// it maps the App's shared panic/bind memory READ-ONLY (handle duplicated to us over the authenticated channel) and
// reports back the panic/boundHwnd/epoch it reads - so the App can confirm we see the same state it wrote (INV-5).
// Input injection (SendInput) reads this same map before every event in Slice 4b. It exits when the parent dies or
// the pipe breaks, so nothing lingers.

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

    var panicView = IntPtr.Zero;
    try
    {
        using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut);
        try { pipe.Connect(5000); }
        catch { return 4; }

        using var reader = new StreamReader(pipe, new UTF8Encoding(false));
        using var writer = new StreamWriter(pipe, new UTF8Encoding(false)) { AutoFlush = true };

        // Handshake: read the App's random challenge, return HMAC(nonce, handshake-tagged challenge). Never echo nonce.
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
            catch { continue; }        // skip one malformed frame
            if (req is null) continue;

            DesktopCuResponse resp;
            switch (req.Kind)
            {
                case DesktopCuKind.Hello:
                {
                    var hello = FromB64<HelloArgs>(req.PayloadB64);
                    if (hello is not null && hello.PanicMapHandle != 0 && panicView == IntPtr.Zero)
                        panicView = MapPanicView(hello.PanicMapHandle, hello.MapCapacity);
                    resp = panicView != IntPtr.Zero
                        ? new DesktopCuResponse(req.RequestId, req.Kind, Ok: true, PayloadB64: ToB64(ReadPanic(panicView)))
                        : new DesktopCuResponse(req.RequestId, req.Kind, Ok: false, Error: "could not map the shared panic view");
                    break;
                }
                case DesktopCuKind.Heartbeat:
                    // Report what we currently read from the shared map, so the App can cross-check (INV-5).
                    resp = new DesktopCuResponse(req.RequestId, req.Kind, Ok: true, PayloadB64: ToB64(ReadPanic(panicView)));
                    break;
                case DesktopCuKind.ExecuteAction:
                {
                    // Slice 4b-2: inject ONE atomic gesture, re-checking panic + confinement before every single INPUT
                    // (CuInputInjector reads the shared MMF itself via ReadPanic; parentPid = Foreman, for INV-9).
                    var ea = FromB64<ExecuteActionArgs>(req.PayloadB64);
                    var result = ea is null
                        ? new ExecuteActionResult(false, "bad ExecuteAction payload")
                        : CuInputInjector.Execute(ea, () => ReadPanic(panicView), parentPid);
                    resp = new DesktopCuResponse(req.RequestId, req.Kind, result.Ok, PayloadB64: ToB64(result), Error: result.Error);
                    break;
                }
                default:
                    resp = new DesktopCuResponse(req.RequestId, req.Kind, Ok: false,
                        Error: "Unsupported desktop CU request kind.");
                    break;
            }

            try { writer.WriteLine(JsonSerializer.Serialize(Sign(resp, nonce), CuJson.Options)); }
            catch { break; }
        }

        return 0;
    }
    catch { return 1; }
    finally
    {
        if (panicView != IntPtr.Zero) { try { Native.UnmapViewOfFile(panicView); } catch { } }
    }
}

// Map the App's shared panic/bind section READ-ONLY from the handle it duplicated into us. We can only read it.
static IntPtr MapPanicView(long handle, int capacity)
{
    try { return Native.MapViewOfFile((IntPtr)handle, Native.FILE_MAP_READ, 0, 0, (UIntPtr)(uint)Math.Max(0, capacity)); }
    catch { return IntPtr.Zero; }
}

// Seqlock read: the App writes the epoch LAST, so reading epoch -> fields -> epoch and retrying on a mismatch yields a
// consistent {panic, boundHwnd, epoch} even under a concurrent write. Aligned 8-byte reads are atomic on x64.
// Read the shared panic/bind state through the App's TRUE seqlock (odd version = write in progress). FAIL CLOSED: an
// unmapped view, an in-progress write that never settles, or a torn read all report HALTED (panic=1) stamped with an
// OUT-OF-BAND version (long.MinValue, which a valid even seqlock version can never be) so the Slice-4b gate refuses to
// inject AND can tell "could not read" from a real map value (a planted -1 no longer mimics the failure signal).
static PanicSnapshot ReadPanic(IntPtr view)
{
    if (view == IntPtr.Zero) return new PanicSnapshot(1, 0, long.MinValue);
    for (var attempt = 0; attempt < 16; attempt++)
    {
        var e1 = Marshal.ReadInt64(view, 16);
        if ((e1 & 1L) != 0) continue;            // odd = write in progress, retry
        Thread.MemoryBarrier();
        var panic = Marshal.ReadByte(view, 0);
        var hwnd = Marshal.ReadInt64(view, 8);
        Thread.MemoryBarrier();
        var e2 = Marshal.ReadInt64(view, 16);
        if (e1 == e2) return new PanicSnapshot(panic, hwnd, e2);
    }
    return new PanicSnapshot(1, 0, long.MinValue);   // contention/torn -> halted, never a torn snapshot
}

// Authenticate the reply with the session nonce so the App can reject any frame it did not get from us. The MAC binds
// the Ok/Error decision bits too, so a tampered frame cannot flip the result without invalidating it.
static DesktopCuResponse Sign(DesktopCuResponse r, string nonce) =>
    r with { Hmac = CuHandshake.Hmac(nonce, CuJson.ResponseMac(r.Kind, r.RequestId, r.Ok, r.Error, r.PayloadB64)) };

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

static class Native
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess,
        uint dwFileOffsetHigh, uint dwFileOffsetLow, UIntPtr dwNumberOfBytesToMap);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);

    public const uint FILE_MAP_READ = 0x0004;
}
