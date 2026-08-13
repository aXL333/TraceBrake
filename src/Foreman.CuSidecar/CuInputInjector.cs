using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Foreman.Core.ComputerUse;

/// <summary>
/// The Slice 4b-2 input injector (sidecar side). Executes ONE atomic gesture as a sequence of SINGLE INPUTs, and
/// before EVERY INPUT re-checks the hard invariants - so a panic, a confinement break, or a bound-window change can
/// never be crossed mid-gesture:
///   - panic: read the shared MMF (seqlock) via <paramref name="panicNow"/>; panic=1 => abort with HaltedMidStream.
///   - INV-2: the action's BoundHwnd must equal the AUTHORITATIVE MMF boundHwnd (never trust the pipe payload alone).
///   - confinement (INV-9 + foreground): the foreground window must BE the bound window, never TraceBrake's own UI, never
///     shell chrome; verified immediately before AND after each single INPUT. No bare absolute move - a move resolves
///     to the bound window's client rect or is refused.
///   - one-INPUT-per-batch: every SendInput call carries exactly ONE INPUT (nInputs=1), so panic interleaves between
///     each. dwExtraInfo is stamped with TraceBrake's magic (INV-4 sub-classifies our injection).
/// Refuses (Ok=false) rather than injecting blind on any failed gate.
/// </summary>
internal static class CuInputInjector
{
    public const ulong Magic = 0x464F5245;   // "FORE"

    public static ExecuteActionResult Execute(ExecuteActionArgs args, Func<PanicSnapshot> panicNow, int foremanPid)
    {
        var bound = (IntPtr)args.BoundHwnd;
        if (bound == IntPtr.Zero) return Fail("no bound window");

        var snap0 = panicNow();
        if (snap0.Panic != 0) return Halted();
        if (snap0.BoundHwnd != args.BoundHwnd) return Fail("BoundHwnd != authoritative MMF boundHwnd (INV-2)");

        // Build the atomic INPUT steps for the verb up front (pure), then gate + inject each one.
        var steps = BuildSteps(args, bound, out var buildErr);
        if (steps is null) return Fail(buildErr);

        // Foreground-LOCK pin: attach to the bound window's input thread and lock SetForegroundWindow so a same-user
        // process cannot steal the foreground in the gap between our pre-check and the kernel dequeuing the INPUT (the
        // SendInput-targets-foreground race). The per-INPUT Confined() check still gates regardless; this just shrinks
        // the window. Always unwound in finally.
        var boundThread = GetWindowThreadProcessId(bound, out _);
        var ourThread = GetCurrentThreadId();
        var attached = boundThread != 0 && AttachThreadInput(ourThread, boundThread, true);
        try { SetForegroundWindow(bound); } catch { }
        try { LockSetForegroundWindow(LSFW_LOCK); } catch { }

        // UPs owed for DOWNs already emitted. Flushed on ANY early return so a panic OR a confine-fail (which does NOT
        // run the App-side floor) can never strand a key/button held - the injector knows exactly what it pressed.
        var owed = new List<INPUT>();
        try
        {
            foreach (var (inp, owe, pays) in steps)
            {
                var snap = panicNow();
                if (snap.Panic != 0) { Flush(owed, args.DryRun); return Halted(); }
                if (snap.BoundHwnd != args.BoundHwnd) { Flush(owed, args.DryRun); return Fail("bound window changed mid-gesture (INV-2)"); }
                if (!Confined(bound, foremanPid, out var why)) { Flush(owed, args.DryRun); return Fail("not confined: " + why); }

                if (!args.DryRun)
                {
                    if (SendInput(1, new[] { inp }, Marshal.SizeOf<INPUT>()) != 1) { Flush(owed, args.DryRun); return Fail("SendInput rejected"); }
                    if (owe is INPUT up) owed.Add(up);                                  // a DOWN: owe its UP
                    else if (pays && owed.Count > 0) owed.RemoveAt(owed.Count - 1);     // the UP: paid (LIFO - pairs are adjacent)
                    // Pace after EVERY input (both the DOWN and the UP). A target with an async text-input pipeline (the
                    // Win11 Notepad XAML island) processes injected events on a separate thread; under a tight burst it
                    // loses intermediate key-UPs, so the last key "sticks" and auto-repeats ("from" -> "mmmm"). A gap
                    // after each event lets the down register, then the up, before the next char. Panic stays responsive
                    // (the next step's top-of-loop gate runs after at most this delay; Flush releases anything held), and
                    // MaxStepsPerGesture keeps the total within the controller's request timeout.
                    if (InterKeyDelayMs > 0) Thread.Sleep(InterKeyDelayMs);
                }

                if (!Confined(bound, foremanPid, out var why2)) { Flush(owed, args.DryRun); return Fail("foreground changed during input: " + why2); }
            }

            GetCursorPos(out var pt);
            var finalFg = GetForegroundWindow();
            return new ExecuteActionResult(Ok: true, Error: null, FinalHwnd: finalFg.ToInt64(), CursorX: pt.X, CursorY: pt.Y, HaltedMidStream: false);
        }
        finally
        {
            try { LockSetForegroundWindow(LSFW_UNLOCK); } catch { }
            if (attached) try { AttachThreadInput(ourThread, boundThread, false); } catch { }
        }
    }

    // Force-release everything we still hold, on ANY early exit. Sent ungated: releasing a key/button is always safe
    // (a key-up for a key not down elsewhere is a harmless no-op).
    private static void Flush(List<INPUT> owed, bool dryRun)
    {
        if (!dryRun)
            for (var i = owed.Count - 1; i >= 0; i--)
                try { SendInput(1, new[] { owed[i] }, Marshal.SizeOf<INPUT>()); } catch { }
        owed.Clear();
    }

    // Foreground confinement + INV-9. The foreground must be exactly the bound window; reject TraceBrake's own windows and
    // shell chrome outright. (Owned-popup / menu-class relaxation for read-only verbs is a later refinement - 4b-2 is strict.)
    private static bool Confined(IntPtr bound, int foremanPid, out string why)
    {
        why = string.Empty;
        var fg = GetForegroundWindow();
        if (fg == IntPtr.Zero) { why = "no foreground window"; return false; }
        GetWindowThreadProcessId(fg, out var fgPid);
        if ((int)fgPid == foremanPid) { why = "foreground is TraceBrake's own UI (INV-9)"; return false; }
        var cls = ClassOf(fg);
        if (cls is "Shell_TrayWnd" or "Shell_SecondaryTrayWnd" or "NotifyIconOverflowWindow" or "Progman" or "WorkerW"
            or "Windows.UI.Core.CoreWindow" or "MultitaskingViewFrame" or "XamlExplorerHostIslandWindow" or "ForegroundStaging")
        { why = $"foreground is shell chrome ({cls})"; return false; }
        // The real gate: fg must be exactly the bound window (an allowlist - any shell/sibling window already fails here).
        if (fg != bound) { why = "foreground is not the bound window"; return false; }
        return true;
    }

    // A step is (the INPUT to send, the UP it owes if it is a DOWN else null, whether it is the UP that pays a prior owe).
    // One ExecuteAction must finish within the controller's request timeout (5s). With InterKeyDelayMs pacing the
    // worst-case time is MaxStepsPerGesture * InterKeyDelayMs (80 * 40ms = 3.2s) - kept comfortably under 5s. The
    // executor pump splits longer text into multiple <=40-char gestures.
    private const int MaxStepsPerGesture = 80;
    private const int InterKeyDelayMs = 40;        // gap after each input so async text targets don't drop/coalesce chars

    private static List<(INPUT inp, INPUT? owe, bool pays)>? BuildSteps(ExecuteActionArgs args, IntPtr bound, out string err)
    {
        err = string.Empty;
        var steps = new List<(INPUT, INPUT?, bool)>();
        var verb = (args.Verb ?? string.Empty).Trim().ToLowerInvariant();
        switch (verb)
        {
            case "move":
                if (!TryClientPoint(args, bound, out var mp, out err)) return null;
                steps.Add((MouseMove(mp), null, false));
                break;
            case "left_click": case "right_click": case "middle_click":
            {
                if (!TryClientPoint(args, bound, out var cp, out err)) return null;
                var (dn, up) = verb switch
                {
                    "right_click" => (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP),
                    "middle_click" => (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP),
                    _ => (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP),
                };
                steps.Add((MouseMove(cp), null, false));
                steps.Add((MouseBtn(dn), MouseBtn(up), false));   // DOWN owes its UP
                steps.Add((MouseBtn(up), null, true));            // UP pays
                break;
            }
            case "scroll":
                if (!int.TryParse(Arg(args, "amount"), out var amt)) { err = "scroll needs an integer 'amount'"; return null; }
                steps.Add((Wheel(amt), null, false));
                break;
            case "key":
            {
                if (!ushort.TryParse(Arg(args, "vk"), out var vk)) { err = "key needs a numeric 'vk'"; return null; }
                // Optional modifiers ("mods"=ctrl/alt/shift/win): pressed before the key, released after in LIFO order -
                // so Ctrl+L, Ctrl+C, etc. work. Each DOWN owes its UP, so the held-key tracking releases the modifiers
                // too on ANY abort/panic/confine-fail (never strands Ctrl held).
                var mods = ParseMods(Arg(args, "mods"));
                foreach (var m in mods) steps.Add((KeyVk(m, true), KeyVk(m, false), false));   // modifier DOWN (owes UP)
                steps.Add((KeyVk(vk, true), KeyVk(vk, false), false));                          // key DOWN (owes UP)
                steps.Add((KeyVk(vk, false), null, true));                                      // key UP (pays)
                for (var i = mods.Count - 1; i >= 0; i--) steps.Add((KeyVk(mods[i], false), null, true));  // modifier UP (pays, LIFO)
                break;
            }
            case "type":
            {
                var text = Arg(args, "text");
                if (string.IsNullOrEmpty(text)) { err = "type needs non-empty 'text'"; return null; }
                foreach (var ch in text)
                {
                    if (char.IsSurrogate(ch)) { err = "type does not support non-BMP characters (emoji / surrogate pairs)"; return null; }
                    steps.Add((KeyUnicode(ch, true), KeyUnicode(ch, false), false));
                    steps.Add((KeyUnicode(ch, false), null, true));
                }
                break;
            }
            default:
                err = $"unsupported verb '{verb}'";
                return null;
        }

        if (steps.Count > MaxStepsPerGesture) { err = $"gesture too long ({steps.Count} inputs > {MaxStepsPerGesture}); split it"; return null; }
        return steps;
    }

    // A move/click point is the bound window's CLIENT coordinates; it must lie inside the client rect (no bare absolute
    // moves anywhere on screen), then maps to a virtual-desktop-normalised absolute coordinate.
    private static bool TryClientPoint(ExecuteActionArgs args, IntPtr bound, out POINT screenAbs, out string err)
    {
        screenAbs = default; err = string.Empty;
        if (!int.TryParse(Arg(args, "x"), out var cx) || !int.TryParse(Arg(args, "y"), out var cy))
        { err = "move/click needs integer client 'x'/'y'"; return false; }
        if (!GetClientRect(bound, out var rc)) { err = "could not read bound client rect"; return false; }
        // rc.Right/Bottom are width/height (one past the last valid pixel), so the valid range is [0, Right) x [0, Bottom).
        if (cx < 0 || cy < 0 || cx >= rc.Right || cy >= rc.Bottom) { err = "point is outside the bound client rect"; return false; }
        var p = new POINT { X = cx, Y = cy };
        if (!ClientToScreen(bound, ref p)) { err = "ClientToScreen failed"; return false; }
        // INV-9 under-the-point: the window ACTUALLY under the target screen point must root-own to the bound window -
        // catches a topmost overlay sitting over the bound client rect to harvest the click/keystroke.
        var under = WindowFromPoint(p);
        if (under == IntPtr.Zero || GetAncestor(under, GA_ROOTOWNER) != bound)
        { err = "another window covers the target point (possible input-harvest overlay)"; return false; }
        screenAbs = p;
        return true;
    }

    private static string Arg(ExecuteActionArgs a, string k) => a.Args.TryGetValue(k, out var v) ? v : string.Empty;

    // Parse a "mods" string (e.g. "ctrl", "ctrl+shift", "ctrl alt") into modifier virtual-key codes, pressed/released
    // around the key in order. Unknown tokens are ignored.
    private static System.Collections.Generic.List<ushort> ParseMods(string? s)
    {
        var list = new System.Collections.Generic.List<ushort>();
        if (string.IsNullOrWhiteSpace(s)) return list;
        foreach (var tok in s.Split(new[] { ',', ' ', '+' }, StringSplitOptions.RemoveEmptyEntries))
            switch (tok.Trim().ToLowerInvariant())
            {
                case "ctrl": case "control": list.Add(0x11); break;   // VK_CONTROL
                case "alt": case "menu":     list.Add(0x12); break;   // VK_MENU
                case "shift":                list.Add(0x10); break;   // VK_SHIFT
                case "win": case "lwin":     list.Add(0x5B); break;   // VK_LWIN
            }
        return list;
    }

    // ── INPUT builders ───────────────────────────────────────────────────────────────────────────────
    private static INPUT MouseMove(POINT screen)
    {
        // Normalise to the VIRTUAL desktop 0..65535 and use ABSOLUTE | VIRTUALDESK so multi-monitor maps correctly.
        var vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
        var vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
        // The kernel reverse-maps ABSOLUTE|VIRTUALDESK across (extent - 1) steps, so normalise by width-1 / height-1.
        var vw = Math.Max(1, GetSystemMetrics(SM_CXVIRTUALSCREEN) - 1);
        var vh = Math.Max(1, GetSystemMetrics(SM_CYVIRTUALSCREEN) - 1);
        var nx = (int)Math.Round((screen.X - vx) * 65535.0 / vw);
        var ny = (int)Math.Round((screen.Y - vy) * 65535.0 / vh);
        return Mouse(nx, ny, 0, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK);
    }

    private static INPUT MouseBtn(uint flags) => Mouse(0, 0, 0, flags);
    // MOUSEEVENTF_WHEEL takes mouseData in signed WHEEL_DELTA (120) units; preserve the sign through the uint field.
    private static INPUT Wheel(int amount) => Mouse(0, 0, unchecked((uint)(amount * WHEEL_DELTA)), MOUSEEVENTF_WHEEL);

    private static INPUT Mouse(int dx, int dy, uint data, uint flags) => new()
    {
        type = INPUT_MOUSE,
        U = new InputUnion { mi = new MOUSEINPUT { dx = dx, dy = dy, mouseData = data, dwFlags = flags, dwExtraInfo = (IntPtr)Magic } },
    };

    private static INPUT KeyVk(ushort vk, bool down) => new()
    {
        type = INPUT_KEYBOARD,
        U = new InputUnion { ki = new KEYBDINPUT { wVk = vk, dwFlags = down ? 0 : KEYEVENTF_KEYUP, dwExtraInfo = (IntPtr)Magic } },
    };

    private static INPUT KeyUnicode(char ch, bool down) => new()
    {
        type = INPUT_KEYBOARD,
        U = new InputUnion { ki = new KEYBDINPUT { wScan = ch, dwFlags = KEYEVENTF_UNICODE | (down ? 0u : KEYEVENTF_KEYUP), dwExtraInfo = (IntPtr)Magic } },
    };

    private static ExecuteActionResult Fail(string err) => new(false, err);
    private static ExecuteActionResult Halted() => new(false, "halted", HaltedMidStream: true);

    private static string ClassOf(IntPtr hwnd)
    {
        var sb = new StringBuilder(256);
        return GetClassName(hwnd, sb, sb.Capacity) > 0 ? sb.ToString() : string.Empty;
    }

    // ── Win32 ────────────────────────────────────────────────────────────────────────────────────────
    private const uint INPUT_MOUSE = 0, INPUT_KEYBOARD = 1;
    private const uint KEYEVENTF_KEYUP = 0x0002, KEYEVENTF_UNICODE = 0x0004;
    private const uint MOUSEEVENTF_MOVE = 0x0001, MOUSEEVENTF_ABSOLUTE = 0x8000, MOUSEEVENTF_VIRTUALDESK = 0x4000, MOUSEEVENTF_WHEEL = 0x0800;
    private const uint MOUSEEVENTF_LEFTDOWN = 0x0002, MOUSEEVENTF_LEFTUP = 0x0004;
    private const uint MOUSEEVENTF_RIGHTDOWN = 0x0008, MOUSEEVENTF_RIGHTUP = 0x0010;
    private const uint MOUSEEVENTF_MIDDLEDOWN = 0x0020, MOUSEEVENTF_MIDDLEUP = 0x0040;
    private const int SM_XVIRTUALSCREEN = 76, SM_YVIRTUALSCREEN = 77, SM_CXVIRTUALSCREEN = 78, SM_CYVIRTUALSCREEN = 79;
    private const int WHEEL_DELTA = 120;
    private const uint LSFW_LOCK = 1, LSFW_UNLOCK = 2;
    private const uint GA_ROOTOWNER = 3;

    [StructLayout(LayoutKind.Sequential)] private struct INPUT { public uint type; public InputUnion U; }
    [StructLayout(LayoutKind.Explicit)] private struct InputUnion { [FieldOffset(0)] public MOUSEINPUT mi; [FieldOffset(0)] public KEYBDINPUT ki; }
    [StructLayout(LayoutKind.Sequential)] private struct MOUSEINPUT { public int dx, dy; public uint mouseData, dwFlags, time; public IntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Sequential)] private struct KEYBDINPUT { public ushort wVk, wScan; public uint dwFlags, time; public IntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Sequential)] private struct POINT { public int X, Y; }
    [StructLayout(LayoutKind.Sequential)] private struct RECT { public int Left, Top, Right, Bottom; }

    [DllImport("user32.dll", SetLastError = true)] private static extern uint SendInput(uint n, INPUT[] inputs, int cb);
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassName(IntPtr hWnd, StringBuilder buf, int max);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetClientRect(IntPtr hWnd, out RECT rc);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ClientToScreen(IntPtr hWnd, ref POINT pt);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetCursorPos(out POINT pt);
    [DllImport("user32.dll")] private static extern int GetSystemMetrics(int index);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, [MarshalAs(UnmanagedType.Bool)] bool fAttach);
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool LockSetForegroundWindow(uint uLockCode);
    [DllImport("user32.dll")] private static extern IntPtr WindowFromPoint(POINT point);
    [DllImport("user32.dll")] private static extern IntPtr GetAncestor(IntPtr hwnd, uint flags);
    [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();
}
