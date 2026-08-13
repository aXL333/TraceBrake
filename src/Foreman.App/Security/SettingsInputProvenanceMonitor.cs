using Foreman.App.ComputerUse;
using Foreman.Core.Settings;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Foreman.App.Security;

/// <summary>
/// Captures only the provenance of actionable input aimed at TraceBrake's own windows. It never records keys,
/// coordinates, text, or target control names. Synthetic Win32 input carries an OS-injected flag; TraceBrake's own
/// desktop-CU injector additionally carries the FORE marker. UI Automation Invoke produces no low-level input and
/// is therefore intentionally classified as unattributed.
/// </summary>
internal sealed class SettingsInputProvenanceMonitor : IDisposable
{
    private const int WhKeyboardLl = 13;
    private const int WhMouseLl = 14;
    private const uint WmKeyDown = 0x0100;
    private const uint WmSysKeyDown = 0x0104;
    private const uint WmLButtonDown = 0x0201;
    private const uint WmRButtonDown = 0x0204;
    private const uint WmMButtonDown = 0x0207;
    private const uint WmXButtonDown = 0x020B;
    private const uint LlkhfInjected = 0x10;
    private const uint LlkhfLowerIlInjected = 0x02;
    private const uint LlmhfInjected = 0x01;
    private const uint LlmhfLowerIlInjected = 0x02;
    private static readonly long FreshnessTicks = (long)(Stopwatch.Frequency * 2.0);

    private readonly HookProc _keyboardProc;
    private readonly HookProc _mouseProc;
    private nint _keyboardHook;
    private nint _mouseHook;
    private long _lastPhysical;
    private long _lastInjected;
    private int _lastInjectedWasForeman;

    public SettingsInputProvenanceMonitor()
    {
        _keyboardProc = KeyboardHook;
        _mouseProc = MouseHook;
    }

    public bool Start()
    {
        if (_keyboardHook != 0 && _mouseHook != 0) return true;
        if (_keyboardHook != 0 || _mouseHook != 0) Dispose();
        var module = GetModuleHandle(null);
        _keyboardHook = SetWindowsHookEx(WhKeyboardLl, _keyboardProc, module, 0);
        _mouseHook = SetWindowsHookEx(WhMouseLl, _mouseProc, module, 0);
        if (_keyboardHook != 0 && _mouseHook != 0) return true;
        Dispose();
        return false;
    }

    public SettingsChangeAttribution Capture(string operation)
    {
        var input = SettingsInputProvenancePolicy.Assess(
            Stopwatch.GetTimestamp(),
            Interlocked.Read(ref _lastPhysical),
            Interlocked.Read(ref _lastInjected),
            Volatile.Read(ref _lastInjectedWasForeman) != 0,
            FreshnessTicks);

        return input switch
        {
            SettingsInputProvenance.Physical => SettingsChangeAttribution.Declared(
                SettingsChangeOrigin.HumanUi, "local-operator", operation, input,
                reason: "A recent non-injected input event targeted a TraceBrake window."),
            SettingsInputProvenance.ForemanComputerUse => SettingsChangeAttribution.Declared(
                SettingsChangeOrigin.HumanUi, "foreman-computer-use", operation, input, true,
                "The UI action followed Foreman-stamped injected input; verify that computer use was intended."),
            SettingsInputProvenance.Injected => SettingsChangeAttribution.Declared(
                SettingsChangeOrigin.HumanUi, "synthetic-input", operation, input, true,
                "The UI action followed OS-flagged injected input from an untrusted source."),
            _ => SettingsChangeAttribution.Declared(
                SettingsChangeOrigin.HumanUi, "unattributed-ui", operation,
                SettingsInputProvenance.Unattributed, true,
                "No recent physical input reached Foreman; UI Automation or programmatic invocation may be involved."),
        };
    }

    private nint KeyboardHook(int code, nuint message, nint data)
    {
        if (code >= 0 && (message == WmKeyDown || message == WmSysKeyDown) && ForegroundBelongsToForeman())
        {
            var value = Marshal.PtrToStructure<KbdLlHookStruct>(data);
            Record((value.flags & (LlkhfInjected | LlkhfLowerIlInjected)) != 0, value.dwExtraInfo);
        }
        return CallNextHookEx(0, code, message, data);
    }

    private nint MouseHook(int code, nuint message, nint data)
    {
        if (code >= 0 && IsActionableMouseMessage(message))
        {
            var value = Marshal.PtrToStructure<MsLlHookStruct>(data);
            if (PointBelongsToForeman(value.pt))
                Record((value.flags & (LlmhfInjected | LlmhfLowerIlInjected)) != 0, value.dwExtraInfo);
        }
        return CallNextHookEx(0, code, message, data);
    }

    private void Record(bool injected, nuint extraInfo)
    {
        var now = Stopwatch.GetTimestamp();
        if (!injected)
        {
            Interlocked.Exchange(ref _lastPhysical, now);
            return;
        }

        Volatile.Write(ref _lastInjectedWasForeman,
            extraInfo == (nuint)CuDesktopPanicFloor.ForemanMagic ? 1 : 0);
        Interlocked.Exchange(ref _lastInjected, now);
    }

    private static bool IsActionableMouseMessage(nuint message) =>
        message is WmLButtonDown or WmRButtonDown or WmMButtonDown or WmXButtonDown;

    private static bool ForegroundBelongsToForeman() => BelongsToForeman(GetForegroundWindow());

    private static bool PointBelongsToForeman(Point point)
    {
        var window = WindowFromPoint(point);
        return BelongsToForeman(window);
    }

    private static bool BelongsToForeman(nint window)
    {
        if (window == 0) return false;
        GetWindowThreadProcessId(window, out var pid);
        return pid == (uint)Environment.ProcessId;
    }

    public void Dispose()
    {
        if (_keyboardHook != 0) UnhookWindowsHookEx(_keyboardHook);
        if (_mouseHook != 0) UnhookWindowsHookEx(_mouseHook);
        _keyboardHook = 0;
        _mouseHook = 0;
    }

    private delegate nint HookProc(int code, nuint message, nint data);

    [StructLayout(LayoutKind.Sequential)]
    private struct Point { public int x; public int y; }

    [StructLayout(LayoutKind.Sequential)]
    private struct KbdLlHookStruct
    {
        public uint vkCode;
        public uint scanCode;
        public uint flags;
        public uint time;
        public nuint dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MsLlHookStruct
    {
        public Point pt;
        public uint mouseData;
        public uint flags;
        public uint time;
        public nuint dwExtraInfo;
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern nint SetWindowsHookEx(int idHook, HookProc callback, nint module, uint threadId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern nint GetModuleHandle(string? moduleName);

    [DllImport("user32.dll")]
    private static extern bool UnhookWindowsHookEx(nint hook);

    [DllImport("user32.dll")]
    private static extern nint CallNextHookEx(nint hook, int code, nuint message, nint data);

    [DllImport("user32.dll")]
    private static extern nint GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern nint WindowFromPoint(Point point);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(nint window, out uint processId);
}

/// <summary>Single App-wide entry point used by settings UI handlers before their first await.</summary>
internal static class SettingsChangeUiScope
{
    private static SettingsInputProvenanceMonitor? _monitor;

    public static void Configure(SettingsInputProvenanceMonitor? monitor) => _monitor = monitor;

    public static IDisposable Begin(string operation) => SettingsChangeContext.Begin(
        _monitor?.Capture(operation) ?? SettingsChangeAttribution.Declared(
            SettingsChangeOrigin.HumanUi,
            "unattributed-ui",
            operation,
            SettingsInputProvenance.Unattributed,
            true,
            "Settings input provenance monitor was unavailable."));
}
