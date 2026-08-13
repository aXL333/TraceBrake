using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Windows.Interop;

namespace Foreman.App.ComputerUse;

/// <summary>
/// System-global hotkey (default Ctrl+Alt+Shift+B) to BIND the desktop computer-use target window. On a dedicated
/// message-only window (like <see cref="PanicHotkey"/>) so it fires regardless of TraceBrake's focus. Pressing it while the
/// intended target window is FOREGROUND is the point: the bind captures that foreground window BEFORE TraceBrake steals
/// focus, then presence-gates the bind. Best-effort; if the chord is taken, <see cref="Registered"/> is false.
/// Must be constructed on the WPF UI thread.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class BindHotkey : IDisposable
{
    private const int WM_HOTKEY = 0x0312;
    private const int HotkeyId = 0xF0C1;                 // distinct from PanicHotkey's id
    private const uint MOD_ALT = 0x0001, MOD_CONTROL = 0x0002, MOD_SHIFT = 0x0004, MOD_NOREPEAT = 0x4000;
    private const uint VK_B = 0x42;
    private static readonly IntPtr HWND_MESSAGE = new(-3);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, uint vk);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool UnregisterHotKey(IntPtr hWnd, int id);

    private readonly HwndSource _source;
    private readonly Action _onPressed;
    private bool _registered;
    private bool _disposed;

    public const string ChordText = "Ctrl+Alt+Shift+B";

    public BindHotkey(Action onPressed)
    {
        _onPressed = onPressed;
        _source = new HwndSource(new HwndSourceParameters("Foreman.BindHotkey")
        {
            WindowStyle = 0,
            ParentWindow = HWND_MESSAGE,
        });
        _source.AddHook(WndProc);
        _registered = RegisterHotKey(_source.Handle, HotkeyId, MOD_CONTROL | MOD_ALT | MOD_SHIFT | MOD_NOREPEAT, VK_B);
    }

    public bool Registered => _registered;

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == WM_HOTKEY && wParam.ToInt32() == HotkeyId)
        {
            handled = true;
            try { _onPressed(); } catch { /* never throw out of the message pump */ }
        }
        return IntPtr.Zero;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_registered) { try { UnregisterHotKey(_source.Handle, HotkeyId); } catch { } _registered = false; }
        try { _source.RemoveHook(WndProc); } catch { }
        _source.Dispose();
    }
}
