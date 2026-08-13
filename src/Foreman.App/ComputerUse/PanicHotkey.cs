using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Windows.Interop;

namespace Foreman.App.ComputerUse;

/// <summary>
/// Registers a SYSTEM-GLOBAL panic hotkey (default Ctrl+Alt+Shift+H) on a DEDICATED message-only window. Using a
/// message-only window (not the dashboard) means the hotkey keeps firing even when TraceBrake has no focused window
/// and, crucially, even if the dashboard/UI is busy or hung — the "give me my screen back" control must never be
/// the thing that's wedged. Fires <paramref name="onPressed"/> on the UI thread when the chord is pressed.
///
/// Best-effort: if registration fails (another app owns the chord), <see cref="Registered"/> is false and the tray
/// STOP item remains the fallback. Must be constructed on the WPF UI thread (it needs a Dispatcher).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PanicHotkey : IDisposable
{
    private const int WM_HOTKEY = 0x0312;
    private const int HotkeyId = 0xF0C0;                 // unique within this window
    private const uint MOD_ALT = 0x0001, MOD_CONTROL = 0x0002, MOD_SHIFT = 0x0004, MOD_NOREPEAT = 0x4000;
    private const uint VK_H = 0x48;
    private static readonly IntPtr HWND_MESSAGE = new(-3);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, uint vk);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool UnregisterHotKey(IntPtr hWnd, int id);

    private readonly HwndSource _source;
    private readonly Action _onPressed;
    private bool _registered;
    private bool _disposed;

    /// <summary>The human-readable chord, for surfacing in the UI ("Ctrl+Alt+Shift+H").</summary>
    public const string ChordText = "Ctrl+Alt+Shift+H";

    public PanicHotkey(Action onPressed)
    {
        _onPressed = onPressed;
        // Message-only window: invisible, no taskbar entry, has a message queue + WndProc to receive WM_HOTKEY.
        _source = new HwndSource(new HwndSourceParameters("Foreman.PanicHotkey")
        {
            WindowStyle = 0,
            ParentWindow = HWND_MESSAGE,
        });
        _source.AddHook(WndProc);
        // MOD_NOREPEAT so holding the chord fires once, not a storm.
        _registered = RegisterHotKey(_source.Handle, HotkeyId, MOD_CONTROL | MOD_ALT | MOD_SHIFT | MOD_NOREPEAT, VK_H);
    }

    /// <summary>True if the OS accepted the hotkey registration (false if the chord was already taken).</summary>
    public bool Registered => _registered;

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == WM_HOTKEY && wParam.ToInt32() == HotkeyId)
        {
            handled = true;
            try { _onPressed(); } catch { /* the panic path must never throw out of the message pump */ }
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
