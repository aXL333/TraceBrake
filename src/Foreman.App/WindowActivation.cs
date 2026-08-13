using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Threading;

namespace Foreman.App;

/// <summary>
/// Reliably brings a WPF window to the foreground from a system-tray app.
///
/// Two Windows quirks make this non-trivial, and TraceBrake hit both:
///   1. SetForegroundWindow is refused for a process that is not already the foreground
///      app (focus-stealing prevention), so a window opened from a tray click silently
///      stays behind. We work around it by briefly attaching our input queue to the
///      current foreground thread's, which grants the foreground right for the call.
///   2. Toggling Topmost true→false synchronously makes the window flash up and then fall
///      straight behind the previous window. We set Topmost on to surface it, then drop it
///      back at ApplicationIdle — once the window has actually come forward.
/// </summary>
internal static class WindowActivation
{
    /// <summary>Shows (if needed) and force-foregrounds a window without leaving it always-on-top.</summary>
    public static void Surface(Window w)
    {
        if (w is null) return;

        if (!w.IsVisible) w.Show();
        if (w.WindowState == WindowState.Minimized) w.WindowState = WindowState.Normal;

        var hwnd = new WindowInteropHelper(w).Handle;

        var foreground = GetForegroundWindow();
        var foreThread = GetWindowThreadProcessId(foreground, out _);
        var thisThread = GetCurrentThreadId();

        var attached = false;
        if (foreThread != 0 && foreThread != thisThread)
            attached = AttachThreadInput(foreThread, thisThread, true);

        try
        {
            w.Topmost = true;          // jump to the top of the Z-order immediately
            w.Activate();
            if (hwnd != IntPtr.Zero)
            {
                BringWindowToTop(hwnd);
                SetForegroundWindow(hwnd);
            }
            w.Focus();
        }
        finally
        {
            if (attached) AttachThreadInput(foreThread, thisThread, false);
        }

        // Release always-on-top only after the window has surfaced; doing it synchronously
        // is exactly what made the alert window drop to the background.
        w.Dispatcher.BeginInvoke(new Action(() => w.Topmost = false),
            DispatcherPriority.ApplicationIdle);
    }

    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] private static extern bool BringWindowToTop(IntPtr hWnd);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
    [DllImport("user32.dll")] private static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);
    [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();
}
