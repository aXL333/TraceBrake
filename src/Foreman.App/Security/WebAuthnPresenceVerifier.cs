using System.Linq;
using System.Windows;
using System.Windows.Interop;
using Foreman.Core.Security;

namespace Foreman.App.Security;

/// <summary>
/// <see cref="IPresenceVerifier"/> over the Windows WebAuthn picker (<see cref="WebAuthnInterop"/>) — the true
/// "all authenticators" path: one native dialog offers Windows Hello (platform) AND roaming FIDO2/U2F keys
/// (YubiKey). Enrollment pins the real FIDO credential id; verification asserts THAT credential. The
/// user-verification requirement follows <see cref="RequireUserVerification"/> (default touch-only) — but every
/// ceremony needs at least a physical touch, the one thing a same-user process can't fake.
///
/// Two Win32 realities are handled here: the calls are SYNCHRONOUS/blocking (run off the UI thread via
/// Task.Run, or the app freezes), and they need a valid FOREGROUND HWND to parent the native dialog — the tray
/// app has no main window, so we use the active TraceBrake window when one is up (the dialog that triggered the
/// weakening) or spin a transient off-screen foreground window for tray-initiated actions (enroll / Exit).
/// </summary>
public sealed class WebAuthnPresenceVerifier : IPresenceVerifier
{
    private const string RpId = "foreman.local";
    private const string RpName = "TraceBrake";

    public bool IsAvailable
    {
        get { try { return WebAuthnInterop.ApiVersion() > 0; } catch { return false; } }
    }

    public async Task<EnrollResult> EnrollAsync(string reason, bool requireUserVerification, CancellationToken ct = default)
    {
        try
        {
            var (hwnd, transient) = await OnUiAsync(AcquireHwnd).ConfigureAwait(false);
            try
            {
                var (ok, id, err) = await Task.Run(() => WebAuthnInterop.MakeCredential(hwnd, RpId, RpName, requireUserVerification), ct).ConfigureAwait(false);
                if (ok && id is { Length: > 0 }) return EnrollResult.Success(Base64Url(id), "Security key / Windows Hello");
                Foreman.App.CrashLog.Note("WebAuthn enroll", new Exception(err ?? "no credential returned"));
                return EnrollResult.Fail(err ?? "Enrollment failed.");
            }
            finally { await CloseAsync(transient).ConfigureAwait(false); }
        }
        catch (Exception ex) { Foreman.App.CrashLog.Note("WebAuthn enroll", ex); return EnrollResult.Fail($"WebAuthn error: {ex.GetType().Name}: {ex.Message}"); }
    }

    public async Task<PresenceResult> VerifyAsync(string credentialId, string reason, bool requireUserVerification, CancellationToken ct = default)
    {
        byte[] id;
        try { id = Base64UrlDecode(credentialId); }
        catch { return PresenceResult.Fail("invalid credential id"); }

        try
        {
            var (hwnd, transient) = await OnUiAsync(AcquireHwnd).ConfigureAwait(false);
            try
            {
                var (ok, err) = await Task.Run(() => WebAuthnInterop.GetAssertion(hwnd, RpId, id, requireUserVerification), ct).ConfigureAwait(false);
                if (ok) return PresenceResult.Ok("Security key / Windows Hello");
                Foreman.App.CrashLog.Note("WebAuthn verify", new Exception(err ?? "not verified"));
                return PresenceResult.Fail(err ?? "not verified");
            }
            finally { await CloseAsync(transient).ConfigureAwait(false); }
        }
        catch (Exception ex) { Foreman.App.CrashLog.Note("WebAuthn verify", ex); return PresenceResult.Fail($"WebAuthn error: {ex.GetType().Name}: {ex.Message}"); }
    }

    // UI thread: an HWND to parent the native dialog — the active TraceBrake window, else a transient foreground one.
    private static (IntPtr Hwnd, Window? Transient) AcquireHwnd()
    {
        var app = Application.Current;
        var active = app?.Windows.OfType<Window>().FirstOrDefault(w => w.IsActive)
                  ?? app?.Windows.OfType<Window>().FirstOrDefault(w => w.IsVisible);
        if (active is not null)
        {
            var h = new WindowInteropHelper(active).EnsureHandle();
            if (h != IntPtr.Zero) { SetForegroundWindow(h); return (h, null); }   // best-effort: surface the native dialog
        }

        // No TraceBrake window up (tray-initiated): WebAuthn needs an ON-SCREEN, VISIBLE owner — an off-screen window
        // is rejected / shows the dialog where you can't reach it — so a tiny centered window, never off-screen.
        var transient = new Window
        {
            Width = 1, Height = 1, WindowStartupLocation = WindowStartupLocation.CenterScreen,
            WindowStyle = WindowStyle.None, ShowInTaskbar = false, ShowActivated = true, Topmost = true,
        };
        transient.Show();
        transient.Activate();
        var th = new WindowInteropHelper(transient).EnsureHandle();
        SetForegroundWindow(th);
        return (th, transient);
    }

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    private static Task<T> OnUiAsync<T>(Func<T> f)
    {
        var d = Application.Current?.Dispatcher;
        return d is null || d.CheckAccess() ? Task.FromResult(f()) : d.InvokeAsync(f).Task;
    }

    private static Task CloseAsync(Window? w)
    {
        if (w is null) return Task.CompletedTask;
        var d = Application.Current?.Dispatcher;
        if (d is null || d.CheckAccess()) { w.Close(); return Task.CompletedTask; }
        return d.InvokeAsync(w.Close).Task;
    }

    private static string Base64Url(byte[] b) =>
        Convert.ToBase64String(b).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    private static byte[] Base64UrlDecode(string s)
    {
        var t = s.Replace('-', '+').Replace('_', '/');
        t += (t.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(t);
    }
}
