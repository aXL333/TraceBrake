using System.Runtime.InteropServices;
using System.Text;

namespace Foreman.App.Security;

/// <summary>
/// Fail-closed probe for whether unattended input is crossing a locked/secure Windows desktop. The universal Trust
/// broker calls this at both admission and delivery; failure/ambiguity reads as locked.
/// </summary>
internal static class SessionLockProbe
{
    private const uint DesktopReadObjects = 0x0001;
    private const int UoiName = 2;

    public static bool IsLocked()
    {
        if (!OperatingSystem.IsWindows()) return true;
        var desktop = OpenInputDesktop(0, false, DesktopReadObjects);
        if (desktop == IntPtr.Zero) return true;
        try
        {
            var name = new StringBuilder(128);
            if (!GetUserObjectInformation(desktop, UoiName, name, name.Capacity * sizeof(char), out _))
                return true;
            return !string.Equals(name.ToString(), "Default", StringComparison.OrdinalIgnoreCase);
        }
        catch { return true; }
        finally { CloseDesktop(desktop); }
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint desiredAccess);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetUserObjectInformation(
        IntPtr handle,
        int index,
        StringBuilder information,
        int length,
        out int needed);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseDesktop(IntPtr desktop);
}
