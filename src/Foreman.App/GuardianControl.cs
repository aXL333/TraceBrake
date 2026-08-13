using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;

namespace Foreman.App;

/// <summary>
/// App-side launcher for the opt-in guardian's elevated install/uninstall (circle-back Phase A, step 6c). One UAC
/// prompt via the runas verb — the same mechanism as the Run-Elevated sidecar. The guardian's own
/// <c>--install</c> re-verifies its Authenticode in the elevated context before <c>sc create</c> (the authoritative
/// LPE guard); the pre-check here is cheap defense-in-depth so we don't even prompt for a clearly-bad binary.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class GuardianControl
{
    public static string GuardianExePath => Path.Combine(AppContext.BaseDirectory, "guardian", "Foreman.Guardian.exe");

    public static bool IsInstalled => GuardianDiscovery.IsGuardianInstalled();

    public static (bool Ok, string Message) Install()
    {
        var exe = GuardianExePath;
        if (!File.Exists(exe))
            return (false, "Guardian component not found next to TraceBrake. Reinstall TraceBrake.");

        // Defense-in-depth pre-check (the elevated --install re-verifies authoritatively before sc create).
        var (trusted, reason) = SidecarIntegrity.Verify(exe);
        if (!trusted)
            return (false, $"Refusing to install — the guardian binary failed its integrity check: {reason}");

        if (!SidecarIntegrity.SelfIsSigned())
            return (false, "This unsigned release cannot install the LocalSystem Guardian safely. Use a signed " +
                           "release; command-line development opt-ins are not a trust boundary.");

        // Pass only our live PID. The elevated guardian resolves the image path itself and requires its own image
        // to occupy this process's canonical guardian subdirectory; an attacker-supplied path is never trusted.
        return Run(exe, $"--install --foreman-pid {Environment.ProcessId}", "install");
    }

    public static (bool Ok, string Message) Uninstall()
    {
        // Weakening/removal executes the administrator-owned installed copy, never the per-user staged helper.
        var exe = GuardianDiscovery.InstalledExePath;
        if (!File.Exists(exe)) return (false, "Installed Guardian component not found in Program Files.");
        return Run(exe, "--uninstall", "uninstall");
    }

    private static (bool, string) Run(string exe, string args, string verb)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = args,
                UseShellExecute = true,   // required for the runas elevation prompt
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            using var p = Process.Start(psi);
            if (p is null) return (false, "Failed to launch the elevated guardian action.");
            p.WaitForExit();
            return p.ExitCode == 0
                ? (true, $"Guardian {verb} succeeded.")
                : (false, $"Guardian {verb} returned exit code {p.ExitCode}. See the Windows Event Log (source 'Foreman Agent Safety') for detail.");
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)   // ERROR_CANCELLED — UAC declined
        {
            return (false, "Elevation was declined at the UAC prompt.");
        }
        catch (Exception ex)
        {
            return (false, $"Guardian {verb} failed to launch: {ex.Message}");
        }
    }
}
