using Foreman.Core.Settings;
using Microsoft.Win32;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;

namespace Foreman.App;

/// <summary>
/// Windows integration for the "start with Windows" feature. It prefers the per-user
/// HKCU Run entry and falls back to a per-user Startup-folder shortcut when endpoint
/// protection blocks that key. All target-selection logic lives in
/// <see cref="StartupRegistration"/> (Core, unit-tested); this type only does the I/O.
/// </summary>
public static class StartupManager
{
    private const string StartupShortcutName = "TraceBrake.lnk";
    private static readonly string[] LegacyStartupShortcutNames =
        { "Foreman.lnk", "Foreman Agent Safety.lnk", "ForemanAgentSafety.lnk" };

    private static string StartupShortcutPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.Startup), StartupShortcutName);

    /// <summary>True if either supported per-user startup mechanism is configured.</summary>
    public static bool IsEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(StartupRegistration.RunKeyPath);
            if (key?.GetValue(StartupRegistration.RunValueName) is string
                || StartupRegistration.LegacyRunValueNames.Any(n => key?.GetValue(n) is string))
                return true;
        }
        catch
        {
            // A security product can protect the Run key even from its owner. The per-user Startup shortcut below
            // remains independently inspectable, so do not report the feature off merely because registry reads fail.
        }

        return File.Exists(StartupShortcutPath);
    }

    /// <summary>
    /// Registers/unregisters the currently running exe. HKCU Run remains the preferred backend. Some endpoint
    /// protection products deliberately veto writes to that persistence key even when its ACL grants the user full
    /// control; enabling then falls back to a standard per-user Startup-folder shortcut instead of silently failing.
    /// </summary>
    public static void SetEnabled(bool on)
    {
        if (on)
        {
            var exe = Environment.ProcessPath
                ?? throw new InvalidOperationException("Cannot resolve TraceBrake's executable path.");

            try
            {
                using var key = Registry.CurrentUser.CreateSubKey(StartupRegistration.RunKeyPath, writable: true)
                    ?? throw new InvalidOperationException("Cannot open the HKCU Run key.");
                key.SetValue(StartupRegistration.RunValueName, StartupRegistration.BuildCommand(exe));
                DeleteLegacyRunValues(key);
                DeleteStartupShortcuts();
                return;
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or SecurityException)
            {
                // Do not fight or weaken the protection layer. The shell's Startup folder is the OS-supported
                // per-user fallback and lets us set WorkingDirectory explicitly (important for WPF unpackaged apps).
                CreateStartupShortcut(exe);
                return;
            }
        }

        Exception? registryFailure = null;
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(StartupRegistration.RunKeyPath, writable: true);
            if (key is not null)
            {
                key.DeleteValue(StartupRegistration.RunValueName, throwOnMissingValue: false);
                DeleteLegacyRunValues(key);
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or SecurityException)
        {
            registryFailure = ex;
        }

        DeleteStartupShortcuts();

        // If the protected Run key still contains one of our values, disabling is incomplete and must be visible.
        if (registryFailure is not null && HasRunValue())
            throw new UnauthorizedAccessException(
                "Windows protected an existing TraceBrake startup registry entry from removal.", registryFailure);
    }

    /// <summary>
    /// If start-with-Windows is on, returns a warning when the registered exe lives on a drive that may be
    /// absent at sign-in (removable / network / a secondary-fixed disk like W: that can be disconnected or
    /// mount late) — the classic "it silently didn't start at boot" cause. Null when off, safe, or unknown.
    /// Reads the live registry value + the target drive's OS type; best-effort.
    /// </summary>
    public static string? GetDriveWarning()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(StartupRegistration.RunKeyPath);
            var value = (key?.GetValue(StartupRegistration.RunValueName) as string)
                     ?? StartupRegistration.LegacyRunValueNames.Select(n => key?.GetValue(n) as string).FirstOrDefault(v => v is not null);
            if (value is null && File.Exists(StartupShortcutPath) && Environment.ProcessPath is { } currentExe)
                value = StartupRegistration.BuildCommand(currentExe);
            var exe = StartupRegistration.ParseExePath(value);
            if (exe is null) return null;   // feature off / malformed

            var root = Path.GetPathRoot(exe);
            var driveType = DriveType.Unknown;
            try { if (!string.IsNullOrEmpty(root)) driveType = new DriveInfo(root).DriveType; }
            catch { /* drive absent right now — ClassifyDriveRisk still flags it via the root != system-drive check */ }

            var systemRoot = Path.GetPathRoot(Environment.SystemDirectory);   // e.g. "C:\"
            var risk = StartupRegistration.ClassifyDriveRisk(exe, systemRoot, driveType);
            return StartupRegistration.DescribeDriveRisk(risk, exe);
        }
        catch { return null; }
    }

    /// <summary>
    /// Called once at app launch: if the feature is on but the registered exe has moved
    /// or the value is malformed, re-point it at the running exe. Best-effort — startup
    /// must never fail over a registry hiccup.
    /// </summary>
    public static void RepairIfNeeded()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(StartupRegistration.RunKeyPath, writable: true);
            var currentValue = key?.GetValue(StartupRegistration.RunValueName) as string;
            // First present legacy alias ("Foreman", "ForemanAgentSafety", …) from any older build.
            var legacyValue = StartupRegistration.LegacyRunValueNames
                .Select(n => key?.GetValue(n) as string)
                .FirstOrDefault(v => v is not null);
            if (currentValue is null && legacyValue is null)
            {
                // Startup-folder fallback is also a durable opt-in. Recreate it from the running product on every
                // launch so an upgrade or Debug/Release transition cannot strand startup on an older executable.
                if (File.Exists(StartupShortcutPath) && Environment.ProcessPath is { } shortcutExe)
                    CreateStartupShortcut(shortcutExe);
                return;
            }

            var value = currentValue ?? legacyValue!;
            var current = Environment.ProcessPath;
            if (current is null) return;

            if (StartupRegistration.NeedsRepair(value, current, File.Exists))
                key!.SetValue(StartupRegistration.RunValueName, StartupRegistration.BuildCommand(current));
            else if (currentValue is null)
                key!.SetValue(StartupRegistration.RunValueName, value);   // migrate a legacy-only entry to the canonical name

            // Always remove EVERY legacy alias so a stale duplicate (e.g. the no-space name) can't double-launch at logon.
            foreach (var name in StartupRegistration.LegacyRunValueNames)
                key!.DeleteValue(name, throwOnMissingValue: false);

            // HKCU Run is authoritative when available; remove a fallback left by an earlier protected-key session.
            DeleteStartupShortcuts();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or SecurityException)
        {
            // If the operator already opted in through the fallback backend, preserve that intent and retarget it
            // to this build. Do not attempt to weaken or bypass the Run-key protection layer.
            if (File.Exists(StartupShortcutPath) && Environment.ProcessPath is { } current)
            {
                try { CreateStartupShortcut(current); } catch { /* best-effort startup repair */ }
            }
        }
        catch { /* best-effort */ }
    }

    private static bool HasRunValue()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(StartupRegistration.RunKeyPath);
            return key?.GetValue(StartupRegistration.RunValueName) is string
                || StartupRegistration.LegacyRunValueNames.Any(n => key?.GetValue(n) is string);
        }
        catch { return true; } // unreadable after a failed removal: fail closed; do not claim startup is disabled
    }

    private static void DeleteLegacyRunValues(RegistryKey key)
    {
        foreach (var name in StartupRegistration.LegacyRunValueNames)
            key.DeleteValue(name, throwOnMissingValue: false);
    }

    private static void DeleteStartupShortcuts()
    {
        File.Delete(StartupShortcutPath);
        var startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        foreach (var legacyName in LegacyStartupShortcutNames)
            File.Delete(Path.Combine(startup, legacyName));
    }

    private static void CreateStartupShortcut(string exe)
    {
        var startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        if (string.IsNullOrWhiteSpace(startup))
            throw new InvalidOperationException("Windows did not provide a per-user Startup folder.");

        Directory.CreateDirectory(startup);
        var finalPath = StartupShortcutPath;
        var temporaryPath = Path.Combine(startup, $"TraceBrake.{Guid.NewGuid():N}.lnk");
        object? shell = null;
        object? shortcut = null;
        try
        {
            var shellType = Type.GetTypeFromProgID("WScript.Shell")
                ?? throw new PlatformNotSupportedException("Windows Script Host shortcut support is unavailable.");
            shell = Activator.CreateInstance(shellType)
                ?? throw new InvalidOperationException("Could not create the Windows shortcut service.");
            shortcut = shellType.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell,
                new object[] { temporaryPath })
                ?? throw new InvalidOperationException("Windows did not create the startup shortcut.");
            var shortcutType = shortcut.GetType();
            shortcutType.InvokeMember("TargetPath", BindingFlags.SetProperty, null, shortcut, new object[] { exe });
            shortcutType.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, shortcut,
                new object[] { Path.GetDirectoryName(exe) ?? string.Empty });
            shortcutType.InvokeMember("Description", BindingFlags.SetProperty, null, shortcut,
                new object[] { "Start TraceBrake when Windows signs in" });
            shortcutType.InvokeMember("IconLocation", BindingFlags.SetProperty, null, shortcut,
                new object[] { $"{exe},0" });
            shortcutType.InvokeMember("Save", BindingFlags.InvokeMethod, null, shortcut, null);
            File.Move(temporaryPath, finalPath, overwrite: true);
            foreach (var legacyName in LegacyStartupShortcutNames)
                File.Delete(Path.Combine(startup, legacyName));
        }
        finally
        {
            try { if (File.Exists(temporaryPath)) File.Delete(temporaryPath); } catch { }
            if (shortcut is not null && Marshal.IsComObject(shortcut)) Marshal.FinalReleaseComObject(shortcut);
            if (shell is not null && Marshal.IsComObject(shell)) Marshal.FinalReleaseComObject(shell);
        }
    }
}
