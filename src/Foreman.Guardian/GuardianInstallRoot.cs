using Microsoft.Win32;
using System.Runtime.Versioning;

namespace Foreman.Guardian;

/// <summary>Administrator-owned install-root anchor for Guardian installation decisions.</summary>
[SupportedOSPlatform("windows")]
internal static class GuardianInstallRoot
{
    // Published SYSTEM-owned security anchor. Keep the legacy registry path so an in-place upgrade reads the
    // same trust root; this is an internal compatibility identifier, not public branding.
    private const string KeyPath = @"SOFTWARE\Foreman Agent Safety";
    private const string ValueName = "InstallRoot";

    public static string? Read()
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = hklm.OpenSubKey(KeyPath, writable: false);
        return key?.GetValue(ValueName) as string;
    }

    public static void Write(string root)
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = hklm.CreateSubKey(KeyPath, writable: true)
            ?? throw new InvalidOperationException("Could not create the Guardian install-root registry key.");
        key.SetValue(ValueName, Canonical(root), RegistryValueKind.String);
    }

    public static void Restore(string? priorRoot)
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = hklm.CreateSubKey(KeyPath, writable: true)
            ?? throw new InvalidOperationException("Could not restore the Guardian install-root registry key.");
        if (string.IsNullOrWhiteSpace(priorRoot)) key.DeleteValue(ValueName, throwOnMissingValue: false);
        else key.SetValue(ValueName, Canonical(priorRoot), RegistryValueKind.String);
    }

    public static string RootForExecutable(string executablePath) =>
        Canonical(Path.GetDirectoryName(Path.GetFullPath(executablePath))
                  ?? throw new InvalidOperationException("Executable directory is unavailable."));

    private static string Canonical(string path) =>
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
}
