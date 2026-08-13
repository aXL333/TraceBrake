using System.Diagnostics;
using System.Runtime.Versioning;

namespace Foreman.Guardian;

/// <summary>
/// Resolves the TraceBrake install reference from the live process that requested elevation. The caller supplies only
/// a PID; the elevated guardian obtains the image path itself and requires its own executable to be the canonical
/// <c>guardian\Foreman.Guardian.exe</c> staged beside that live TraceBrake process.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class GuardianInstallReference
{
    public static bool TryResolve(
        int? foremanPid,
        string? guardianProcessPath,
        out string foremanPath,
        out string reason)
    {
        foremanPath = string.Empty;
        reason = string.Empty;
        if (foremanPid is null or <= 0)
        {
            reason = "a live TraceBrake launcher PID is required.";
            return false;
        }

        try
        {
            using var process = Process.GetProcessById(foremanPid.Value);
            var imagePath = process.MainModule?.FileName;
            if (string.IsNullOrWhiteSpace(imagePath) || !File.Exists(imagePath))
            {
                reason = "the launcher process image could not be resolved.";
                return false;
            }

            var canonicalForeman = CanonicalPath(imagePath);
            var launcherName = Path.GetFileName(canonicalForeman);
            if (!IsSupportedLauncherName(launcherName))
            {
                reason = "the live launcher is not TraceBrake.exe (or the supported legacy Foreman.exe).";
                return false;
            }

            if (string.IsNullOrWhiteSpace(guardianProcessPath))
            {
                reason = "the guardian process image path is unavailable.";
                return false;
            }

            var expectedGuardian = CanonicalPath(Path.Combine(
                Path.GetDirectoryName(canonicalForeman)!, "guardian", "Foreman.Guardian.exe"));
            var actualGuardian = CanonicalPath(guardianProcessPath);
            if (!string.Equals(expectedGuardian, actualGuardian, StringComparison.OrdinalIgnoreCase))
            {
                reason = "the elevated guardian was not launched from TraceBrake's canonical staged guardian path.";
                return false;
            }

            foremanPath = canonicalForeman;
            reason = $"resolved {launcherName} from the live launcher process.";
            return true;
        }
        catch (Exception ex)
        {
            reason = $"the live TraceBrake launcher could not be verified: {ex.Message}";
            return false;
        }
    }

    internal static bool LayoutMatches(string foremanPath, string guardianPath)
    {
        try
        {
            var expected = CanonicalPath(Path.Combine(
                Path.GetDirectoryName(CanonicalPath(foremanPath))!, "guardian", "Foreman.Guardian.exe"));
            return string.Equals(expected, CanonicalPath(guardianPath), StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    internal static bool IsSupportedLauncherName(string? fileName) =>
        string.Equals(fileName, "TraceBrake.exe", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(fileName, "Foreman.exe", StringComparison.OrdinalIgnoreCase);

    private static string CanonicalPath(string path) =>
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
}
