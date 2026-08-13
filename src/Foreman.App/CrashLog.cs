using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Foreman.App;

/// <summary>
/// Best-effort fault log at %LocalAppData%\TraceBrake\crash.log. A watchdog must survive transient UI faults
/// (the tray Shell_NotifyIcon API is flaky across Explorer restarts) and RECORD them, not crash. Never throws.
/// </summary>
internal static class CrashLog
{
    private static readonly object Gate = new();
    private static readonly TimeSpan RepeatWindow = TimeSpan.FromMinutes(5);
    private const long MaxBytes = 1024 * 1024;
    private static string? _lastSignature;
    private static DateTimeOffset _lastOccurrence;
    private static int _suppressed;

    public static void Note(string context, Exception ex)
    {
        try
        {
            var now = DateTimeOffset.UtcNow;
            var message = ex.Message.Length > 4096 ? ex.Message[..4096] + "…[truncated]" : ex.Message;
            var fingerprintText = Foreman.Core.Security.SecretRedactor.Redact(
                $"{context}|{ex.GetType().FullName}|{message}");
            var signature = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fingerprintText)));
            lock (Gate)
            {
                if (string.Equals(signature, _lastSignature, StringComparison.Ordinal) &&
                    now - _lastOccurrence < RepeatWindow)
                {
                    _lastOccurrence = now;
                    _suppressed++;
                    return;
                }

                var dir = Foreman.Core.ProductIdentity.LocalDataRoot;
                Directory.CreateDirectory(dir);
                var path = Path.Combine(dir, "crash.log");
                var repeatNote = _suppressed > 0
                    ? $"[{now:O}] CrashLog: suppressed {_suppressed} repeated occurrence(s) of the prior fault.\n\n"
                    : string.Empty;
                var detail = Foreman.Core.Security.SecretRedactor.Redact($"[{now:O}] {context}: {ex}");
                if (detail.Length > 128 * 1024)
                    detail = detail[..(128 * 1024)] + "\n…[crash detail truncated]";
                var entry = repeatNote + detail + "\n\n";
                var bytes = Encoding.UTF8.GetByteCount(entry);
                if (File.Exists(path) && new FileInfo(path).Length + bytes > MaxBytes)
                {
                    var prior = path + ".1";
                    if (File.Exists(prior)) File.Delete(prior);
                    File.Move(path, prior);
                }
                File.AppendAllText(path, entry, Encoding.UTF8);
                _lastSignature = signature;
                _lastOccurrence = now;
                _suppressed = 0;
            }
        }
        catch { /* logging must never throw */ }
    }
}
