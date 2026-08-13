using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Foreman.Core.ComputerUse;

/// <summary>
/// Configuration for TraceBrake's bounded Android Debug Bridge executor. The executable is an absolute, operator-chosen
/// path (never a PATH lookup) and every target serial must be explicitly enrolled before a device-scoped action can
/// enter the broker.
/// </summary>
public sealed record AdbBridgeOptions(
    string ExecutablePath,
    string ExecutableSha256,
    IReadOnlyCollection<string> EnrolledSerials,
    TimeSpan CommandTimeout)
{
    /// <summary>APK transfer/package-manager work is slower than interactive input, but remains bounded.</summary>
    public TimeSpan InstallTimeout { get; init; } = TimeSpan.FromMinutes(5);

    public static AdbBridgeOptions Create(
        string executablePath,
        IEnumerable<string>? enrolledSerials,
        string? executableSha256 = null,
        TimeSpan? commandTimeout = null,
        TimeSpan? installTimeout = null) =>
        new(
            executablePath,
            (executableSha256 ?? string.Empty).Trim().ToUpperInvariant(),
            (enrolledSerials ?? [])
                .Select(static s => (s ?? string.Empty).Trim())
                .Where(static s => s.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            commandTimeout ?? TimeSpan.FromSeconds(30))
        {
            InstallTimeout = installTimeout ?? TimeSpan.FromMinutes(5),
        };
}

public sealed record AdbCommandResult(int ExitCode, byte[] StandardOutput, string StandardError);

/// <summary>Small seam around adb process execution so command construction and executor behaviour are unit-testable.</summary>
public interface IAdbCommandRunner
{
    bool IsAvailable { get; }
    Task<AdbCommandResult> RunAsync(
        IReadOnlyList<string> arguments,
        int maxOutputBytes,
        TimeSpan timeout,
        CancellationToken ct = default);
    void CancelCurrent();
}

/// <summary>
/// Launches one fixed adb executable without a shell. ArgumentList is used throughout, output is bounded, and a panic
/// can kill the current adb client process tree. TraceBrake never exposes this runner directly to an MCP caller.
/// </summary>
public sealed class AdbProcessRunner : IAdbCommandRunner, IDisposable
{
    private readonly string _executablePath;
    private readonly string _launchPath;
    private readonly FileStream? _binaryPin;
    private readonly string? _unavailableReason;
    private readonly object _gate = new();
    private Process? _current;

    public AdbProcessRunner(string executablePath, string? expectedSha256 = null)
    {
        _executablePath = executablePath ?? string.Empty;
        _launchPath = _executablePath;
        try
        {
            if (!Path.IsPathFullyQualified(_executablePath) || !File.Exists(_executablePath))
            {
                _unavailableReason = "The configured adb executable is unavailable.";
                return;
            }

            // Pin the enrolled binary against write/delete for TraceBrake's lifetime. This closes the hash-check→launch
            // replacement window and deliberately makes an SDK update require closing TraceBrake + re-enrolling the hash.
            _binaryPin = new FileStream(_executablePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            _launchPath = ResolveFinalPath(_binaryPin) ?? Path.GetFullPath(_executablePath);
            var actual = ComputeSha256(_binaryPin);
            var expected = (expectedSha256 ?? string.Empty).Trim();
            if (expected.Length > 0 && !string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
            {
                _binaryPin.Dispose();
                _binaryPin = null;
                _unavailableReason = "The adb executable changed since the operator enrolled it.";
            }
        }
        catch (Exception ex)
        {
            _binaryPin?.Dispose();
            _binaryPin = null;
            _unavailableReason = $"The adb executable could not be pinned: {ex.Message}";
        }
    }

    public bool IsAvailable => _binaryPin is not null;

    public async Task<AdbCommandResult> RunAsync(
        IReadOnlyList<string> arguments,
        int maxOutputBytes,
        TimeSpan timeout,
        CancellationToken ct = default)
    {
        if (!IsAvailable)
            return new AdbCommandResult(-1, [], _unavailableReason ?? "The configured adb executable is unavailable.");
        if (maxOutputBytes is < 1 or > 16 * 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(maxOutputBytes));

        var psi = new ProcessStartInfo
        {
            // Launch the final path resolved from the PINNED file handle, not the configurable path text. An NTFS
            // junction swap of a parent directory can no longer redirect a later Process.Start to different bytes.
            FileName = _launchPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = false,
        };
        // Do not inherit caller-controlled ADB routing. In particular, ADB_SERVER_SOCKET can redirect the trusted
        // client to a remote/untrusted server and ANDROID_SERIAL can create an implicit target. TraceBrake always uses
        // the local ADB server and supplies an explicit enrolled serial for device-scoped commands.
        psi.Environment.Remove("ADB_SERVER_SOCKET");
        psi.Environment.Remove("ANDROID_ADB_SERVER_PORT");
        psi.Environment.Remove("ANDROID_SERIAL");
        foreach (var arg in arguments)
            psi.ArgumentList.Add(arg);

        using var process = new Process { StartInfo = psi };

        try
        {
            // Publish + start under the same lock used by CancelCurrent. A panic can therefore happen before publish,
            // or wait until Start returns and kill the live client; it cannot fall into a pre-start gap and be lost.
            lock (_gate)
            {
                if (_current is not null)
                    throw new InvalidOperationException("Another adb command is already running.");
                _current = process;
                if (!process.Start())
                    return new AdbCommandResult(-1, [], "adb did not start.");
            }

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(timeout);
            var stdout = ReadBoundedAsync(process.StandardOutput.BaseStream, maxOutputBytes, timeoutCts.Token);
            var stderr = ReadBoundedAsync(process.StandardError.BaseStream, 64 * 1024, timeoutCts.Token);

            try
            {
                await process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
                var outBytes = await stdout.ConfigureAwait(false);
                var errBytes = await stderr.ConfigureAwait(false);
                return new AdbCommandResult(
                    process.ExitCode,
                    outBytes,
                    Encoding.UTF8.GetString(errBytes));
            }
            catch (OperationCanceledException)
            {
                TryKill(process);
                return new AdbCommandResult(-1, [], ct.IsCancellationRequested
                    ? "adb action cancelled."
                    : $"adb action timed out after {timeout.TotalSeconds:0} seconds.");
            }
            catch (InvalidDataException ex)
            {
                TryKill(process);
                return new AdbCommandResult(-1, [], ex.Message);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            TryKill(process);
            return new AdbCommandResult(-1, [], $"adb failed: {ex.Message}");
        }
        finally
        {
            lock (_gate)
            {
                if (ReferenceEquals(_current, process))
                    _current = null;
            }
        }
    }

    public void CancelCurrent()
    {
        Process? process;
        lock (_gate) process = _current;
        if (process is not null) TryKill(process);
    }

    public void Dispose()
    {
        CancelCurrent();
        _binaryPin?.Dispose();
    }

    public static string ComputeSha256(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return ComputeSha256(stream);
    }

    private static string ComputeSha256(Stream stream)
    {
        stream.Position = 0;
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    internal static string? ResolveFinalPath(FileStream stream)
    {
        if (!OperatingSystem.IsWindows()) return Path.GetFullPath(stream.Name);
        var buffer = new StringBuilder(1024);
        var length = GetFinalPathNameByHandle(stream.SafeFileHandle, buffer, (uint)buffer.Capacity, 0);
        if (length == 0) return null;
        if (length >= buffer.Capacity)
        {
            buffer = new StringBuilder(checked((int)length + 1));
            length = GetFinalPathNameByHandle(stream.SafeFileHandle, buffer, (uint)buffer.Capacity, 0);
            if (length == 0 || length >= buffer.Capacity) return null;
        }
        return NormalizeExtendedPath(buffer.ToString());
    }

    private static string NormalizeExtendedPath(string path)
    {
        const string uncPrefix = @"\\?\UNC\";
        const string localPrefix = @"\\?\";
        if (path.StartsWith(uncPrefix, StringComparison.OrdinalIgnoreCase))
            return @"\\" + path[uncPrefix.Length..];
        return path.StartsWith(localPrefix, StringComparison.OrdinalIgnoreCase)
            ? path[localPrefix.Length..]
            : path;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        Microsoft.Win32.SafeHandles.SafeFileHandle hFile,
        StringBuilder lpszFilePath,
        uint cchFilePath,
        uint dwFlags);

    private static async Task<byte[]> ReadBoundedAsync(Stream stream, int cap, CancellationToken ct)
    {
        using var output = new MemoryStream(Math.Min(cap, 64 * 1024));
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false);
            if (read == 0) break;
            if (output.Length + read > cap)
                throw new InvalidDataException($"adb output exceeded the {cap / 1024} KiB safety cap.");
            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }

    private static void TryKill(Process process)
    {
        try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
        catch { /* best-effort panic/timeout cancellation */ }
    }
}

/// <summary>
/// The in-process executor for TraceBrake's Android modality. It accepts only the structured verbs below, targets only
/// enrolled device serials, performs a fresh device-state check, and never offers raw adb shell/exec access.
/// </summary>
public sealed class AdbBridgeExecutor : ICuExecutor, IDisposable
{
    private const int TextOutputCap = 2 * 1024 * 1024;
    private const int ScreenshotOutputCap = 8 * 1024 * 1024;
    private const long MaxApkBytes = 2L * 1024 * 1024 * 1024;
    private readonly AdbBridgeOptions _options;
    private readonly IAdbCommandRunner _runner;
    private readonly HashSet<string> _enrolled;
    private readonly Func<bool> _isHalted;

    public AdbBridgeExecutor(AdbBridgeOptions options, IAdbCommandRunner? runner = null, Func<bool>? isHalted = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _runner = runner ?? new AdbProcessRunner(options.ExecutablePath, options.ExecutableSha256);
        _enrolled = new HashSet<string>(options.EnrolledSerials, StringComparer.OrdinalIgnoreCase);
        _isHalted = isHalted ?? (() => false);
    }

    public CuModality Modality => CuModality.Android;
    public bool IsReady => _runner.IsAvailable;
    public string ExecutablePath => _options.ExecutablePath;
    public IReadOnlyList<string> EnrolledSerials => _enrolled.Order(StringComparer.OrdinalIgnoreCase).ToArray();

    /// <summary>
    /// Resolves and fingerprints an APK before the action is audited or approved. Caller-supplied fingerprint/size
    /// fields are overwritten, so approval is bound to the exact bytes TraceBrake observed rather than an agent claim.
    /// The executor pins and verifies the same tuple again immediately before invoking adb.
    /// </summary>
    public static async Task<(CuAction? Action, string? Error)> PrepareInstallActionAsync(
        CuAction action,
        CancellationToken ct = default)
    {
        if (!string.Equals(action.Verb?.Trim(), "install", StringComparison.OrdinalIgnoreCase))
            return (action, null);

        var requestedPath = action.Arg("apkPath").Trim();
        if (!TryOpenApk(requestedPath, out var pin, out var error))
            return (null, error);

        using (var preparedPin = pin!)
        {
            string hash;
            try { hash = await preparedPin.ComputeSha256Async(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return (null, "APK fingerprinting was cancelled."); }
            catch (Exception ex) { return (null, $"Could not fingerprint the APK: {ex.Message}"); }

            var args = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (key, value) in action.Args)
                args[key] = value;
            args["apkPath"] = preparedPin.CanonicalPath;
            args["apkSha256"] = hash;
            args["apkBytes"] = preparedPin.Length.ToString(CultureInfo.InvariantCulture);

            foreach (var flag in new[] { "replace", "allowDowngrade", "grantPermissions" })
            {
                if (!TryBooleanFlag(action.Arg(flag), out var enabled))
                    return (null, $"{flag} must be true or false.");
                args[flag] = enabled ? "true" : "false";
            }

            return (action with { Args = args }, null);
        }
    }

    public async Task<CuExecResult> ExecuteAsync(CuBrokerItem item, CancellationToken ct = default)
    {
        if (_isHalted()) return Fail("Computer use is halted by the operator panic stop.");
        if (item.Action.Modality != CuModality.Android)
            return Fail("The ADB bridge only executes Android actions.");
        if (!CuVerbs.IsKnownAndroid(item.Action.Verb))
            return Fail("Unsupported Android verb.");

        var verb = item.Action.Verb.Trim().ToLowerInvariant();
        if (verb == "devices")
        {
            var inventory = await _runner.RunAsync(
                ["devices", "-l"], 256 * 1024, _options.CommandTimeout, ct).ConfigureAwait(false);
            if (inventory.ExitCode != 0) return FromFailure(inventory);
            return new CuExecResult(true, new
            {
                devices = ParseDevices(Text(inventory.StandardOutput), _enrolled),
                enrolledSerials = EnrolledSerials,
            }, null);
        }

        var serial = item.Action.Arg("serial").Trim();
        if (!_enrolled.Contains(serial))
            return Fail("Target device is not enrolled.");

        // Re-check immediately before every scoped operation. "unauthorized", "offline", or a disconnected/recycled
        // endpoint fails closed rather than sending the approved action somewhere ambiguous.
        var state = await _runner.RunAsync(
            ["-s", serial, "get-state"], 16 * 1024, _options.CommandTimeout, ct).ConfigureAwait(false);
        if (state.ExitCode != 0 || !string.Equals(Text(state.StandardOutput).Trim(), "device", StringComparison.Ordinal))
            return Fail($"Enrolled device '{serial}' is not connected and authorised.");

        // Panic may have fired while get-state was running. Re-check before any APK hashing and again at the final
        // boundary below so a halt cannot lose either the get-state gap or a slow package-validation gap.
        if (_isHalted()) return Fail("Computer use was halted before the Android action could execute.");

        PinnedApk? apkPin = null;
        try
        {
            if (verb == "install")
            {
                if (!TryOpenApk(item.Action.Arg("apkPath"), out apkPin, out var pinError))
                    return Fail(pinError);
                var verifiedPin = apkPin!;

                var expectedHash = item.Action.Arg("apkSha256").Trim();
                var expectedBytes = item.Action.Arg("apkBytes").Trim();
                if (!IsSha256(expectedHash)
                    || !long.TryParse(expectedBytes, NumberStyles.None, CultureInfo.InvariantCulture, out var expectedLength))
                    return Fail("The APK action is missing TraceBrake's approved fingerprint.");
                if (!PathsEqual(verifiedPin.CanonicalPath, item.Action.Arg("apkPath").Trim()))
                    return Fail("The APK path changed after approval.");
                if (verifiedPin.Length != expectedLength)
                    return Fail("The APK size changed after approval.");

                string actualHash;
                try { actualHash = await verifiedPin.ComputeSha256Async(ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return Fail("APK verification was cancelled."); }
                catch (Exception ex) { return Fail($"Could not verify the APK: {ex.Message}"); }
                if (!string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
                    return Fail("The APK contents changed after approval.");
            }

            // Hashing a large package can take materially longer than get-state. Panic must still win before adb
            // receives the install request.
            if (_isHalted()) return Fail("Computer use was halted before the Android action could execute.");

            if (!TryBuildArguments(item.Action, serial, out var arguments, out var error))
                return Fail(error);

            var cap = verb == "screenshot" ? ScreenshotOutputCap : TextOutputCap;
            var timeout = verb == "install" ? _options.InstallTimeout : _options.CommandTimeout;
            var result = await _runner.RunAsync(arguments, cap, timeout, ct).ConfigureAwait(false);
            if (result.ExitCode != 0) return FromFailure(result);

            if (verb == "screenshot")
            {
                return new CuExecResult(true, new
                {
                    serial,
                    mimeType = "image/png",
                    bytes = result.StandardOutput.Length,
                    base64 = Convert.ToBase64String(result.StandardOutput),
                }, null);
            }

            var output = Foreman.Core.Security.SecretRedactor.Redact(Text(result.StandardOutput));
            if (verb == "install")
            {
                return new CuExecResult(true, new
                {
                    serial,
                    installed = true,
                    apkPath = item.Action.Arg("apkPath"),
                    apkSha256 = item.Action.Arg("apkSha256"),
                    apkBytes = apkPin!.Length,
                    output,
                }, null);
            }

            return new CuExecResult(true, new { serial, output }, null);
        }
        finally
        {
            apkPin?.Dispose();
        }
    }

    /// <summary>Best-effort immediate stop for the current adb client. Pending actions remain blocked by CuPanicState.</summary>
    public void PanicStop() => _runner.CancelCurrent();

    public void Dispose()
    {
        if (_runner is IDisposable disposable)
            disposable.Dispose();
        else
            _runner.CancelCurrent();
    }

    public static bool TryBuildArguments(
        CuAction action,
        string serial,
        out IReadOnlyList<string> arguments,
        out string error)
    {
        arguments = [];
        error = string.Empty;
        if (!IsSafeSerial(serial))
        {
            error = "Invalid Android device serial.";
            return false;
        }

        switch (action.Verb.Trim().ToLowerInvariant())
        {
            case "screenshot":
                arguments = ["-s", serial, "exec-out", "screencap", "-p"];
                return true;
            case "ui_dump":
                arguments = ["-s", serial, "exec-out", "uiautomator", "dump", "/dev/tty"];
                return true;
            case "logcat":
                if (!TryInt(action.Arg("lines"), 1, 500, defaultValue: 200, out var lines))
                {
                    error = "logcat lines must be an integer from 1 to 500.";
                    return false;
                }
                arguments = ["-s", serial, "logcat", "-d", "-t", lines.ToString(CultureInfo.InvariantCulture)];
                return true;
            case "install":
                var apkPath = action.Arg("apkPath").Trim();
                if (!Path.IsPathFullyQualified(apkPath)
                    || !string.Equals(Path.GetExtension(apkPath), ".apk", StringComparison.OrdinalIgnoreCase)
                    || !IsSha256(action.Arg("apkSha256"))
                    || !long.TryParse(action.Arg("apkBytes"), NumberStyles.None, CultureInfo.InvariantCulture, out var apkBytes)
                    || apkBytes is < 1 or > MaxApkBytes)
                {
                    error = "install requires a Foreman-prepared absolute .apk path and fingerprint.";
                    return false;
                }
                if (!TryBooleanFlag(action.Arg("replace"), out var replace)
                    || !TryBooleanFlag(action.Arg("allowDowngrade"), out var allowDowngrade)
                    || !TryBooleanFlag(action.Arg("grantPermissions"), out var grantPermissions))
                {
                    error = "install flags replace, allowDowngrade and grantPermissions must be true or false.";
                    return false;
                }
                var install = new List<string> { "-s", serial, "install" };
                if (replace) install.Add("-r");
                if (allowDowngrade) install.Add("-d");
                if (grantPermissions) install.Add("-g");
                install.Add(apkPath);
                arguments = install;
                return true;
            case "tap":
                if (!TryCoordinate(action, "x", out var tx) || !TryCoordinate(action, "y", out var ty))
                {
                    error = "tap requires integer x/y coordinates from 0 to 100000.";
                    return false;
                }
                arguments = ["-s", serial, "shell", "input", "tap", tx, ty];
                return true;
            case "swipe":
                if (!TryCoordinate(action, "x1", out var x1) || !TryCoordinate(action, "y1", out var y1)
                    || !TryCoordinate(action, "x2", out var x2) || !TryCoordinate(action, "y2", out var y2)
                    || !TryInt(action.Arg("durationMs"), 0, 10_000, defaultValue: 300, out var duration))
                {
                    error = "swipe requires x1/y1/x2/y2 coordinates and optional durationMs from 0 to 10000.";
                    return false;
                }
                arguments =
                [
                    "-s", serial, "shell", "input", "swipe", x1, y1, x2, y2,
                    duration.ToString(CultureInfo.InvariantCulture),
                ];
                return true;
            case "type":
                var text = action.Arg("text");
                if (!TryEncodeInputText(text, out var encoded))
                {
                    error = "Android text must be 1-1000 characters and use only letters, numbers, spaces, or .,_@:/+-.";
                    return false;
                }
                arguments = ["-s", serial, "shell", "input", "text", encoded];
                return true;
            case "key":
                if (!TryKey(action.Arg("key"), out var key))
                {
                    error = "Unsupported Android key. Allowed: back, home, enter, tab, delete, escape, dpad directions, app_switch, volume_up/down/mute.";
                    return false;
                }
                arguments = ["-s", serial, "shell", "input", "keyevent", key];
                return true;
            default:
                error = "Unsupported Android verb.";
                return false;
        }
    }

    private static readonly Regex SafeSerial = new(
        "^[A-Za-z0-9._:-]{1,128}$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(50));

    public static bool IsSafeSerial(string? serial)
    {
        try { return SafeSerial.IsMatch((serial ?? string.Empty).Trim()); }
        catch (RegexMatchTimeoutException) { return false; }
    }

    private static bool TryCoordinate(CuAction action, string name, out string canonical)
    {
        canonical = string.Empty;
        if (!int.TryParse(action.Arg(name), NumberStyles.None, CultureInfo.InvariantCulture, out var value)
            || value is < 0 or > 100_000)
            return false;
        canonical = value.ToString(CultureInfo.InvariantCulture);
        return true;
    }

    private static bool TryInt(string text, int min, int max, int defaultValue, out int value)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            value = defaultValue;
            return true;
        }
        return int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value)
               && value >= min && value <= max;
    }

    private static bool TryBooleanFlag(string? text, out bool value)
    {
        var normalized = (text ?? string.Empty).Trim();
        if (normalized.Length == 0)
        {
            value = false;
            return true;
        }
        if (bool.TryParse(normalized, out value)) return true;
        if (normalized == "1") { value = true; return true; }
        if (normalized == "0") { value = false; return true; }
        value = false;
        return false;
    }

    private static bool IsSha256(string? value)
    {
        var text = (value ?? string.Empty).Trim();
        return text.Length == 64 && text.All(Uri.IsHexDigit);
    }

    private static bool PathsEqual(string left, string right) =>
        string.Equals(left, right, OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal);

    private static bool TryOpenApk(string? path, out PinnedApk? pin, out string error)
    {
        pin = null;
        error = string.Empty;
        var requested = (path ?? string.Empty).Trim();
        if (!Path.IsPathFullyQualified(requested)
            || !string.Equals(Path.GetExtension(requested), ".apk", StringComparison.OrdinalIgnoreCase))
        {
            error = "install requires apkPath to be an absolute .apk file path.";
            return false;
        }
        if (OperatingSystem.IsWindows())
        {
            // SMB servers are not obliged to honour local Win32 sharing semantics across clients, so a remote APK
            // cannot satisfy the pin-until-adb-opens-it invariant. Copy it to a local drive first.
            if (requested.StartsWith(@"\\", StringComparison.Ordinal))
            {
                error = "APK packages must be on a local drive; copy the file locally before installing it.";
                return false;
            }
            try
            {
                var root = Path.GetPathRoot(requested);
                if (!string.IsNullOrWhiteSpace(root) && new DriveInfo(root).DriveType == DriveType.Network)
                {
                    error = "APK packages must be on a local drive; copy the file locally before installing it.";
                    return false;
                }
            }
            catch (Exception ex)
            {
                error = $"APK drive could not be verified: {ex.Message}";
                return false;
            }
        }

        try
        {
            var stream = new FileStream(
                requested,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            try
            {
                var canonical = AdbProcessRunner.ResolveFinalPath(stream) ?? Path.GetFullPath(requested);
                if (OperatingSystem.IsWindows() && canonical.StartsWith(@"\\", StringComparison.Ordinal))
                    throw new InvalidDataException("The resolved APK is not on a local drive.");
                if (!string.Equals(Path.GetExtension(canonical), ".apk", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("The resolved package is not an .apk file.");
                if (stream.Length is < 1 or > MaxApkBytes)
                    throw new InvalidDataException($"APK size must be between 1 byte and {MaxApkBytes / (1024 * 1024)} MiB.");
                pin = new PinnedApk(stream, canonical, stream.Length);
                return true;
            }
            catch
            {
                stream.Dispose();
                throw;
            }
        }
        catch (Exception ex)
        {
            error = $"APK could not be opened and pinned: {ex.Message}";
            return false;
        }
    }

    private sealed class PinnedApk(FileStream stream, string canonicalPath, long length) : IDisposable
    {
        private readonly FileStream _stream = stream;
        public string CanonicalPath { get; } = canonicalPath;
        public long Length { get; } = length;

        public async Task<string> ComputeSha256Async(CancellationToken ct)
        {
            _stream.Position = 0;
            var hash = await SHA256.HashDataAsync(_stream, ct).ConfigureAwait(false);
            _stream.Position = 0;
            return Convert.ToHexString(hash);
        }

        public void Dispose() => _stream.Dispose();
    }

    private static bool TryEncodeInputText(string text, out string encoded)
    {
        encoded = string.Empty;
        if (string.IsNullOrEmpty(text) || text.Length > 1000) return false;
        foreach (var c in text)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is ' ' or '.' or ',' or '_' or '@' or ':' or '/' or '+' or '-'))
                return false;
        }
        encoded = text.Replace(" ", "%s", StringComparison.Ordinal);
        return true;
    }

    private static readonly Dictionary<string, string> Keys = new(StringComparer.OrdinalIgnoreCase)
    {
        ["back"] = "KEYCODE_BACK",
        ["home"] = "KEYCODE_HOME",
        ["enter"] = "KEYCODE_ENTER",
        ["tab"] = "KEYCODE_TAB",
        ["delete"] = "KEYCODE_DEL",
        ["del"] = "KEYCODE_DEL",
        ["escape"] = "KEYCODE_ESCAPE",
        ["dpad_up"] = "KEYCODE_DPAD_UP",
        ["dpad_down"] = "KEYCODE_DPAD_DOWN",
        ["dpad_left"] = "KEYCODE_DPAD_LEFT",
        ["dpad_right"] = "KEYCODE_DPAD_RIGHT",
        ["dpad_center"] = "KEYCODE_DPAD_CENTER",
        ["app_switch"] = "KEYCODE_APP_SWITCH",
        ["volume_up"] = "KEYCODE_VOLUME_UP",
        ["volume_down"] = "KEYCODE_VOLUME_DOWN",
        ["volume_mute"] = "KEYCODE_VOLUME_MUTE",
    };

    private static bool TryKey(string? value, out string key) =>
        Keys.TryGetValue((value ?? string.Empty).Trim(), out key!);

    private static object[] ParseDevices(string output, IReadOnlySet<string> enrolled) =>
        output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Skip(1)
            .Select(static line => line.Trim())
            .Where(static line => line.Length > 0 && !line.StartsWith("*", StringComparison.Ordinal))
            .Select(line =>
            {
                var fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                var serial = fields.ElementAtOrDefault(0) ?? string.Empty;
                return (object)new
                {
                    serial,
                    state = fields.ElementAtOrDefault(1) ?? "unknown",
                    enrolled = enrolled.Contains(serial),
                    details = fields.Skip(2).Take(12).ToArray(),
                };
            })
            .ToArray();

    private static string Text(byte[] bytes) => Encoding.UTF8.GetString(bytes);

    private static CuExecResult FromFailure(AdbCommandResult result)
    {
        var message = string.IsNullOrWhiteSpace(result.StandardError)
            ? $"adb exited with code {result.ExitCode}."
            : result.StandardError.Trim();
        message = Foreman.Core.Security.SecretRedactor.Redact(message);
        return Fail(message.Length <= 500 ? message : message[..500] + "…");
    }

    private static CuExecResult Fail(string error) => new(false, null, error);
}
