using System.Text;
using Foreman.Core.ComputerUse;

namespace Foreman.Core.Tests.ComputerUse;

public sealed class AdbBridgeTests
{
    private const string AndroidExecutor = "android-test-executor";

    private sealed class Allow : IAuditor
    {
        public Task<CuVerdict> JudgeAsync(CuAction a, CuContext c, CancellationToken ct = default) =>
            Task.FromResult(CuVerdict.Allow("test"));
    }

    private sealed class FakeRunner : IAdbCommandRunner
    {
        public bool IsAvailable { get; set; } = true;
        public bool Cancelled { get; private set; }
        public List<IReadOnlyList<string>> Calls { get; } = [];
        public List<TimeSpan> Timeouts { get; } = [];
        public Queue<AdbCommandResult> Results { get; } = [];
        public Action<IReadOnlyList<string>>? OnRun { get; set; }

        public Task<AdbCommandResult> RunAsync(
            IReadOnlyList<string> arguments,
            int maxOutputBytes,
            TimeSpan timeout,
            CancellationToken ct = default)
        {
            Calls.Add(arguments.ToArray());
            Timeouts.Add(timeout);
            OnRun?.Invoke(arguments);
            return Task.FromResult(Results.Count > 0
                ? Results.Dequeue()
                : new AdbCommandResult(0, Encoding.UTF8.GetBytes("device\n"), string.Empty));
        }

        public void CancelCurrent() => Cancelled = true;
    }

    private static CuAction Android(string verb, Dictionary<string, string>? args = null, string by = "codex") =>
        new(CuModality.Android, verb, args ?? new(), ByHarness: by);

    private static IReadOnlyList<CuBrokerItem> Claim(CuBroker broker, int limit = 5) =>
        broker.Claim(limit, CuModality.Android, AndroidExecutor);

    [Fact]
    public void CommandBuilder_BuildsFixedTapArguments_NoRawCommandString()
    {
        var action = Android("tap", new() { ["x"] = "120", ["y"] = "340" });

        Assert.True(AdbBridgeExecutor.TryBuildArguments(action, "emulator-5554", out var args, out _));
        Assert.Equal(["-s", "emulator-5554", "shell", "input", "tap", "120", "340"], args);
        Assert.DoesNotContain(args, a => a.Contains(';') || a.Contains("&&", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("device;rm -rf /")]
    [InlineData("device && whoami")]
    [InlineData("../transport")]
    [InlineData("")]
    public void SerialInjection_IsRejected(string serial)
    {
        var action = Android("screenshot");
        Assert.False(AdbBridgeExecutor.TryBuildArguments(action, serial, out _, out _));
    }

    [Theory]
    [InlineData("hello;reboot")]
    [InlineData("$(id)")]
    [InlineData("a&b")]
    [InlineData("`whoami`")]
    [InlineData("quote\"")]
    public void TypeShellMetacharacters_AreRejected(string text)
    {
        var action = Android("type", new() { ["text"] = text });
        Assert.False(AdbBridgeExecutor.TryBuildArguments(action, "device-1", out _, out _));
    }

    [Fact]
    public void TypeSpaces_AreEncodedWithoutShellMetacharacters()
    {
        var action = Android("type", new() { ["text"] = "hello Android_1@example.com" });
        Assert.True(AdbBridgeExecutor.TryBuildArguments(action, "device-1", out var args, out _));
        Assert.Equal("hello%sAndroid_1@example.com", args[^1]);
    }

    [Fact]
    public async Task Broker_ObserveOnlyAction_FromApprovedHarness_IsApproved()
    {
        var broker = new CuBroker(new Allow());
        broker.SetDrivers(["codex", "claude-code"]);
        broker.SetAndroidDevices(["device-1"]);

        var item = await broker.SubmitAsync(Android("ui_dump", new() { ["serial"] = "device-1" }), new CuContext("codex"));

        Assert.Equal(CuActionState.Approved, item.State);
        Assert.Single(Claim(broker));
    }

    [Fact]
    public async Task Broker_EachApprovedHarness_CanUseTheSameAndroidModality()
    {
        var broker = new CuBroker(new Allow());
        broker.SetDrivers(["codex", "claude-code"]);
        broker.SetAndroidDevices(["device-1"]);

        var codex = await broker.SubmitAsync(Android("screenshot", new() { ["serial"] = "device-1" }, "codex"), new CuContext("codex"));
        var claude = await broker.SubmitAsync(Android("logcat", new() { ["serial"] = "device-1" }, "claude-code"), new CuContext("claude-code"));
        var cursor = await broker.SubmitAsync(Android("ui_dump", new() { ["serial"] = "device-1" }, "cursor"), new CuContext("cursor"));

        Assert.Equal(CuActionState.Approved, codex.State);
        Assert.Equal(CuActionState.Approved, claude.State);
        Assert.Equal(CuActionState.Blocked, cursor.State);
    }

    [Fact]
    public async Task Broker_Install_FromEveryApprovedHarness_IsFingerprintBoundAndHeld()
    {
        var apk = TempApk("approved package bytes");
        try
        {
            var broker = new CuBroker(new Allow());
            broker.SetDrivers(["codex", "claude-code"]);
            broker.SetAndroidDevices(["device-1"]);
            var claimedHash = new string('0', 64);

            var codex = await broker.SubmitAsync(Android("install", new()
            {
                ["serial"] = "device-1",
                ["apkPath"] = apk,
                ["apkSha256"] = claimedHash,
                ["replace"] = "true",
            }, "codex"), new CuContext("codex"));
            var claude = await broker.SubmitAsync(Android("install", new()
            {
                ["serial"] = "device-1",
                ["apkPath"] = apk,
            }, "claude-code"), new CuContext("claude-code"));

            Assert.Equal(CuActionState.Held, codex.State);
            Assert.Equal(CuActionState.Held, claude.State);
            Assert.NotEqual(claimedHash, codex.Action.Arg("apkSha256"));
            Assert.Equal(AdbProcessRunner.ComputeSha256(apk), codex.Action.Arg("apkSha256"));
            Assert.Equal("true", codex.Action.Arg("replace"));
            Assert.Equal("false", claude.Action.Arg("replace"));
            Assert.Empty(Claim(broker));
        }
        finally
        {
            File.Delete(apk);
        }
    }

    [Fact]
    public async Task Broker_StateChangingAndroidAction_IsHeldUntilOperatorApproves()
    {
        var broker = new CuBroker(new Allow());
        broker.SetDriver("codex");
        broker.SetAndroidDevices(["device-1"]);
        var item = await broker.SubmitAsync(
            Android("tap", new() { ["serial"] = "device-1", ["x"] = "1", ["y"] = "2" }),
            new CuContext("codex"));

        Assert.Equal(CuActionState.Held, item.State);
        Assert.Empty(Claim(broker));
        Assert.True(broker.ApproveHeld(item.ActionId).Ok);
        Assert.Single(Claim(broker));
    }

    [Fact]
    public async Task Broker_UnknownVerbAndUnenrolledDevice_FailClosed()
    {
        var broker = new CuBroker(new Allow());
        broker.SetDriver("codex");
        broker.SetAndroidDevices(["device-1"]);

        var raw = await broker.SubmitAsync(Android("shell", new() { ["serial"] = "device-1" }), new CuContext("codex"));
        var other = await broker.SubmitAsync(Android("screenshot", new() { ["serial"] = "device-2" }), new CuContext("codex"));

        Assert.Equal(CuActionState.Blocked, raw.State);
        Assert.Equal(CuActionState.Blocked, other.State);
    }

    [Fact]
    public async Task Broker_OneEnrolledDevice_IsStampedBeforeAudit()
    {
        var broker = new CuBroker(new Allow());
        broker.SetDriver("codex");
        broker.SetAndroidDevices(["device-1"]);

        var item = await broker.SubmitAsync(Android("screenshot"), new CuContext("codex"));

        Assert.Equal(CuActionState.Approved, item.State);
        Assert.Equal("device-1", item.Action.Arg("serial"));
    }

    [Fact]
    public async Task Broker_PanicRejectsQueuedAndExecutingAndroidActions()
    {
        var broker = new CuBroker(new Allow());
        broker.SetDriver("codex");
        broker.SetAndroidDevices(["device-1"]);
        _ = await broker.SubmitAsync(
            Android("screenshot", new() { ["serial"] = "device-1" }), new CuContext("codex"));
        var executing = Claim(broker, 1).Single();
        var held = await broker.SubmitAsync(
            Android("tap", new() { ["serial"] = "device-1", ["x"] = "1", ["y"] = "2" }), new CuContext("codex"));

        broker.OnPanicHalt();

        Assert.Equal(CuActionState.Rejected, broker.Get(executing.ActionId)!.State);
        Assert.Equal(CuActionState.Rejected, broker.Get(held.ActionId)!.State);
        Assert.Empty(Claim(broker));
    }

    [Fact]
    public async Task Broker_LiveRevocationRejectsPreviouslyApprovedAndroidActions()
    {
        var broker = new CuBroker(new Allow());
        broker.SetDriver("codex");
        broker.SetAndroidDevices(["device-1"]);
        var approved = await broker.SubmitAsync(
            Android("screenshot", new() { ["serial"] = "device-1" }), new CuContext("codex"));

        var count = broker.RevokeModality(CuModality.Android, "settings changed");
        broker.SetAndroidDevices([]);

        Assert.Equal(1, count);
        Assert.Equal(CuActionState.Rejected, broker.Get(approved.ActionId)!.State);
        Assert.Empty(Claim(broker));
    }

    [Fact]
    public async Task Executor_RechecksDeviceState_ThenRunsBoundedCommand()
    {
        var runner = new FakeRunner();
        runner.Results.Enqueue(new AdbCommandResult(0, Encoding.UTF8.GetBytes("device\n"), ""));
        runner.Results.Enqueue(new AdbCommandResult(0, Encoding.UTF8.GetBytes("<hierarchy />"), ""));
        using var executor = new AdbBridgeExecutor(
            AdbBridgeOptions.Create(@"C:\Android\adb.exe", ["device-1"]),
            runner);
        var item = new CuBrokerItem("a1", Android("ui_dump", new() { ["serial"] = "device-1" }),
            CuActionState.Executing, null, DateTimeOffset.UtcNow);

        var result = await executor.ExecuteAsync(item);

        Assert.True(result.Ok);
        Assert.Equal(["-s", "device-1", "get-state"], runner.Calls[0]);
        Assert.Equal(["-s", "device-1", "exec-out", "uiautomator", "dump", "/dev/tty"], runner.Calls[1]);
    }

    [Fact]
    public async Task Executor_Install_UsesPinnedPackageAndFixedOptions()
    {
        var apk = TempApk("installable package bytes");
        try
        {
            var prepared = await AdbBridgeExecutor.PrepareInstallActionAsync(Android("install", new()
            {
                ["serial"] = "device-1",
                ["apkPath"] = apk,
                ["replace"] = "true",
                ["allowDowngrade"] = "false",
                ["grantPermissions"] = "true",
            }));
            Assert.NotNull(prepared.Action);

            var runner = new FakeRunner();
            runner.Results.Enqueue(new AdbCommandResult(0, Encoding.UTF8.GetBytes("device\n"), ""));
            runner.Results.Enqueue(new AdbCommandResult(0, Encoding.UTF8.GetBytes("Success\n"), ""));
            using var executor = new AdbBridgeExecutor(
                AdbBridgeOptions.Create(
                    @"C:\Android\adb.exe",
                    ["device-1"],
                    installTimeout: TimeSpan.FromMinutes(4)),
                runner);
            var item = new CuBrokerItem("a1", prepared.Action!,
                CuActionState.Executing, null, DateTimeOffset.UtcNow);

            var result = await executor.ExecuteAsync(item);

            Assert.True(result.Ok, result.Error);
            Assert.Equal(["-s", "device-1", "get-state"], runner.Calls[0]);
            Assert.Equal(
                ["-s", "device-1", "install", "-r", "-g", prepared.Action!.Arg("apkPath")],
                runner.Calls[1]);
            Assert.Equal(TimeSpan.FromMinutes(4), runner.Timeouts[1]);
            Assert.Contains("\"installed\":true", System.Text.Json.JsonSerializer.Serialize(result.Result));
        }
        finally
        {
            File.Delete(apk);
        }
    }

    [Fact]
    public async Task Executor_Install_RejectsSameSizePackageSwapAfterApproval()
    {
        var apk = TempApk("package-version-one");
        try
        {
            var broker = new CuBroker(new Allow());
            broker.SetDriver("codex");
            broker.SetAndroidDevices(["device-1"]);
            var held = await broker.SubmitAsync(Android("install", new()
            {
                ["serial"] = "device-1",
                ["apkPath"] = apk,
            }), new CuContext("codex"));
            Assert.Equal(CuActionState.Held, held.State);

            // This is the bypass the fingerprint must close: keep the approved path and size, replace only the bytes.
            File.WriteAllText(apk, "package-evil-000000");
            Assert.Equal(held.Action.Arg("apkBytes"), new FileInfo(apk).Length.ToString());
            Assert.True(broker.ApproveHeld(held.ActionId).Ok);

            var runner = new FakeRunner();
            runner.Results.Enqueue(new AdbCommandResult(0, Encoding.UTF8.GetBytes("device\n"), ""));
            using var executor = new AdbBridgeExecutor(
                AdbBridgeOptions.Create(@"C:\Android\adb.exe", ["device-1"]),
                runner);
            var result = await executor.ExecuteAsync(Claim(broker, 1).Single());

            Assert.False(result.Ok);
            Assert.Contains("contents changed", result.Error, StringComparison.OrdinalIgnoreCase);
            Assert.Single(runner.Calls); // get-state ran; adb install never received the swapped package.
        }
        finally
        {
            File.Delete(apk);
        }
    }

    [Theory]
    [InlineData("not-an-apk.txt", "false")]
    [InlineData("package.apk", "sometimes")]
    public async Task Broker_Install_InvalidPackageOrFlag_FailsClosed(string fileName, string replace)
    {
        var path = Path.Combine(Path.GetTempPath(), $"foreman-{Guid.NewGuid():N}-{fileName}");
        File.WriteAllText(path, "package bytes");
        try
        {
            var broker = new CuBroker(new Allow());
            broker.SetDriver("codex");
            broker.SetAndroidDevices(["device-1"]);

            var item = await broker.SubmitAsync(Android("install", new()
            {
                ["serial"] = "device-1",
                ["apkPath"] = path,
                ["replace"] = replace,
            }), new CuContext("codex"));

            Assert.Equal(CuActionState.Blocked, item.State);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task PrepareInstall_WindowsUncPackage_IsRejectedBeforeNetworkAccess()
    {
        if (!OperatingSystem.IsWindows()) return;

        var prepared = await AdbBridgeExecutor.PrepareInstallActionAsync(Android("install", new()
        {
            ["apkPath"] = @"\\untrusted.invalid\drop\payload.apk",
        }));

        Assert.Null(prepared.Action);
        Assert.Contains("local drive", prepared.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Executor_PanicBetweenStateCheckAndAction_StopsBeforeSecondAdbCall()
    {
        var halted = false;
        var runner = new FakeRunner { OnRun = _ => halted = true };
        using var executor = new AdbBridgeExecutor(
            AdbBridgeOptions.Create(@"C:\Android\adb.exe", ["device-1"]),
            runner,
            () => halted);
        var item = new CuBrokerItem("a1", Android("tap", new()
        {
            ["serial"] = "device-1", ["x"] = "1", ["y"] = "2",
        }), CuActionState.Executing, null, DateTimeOffset.UtcNow);

        var result = await executor.ExecuteAsync(item);

        Assert.False(result.Ok);
        Assert.Single(runner.Calls);
        Assert.Contains("halted", result.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Executor_InventoryMarksOnlyEnrolledDevices()
    {
        var runner = new FakeRunner();
        runner.Results.Enqueue(new AdbCommandResult(0,
            Encoding.UTF8.GetBytes("List of devices attached\ndevice-1 device product:x\nother offline\n"), ""));
        using var executor = new AdbBridgeExecutor(
            AdbBridgeOptions.Create(@"C:\Android\adb.exe", ["device-1"]),
            runner);
        var item = new CuBrokerItem("a1", Android("devices"), CuActionState.Executing, null, DateTimeOffset.UtcNow);

        var result = await executor.ExecuteAsync(item);

        Assert.True(result.Ok);
        var json = System.Text.Json.JsonSerializer.Serialize(result.Result);
        Assert.Contains("\"serial\":\"device-1\"", json);
        Assert.Contains("\"enrolled\":true", json);
        Assert.Contains("\"serial\":\"other\"", json);
        Assert.Contains("\"enrolled\":false", json);
    }

    [Fact]
    public void PanicStop_CancelsTheCurrentAdbClient()
    {
        var runner = new FakeRunner();
        using var executor = new AdbBridgeExecutor(
            AdbBridgeOptions.Create(@"C:\Android\adb.exe", ["device-1"]),
            runner);

        executor.PanicStop();

        Assert.True(runner.Cancelled);
    }

    [Fact]
    public void ProcessRunner_RefusesBinaryWhoseEnrolledHashDoesNotMatch()
    {
        var path = Path.Combine(Path.GetTempPath(), $"foreman-adb-{Guid.NewGuid():N}.bin");
        try
        {
            File.WriteAllText(path, "known adb test bytes");
            var hash = AdbProcessRunner.ComputeSha256(path);
            using var matching = new AdbProcessRunner(path, hash);
            using var replaced = new AdbProcessRunner(path, new string('0', 64));

            Assert.True(matching.IsAvailable);
            Assert.False(replaced.IsAvailable);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    [Fact]
    public async Task ProcessRunner_HashPinnedExecutable_CanLaunchAndCaptureBoundedOutput()
    {
        var windows = OperatingSystem.IsWindows();
        var executable = windows
            ? Environment.GetEnvironmentVariable("ComSpec")!
            : "/bin/sh";
        var arguments = windows
            ? new[] { "/d", "/c", "echo adb-runner-ok" }
            : new[] { "-c", "printf adb-runner-ok" };
        var hash = AdbProcessRunner.ComputeSha256(executable);
        using var runner = new AdbProcessRunner(executable, hash);

        var result = await runner.RunAsync(arguments, 16 * 1024, TimeSpan.FromSeconds(5));

        Assert.True(runner.IsAvailable);
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("adb-runner-ok", Encoding.UTF8.GetString(result.StandardOutput));
    }

    private static string TempApk(string contents)
    {
        var path = Path.Combine(Path.GetTempPath(), $"foreman-{Guid.NewGuid():N}.apk");
        File.WriteAllText(path, contents);
        return path;
    }
}
