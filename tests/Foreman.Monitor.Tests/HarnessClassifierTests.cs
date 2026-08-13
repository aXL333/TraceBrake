using Foreman.Core.Models;

namespace Foreman.Monitor.Tests;

public sealed class HarnessClassifierTests
{
    [Theory]
    [InlineData("T3 Code.exe", "", "t3-code")]
    [InlineData("t3code.exe", "", "t3-code")]
    [InlineData("node.exe", "node W:\\src\\t3code\\apps\\desktop\\main.js", "t3-code")]
    [InlineData("opencode.exe", "", "opencode")]
    [InlineData("node.exe", "node C:\\Users\\user\\AppData\\Roaming\\npm\\node_modules\\opencode-ai\\bin\\opencode", "opencode")]
    [InlineData("copilot.exe", "", "github-copilot")]   // standalone GitHub Copilot CLI, not 'gh copilot'
    [InlineData("node.exe", "node C:\\Users\\user\\AppData\\Roaming\\npm\\node_modules\\@github\\copilot\\index.js", "github-copilot")]
    [InlineData("cursor.exe", "", "cursor")]
    public void Classify_DetectsNewBuiltInHarnesses(string processName, string commandLine, string expectedHarnessId)
    {
        var record = new ProcessRecord
        {
            Pid = 940_001,
            Name = processName,
            CommandLine = commandLine,
            StartTime = DateTimeOffset.UtcNow,
        };

        HarnessClassifier.Classify(record);

        Assert.True(record.IsHarness);
        Assert.Equal(expectedHarnessId, record.HarnessType);
    }

    [Fact]
    public void Classify_StillWritesHarnessType_WhenHarnessIsDisabled()
    {
        var record = new ProcessRecord
        {
            Pid = 940_101,
            Name = "opencode.exe",
            StartTime = DateTimeOffset.UtcNow,
        };

        HarnessClassifier.Classify(record, new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "opencode" });

        Assert.False(record.IsHarness);
        Assert.Equal("opencode", record.HarnessType);
    }

    [Fact]
    public void Classify_DoesNotTreatPlainT3CodeRepoNodeProcessAsHarness()
    {
        var record = new ProcessRecord
        {
            Pid = 940_201,
            Name = "node.exe",
            CommandLine = "node W:\\src\\t3code\\scripts\\build.js",
            StartTime = DateTimeOffset.UtcNow,
        };

        HarnessClassifier.Classify(record);

        Assert.False(record.IsHarness);
        Assert.Null(record.HarnessType);
    }

    [Fact]
    public void Classify_AttributesClaudeNativeHostByVendorPath()
    {
        var record = new ProcessRecord
        {
            Pid = 940_301,
            Name = "chrome-native-host.exe",
            ExecutablePath = @"C:\Users\dev\AppData\Roaming\Claude\ChromeNativeHost\chrome-native-host.exe",
            CommandLine = @"chrome-native-host.exe chrome-extension://example/",
            StartTime = DateTimeOffset.UtcNow,
        };

        HarnessClassifier.Classify(record);

        Assert.True(record.IsHarness);
        Assert.Equal("claude-code", record.HarnessType);
    }

    [Fact]
    public void Classify_DoesNotAttributeAnotherVendorNativeHost()
    {
        var record = new ProcessRecord
        {
            Pid = 940_302,
            Name = "chrome-native-host.exe",
            ExecutablePath = @"C:\Users\dev\AppData\Roaming\OtherVendor\chrome-native-host.exe",
            StartTime = DateTimeOffset.UtcNow,
        };

        HarnessClassifier.Classify(record);

        Assert.False(record.IsHarness);
        Assert.Null(record.HarnessType);
    }

    // ── Local-model hosts (task #77) ──────────────────────────────────────────────────────────────────
    [Theory]
    [InlineData("LM Studio.exe", "", "lm-studio")]
    [InlineData("lms.exe", "lms server start", "lm-studio")]
    [InlineData("ollama.exe", "ollama serve", "ollama")]
    [InlineData("ollama.exe", "ollama runner --ollama-engine --port 51234", "ollama")] // the inference child (same binary)
    [InlineData("ollama app.exe", "", "ollama")]
    [InlineData("jan.exe", "", "jan")]
    [InlineData("koboldcpp.exe", "koboldcpp.exe --model m.gguf --port 5001", "koboldcpp")]
    [InlineData("local-ai.exe", "", "localai")]
    [InlineData("python.exe", "python server.py --portable --api", "text-generation-webui")]
    public void Classify_DetectsLocalModelHosts(string name, string cmd, string expectedId)
    {
        var record = new ProcessRecord { Pid = 950_001, Name = name, CommandLine = cmd, StartTime = DateTimeOffset.UtcNow };
        HarnessClassifier.Classify(record);
        Assert.Equal(expectedId, record.HarnessType);
        Assert.True(record.IsHarness);
        Assert.True(KnownHarnesses.IsLocalModelHost(record.HarnessType));   // → exempt from hang/idle/orphan
    }

    [Fact]
    public void CodingAgent_IsNotLocalModelHost()
    {
        Assert.False(KnownHarnesses.IsLocalModelHost("claude-code"));
        Assert.False(KnownHarnesses.IsLocalModelHost("codex"));
        Assert.False(KnownHarnesses.IsLocalModelHost(null));
        Assert.False(KnownHarnesses.IsLocalModelHost("custom:foo.exe"));
    }

    [Theory]
    [InlineData("chat.exe", "")]                                  // GPT4All — too generic to match by name (would falsely exempt)
    [InlineData("llama-server.exe", "llama-server -m m.gguf")]    // shared inference binary — covered via parent, not matched bare
    [InlineData("python.exe", "python manage.py runserver")]     // unrelated python server
    public void Classify_DoesNotMatchGenericBinariesAsModelHost(string name, string cmd)
    {
        var record = new ProcessRecord { Pid = 950_101, Name = name, CommandLine = cmd, StartTime = DateTimeOffset.UtcNow };
        HarnessClassifier.Classify(record);
        Assert.False(record.IsHarness);
        Assert.Null(record.HarnessType);
    }
}
