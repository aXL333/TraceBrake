using Foreman.Core.Integration;

namespace Foreman.Core.Tests.Integration;

public sealed class CodexMcpConnectorTests : IDisposable
{
    private readonly string _dir;
    private readonly string _cfg;
    private readonly string _agents;

    // Capture env-var writes instead of touching the test host's real user environment.
    private readonly List<KeyValuePair<string, string>> _envSets = [];
    private void Env(string name, string value) => _envSets.Add(new(name, value));

    public CodexMcpConnectorTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "foreman-codex-conn-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_dir);
        _cfg = Path.Combine(_dir, "config.toml");
        _agents = Path.Combine(_dir, "AGENTS.md");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    [Fact]
    public void Connect_AddsForemanSection_PreservesOtherConfig_AndBacksUp()
    {
        File.WriteAllText(_cfg, """
        model = "gpt-5.5"

        [mcp_servers.figma]
        url = "https://mcp.figma.com/mcp"
        enabled = false
        """);

        var r = CodexMcpConnector.Connect(54321, "TOKEN123", _cfg, _agents, Env);

        Assert.Equal(ConnectStatus.Added, r.Status);
        Assert.True(File.Exists(_cfg + ".foreman-bak"));

        var toml = File.ReadAllText(_cfg);
        Assert.Contains("model = \"gpt-5.5\"", toml);
        Assert.Contains("[mcp_servers.figma]", toml);
        Assert.Contains("[mcp_servers.foreman]", toml);
        Assert.Contains("url = \"http://localhost:54321/mcp\"", toml);
        Assert.Contains($"bearer_token_env_var = \"{CodexMcpConnector.BearerTokenEnvVar}\"", toml);
        Assert.True(CodexMcpConnector.IsConfigured(54321, _cfg));

        // The token goes to the env var Codex reads, not into the TOML as an inline header.
        Assert.Contains(_envSets, kv => kv.Key == CodexMcpConnector.BearerTokenEnvVar && kv.Value == "TOKEN123");

        var agents = File.ReadAllText(_agents);
        Assert.Contains("TraceBrake MCP Monitor", agents);
        Assert.Contains("list_ask_harness_requests(harnessId: \"codex\")", agents);
        Assert.Contains("reply_to_ask_harness_request(requestId, response, actionTaken, harnessId: \"codex\")", agents);
    }

    [Fact]   // the core fix: supported auth form, no inline header, token delivered via the env var
    public void Connect_UsesBearerTokenEnvVar_NotInlineHeader_AndSetsEnv()
    {
        var r = CodexMcpConnector.Connect(54321, "TOKVAL", _cfg, _agents, Env);

        Assert.NotEqual(ConnectStatus.Failed, r.Status);
        var toml = File.ReadAllText(_cfg);
        Assert.Contains($"bearer_token_env_var = \"{CodexMcpConnector.BearerTokenEnvVar}\"", toml);
        Assert.DoesNotContain("http_headers", toml);
        Assert.DoesNotContain("Authorization", toml);
        Assert.Equal(new KeyValuePair<string, string>(CodexMcpConnector.BearerTokenEnvVar, "TOKVAL"), Assert.Single(_envSets));
    }

    [Fact]
    public void Connect_OnMissingFile_CreatesIt()
    {
        var r = CodexMcpConnector.Connect(54321, "T", _cfg, _agents, Env);

        Assert.Equal(ConnectStatus.Added, r.Status);
        Assert.Null(r.BackupPath);
        Assert.True(CodexMcpConnector.IsConfigured(54321, _cfg));
    }

    [Fact]
    public void Connect_Twice_ReportsUpdated_AndRefreshesEnvToken()
    {
        CodexMcpConnector.Connect(54321, "old", _cfg, _agents, Env);

        var r = CodexMcpConnector.Connect(54321, "new", _cfg, _agents, Env);

        Assert.Equal(ConnectStatus.Updated, r.Status);
        // The TOML is unchanged (the env-var name is constant); the rotated token lands in the env var.
        var toml = File.ReadAllText(_cfg);
        Assert.Contains($"bearer_token_env_var = \"{CodexMcpConnector.BearerTokenEnvVar}\"", toml);
        Assert.Equal("new", _envSets[^1].Value);
        Assert.All(_envSets, kv => Assert.Equal(CodexMcpConnector.BearerTokenEnvVar, kv.Key));
    }

    [Fact]
    public void Connect_ReplacesQuotedForemanSection_AndChildTables()
    {
        File.WriteAllText(_cfg, """
        [mcp_servers."foreman"]
        command = "old"

        [mcp_servers.foreman.env]
        X = "Y"

        [mcp_servers.other]
        command = "npx"
        """);

        var r = CodexMcpConnector.Connect(54321, "T", _cfg, _agents, Env);

        Assert.Equal(ConnectStatus.Updated, r.Status);
        var toml = File.ReadAllText(_cfg);
        Assert.Contains("[mcp_servers.foreman]", toml);
        Assert.Contains("[mcp_servers.other]", toml);
        Assert.DoesNotContain("[mcp_servers.foreman.env]", toml);
        Assert.DoesNotContain("command = \"old\"", toml);
    }

    [Fact]
    public void IsConfigured_FalseForWrongPortOrNoToken()
    {
        CodexMcpConnector.Connect(54321, "T", _cfg, _agents, Env);

        Assert.False(CodexMcpConnector.IsConfigured(9999, _cfg));
        Assert.False(CodexMcpConnector.IsConfigured(54321, Path.Combine(_dir, "missing.toml")));
    }

    [Fact]
    public void Connect_LeavesUsersOwnBearerTokenEnvVarEntryUnchanged()
    {
        // A user who wired their OWN env-var name must not have it clobbered, and Foreman must not touch
        // that variable (it's theirs to manage).
        File.WriteAllText(_cfg, """
        [mcp_servers.foreman]
        url = "http://localhost:54321/mcp"
        bearer_token_env_var = "MY_OWN_TOKEN_VAR"
        enabled = true
        """);

        var r = CodexMcpConnector.Connect(54321, "IGNORED", _cfg, _agents, Env);

        Assert.Equal(ConnectStatus.Updated, r.Status);
        var toml = File.ReadAllText(_cfg);
        Assert.Contains("bearer_token_env_var = \"MY_OWN_TOKEN_VAR\"", toml);
        Assert.DoesNotContain(CodexMcpConnector.BearerTokenEnvVar, toml);
        Assert.Empty(_envSets);   // didn't touch the user's variable

        var agents = File.ReadAllText(_agents);
        Assert.Contains("reply_to_ask_harness_request", agents);
    }

    [Fact]
    public void Connect_PreservesLfLineEndings()
    {
        // LF-only input (common on WSL/macOS, and under git) must not be rewritten to CRLF.
        File.WriteAllText(_cfg, "model = \"x\"\n\n[mcp_servers.other]\ncommand = \"npx\"\n");

        CodexMcpConnector.Connect(54321, "T", _cfg, _agents, Env);

        var raw = File.ReadAllText(_cfg);
        Assert.DoesNotContain("\r\n", raw);
        Assert.Contains("[mcp_servers.foreman]", raw);
        Assert.Contains("[mcp_servers.other]", raw);
    }

    [Fact]
    public void Connect_UpsertsMarkedAgentsSection_PreservesUserInstructions_AndBacksUp()
    {
        File.WriteAllText(_agents, """
        # My Codex instructions

        Keep answers concise.

        <!-- foreman-mcp:begin -->
        stale foreman text
        <!-- foreman-mcp:end -->

        Leave this alone.
        """);

        var r = CodexMcpConnector.Connect(54321, "T", _cfg, _agents, Env);

        Assert.Equal(ConnectStatus.Added, r.Status);
        Assert.True(File.Exists(_agents + ".foreman-bak"));

        var agents = File.ReadAllText(_agents);
        Assert.Contains("# My Codex instructions", agents);
        Assert.Contains("Keep answers concise.", agents);
        Assert.Contains("Leave this alone.", agents);
        Assert.Contains("report_task_start(taskDescription, harnessId: \"codex\")", agents);
        Assert.Contains("pendingAskHarnessRequests", agents);
        Assert.Contains("queued audit prompt", agents);
        Assert.DoesNotContain("stale foreman text", agents);
    }
}
