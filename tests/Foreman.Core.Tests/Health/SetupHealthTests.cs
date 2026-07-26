using Foreman.Core.Health;

namespace Foreman.Core.Tests.Health;

public sealed class SetupHealthTests
{
    /// <summary>A snapshot where everything is set up and working.</summary>
    private static SetupHealthSnapshot Healthy() => new()
    {
        DataDirRedirectedTo = null,
        McpListening = true, McpPort = 54321,
        ConnectedMcpClients = 2, ConnectedClientNames = ["claude-code", "codex"],
        ExtensionPaired = true,
        PresenceEnrolled = true,
        VaultEnrolled = true, VaultUnlocked = true,
        DecoysEnabled = true, DecoysPlanted = 14, ReadAuditingEnabled = true, SidecarConnected = true,
        DecoyAuditExpected = 14, DecoyAuditArmed = 14,
        GuardianInstalled = true, GuardianTrustMode = "publisher_signed", OsEventLogAvailable = true,
    };

    private static SetupHealthItem Row(IReadOnlyList<SetupHealthItem> items, string title) =>
        Assert.Single(items, i => i.Title == title);

    [Fact]
    public void HealthySnapshot_HasNoAttentionRows()
    {
        var items = SetupHealth.Evaluate(Healthy());
        Assert.DoesNotContain(items, i => i.Status == SetupHealthStatus.Attention);
        Assert.DoesNotContain(items, i => i.Status == SetupHealthStatus.Off);
    }

    [Fact]
    public void LaunchContext_IsTheFirstRow_AndFlagsRedirection()
    {
        var items = SetupHealth.Evaluate(Healthy() with { DataDirRedirectedTo = @"C:\overlay\Foreman" });
        Assert.Equal("Launch context", items[0].Title);   // everything below lies if this is wrong — keep it first
        Assert.Equal(SetupHealthStatus.Attention, items[0].Status);
        Assert.Contains(@"C:\overlay\Foreman", items[0].Detail);
        Assert.NotNull(items[0].Remedy);
    }

    [Fact]
    public void DecoysEnabledButZeroTracked_IsAttention_NotOk()
    {
        // The split-brain regression: enabled-on-paper, tracking nothing.
        var row = Row(SetupHealth.Evaluate(Healthy() with { DecoysPlanted = 0 }), "Decoy credentials");
        Assert.Equal(SetupHealthStatus.Attention, row.Status);
        Assert.NotNull(row.Remedy);
    }

    [Fact]
    public void ReadAuditingWithoutSidecar_IsAttention()
    {
        var row = Row(SetupHealth.Evaluate(Healthy() with { SidecarConnected = false }), "Decoy read-auditing");
        Assert.Equal(SetupHealthStatus.Attention, row.Status);
    }

    [Fact]
    public void ConnectedSidecarWithMissingDecoyCoverage_FlagsBothRows()
    {
        var items = SetupHealth.Evaluate(Healthy() with
        {
            DecoysPlanted = 3,
            SidecarConnected = true,
            DecoyAuditExpected = 3,
            DecoyAuditArmed = 2,
        });

        Assert.Equal(SetupHealthStatus.Attention, Row(items, "Decoy credentials").Status);
        Assert.Equal(SetupHealthStatus.Attention, Row(items, "Decoy read-auditing").Status);
    }

    [Fact]
    public void VaultAbsent_IsOff_AndDepositRowsAreSuppressed()
    {
        var items = SetupHealth.Evaluate(Healthy() with
        {
            VaultEnrolled = false, VaultUnlocked = false, PendingDeposits = 3, DepositKeyTampered = true,
        });
        Assert.Equal(SetupHealthStatus.Off, Row(items, "Vault").Status);
        // Deposit state is meaningless without a vault — never render a scary row about it.
        Assert.DoesNotContain(items, i => i.Title == "Sign-up deposits");
    }

    [Fact]
    public void PendingDeposits_SurfaceAsAttention_AndTamperTrumpsPending()
    {
        var pending = Row(SetupHealth.Evaluate(Healthy() with { PendingDeposits = 2 }), "Sign-up deposits");
        Assert.Equal(SetupHealthStatus.Attention, pending.Status);
        Assert.Contains("2", pending.Detail);

        var tampered = Row(SetupHealth.Evaluate(Healthy() with { PendingDeposits = 2, DepositKeyTampered = true }),
            "Sign-up deposits");
        Assert.Contains("swap", tampered.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void McpDown_IsAttention_WithThePortNamed()
    {
        var row = Row(SetupHealth.Evaluate(Healthy() with { McpListening = false, McpPort = 4444 }), "MCP server");
        Assert.Equal(SetupHealthStatus.Attention, row.Status);
        Assert.Contains("4444", row.Detail);
    }

    [Fact]
    public void OptionalFeaturesOff_ReadAsOff_NeverAttention()
    {
        var items = SetupHealth.Evaluate(Healthy() with
        {
            ExtensionPaired = false, PresenceEnrolled = false, GuardianInstalled = false,
            DecoysEnabled = false, ReadAuditingEnabled = false,
        });
        foreach (var title in new[] { "Browser extension", "Presence lock", "Hardened guardian", "Decoy credentials" })
            Assert.Equal(SetupHealthStatus.Off, Row(items, title).Status);
        // Read-auditing rides the decoys feature; with decoys disabled there is no separate row at all.
        Assert.DoesNotContain(items, i => i.Title == "Decoy read-auditing");
    }

    [Fact]
    public void NoAgentsConnected_IsNeutralInfo()
    {
        var row = Row(SetupHealth.Evaluate(Healthy() with { ConnectedMcpClients = 0, ConnectedClientNames = [] }),
            "Connected agents");
        Assert.Equal(SetupHealthStatus.Info, row.Status);
    }

    [Fact]
    public void UnsignedGuardian_IsExplicitlyDevelopmentAttention()
    {
        var row = Row(SetupHealth.Evaluate(Healthy() with { GuardianTrustMode = "path_hash_pinned" }),
            "Hardened guardian");
        Assert.Equal(SetupHealthStatus.Attention, row.Status);
        Assert.Contains("not by publisher", row.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void LegacyGuardian_IsIgnoredAndNeedsReinstall()
    {
        var row = Row(SetupHealth.Evaluate(Healthy() with { GuardianTrustMode = "legacy_or_unavailable" }),
            "Hardened guardian");
        Assert.Equal(SetupHealthStatus.Attention, row.Status);
        Assert.Contains("ignoring", row.Detail, StringComparison.OrdinalIgnoreCase);
    }
}
