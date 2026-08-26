using Foreman.Core.Models;
using Foreman.Core.Mcp;
using Foreman.Core.Settings;

namespace Foreman.Core.Tests.Settings;

public sealed class SettingsSealTests
{
    private const string Secret = "install-secret-abc123";

    private static ForemanSettings Base()
    {
        var s = new ForemanSettings
        {
            RunElevated = false,
            EventLogPersist = true,
            MonitorAllProcesses = false,
            ScanMcpTools = true,
            McpPeerBindingEnforce = true,
            DisabledHarnesses = ["aider", "cline"],
            EmergencyRuleIds = ["cred-004", "net-001"],
            HarnessTrust = new() { ["codex"] = 3, ["claude-code"] = 4 },
            HarnessCapabilityRestrictions = new()
            {
                ["claude-code"] = new()
                {
                    ComputerUse = HarnessCapabilityAccess.AskFirst,
                    BrowserUse = HarnessCapabilityAccess.Block,
                },
            },
        };
        s.PresenceLock.Enabled = true;
        s.DecoyCredentials.EnableReadAuditing = true;
        return s;
    }

    [Fact]   // seal then verify the same settings → Sealed
    public void SealThenVerify_Matches()
    {
        var s = Base();
        var seal = SettingsSeal.Compute(s, Secret);
        Assert.Equal(SettingsSealVerdict.Sealed, SettingsSeal.Verify(s, seal, Secret));
    }

    [Fact]   // no seal yet (first run / upgrade) → Unsealed, not a false tamper
    public void NoSeal_IsUnsealed()
    {
        Assert.Equal(SettingsSealVerdict.Unsealed, SettingsSeal.Verify(Base(), null, Secret));
        Assert.Equal(SettingsSealVerdict.Unsealed, SettingsSeal.Verify(Base(), "", Secret));
    }

    [Theory]   // flipping ANY security-significant field invalidates the seal (the attack we must detect)
    [InlineData("runElevated")]
    [InlineData("eventLogPersist")]
    [InlineData("presence")]
    [InlineData("hashChain")]
    [InlineData("disabled")]
    [InlineData("trust")]
    [InlineData("emergency")]
    [InlineData("decoyRead")]
    [InlineData("peerBinding")]
    [InlineData("capabilities")]
    [InlineData("universalTrust")]
    [InlineData("adb")]
    [InlineData("adbHash")]
    [InlineData("mute")]
    [InlineData("cuTabOverride")]
    [InlineData("modalities")]
    [InlineData("threshold")]
    [InlineData("customHarness")]
    [InlineData("pairedOrigin")]
    [InlineData("deadMan")]
    [InlineData("presenceTtl")]
    [InlineData("sealHead")]
    [InlineData("decoyPaths")]
    public void TamperingASecurityField_IsDetected(string field)
    {
        var s = Base();
        var seal = SettingsSeal.Compute(s, Secret);   // sealed by Foreman

        switch (field)   // ...then an external edit weakens posture
        {
            case "runElevated":     s.RunElevated = true; break;
            case "eventLogPersist": s.EventLogPersist = false; break;
            case "presence":        s.PresenceLock.Enabled = false; break;
            case "hashChain":       s.LogIntegrity.HashChainEnabled = false; break;
            case "disabled":        s.DisabledHarnesses.Add("codex"); break;
            case "trust":           s.HarnessTrust["codex"] = 1; break;
            case "emergency":       s.EmergencyRuleIds = ["cred-004"]; break;   // dropped net-001
            case "decoyRead":       s.DecoyCredentials.EnableReadAuditing = false; break;
            case "peerBinding":     s.McpPeerBindingEnforce = false; break;
            case "capabilities":    s.HarnessCapabilityRestrictions["claude-code"].BrowserUse = HarnessCapabilityAccess.Allow; break;
            case "universalTrust":  s.UniversalTrust.Profiles[3].AdbControl = TrustPrivilegeMode.UnattendedIncludingLocked; break;
            case "adb":
                s.AdbBridge.Enabled = true;
                s.AdbBridge.ExecutablePath = @"C:\Android\platform-tools\adb.exe";
                s.AdbBridge.EnrolledDeviceSerials = ["device-1"];
                break;
            case "adbHash":         s.AdbBridge.ExecutableSha256 = new string('0', 64); break;
            case "mute":            s.Mutes.Add(new MuteEntry { Scope = "category", Value = "cred" }); break;
            case "cuTabOverride":   s.CuTabOverride = true; break;
            case "modalities":      s.HarnessModalities["codex"] = ["self-check"]; break;
            case "threshold":       s.EmergencyLevelTotalAlerts = 999; break;
            case "customHarness":   s.CustomHarnessExes.Add("trusted-looking-agent.exe"); break;
            case "pairedOrigin":    s.PairedExtensionOrigins.Add("chrome-extension://attacker"); break;
            case "deadMan":         s.DeadMansSwitch.Enabled = !s.DeadMansSwitch.Enabled; break;
            case "presenceTtl":     s.PresenceLock.ApprovalTtlSeconds = 300; break;
            case "sealHead":        s.LogIntegrity.SealHeadEnabled = false; break;
            case "decoyPaths":      s.DecoyCredentials.PlantedPaths.Add(@"C:\fake\vault.txt"); break;
        }

        Assert.Equal(SettingsSealVerdict.Tampered, SettingsSeal.Verify(s, seal, Secret));
    }

    [Fact]
    public void DenyByDefaultProjection_AlsoDetectsOperationalSettingEdits()
    {
        var s = Base();
        var seal = SettingsSeal.Compute(s, Secret);
        s.HangThresholdMinutes = 999;
        s.NotifyOnHang = false;
        Assert.Equal(SettingsSealVerdict.Tampered, SettingsSeal.Verify(s, seal, Secret));
    }

    [Fact]
    public void RequireUserVerification_IsSealedByDenyByDefaultProjection()
    {
        var s = Base();
        var seal = SettingsSeal.Compute(s, Secret);
        s.PresenceLock.RequireUserVerification = !s.PresenceLock.RequireUserVerification;
        Assert.Equal(SettingsSealVerdict.Tampered, SettingsSeal.Verify(s, seal, Secret));
    }

    [Fact]   // the seal is order-independent (re-serialization can't cause a false tamper)
    public void ProjectionIsOrderIndependent()
    {
        var a = Base();
        var b = Base();
        b.DisabledHarnesses = ["cline", "aider"];          // reversed
        b.EmergencyRuleIds = ["net-001", "cred-004"];      // reversed
        a.AdbBridge.EnrolledDeviceSerials = ["device-b", "device-a"];
        b.AdbBridge.EnrolledDeviceSerials = ["device-a", "device-b"];
        Assert.Equal(SettingsSeal.Compute(a, Secret), SettingsSeal.Compute(b, Secret));
    }

    [Fact]   // a different install secret can't produce a matching seal (blocks cross-user/offline tamper)
    public void WrongSecret_IsTampered()
    {
        var s = Base();
        var seal = SettingsSeal.Compute(s, Secret);
        Assert.Equal(SettingsSealVerdict.Tampered, SettingsSeal.Verify(s, seal, "different-secret"));
    }

    [Fact]
    public void PreviousL2Projection_IsRecognisedAndMigratedInsteadOfReportedTampered()
    {
        var settings = Base();
        var oldSeal = SettingsSeal.LocalScheme
            + SettingsSeal.ComputeMac(SettingsSeal.LegacySecurityProjectionV2(settings), Secret);

        Assert.Equal(SettingsSealVerdict.LegacySealed, SettingsSeal.Verify(settings, oldSeal, Secret));
    }

    [Fact]
    public void PreviousV3Projection_IsRecognisedAndMigratedInsteadOfReportedTampered()
    {
        var settings = Base();
        var oldSeal = SettingsSeal.LocalScheme
            + SettingsSeal.ComputeMac(SettingsSeal.LegacySecurityProjectionV3(settings), Secret);

        Assert.Equal(SettingsSealVerdict.LegacySealed, SettingsSeal.Verify(settings, oldSeal, Secret));
    }
}
