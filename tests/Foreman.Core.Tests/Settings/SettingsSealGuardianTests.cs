using Foreman.Core.Settings;

namespace Foreman.Core.Tests.Settings;

/// <summary>
/// Circle-back Phase A, step 7: the shared MAC helper + scheme-aware local verify that lets the settings seal move
/// behind the guardian without false tamper on opt-in/opt-out.
/// </summary>
public sealed class SettingsSealGuardianTests
{
    [Fact]
    public void ComputeMac_IsDeterministic_AndKeyed()
    {
        const string p = "{\"presenceEnabled\":true}";
        Assert.Equal(SettingsSeal.ComputeMac(p, "s1"), SettingsSeal.ComputeMac(p, "s1"));
        Assert.NotEqual(SettingsSeal.ComputeMac(p, "s1"), SettingsSeal.ComputeMac(p, "s2"));
        Assert.NotEqual(SettingsSeal.ComputeMac(p, "s1"), SettingsSeal.ComputeMac("{\"presenceEnabled\":false}", "s1"));
    }

    [Fact]
    public void MacEquals_IsCorrect()
    {
        Assert.True(SettingsSeal.MacEquals("abc", "abc"));
        Assert.False(SettingsSeal.MacEquals("abc", "abd"));
        Assert.False(SettingsSeal.MacEquals("abc", "abcd"));
    }

    [Fact]
    public void Compute_MatchesComputeMacOverProjection()
    {
        var s = new ForemanSettings();
        Assert.Equal(
            SettingsSeal.LocalScheme + SettingsSeal.ComputeMac(SettingsSeal.SecurityProjection(s), "secret"),
            SettingsSeal.Compute(s, "secret"));
    }

    [Fact]
    public void LocalVerify_GuardianSchemeSeal_IsUnsealed_NotTampered()
    {
        // After opting out (guardian gone), a leftover guardian-scheme seal must read as Unsealed (adopt + re-seal
        // locally), never Tampered — otherwise opt-out would falsely cry tamper on the next launch.
        var s = new ForemanSettings();
        Assert.Equal(SettingsSealVerdict.Unsealed,
            SettingsSeal.Verify(s, SettingsSeal.GuardianScheme + "anyMacHere", "local-secret"));
    }

    [Fact]
    public void LocalVerify_LocalSeal_StillWorks()
    {
        var s = new ForemanSettings();
        var seal = SettingsSeal.Compute(s, "local-secret");
        Assert.Equal(SettingsSealVerdict.Sealed, SettingsSeal.Verify(s, seal, "local-secret"));
        Assert.Equal(SettingsSealVerdict.Tampered, SettingsSeal.Verify(s, seal, "different-secret"));
    }
}
