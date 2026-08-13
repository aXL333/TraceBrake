using Foreman.Core.Settings;

namespace Foreman.Core.Tests.Settings;

public sealed class SettingsStoreTests : IDisposable
{
    private readonly string _dir;
    private readonly string _path;

    public SettingsStoreTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "foreman-settings-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_dir);
        _path = Path.Combine(_dir, "settings.json");
    }

    public void Dispose()
    {
        SettingsStore.IntegritySecret = null;
        SettingsStore.Sealer = null;
        SettingsStore.HasPriorSealEvidence = null;
        SettingsStore.RecordSealEvidence = null;
        SettingsStore.IntegritySecretRecentlyRegenerated = null;
        SettingsStore.SaveAuditSink = null;
        try { Directory.Delete(_dir, true); } catch { }
    }

    [Fact]
    public void Save_ThenLoad_RoundTrips()
    {
        var settings = new ForemanSettings { McpPort = 49152, HangThresholdMinutes = 7, IdleCleanupEnabled = true };
        settings.CustomHarnessExes.Add("myagent.exe");

        SettingsStore.Save(settings, _path);
        var loaded = SettingsStore.Load(_path);

        Assert.Equal(49152, loaded.McpPort);
        Assert.Equal(7, loaded.HangThresholdMinutes);
        Assert.True(loaded.IdleCleanupEnabled);
        Assert.Contains("myagent.exe", loaded.CustomHarnessExes);
        Assert.Null(SettingsStore.LastLoadFault);
    }

    [Fact]
    public void Save_OverwritesExisting_Atomically_NoTempLeft()
    {
        SettingsStore.Save(new ForemanSettings { McpPort = 11111 }, _path);
        SettingsStore.Save(new ForemanSettings { McpPort = 22222 }, _path);   // exercises the File.Replace swap path

        Assert.Equal(22222, SettingsStore.Load(_path).McpPort);
        Assert.False(File.Exists(_path + ".tmp"), "atomic write should not leave a .tmp behind");
    }

    [Fact]
    public void MissingFile_ReturnsDefaults_NoFault()
    {
        var loaded = SettingsStore.Load(_path);
        Assert.Equal(new ForemanSettings().McpPort, loaded.McpPort);
        Assert.Null(SettingsStore.LastLoadFault);
    }

    [Fact]
    public void DeletedPrimary_WithVerifiedRecovery_RestoresSealedPosture()
    {
        SettingsStore.IntegritySecret = () => "test-install-secret";
        var approved = new ForemanSettings { CuDriver = "codex" };
        approved.PresenceLock.Enabled = true;
        SettingsStore.Save(approved, _path);
        File.Delete(_path);

        var loaded = SettingsStore.Load(_path);

        Assert.Equal(SettingsSealVerdict.Tampered, SettingsStore.LastSealVerdict);
        Assert.True(loaded.PresenceLock.Enabled);
        Assert.Equal("codex", loaded.CuDriver);
        Assert.True(File.Exists(_path));
        Assert.Contains("was removed", SettingsStore.LastLoadFault);
    }

    [Fact]
    public void GuardianSeal_WhenAuthorityTemporarilyUnavailable_IsNotQuarantined()
    {
        var settings = new ForemanSettings { CuDriver = "codex" };
        settings.PresenceLock.Enabled = true;
        File.WriteAllText(_path, System.Text.Json.JsonSerializer.Serialize(settings));
        File.WriteAllText(_path + ".seal", SettingsSeal.GuardianScheme + "unavailable-test-seal");
        SettingsStore.Sealer = new UnavailableGuardianSettingsSealer(() => "local-secret");

        var loaded = SettingsStore.Load(_path);

        Assert.Equal(SettingsSealVerdict.Unverified, SettingsStore.LastSealVerdict);
        Assert.True(loaded.PresenceLock.Enabled);
        Assert.Equal("codex", loaded.CuDriver);
        Assert.True(File.Exists(_path));
        Assert.Empty(Directory.GetFiles(_dir, "*.tampered"));
    }

    [Fact]
    public void PreviousProjectionSeal_IsPreservedAndUpgradedWithoutAlarm()
    {
        const string secret = "test-install-secret";
        SettingsStore.IntegritySecret = () => secret;
        var settings = new ForemanSettings { CuDriver = "codex" };
        settings.PresenceLock.Enabled = true;
        var json = System.Text.Json.JsonSerializer.Serialize(settings);
        var legacySeal = SettingsSeal.ComputeMac(SettingsSeal.LegacySecurityProjectionV1(settings), secret);
        File.WriteAllText(_path, json);
        File.WriteAllText(_path + ".seal", legacySeal);

        var loaded = SettingsStore.Load(_path);

        Assert.True(loaded.PresenceLock.Enabled);
        Assert.Equal("codex", loaded.CuDriver);
        Assert.Equal(SettingsSealVerdict.Sealed, SettingsStore.LastSealVerdict);
        Assert.Null(SettingsStore.LastLoadFault);
        Assert.StartsWith(SettingsSeal.LocalScheme, File.ReadAllText(_path + ".seal"));
    }

    [Fact]
    public void CorruptFile_IsQuarantined_DefaultsLoaded_FaultReported()
    {
        File.WriteAllText(_path, "{ this is not valid json ");

        var loaded = SettingsStore.Load(_path);

        // defaults, not a crash or partial state
        Assert.Equal(new ForemanSettings().McpPort, loaded.McpPort);
        // the unreadable file was moved aside (so security posture isn't silently reset without trace)
        Assert.False(File.Exists(_path), "corrupt settings.json should be moved aside");
        Assert.NotEmpty(Directory.GetFiles(_dir, "settings.json.*.bad"));
        // and the fault is reported for the UI to surface
        Assert.NotNull(SettingsStore.LastLoadFault);
        Assert.Contains(".bad", SettingsStore.LastLoadFault!);
    }

    [Fact]
    public void CorruptPrimary_WithVerifiedRecovery_RestoresInsteadOfResetting()
    {
        SettingsStore.IntegritySecret = () => "test-install-secret";
        var approved = new ForemanSettings { CuDriver = "codex" };
        approved.PresenceLock.Enabled = true;
        SettingsStore.Save(approved, _path);
        File.WriteAllText(_path, "{broken");

        var loaded = SettingsStore.Load(_path);

        Assert.Equal(SettingsSealVerdict.Tampered, SettingsStore.LastSealVerdict);
        Assert.True(SettingsStore.RecoveryRestored);
        Assert.True(loaded.PresenceLock.Enabled);
        Assert.Equal("codex", loaded.CuDriver);
        Assert.True(File.Exists(_path));
    }

    [Fact]
    public void Quarantine_ThenSave_ProducesAReadableFileAgain()
    {
        File.WriteAllText(_path, "}{ broken");
        SettingsStore.Load(_path);                                   // quarantines
        SettingsStore.Save(new ForemanSettings { McpPort = 33333 }, _path);

        Assert.Equal(33333, SettingsStore.Load(_path).McpPort);
        Assert.Null(SettingsStore.LastLoadFault);                    // a clean load clears the prior fault
    }

    [Fact]
    public void TamperedSecuritySettings_AreRevertedBeforeLoadReturns()
    {
        SettingsStore.IntegritySecret = () => "test-install-secret";
        var approved = new ForemanSettings { CuDriver = "codex" };
        approved.PresenceLock.Enabled = true;
        approved.AdbBridge.Enabled = false;
        SettingsStore.Save(approved, _path);

        var attackerJson = File.ReadAllText(_path)
            .Replace("\"Enabled\": true", "\"Enabled\": false", StringComparison.Ordinal)
            .Replace("\"CuDriver\": \"codex\"", "\"CuDriver\": \"any\"", StringComparison.Ordinal);
        File.WriteAllText(_path, attackerJson);

        var loaded = SettingsStore.Load(_path);

        Assert.Equal(SettingsSealVerdict.Tampered, SettingsStore.LastSealVerdict);
        Assert.True(loaded.PresenceLock.Enabled);
        Assert.Equal("codex", loaded.CuDriver);
        Assert.False(loaded.AdbBridge.Enabled);
        Assert.Contains("last-known-good", SettingsStore.LastLoadFault!);
        Assert.NotEmpty(Directory.GetFiles(_dir, "settings.json.*.tampered"));
    }

    [Fact]
    public void TamperedSecuritySettings_WithoutRecovery_LoadSafeDefaults()
    {
        const string secret = "test-install-secret";
        SettingsStore.IntegritySecret = () => secret;
        var attackerSettings = new ForemanSettings { CuDriver = "any", RunElevated = true };
        attackerSettings.AdbBridge.Enabled = true;
        attackerSettings.AdbBridge.ExecutablePath = @"C:\attacker.exe";
        File.WriteAllText(_path, System.Text.Json.JsonSerializer.Serialize(attackerSettings));
        File.WriteAllText(_path + ".seal", SettingsSeal.Compute(new ForemanSettings(), secret));

        var loaded = SettingsStore.Load(_path);

        Assert.Equal(SettingsSealVerdict.Tampered, SettingsStore.LastSealVerdict);
        Assert.Null(loaded.CuDriver);
        Assert.False(loaded.RunElevated);
        Assert.False(loaded.AdbBridge.Enabled);
        Assert.Contains("safe defaults", SettingsStore.LastLoadFault!);
    }

    [Fact]
    public void MissingPrimarySeal_WithVerifiedRecovery_IsTamperAndRestoresRecovery()
    {
        SettingsStore.IntegritySecret = () => "test-install-secret";
        var approved = new ForemanSettings { CuDriver = "codex" };
        approved.PresenceLock.Enabled = true;
        SettingsStore.Save(approved, _path);

        var attackerJson = File.ReadAllText(_path)
            .Replace("\"Enabled\": true", "\"Enabled\": false", StringComparison.Ordinal)
            .Replace("\"CuDriver\": \"codex\"", "\"CuDriver\": \"any\"", StringComparison.Ordinal);
        File.WriteAllText(_path, attackerJson);
        File.Delete(_path + ".seal");

        var loaded = SettingsStore.Load(_path);

        Assert.Equal(SettingsSealVerdict.Tampered, SettingsStore.LastSealVerdict);
        Assert.True(loaded.PresenceLock.Enabled);
        Assert.Equal("codex", loaded.CuDriver);
        Assert.Contains("last-known-good", SettingsStore.LastLoadFault!);
    }

    [Fact]
    public void MissingAllSeals_AfterDurableSealEvidence_LoadsSafeDefaults()
    {
        SettingsStore.IntegritySecret = () => "test-install-secret";
        SettingsStore.HasPriorSealEvidence = () => true;
        var attacker = new ForemanSettings { RunElevated = true };
        attacker.AdbBridge.Enabled = true;
        File.WriteAllText(_path, System.Text.Json.JsonSerializer.Serialize(attacker));

        var loaded = SettingsStore.Load(_path);

        Assert.Equal(SettingsSealVerdict.Tampered, SettingsStore.LastSealVerdict);
        Assert.False(loaded.RunElevated);
        Assert.False(loaded.AdbBridge.Enabled);
    }

    [Fact]
    public void RecentLocalSecretRotation_PreservesAndResealsUnchangedSettings()
    {
        var secret = "old-test-install-secret";
        SettingsStore.IntegritySecret = () => secret;
        SettingsStore.Save(new ForemanSettings { McpPort = 49199, CuDriver = "codex" }, _path);

        secret = "new-test-install-secret";
        SettingsStore.IntegritySecretRecentlyRegenerated = () => true;
        var loaded = SettingsStore.Load(_path);

        Assert.Equal(49199, loaded.McpPort);
        Assert.Equal("codex", loaded.CuDriver);
        Assert.Equal(SettingsSealVerdict.Sealed, SettingsStore.LastSealVerdict);
        Assert.Equal(SettingsSealVerdict.Sealed,
            SettingsSeal.Verify(loaded, File.ReadAllText(_path + ".seal").Trim(), secret));
    }

    [Fact]
    public void RecentLocalSecretRotation_DoesNotBlessCurrentOnlyEdit()
    {
        var secret = "old-test-install-secret";
        SettingsStore.IntegritySecret = () => secret;
        SettingsStore.Save(new ForemanSettings { CuDriver = "codex" }, _path);
        File.WriteAllText(_path, File.ReadAllText(_path)
            .Replace("\"CuDriver\": \"codex\"", "\"CuDriver\": \"any\"", StringComparison.Ordinal));

        secret = "new-test-install-secret";
        SettingsStore.IntegritySecretRecentlyRegenerated = () => true;
        var loaded = SettingsStore.Load(_path);

        Assert.NotEqual("any", loaded.CuDriver);
        Assert.Equal(SettingsSealVerdict.Tampered, SettingsStore.LastSealVerdict);
    }

    [Fact]
    public void SaveAudit_AttributesRoute_AndDistinguishesSecurityProjection()
    {
        var settings = new ForemanSettings { McpPort = 49152 };
        SettingsStore.Save(settings, _path);
        SettingsSaveAudit? observed = null;
        SettingsStore.SaveAuditSink = audit => observed = audit;

        using (SettingsChangeContext.Begin(SettingsChangeAttribution.Declared(
                   SettingsChangeOrigin.AuthenticatedMcp, "codex", "test-non-security-save")))
        {
            settings.McpPort = 49153;
            SettingsStore.Save(settings, _path);
        }

        Assert.NotNull(observed);
        Assert.True(observed!.SettingsChanged);
        Assert.False(observed.SecurityProjectionChanged);
        Assert.Equal(SettingsChangeOrigin.AuthenticatedMcp, observed.Attribution.Origin);
        Assert.Equal("codex", observed.Attribution.Actor);

        settings.PresenceLock.Enabled = true;
        SettingsStore.Save(settings, _path);

        Assert.True(observed.SecurityProjectionChanged);
        Assert.True(observed.Attribution.Suspicious);
        Assert.Equal(SettingsChangeOrigin.Unattributed, observed.Attribution.Origin);
        Assert.NotEqual(observed.PriorSecurityProjectionHash, observed.CurrentSecurityProjectionHash);
    }

    [Fact]
    public void SaveAudit_NoOpSave_IsIdentifiedWithoutFalseChange()
    {
        var settings = new ForemanSettings();
        SettingsStore.Save(settings, _path);
        SettingsSaveAudit? observed = null;
        SettingsStore.SaveAuditSink = audit => observed = audit;

        SettingsStore.Save(settings, _path);

        Assert.NotNull(observed);
        Assert.False(observed!.SettingsChanged);
        Assert.False(observed.SecurityProjectionChanged);
    }
}
