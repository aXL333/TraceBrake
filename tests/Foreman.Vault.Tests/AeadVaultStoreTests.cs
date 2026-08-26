using System.Text.Json.Nodes;
using Foreman.Core.Vault;
using Foreman.Vault;

namespace Foreman.Vault.Tests;

public sealed class AeadVaultStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "foreman-vault-test-" + Guid.NewGuid().ToString("N"));
    public AeadVaultStoreTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, recursive: true); } catch { /* best-effort cleanup */ } }

    private string VaultPath => Path.Combine(_dir, "vault.fvault");
    private static readonly byte[] KeyComp = Enumerable.Range(0, 32).Select(i => (byte)(i * 7)).ToArray();
    private const string Pw = "correct horse battery staple";

    private static VaultEntry GitHub() => new()
    {
        Name = "GitHub",
        Origins = { "github.com" },
        Harnesses = { "claude-code" },
        Username = "alice",
        Password = "s3cret",
        TotpSeedBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    };

    [Fact]
    public void Roundtrip_CreateUpsertReopen()
    {
        var store = AeadVaultStore.Create(VaultPath, Pw, KeyComp);
        store.Upsert(GitHub());
        store.WipeInMemoryKeys();
        Assert.False(store.IsUnlocked);

        var reopened = new AeadVaultStore(VaultPath);
        reopened.Open(Pw, KeyComp);
        Assert.True(reopened.IsUnlocked);

        var info = reopened.FindByOrigin("github.com");
        Assert.NotNull(info);
        Assert.True(info!.HasTotp);
        Assert.Equal("s3cret", reopened.GetSecret("github.com", VaultField.Password));
        Assert.Equal("alice", reopened.GetSecret("github.com", VaultField.Username));
    }

    [Fact]
    public void WrongPassword_Throws()
    {
        AeadVaultStore.Create(VaultPath, Pw, KeyComp).Upsert(GitHub());
        Assert.ThrowsAny<Exception>(() => new AeadVaultStore(VaultPath).Open("wrong-password", KeyComp));
    }

    [Fact]
    public void WrongKeyComponent_Throws()
    {
        AeadVaultStore.Create(VaultPath, Pw, KeyComp).Upsert(GitHub());
        var bad = (byte[])KeyComp.Clone();
        bad[0] ^= 0xFF;
        Assert.ThrowsAny<Exception>(() => new AeadVaultStore(VaultPath).Open(Pw, bad));
    }

    [Fact]
    public void TamperedCiphertext_Throws()
    {
        AeadVaultStore.Create(VaultPath, Pw, KeyComp).Upsert(GitHub());
        var node = JsonNode.Parse(File.ReadAllText(VaultPath))!;
        var ct = Convert.FromBase64String(node["CtB64"]!.GetValue<string>());
        ct[0] ^= 0xFF;
        node["CtB64"] = Convert.ToBase64String(ct);
        File.WriteAllText(VaultPath, node.ToJsonString());

        Assert.ThrowsAny<Exception>(() => new AeadVaultStore(VaultPath).Open(Pw, KeyComp));
    }

    [Theory]
    [InlineData("MemoryKib", 2_000_000_000)]
    [InlineData("Iterations", 2_000_000_000)]
    [InlineData("Parallelism", 2_000_000_000)]
    public void AttackerControlledKdfCost_IsRejectedBeforeArgon2(string property, int value)
    {
        AeadVaultStore.Create(VaultPath, Pw, KeyComp);
        var node = JsonNode.Parse(File.ReadAllText(VaultPath))!;
        node[property] = value;
        File.WriteAllText(VaultPath, node.ToJsonString());

        var ex = Assert.Throws<FormatException>(() => new AeadVaultStore(VaultPath).Open(Pw, KeyComp));
        Assert.Contains("KDF parameters", ex.Message);
    }

    [Fact]
    public void OversizedEnvelopeFile_IsRejectedBeforeReadAllText()
    {
        using (var stream = new FileStream(VaultPath, FileMode.Create, FileAccess.Write, FileShare.None))
            stream.SetLength(AeadVaultStore.MaxEnvelopeBytes + 1L);

        var ex = Assert.Throws<FormatException>(() => new AeadVaultStore(VaultPath).Open(Pw, KeyComp));
        Assert.Contains("maximum size", ex.Message);
    }

    [Fact]
    public void GetSecret_Totp_ReturnsSixDigitCode()
    {
        var store = AeadVaultStore.Create(VaultPath, Pw, KeyComp);
        store.Upsert(GitHub());
        var code = store.GetSecret("github.com", VaultField.Totp);
        Assert.NotNull(code);
        Assert.Matches(@"^\d{6}$", code!);
    }

    [Fact]
    public void Resolver_ResolvesReferenceThroughStore()   // full Core + Vault path
    {
        var store = AeadVaultStore.Create(VaultPath, Pw, KeyComp);
        store.Upsert(GitHub());

        var r = new VaultResolver(store)
            .Resolve("login {{vault:github.com/password}}", liveTargetHost: "github.com", harnessId: "claude-code", isOperator: false);

        Assert.True(r.Ok);
        Assert.Equal("login s3cret", r.Resolved);
        Assert.Contains("github.com/password", r.ResolvedRefs);
    }

    [Fact]
    public void Resolver_DeniesWrongLiveTarget_Phishing()
    {
        var store = AeadVaultStore.Create(VaultPath, Pw, KeyComp);
        store.Upsert(GitHub());

        var r = new VaultResolver(store)
            .Resolve("{{vault:github.com/password}}", liveTargetHost: "evil.com", harnessId: "claude-code", isOperator: false);

        Assert.False(r.Ok);
        Assert.Null(r.Resolved);
    }

    [Fact]   // editing with blank secrets keeps the existing ones (the UI can't round-trip a secret value)
    public void UpdateItem_BlankSecrets_KeepsExisting_ChangesMetadata()
    {
        var store = AeadVaultStore.Create(VaultPath, Pw, KeyComp);
        store.Upsert(GitHub());

        var updated = new VaultEntry { Name = "GitHub", Origins = { "github.com" }, Harnesses = { "claude-code", "codex" } };
        Assert.True(store.UpdateItem("GitHub", updated));

        Assert.Equal("s3cret", store.GetSecret("github.com", VaultField.Password));   // preserved
        Assert.Equal("alice", store.GetSecret("github.com", VaultField.Username));    // preserved
        Assert.NotNull(store.GetSecret("github.com", VaultField.Totp));               // preserved
        Assert.Equal(2, store.FindByOrigin("github.com")!.Harnesses.Count);           // ACL updated
    }

    [Fact]   // editing WITH a new password replaces it
    public void UpdateItem_NewPassword_Replaces()
    {
        var store = AeadVaultStore.Create(VaultPath, Pw, KeyComp);
        store.Upsert(GitHub());
        store.UpdateItem("GitHub", new VaultEntry { Name = "GitHub", Origins = { "github.com" }, Harnesses = { "claude-code" }, Password = "new-pw" });
        Assert.Equal("new-pw", store.GetSecret("github.com", VaultField.Password));
    }

    [Fact]   // rename keeps the secrets, doesn't duplicate, drops the old name
    public void UpdateItem_Rename_KeepsSecrets_NoDuplicate()
    {
        var store = AeadVaultStore.Create(VaultPath, Pw, KeyComp);
        store.Upsert(GitHub());
        Assert.True(store.UpdateItem("GitHub", new VaultEntry { Name = "GitHub work", Origins = { "github.com" }, Harnesses = { "claude-code" } }));
        Assert.Equal("s3cret", store.GetSecret("github.com", VaultField.Password));   // still resolvable by origin
        Assert.Single(store.ListItems());
        Assert.Equal("GitHub work", store.ListItems()[0].Name);
    }

    [Fact]
    public void UpdateItem_UnknownName_ReturnsFalse()
        => Assert.False(AeadVaultStore.Create(VaultPath, Pw, KeyComp).UpdateItem("nope", new VaultEntry { Name = "nope", Origins = { "x.com" } }));

    [Fact]
    public void Delete_RemovesItem()
    {
        var store = AeadVaultStore.Create(VaultPath, Pw, KeyComp);
        store.Upsert(GitHub());
        Assert.True(store.Delete("GitHub"));
        Assert.Null(store.FindByOrigin("github.com"));
        Assert.Empty(store.ListItems());
        Assert.False(store.Delete("GitHub"));   // already gone
    }

    [Fact]
    public void PaymentCards_SharingOrigin_ResolveOnlySelectedEntry()
    {
        var store = AeadVaultStore.Create(VaultPath, Pw, KeyComp);
        store.Upsert(new VaultEntry
        {
            EntryId = "personal01",
            Kind = VaultEntryKind.PaymentCard,
            Name = "Personal Visa",
            Origins = { "shop.example" },
            Harnesses = { "codex" },
            PaymentCard = new VaultPaymentCard
                { CardNumber = "4111 1111 1111 1111", CardholderName = "A User", ExpiryMonth = "12", ExpiryYear = "2099" },
        });
        store.Upsert(new VaultEntry
        {
            EntryId = "workcard01",
            Kind = VaultEntryKind.PaymentCard,
            Name = "Work card",
            Origins = { "shop.example" },
            Harnesses = { "claude-code" },
            PaymentCard = new VaultPaymentCard
                { CardNumber = "5555 5555 5555 4444", CardholderName = "A User", ExpiryMonth = "12", ExpiryYear = "2099" },
        });

        var allowed = new VaultResolver(store).Resolve(
            "{{vault:shop.example/personal01/cardnumber}}", "shop.example", "codex", isOperator: false);
        var siblingAclBypass = new VaultResolver(store).Resolve(
            "{{vault:shop.example/workcard01/cardnumber}}", "shop.example", "codex", isOperator: false);

        Assert.True(allowed.Ok);
        Assert.Equal("4111111111111111", allowed.Resolved);
        Assert.False(siblingAclBypass.Ok);
        Assert.Null(siblingAclBypass.Resolved);
    }

    [Fact]
    public void PaymentCard_EditBlankNumberAndCvc_PreservesSecretsButUpdatesAcl()
    {
        var store = AeadVaultStore.Create(VaultPath, Pw, KeyComp);
        store.Upsert(new VaultEntry
        {
            EntryId = "personal01",
            Kind = VaultEntryKind.PaymentCard,
            Name = "Personal Visa",
            Origins = { "shop.example" },
            Harnesses = { "codex" },
            PaymentCard = new VaultPaymentCard
                { CardNumber = "4111111111111111", SecurityCode = "123", ExpiryMonth = "12", ExpiryYear = "2099" },
        });

        Assert.True(store.UpdateItem("Personal Visa", new VaultEntry
        {
            Kind = VaultEntryKind.PaymentCard,
            Name = "Personal Visa",
            Origins = { "shop.example" },
            Harnesses = { "claude-code" },
            PaymentCard = new VaultPaymentCard { ExpiryMonth = "11", ExpiryYear = "2098" },
        }));

        Assert.Equal("4111111111111111", store.GetSecret("shop.example", VaultField.CardNumber, "personal01"));
        Assert.Equal("123", store.GetSecret("shop.example", VaultField.CardSecurityCode, "personal01"));
        Assert.True(store.FindByOrigin("shop.example", "personal01")!.AllowsHarness("claude-code"));
        Assert.False(store.FindByOrigin("shop.example", "personal01")!.AllowsHarness("codex"));
    }

    [Fact]
    public void PaymentCard_OnSameOrigin_DoesNotHijackLegacyLoginReference()
    {
        var store = AeadVaultStore.Create(VaultPath, Pw, KeyComp);
        store.Upsert(new VaultEntry
        {
            EntryId = "personal01",
            Kind = VaultEntryKind.PaymentCard,
            Name = "Personal Visa",
            Origins = { "shop.example" },
            PaymentCard = new VaultPaymentCard
                { CardNumber = "4111111111111111", ExpiryMonth = "12", ExpiryYear = "2099" },
        });
        store.Upsert(new VaultEntry
        {
            Name = "Shop login", Origins = { "shop.example" }, Username = "alice", Password = "login-secret",
        });

        Assert.Equal("login-secret", store.GetSecret("shop.example", VaultField.Password));
        Assert.Equal("4111111111111111",
            store.GetSecret("shop.example", VaultField.CardNumber, "personal01"));
    }
}
