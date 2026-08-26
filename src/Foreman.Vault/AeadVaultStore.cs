using System.Text.Json;
using Foreman.Core.Vault;

namespace Foreman.Vault;

/// <summary>
/// Native authenticated credential store: AES-256-GCM + Argon2id, composite key = master password + a TPM-sealed key
/// component (the seal of the component is wired App-side; this store just takes the bytes). Cross-platform. Implements
/// <see cref="IVaultStore"/> so Core's <see cref="VaultResolver"/> works against it unchanged. The decrypted document
/// lives in memory only while unlocked and is dropped on <see cref="WipeInMemoryKeys"/>.
/// </summary>
public sealed class AeadVaultStore(string path) : IVaultStore
{
    public const int MaxEnvelopeBytes = 12 * 1024 * 1024;
    private readonly string _path = path;
    private readonly object _gate = new();
    private string? _password;
    private byte[]? _keyComponent;
    private VaultDocument? _doc;

    public bool IsUnlocked { get { lock (_gate) return _doc is not null; } }

    /// <summary>Provision THIS instance as a brand-new empty vault (first-run enrollment) and persist it. Overwrites
    /// any existing file at the path. Lets a long-lived store instance be enrolled in place (stable resolver).</summary>
    public void Provision(string masterPassword, byte[] keyComponent)
    {
        lock (_gate)
        {
            _password = masterPassword;
            _keyComponent = (byte[])keyComponent.Clone();
            _doc = new VaultDocument();
            SaveLocked();
        }
    }

    /// <summary>Convenience: a new store provisioned as an empty vault at the path. Used by tests/enrollment.</summary>
    public static AeadVaultStore Create(string path, string masterPassword, byte[] keyComponent)
    {
        var store = new AeadVaultStore(path);
        store.Provision(masterPassword, keyComponent);
        return store;
    }

    /// <summary>Open + decrypt. Throws on wrong master password / wrong key component / tampered file (AES-GCM tag mismatch).</summary>
    public void Open(string masterPassword, byte[] keyComponent)
    {
        string envelope;
        using (var stream = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            if (stream.Length > MaxEnvelopeBytes)
                throw new FormatException("vault envelope exceeds the maximum size");
            using var reader = new StreamReader(stream);
            envelope = reader.ReadToEnd();
        }
        var json = VaultCrypto.Decrypt(envelope, masterPassword, keyComponent);
        var doc = JsonSerializer.Deserialize<VaultDocument>(json) ?? new VaultDocument();
        lock (_gate)
        {
            _password = masterPassword;
            _keyComponent = (byte[])keyComponent.Clone();
            _doc = doc;
        }
    }

    public VaultItemInfo? FindByOrigin(string origin, string? entryId = null)
    {
        lock (_gate)
        {
            var e = FindEntryLocked(origin, entryId);
            return e is null ? null : ToInfo(e);
        }
    }

    /// <summary>Metadata for every item (names/origins/which fields/ACL — never secret VALUES), for the management UI.
    /// Returns empty while locked.</summary>
    public IReadOnlyList<VaultItemInfo> ListItems()
    {
        lock (_gate) return _doc is null ? [] : _doc.Items.Select(ToInfo).ToArray();
    }

    private static VaultItemInfo ToInfo(VaultEntry e) =>
        new(e.Name, e.Origins.ToArray(), e.Harnesses.ToArray(), HasTotp: !string.IsNullOrWhiteSpace(e.TotpSeedBase32))
        {
            HasUsername = !string.IsNullOrWhiteSpace(e.Username),
            HasPassword = !string.IsNullOrWhiteSpace(e.Password),
            EntryId = e.EntryId,
            IsPaymentCard = e.Kind == VaultEntryKind.PaymentCard,
            CardholderName = e.PaymentCard?.CardholderName,
            CardLastFour = LastFour(e.PaymentCard?.CardNumber),
            CardExpiryMonth = e.PaymentCard?.ExpiryMonth,
            CardExpiryYear = e.PaymentCard?.ExpiryYear,
            BillingAddress = e.PaymentCard?.BillingAddress,
            HasCardSecurityCode = !string.IsNullOrWhiteSpace(e.PaymentCard?.SecurityCode),
        };

    public string? GetSecret(string origin, VaultField field, string? entryId = null)
    {
        lock (_gate)
        {
            var e = FindEntryLocked(origin, entryId);
            if (e is null) return null;
            return field switch
            {
                VaultField.Username => e.Username,
                VaultField.Password => e.Password,
                VaultField.Note     => e.Notes,
                VaultField.Totp     => string.IsNullOrWhiteSpace(e.TotpSeedBase32)
                                          ? null
                                          : VaultTotp.FromBase32(e.TotpSeedBase32!, DateTime.UtcNow),
                VaultField.CardholderName  when e.Kind == VaultEntryKind.PaymentCard => e.PaymentCard?.CardholderName,
                VaultField.CardNumber      when e.Kind == VaultEntryKind.PaymentCard => DigitsOnly(e.PaymentCard?.CardNumber),
                VaultField.CardExpiryMonth when e.Kind == VaultEntryKind.PaymentCard => e.PaymentCard?.ExpiryMonth,
                VaultField.CardExpiryYear  when e.Kind == VaultEntryKind.PaymentCard => e.PaymentCard?.ExpiryYear,
                VaultField.CardSecurityCode when e.Kind == VaultEntryKind.PaymentCard => DigitsOnly(e.PaymentCard?.SecurityCode),
                VaultField.BillingAddress  when e.Kind == VaultEntryKind.PaymentCard => e.PaymentCard?.BillingAddress,
                _ => null,
            };
        }
    }

    /// <summary>Add or replace the item with the same name (operator mutation) and persist. Requires an unlocked vault.</summary>
    public void Upsert(VaultEntry entry)
    {
        lock (_gate)
        {
            EnsureUnlockedLocked();
            PrepareEntry(entry);
            ValidateEntry(entry);
            _doc!.Items.RemoveAll(i => string.Equals(i.Name, entry.Name, StringComparison.OrdinalIgnoreCase));
            _doc.Items.Add(entry);
            SaveLocked();
        }
    }

    /// <summary>
    /// NON-destructive add (for agent self-signup, a WRITE): add <paramref name="entry"/> only if NO existing item
    /// shares its Name OR any of its origins. Returns false (and changes nothing) on any collision. Unlike
    /// <see cref="Upsert"/> — which deletes any same-named item before adding — this can never clobber an operator
    /// credential, so the by-name store op agrees with the by-origin no-clobber intent. Requires an unlocked vault.
    /// </summary>
    public bool TryAddNew(VaultEntry entry)
    {
        lock (_gate)
        {
            EnsureUnlockedLocked();
            PrepareEntry(entry);
            ValidateEntry(entry);
            var nameTaken = _doc!.Items.Any(i => string.Equals(i.Name, entry.Name, StringComparison.OrdinalIgnoreCase));
            var originTaken = entry.Origins.Any(o => _doc.Items.Any(i =>
                i.Kind == VaultEntryKind.Login &&
                i.Origins.Any(existingOrigin => VaultDomainBinding.HostMatches(existingOrigin, o))));
            if (nameTaken || originTaken) return false;
            _doc.Items.Add(entry);
            SaveLocked();
            return true;
        }
    }

    /// <summary>
    /// Edit the item currently named <paramref name="originalName"/>, replacing it with <paramref name="updated"/>.
    /// A null/blank secret field (Username/Password/TotpSeedBase32/Notes) in <paramref name="updated"/> KEEPS the
    /// existing value — the management UI never sees secret values, so "leave blank to keep" is the only safe edit.
    /// Supports rename (originalName may differ from updated.Name). Returns false if no item matched. Operator
    /// mutation; requires an unlocked vault.
    /// </summary>
    public bool UpdateItem(string originalName, VaultEntry updated)
    {
        lock (_gate)
        {
            EnsureUnlockedLocked();
            var existing = _doc!.Items.FirstOrDefault(i => string.Equals(i.Name, originalName, StringComparison.OrdinalIgnoreCase));
            if (existing is null) return false;
            if (string.IsNullOrWhiteSpace(updated.EntryId)) updated.EntryId = existing.EntryId;
            PrepareEntry(updated);
            // Preserve unchanged secrets (blank field == keep), since the UI can't round-trip the real value.
            updated.Username       = string.IsNullOrEmpty(updated.Username)       ? existing.Username       : updated.Username;
            updated.Password       = string.IsNullOrEmpty(updated.Password)       ? existing.Password       : updated.Password;
            updated.TotpSeedBase32 = string.IsNullOrWhiteSpace(updated.TotpSeedBase32) ? existing.TotpSeedBase32 : updated.TotpSeedBase32;
            updated.Notes          = string.IsNullOrEmpty(updated.Notes)          ? existing.Notes          : updated.Notes;
            if (updated.Kind == VaultEntryKind.PaymentCard && existing.Kind == VaultEntryKind.PaymentCard)
            {
                updated.PaymentCard ??= new VaultPaymentCard();
                var old = existing.PaymentCard;
                if (old is not null)
                {
                    updated.PaymentCard.CardNumber = string.IsNullOrWhiteSpace(updated.PaymentCard.CardNumber)
                        ? old.CardNumber : updated.PaymentCard.CardNumber;
                    updated.PaymentCard.SecurityCode = string.IsNullOrWhiteSpace(updated.PaymentCard.SecurityCode)
                        ? old.SecurityCode : updated.PaymentCard.SecurityCode;
                }
            }
            ValidateEntry(updated);
            // Remove the old record (and any item already holding the NEW name, so a rename can't duplicate).
            _doc.Items.RemoveAll(i => string.Equals(i.Name, originalName, StringComparison.OrdinalIgnoreCase)
                                   || string.Equals(i.Name, updated.Name, StringComparison.OrdinalIgnoreCase));
            _doc.Items.Add(updated);
            SaveLocked();
            return true;
        }
    }

    /// <summary>Remove the item named <paramref name="name"/> and persist. Returns false if none matched. Operator
    /// mutation; requires an unlocked vault.</summary>
    public bool Delete(string name)
    {
        lock (_gate)
        {
            EnsureUnlockedLocked();
            var removed = _doc!.Items.RemoveAll(i => string.Equals(i.Name, name, StringComparison.OrdinalIgnoreCase));
            if (removed > 0) SaveLocked();
            return removed > 0;
        }
    }

    /// <summary>The sealed deposit keypair (SPKI public, PKCS#8 private), or (null,null) if not yet generated. Requires
    /// an unlocked vault (the keys live in the encrypted document).</summary>
    public (byte[]? Pub, byte[]? Priv) GetDepositKeys()
    {
        lock (_gate)
        {
            EnsureUnlockedLocked();
            return (_doc!.DepositPublicKeySpki, _doc.DepositPrivateKeyPkcs8);
        }
    }

    /// <summary>Store the deposit keypair in the sealed document and persist. Requires an unlocked vault.</summary>
    public void SetDepositKeys(byte[] publicSpki, byte[] privatePkcs8)
    {
        lock (_gate)
        {
            EnsureUnlockedLocked();
            _doc!.DepositPublicKeySpki = publicSpki;
            _doc.DepositPrivateKeyPkcs8 = privatePkcs8;
            SaveLocked();
        }
    }

    public void WipeInMemoryKeys()
    {
        lock (_gate)
        {
            if (_keyComponent is not null) Array.Clear(_keyComponent);
            _keyComponent = null;
            _password = null;
            _doc = null;   // drop the plaintext document (managed strings can't be zeroed; see docs/vault-design.md)
        }
    }

    private VaultEntry? FindEntryLocked(string origin, string? entryId = null) =>
        _doc?.Items.FirstOrDefault(i =>
            (string.IsNullOrWhiteSpace(entryId)
                ? i.Kind == VaultEntryKind.Login
                : string.Equals(i.EntryId, entryId, StringComparison.OrdinalIgnoreCase)) &&
            i.Origins.Any(o => VaultDomainBinding.HostMatches(o, origin)));

    private static void PrepareEntry(VaultEntry entry)
    {
        if (string.IsNullOrWhiteSpace(entry.EntryId))
            entry.EntryId = Guid.NewGuid().ToString("N")[..12];
        if (entry.Kind != VaultEntryKind.PaymentCard) return;
        entry.PaymentCard ??= new VaultPaymentCard();
        entry.PaymentCard.CardNumber = DigitsOnly(entry.PaymentCard.CardNumber);
        entry.PaymentCard.SecurityCode = DigitsOnly(entry.PaymentCard.SecurityCode);
    }

    private static void ValidateEntry(VaultEntry entry)
    {
        if (entry.Kind != VaultEntryKind.PaymentCard) return;
        var card = entry.PaymentCard ?? throw new InvalidOperationException("payment-card details are required");
        if (entry.Origins.Count == 0) throw new InvalidOperationException("a payment card needs at least one checkout origin");
        var number = card.CardNumber ?? "";
        if (number.Length is < 12 or > 19 || !PassesLuhn(number))
            throw new InvalidOperationException("payment-card number is invalid");
        if (!int.TryParse(card.ExpiryMonth, out var month) || month is < 1 or > 12)
            throw new InvalidOperationException("payment-card expiry month is invalid");
        if (!int.TryParse(card.ExpiryYear, out var year) || card.ExpiryYear!.Length != 4 || year < DateTime.UtcNow.Year)
            throw new InvalidOperationException("payment-card expiry year is invalid");
        if (year == DateTime.UtcNow.Year && month < DateTime.UtcNow.Month)
            throw new InvalidOperationException("payment card has expired");
        if (card.SecurityCode is { Length: > 0 } cvc && cvc.Length is < 3 or > 4)
            throw new InvalidOperationException("payment-card security code is invalid");
    }

    private static bool PassesLuhn(string digits)
    {
        var sum = 0;
        var alternate = false;
        for (var i = digits.Length - 1; i >= 0; i--)
        {
            var n = digits[i] - '0';
            if (alternate && (n *= 2) > 9) n -= 9;
            sum += n;
            alternate = !alternate;
        }
        return digits.Length > 0 && sum % 10 == 0;
    }

    private static string? DigitsOnly(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var digits = new string(value.Where(char.IsAsciiDigit).ToArray());
        return digits.Length == 0 ? null : digits;
    }

    private static string? LastFour(string? value)
    {
        var digits = DigitsOnly(value);
        return digits is null ? null : digits[^Math.Min(4, digits.Length)..];
    }

    private void EnsureUnlockedLocked()
    {
        if (_doc is null || _password is null || _keyComponent is null)
            throw new InvalidOperationException("vault is locked");
    }

    private void SaveLocked()
    {
        EnsureUnlockedLocked();
        var envelope = VaultCrypto.Encrypt(JsonSerializer.Serialize(_doc), _password!, _keyComponent!);
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, envelope);
        if (File.Exists(_path)) File.Replace(tmp, _path, null); else File.Move(tmp, _path);   // atomic-ish swap
    }
}
