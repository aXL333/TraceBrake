using System.Security.Cryptography;
using Foreman.Core.Vault;

namespace Foreman.Vault;

/// <summary>
/// The vault lifecycle the App drives: enroll (first run) → unlock (per session) → lock (panic / exit). Holds ONE
/// long-lived <see cref="AeadVaultStore"/> + <see cref="VaultResolver"/>, so the injection hooks always have a resolver
/// that simply fails closed while the store is locked. The composite key is the master password plus a random key
/// component that the <see cref="IVaultKeyProtector"/> binds to this user+machine at rest (DPAPI, App-side). The
/// presence/Hello gate on each release is applied by the caller (<see cref="WeakeningAction.ResolveVaultCredential"/>).
/// </summary>
public sealed class VaultService
{
    private readonly string _vaultPath;
    private readonly string _componentPath;
    private readonly IVaultKeyProtector _protector;
    private readonly AeadVaultStore _store;
    private readonly VaultResolver _resolver;
    private readonly object _gate = new();
    private readonly string _depositPubPath;   // clear sidecar: the deposit PUBLIC key, usable while the vault is locked
    private readonly DepositQueue _deposits;    // clear, append-only ciphertext queue of locked-time sign-ups
    // Rate guard for agent self-signup (a WRITE). SECONDARY brake only: the primary control is that each signup is now
    // an explicitly operator-approved CU action (the fast-path auditor HOLDs it) plus a distinct presence tap. This caps
    // SUCCESSFUL creations in a sliding window, both overall and per harness (so one runaway harness can't exhaust the
    // budget for others). In-memory by design - a relaunch resets it, but the operator-approval gate above still fires
    // on every attempt, so a reset can't enable silent spam.
    private readonly List<(DateTimeOffset At, string Who)> _recentSignups = new();
    private const int MaxSignupsPerWindow = 5;            // overall
    private const int MaxSignupsPerHarnessPerWindow = 3;  // per submitting harness
    private static readonly TimeSpan SignupWindow = TimeSpan.FromMinutes(10);

    public VaultService(string vaultPath, string componentPath, IVaultKeyProtector protector)
    {
        _vaultPath = vaultPath;
        _componentPath = componentPath;
        _protector = protector;
        _store = new AeadVaultStore(vaultPath);
        _resolver = new VaultResolver(_store);   // stable; reflects _store.IsUnlocked, so it fails closed while locked
        var dir = Path.GetDirectoryName(Path.GetFullPath(vaultPath)) ?? ".";
        _depositPubPath = Path.Combine(dir, "vault-deposit.pub");
        _deposits = new DepositQueue(Path.Combine(dir, "vault-deposits.jsonl"));
    }

    /// <summary>A vault exists on disk (both the sealed component and the encrypted vault file).</summary>
    public bool IsEnrolled => File.Exists(_vaultPath) && File.Exists(_componentPath);
    public bool IsUnlocked => _store.IsUnlocked;

    /// <summary>Always non-null; resolves only while unlocked (otherwise returns a "vault is locked" failure).</summary>
    public IVaultResolver Resolver => _resolver;

    /// <summary>Raised after a successful Unlock (outside the lock). The App uses it to surface a swapped-key tamper
    /// alert (see <see cref="LastDepositStatus"/>) and any pending locked-time deposits for operator review.</summary>
    public event Action? Unlocked;

    /// <summary>First-run: generate a random key component, protect it for this user+machine, and create the vault.</summary>
    public void Enroll(string masterPassword)
    {
        lock (_gate)
        {
            if (IsEnrolled) throw new InvalidOperationException("vault is already enrolled");
            var component = RandomNumberGenerator.GetBytes(32);
            try
            {
                var dir = Path.GetDirectoryName(_componentPath);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.WriteAllBytes(_componentPath, _protector.Protect(component));
                _store.Provision(masterPassword, component);
                LastDepositStatus = EnsureDepositKeysLocked();   // generate the deposit keypair + write the clear sidecar
            }
            finally { Array.Clear(component); }
        }
    }

    /// <summary>Open the vault: the protector releases the component (this user+machine), then the master password
    /// completes the composite key. Throws on a wrong password / wrong machine / tampered file.</summary>
    public void Unlock(string masterPassword)
    {
        lock (_gate)
        {
            if (!IsEnrolled) throw new InvalidOperationException("vault is not enrolled");
            var component = _protector.Unprotect(File.ReadAllBytes(_componentPath));
            try { _store.Open(masterPassword, component); }
            finally { Array.Clear(component); }
            LastDepositStatus = EnsureDepositKeysLocked();   // migrate older vaults + detect a swapped clear sidecar
        }
        Unlocked?.Invoke();   // after releasing the gate: subscribers may read PendingDepositCount / DrainDeposits
    }

    /// <summary>Forget the in-memory key + decrypted document (panic / exit). Safe to call when already locked.</summary>
    public void Lock() => _store.WipeInMemoryKeys();

    /// <summary>Operator mutation: add or replace an item, then persist. Requires an unlocked vault.</summary>
    public void Upsert(VaultEntry entry)
    {
        lock (_gate)
        {
            if (!_store.IsUnlocked) throw new InvalidOperationException("vault is locked");
            _store.Upsert(entry);
        }
    }

    /// <summary>Operator mutation: edit the item named <paramref name="originalName"/> (a blank secret field keeps the
    /// existing value; rename supported). Returns false if no item matched. Requires an unlocked vault.</summary>
    public bool UpdateItem(string originalName, VaultEntry updated)
    {
        lock (_gate)
        {
            if (!_store.IsUnlocked) throw new InvalidOperationException("vault is locked");
            return _store.UpdateItem(originalName, updated);
        }
    }

    /// <summary>Operator mutation: delete the item named <paramref name="name"/>. Returns false if none matched.
    /// Requires an unlocked vault.</summary>
    public bool Delete(string name)
    {
        lock (_gate)
        {
            if (!_store.IsUnlocked) throw new InvalidOperationException("vault is locked");
            return _store.Delete(name);
        }
    }

    /// <summary>
    /// Agent self-signup: GENERATE a strong password, store it as a NEW credential bound to <paramref name="origin"/>,
    /// and return it for the agent to fill into the signup form (the agent never picks or sees a stored secret). Gated:
    /// vault unlocked; the requested origin must match the LIVE target (no cross-site); a credential must NOT already
    /// exist under that origin OR name (never clobber an existing login - non-destructive add); and a per-harness +
    /// overall rate guard. The caller additionally requires the operator-approved CU action + a distinct presence tap.
    /// The new item is stored OPERATOR-ONLY (empty harness ACL): an agent can never self-authorize a credential it
    /// could later auto-resolve for an origin it chose (phishing-grant); the operator confirms + grants reuse via the
    /// management UI. A Note marks it machine-created. Returns (ok, generated-password, reason); reason is "" on success.
    /// </summary>
    public (bool Ok, string? Value, string Reason) SelfSignup(string origin, string liveOrigin, string? byHarness)
    {
        lock (_gate)
        {
            if (!_store.IsUnlocked) return (false, null, "vault is locked");

            var host = VaultDomainBinding.NormalizeHost(origin);
            if (string.IsNullOrEmpty(host)) return (false, null, "invalid signup origin");
            if (!string.Equals(host, VaultDomainBinding.NormalizeHost(liveOrigin), StringComparison.OrdinalIgnoreCase))
                return (false, null, $"signup origin does not match the live target '{liveOrigin}'");

            var who = string.IsNullOrEmpty(byHarness) ? "operator" : byHarness;
            if (!RateGuardAllowsLocked(who))
                return (false, null, "too many sign-ups in a short window; try again shortly");

            // OPERATOR-ONLY (no harness on the ACL): the creating agent cannot later auto-resolve this credential.
            var entry = new VaultEntry
            {
                Name = host,
                Origins = { host },
                Password = VaultPasswordGenerator.Generate(20),
                Notes = $"created via agent self-signup ({who})",
            };
            // Non-destructive add: refuses on a Name OR origin collision, so the WRITE can never clobber an operator login.
            if (!_store.TryAddNew(entry))
                return (false, null, "a credential already exists for this site; signup would overwrite it");

            RecordSignupLocked(who);
            return (true, entry.Password, "");
        }
    }

    // ── Locked-vault deposit queue (P-BM4b) ──────────────────────────────────────────────────────────────────────
    // A self-signup that arrives while the vault is LOCKED can't write the encrypted store, so TraceBrake encrypts the
    // generated credential to the deposit PUBLIC key (clear sidecar) and queues the ciphertext; the operator reviews +
    // commits each one on unlock. Because the public key is in the clear the queue is FORGEABLE, so: nothing
    // auto-commits, the review UI must show origin/harness/time as unverified CLAIMS, commit routes through the same
    // no-clobber operator-only path as live signup, and a swapped clear sidecar is detected on unlock.

    /// <summary>Result of reconciling the deposit keypair on enroll/unlock.</summary>
    public enum DepositKeyStatus { None, Ok, Generated, Tampered }

    /// <summary>Set on the last enroll/unlock: Generated (first run / migrated older vault), Ok, or Tampered (the clear
    /// public-key sidecar does NOT match the sealed copy - a swap; the deposit queue must not be trusted/drained).</summary>
    public DepositKeyStatus LastDepositStatus { get; private set; } = DepositKeyStatus.None;

    /// <summary>Number of locked-time sign-ups waiting for operator review (readable any time; needs no key).</summary>
    public int PendingDepositCount => _deposits.Count;

    /// <summary>
    /// LOCKED-vault self-signup: generate a strong password, encrypt it (+ origin/harness/time) to the deposit public
    /// key, and queue it for operator review on unlock; return the password so the agent can still fill the form now.
    /// Gated like the unlocked path (domain-binding to the live target + the per-harness/overall rate guard) plus the
    /// queue's hard size cap. Refuses if the vault has never been unlocked since the feature shipped (no deposit key
    /// yet). The caller still requires the operator-approved CU action + the distinct presence tap.
    /// </summary>
    public (bool Ok, string? Value, string Reason) SelfSignupDeposit(string origin, string liveOrigin, string? byHarness)
    {
        lock (_gate)
        {
            var pub = ReadClearPubkey();
            if (pub is null)
                return (false, null, "locked sign-up isn't available yet - unlock the vault once to enable it");

            var host = VaultDomainBinding.NormalizeHost(origin);
            if (string.IsNullOrEmpty(host)) return (false, null, "invalid signup origin");
            if (!string.Equals(host, VaultDomainBinding.NormalizeHost(liveOrigin), StringComparison.OrdinalIgnoreCase))
                return (false, null, $"signup origin does not match the live target '{liveOrigin}'");

            var who = string.IsNullOrEmpty(byHarness) ? "operator" : byHarness;
            if (!RateGuardAllowsLocked(who))
                return (false, null, "too many sign-ups in a short window; try again shortly");

            var deposit = new DepositQueue.PendingDeposit(
                host, Username: null, Password: VaultPasswordGenerator.Generate(20), ByHarness: who,
                CreatedAtUtc: DateTimeOffset.UtcNow.ToString("o"));
            if (!_deposits.Enqueue(pub, deposit))
                return (false, null, "the locked sign-up queue is full - unlock the vault to review pending sign-ups");

            RecordSignupLocked(who);
            return (true, deposit.Password, "");
        }
    }

    /// <summary>Unlock-time: decrypt + dedupe the queued deposits for operator review. NEVER commits. Returns the
    /// pending deposits, a count of lines that failed to decrypt (tamper/corruption), and whether the deposit key
    /// itself was tampered (a swapped sidecar - the queue is then NOT trusted and nothing is returned).</summary>
    public (IReadOnlyList<DepositQueue.PendingDeposit> Deposits, int Failed, bool KeyTampered) DrainDeposits()
    {
        lock (_gate)
        {
            if (!_store.IsUnlocked) return ([], 0, false);
            if (LastDepositStatus == DepositKeyStatus.Tampered) return ([], 0, true);
            var (_, priv) = _store.GetDepositKeys();
            if (priv is null) return ([], 0, false);
            var r = _deposits.Drain(priv);
            return (Dedupe(r.Deposits), r.Failed, false);
        }
    }

    /// <summary>Operator action: commit ONE reviewed deposit into the vault via the same no-clobber, OPERATOR-ONLY path
    /// as live self-signup (so a forged deposit can neither clobber a real login nor self-grant a harness ACL). Requires
    /// an unlocked vault. Returns (ok, reason).</summary>
    public (bool Ok, string Reason) CommitDeposit(DepositQueue.PendingDeposit deposit)
    {
        lock (_gate)
        {
            if (!_store.IsUnlocked) return (false, "vault is locked");
            var host = VaultDomainBinding.NormalizeHost(deposit.Origin);
            if (string.IsNullOrEmpty(host)) return (false, "invalid origin");
            var entry = new VaultEntry
            {
                Name = host,
                Origins = { host },
                Password = deposit.Password,
                Notes = $"created via agent self-signup while locked ({deposit.ByHarness})",
            };
            return _store.TryAddNew(entry) ? (true, "") : (false, "a credential already exists for this site");
        }
    }

    /// <summary>Remove the deposit queue file (only AFTER the operator has reviewed + committed/rejected every deposit).</summary>
    public void ClearDeposits() { lock (_gate) _deposits.Clear(); }

    // Generate the deposit keypair if absent (enroll / older-vault migration), else verify the clear sidecar matches the
    // sealed public key (swap detection). Must be called while UNLOCKED (reads/writes the sealed keys).
    private DepositKeyStatus EnsureDepositKeysLocked()
    {
        var (pub, priv) = _store.GetDepositKeys();
        if (pub is null || priv is null)
        {
            var (newPub, newPriv) = DepositCrypto.GenerateKeyPair();
            _store.SetDepositKeys(newPub, newPriv);
            WriteClearPubkey(newPub);
            return DepositKeyStatus.Generated;
        }
        var clear = ReadClearPubkey();
        if (clear is null) { WriteClearPubkey(pub); return DepositKeyStatus.Ok; }   // sidecar missing -> restore from sealed
        return clear.AsSpan().SequenceEqual(pub) ? DepositKeyStatus.Ok : DepositKeyStatus.Tampered;
    }

    private byte[]? ReadClearPubkey()
    {
        try { return File.Exists(_depositPubPath) ? File.ReadAllBytes(_depositPubPath) : null; }
        catch { return null; }
    }

    private void WriteClearPubkey(byte[] pub)
    {
        var dir = Path.GetDirectoryName(_depositPubPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        File.WriteAllBytes(_depositPubPath, pub);
    }

    // Rate guard shared by the unlocked + locked sign-up paths (in-memory; per-harness + overall sliding window).
    private bool RateGuardAllowsLocked(string who)
    {
        var now = DateTimeOffset.UtcNow;
        _recentSignups.RemoveAll(t => now - t.At > SignupWindow);
        return _recentSignups.Count < MaxSignupsPerWindow
            && _recentSignups.Count(t => string.Equals(t.Who, who, StringComparison.OrdinalIgnoreCase)) < MaxSignupsPerHarnessPerWindow;
    }

    private void RecordSignupLocked(string who) => _recentSignups.Add((DateTimeOffset.UtcNow, who));

    // Collapse exact replays (same origin + password + harness): a captured envelope re-appended to the clear queue
    // must not surface as a second committable credential.
    private static IReadOnlyList<DepositQueue.PendingDeposit> Dedupe(IReadOnlyList<DepositQueue.PendingDeposit> deposits)
    {
        var seen = new HashSet<(string, string, string)>();
        var outp = new List<DepositQueue.PendingDeposit>();
        foreach (var d in deposits)
            if (seen.Add((d.Origin, d.Password, d.ByHarness)))
                outp.Add(d);
        return outp;
    }

    /// <summary>Item metadata for the management UI (no secret values). Requires an unlocked vault.</summary>
    public IReadOnlyList<VaultItemInfo> ListItems()
    {
        lock (_gate)
        {
            if (!_store.IsUnlocked) throw new InvalidOperationException("vault is locked");
            return _store.ListItems();
        }
    }
}
