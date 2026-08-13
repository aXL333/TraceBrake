using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Foreman.App.Security;
using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.Core.Security;
using Foreman.Vault;

namespace Foreman.App.Windows;

/// <summary>
/// Operator-only vault UI: enroll (first run) -> unlock (master password + a Windows Hello tap) -> manage (list +
/// add / edit / delete credentials + review locked-time sign-up deposits inline). A <see cref="UserControl"/> hosted
/// in the dashboard's Vault tab (tray "Vault…" opens it). All mutations are operator-only by construction (this
/// surface is never reachable over MCP). Secret VALUES never appear here - only names/origins/which-fields/ACL. The
/// agent-facing resolve path is the injection hook (P1.4); this is the human's management surface.
/// </summary>
public partial class VaultView : UserControl
{
    private readonly VaultService _vault;
    private string? _editingOriginalName;   // non-null while the add form is editing an existing item (its original name)
    private string? _editingEntryId;
    private readonly List<VaultHarnessChoice> _cardHarnessChoices = [];

    /// <summary>Injected by the composition root so locked-time sign-ups are reviewed INLINE on this surface (no
    /// separate window): the pending count, a drained snapshot (no secrets), and per-item accept / reject / clear.</summary>
    public Func<int>? PendingDepositCount { get; set; }
    public Func<DepositReviewSnapshot>? GetDepositReview { get; set; }
    public Func<string, (bool Ok, string Reason)>? AcceptDeposit { get; set; }
    public Action<string>? RejectDeposit { get; set; }
    public Action? ClearDepositQueue { get; set; }
    public Func<IReadOnlyList<VaultHarnessChoice>>? GetEligibleCardHarnesses { get; set; }

    private readonly List<DepositReviewItem> _reviewItems = [];

    public VaultView(VaultService vault)
    {
        _vault = vault;
        InitializeComponent();
        // Enter in any password field triggers that screen's primary action, so unlocking / enrolling / saving
        // never needs a mouse trip to the button.
        EnrollPw.KeyDown      += (_, e) => SubmitOnEnter(e, EnrollClick);
        EnrollConfirm.KeyDown += (_, e) => SubmitOnEnter(e, EnrollClick);
        UnlockPw.KeyDown      += (_, e) => SubmitOnEnter(e, UnlockClick);
        AddPw.KeyDown         += (_, e) => SubmitOnEnter(e, SaveItemClick);
        CardNumber.KeyDown    += (_, e) => SubmitOnEnter(e, SaveCardClick);
        Loaded += (_, _) => RefreshState();
    }

    // Treat Enter in an input as a click of that screen's primary button.
    private void SubmitOnEnter(System.Windows.Input.KeyEventArgs e, RoutedEventHandler action)
    {
        if (e.Key != System.Windows.Input.Key.Enter) return;
        e.Handled = true;
        action(this, new RoutedEventArgs());
    }

    /// <summary>Re-read vault state and show the right panel. Safe to call when the tab is shown.</summary>
    public void RefreshState()
    {
        var enrolled = _vault.IsEnrolled;
        var unlocked = _vault.IsUnlocked;
        EnrollPanel.Visibility  = !enrolled ? Visibility.Visible : Visibility.Collapsed;
        UnlockPanel.Visibility  = enrolled && !unlocked ? Visibility.Visible : Visibility.Collapsed;
        ManagerPanel.Visibility = unlocked ? Visibility.Visible : Visibility.Collapsed;
        if (unlocked) { PopulateItems(); RefreshDepositBanner(); }
    }

    // Show the "pending sign-ups to review" banner when the vault is unlocked and the queue is non-empty (and the
    // inline review panel isn't already open).
    private void RefreshDepositBanner()
    {
        var pending = PendingDepositCount?.Invoke() ?? 0;
        var reviewing = DepositReviewPanel.Visibility == Visibility.Visible;
        DepositReviewBanner.Visibility = pending > 0 && !reviewing ? Visibility.Visible : Visibility.Collapsed;
        if (pending > 0)
            DepositReviewText.Text = pending == 1
                ? "1 agent sign-up is waiting for your review"
                : $"{pending} agent sign-ups are waiting for your review";
    }

    // Open the INLINE review panel (drains the queue). Replaces the old pop-up DepositReviewWindow.
    private void ReviewDepositsClick(object sender, RoutedEventArgs e)
    {
        if (GetDepositReview is null) return;
        var snap = GetDepositReview();
        _reviewItems.Clear();
        _reviewItems.AddRange(snap.Items);

        ReviewWarningBox.Visibility = Visibility.Collapsed;
        ClearQueueButton.Content = "Finish & clear queue";
        if (snap.KeyTampered)
        {
            ReviewWarningText.Text = "The deposit key sidecar does not match the sealed key - it may have been swapped "
                + "since these were queued. The queue is NOT trusted and was not decrypted. Treat any of these as suspect.";
            ReviewWarningBox.Visibility = Visibility.Visible;
            ClearQueueButton.Content = "Discard the suspect queue";
        }
        else if (snap.Failed > 0)
        {
            ReviewWarningText.Text = $"{snap.Failed} queued line(s) could not be decrypted (possible tampering or "
                + "corruption). The readable sign-ups below are still shown; the bad lines are left for forensics.";
            ReviewWarningBox.Visibility = Visibility.Visible;
            ClearQueueButton.Content = $"Finish & clear (also discards {snap.Failed} unreadable line(s))";
        }

        ReviewStatusText.Text = string.Empty;
        DepositReviewPanel.Visibility = Visibility.Visible;
        DepositReviewBanner.Visibility = Visibility.Collapsed;
        RebindReview();
    }

    private void RebindReview()
    {
        DepositList.ItemsSource = null;
        DepositList.ItemsSource = _reviewItems;
        ReviewEmptyText.Visibility = _reviewItems.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void AcceptDepositClick(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not string id || AcceptDeposit is null) return;
        var (ok, reason) = AcceptDeposit(id);
        if (ok) { _reviewItems.RemoveAll(i => i.Id == id); RebindReview(); ReviewStatusText.Text = "Stored in the vault."; PopulateItems(); }
        else ReviewStatusText.Text = "Not stored: " + reason;
    }

    private void RejectDepositClick(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not string id) return;
        RejectDeposit?.Invoke(id);
        _reviewItems.RemoveAll(i => i.Id == id);
        RebindReview();
        ReviewStatusText.Text = "Discarded.";
    }

    private void ClearQueueClick(object sender, RoutedEventArgs e)
    {
        ClearDepositQueue?.Invoke();
        CloseReview();
    }

    private void CloseReviewClick(object sender, RoutedEventArgs e) => CloseReview();

    private void CloseReview()
    {
        DepositReviewPanel.Visibility = Visibility.Collapsed;
        _reviewItems.Clear();
        RefreshDepositBanner();   // reflect commits/rejects: the banner count updates or hides when the queue is empty
    }

    private void EnrollClick(object sender, RoutedEventArgs e)
    {
        EnrollError.Text = string.Empty;
        var pw = EnrollPw.Password;
        if (pw.Length < 8) { EnrollError.Text = "Use at least 8 characters."; return; }
        if (pw != EnrollConfirm.Password) { EnrollError.Text = "Passwords do not match."; return; }
        try { _vault.Enroll(pw); }
        catch (Exception ex) { EnrollError.Text = ex.Message; return; }
        EnrollPw.Clear(); EnrollConfirm.Clear();
        Log("Credential vault created.");
        RefreshState();
    }

    private async void UnlockClick(object sender, RoutedEventArgs e)
    {
        UnlockError.Text = string.Empty;
        // Presence tap when the lock is on (no-op otherwise) — proving the human is here before the vault opens.
        if (!await PresenceGuard.AuthorizeAsync(WeakeningAction.ResolveVaultCredential, "unlock the credential vault"))
        { UnlockError.Text = "Presence not verified — the vault stays locked."; return; }
        try { _vault.Unlock(UnlockPw.Password); }
        catch { UnlockError.Text = "Wrong master password, or the vault can't be opened on this machine."; return; }
        UnlockPw.Clear();
        Log("Vault unlocked.");
        RefreshState();
    }

    private void LockClick(object sender, RoutedEventArgs e)
    {
        _vault.Lock();
        Log("Vault locked.");
        RefreshState();
    }

    private void PopulateItems()
    {
        var rows = _vault.ListItems().Select(VaultItemRow.From).ToList();
        ItemsList.ItemsSource = rows;
        EmptyHint.Visibility = rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OpenAddForm()
    {
        _editingOriginalName = null;                       // a fresh open is always ADD mode
        _editingEntryId = null;
        AddFormTitle.Text = "Add credential";
        EditKeepHint.Visibility = Visibility.Collapsed;
        AddForm.Visibility = Visibility.Visible;
        CardForm.Visibility = Visibility.Collapsed;
        AddButton.Visibility = Visibility.Collapsed;
        AddCardButton.Visibility = Visibility.Collapsed;
        AddOrigins.Focus();   // the website is the one required field, so start there
    }

    private void ShowAddFormClick(object sender, RoutedEventArgs e) => OpenAddForm();

    private void ShowCardFormClick(object sender, RoutedEventArgs e) => OpenCardForm(null);

    private void OpenCardForm(VaultItemRow? row)
    {
        _editingOriginalName = row?.Name;
        _editingEntryId = row?.EntryId;
        CardFormTitle.Text = row is null ? "Add payment card" : "Edit payment card";
        CardEditKeepHint.Visibility = row is null ? Visibility.Collapsed : Visibility.Visible;
        CardName.Text = row?.Name ?? string.Empty;
        CardHolder.Text = row?.CardholderName ?? string.Empty;
        CardExpiryMonth.Text = row?.CardExpiryMonth ?? string.Empty;
        CardExpiryYear.Text = row?.CardExpiryYear ?? string.Empty;
        CardBillingAddress.Text = row?.BillingAddress ?? string.Empty;
        CardOrigins.Text = row is null ? string.Empty : string.Join(", ", row.OriginList);
        CardNumber.Clear();
        CardSecurityCode.Clear();
        CardError.Text = string.Empty;
        BindCardHarnesses(row?.HarnessList ?? []);
        AddForm.Visibility = Visibility.Collapsed;
        CardForm.Visibility = Visibility.Visible;
        AddButton.Visibility = Visibility.Collapsed;
        AddCardButton.Visibility = Visibility.Collapsed;
        CardName.Focus();
    }

    private void BindCardHarnesses(IReadOnlyList<string> allowed)
    {
        _cardHarnessChoices.Clear();
        var eligible = (GetEligibleCardHarnesses?.Invoke() ?? []).ToList();
        // A previously selected ACL is itself durable evidence that the connector was eligible when the operator
        // opted in. Keep it visible if the harness is currently offline or its config temporarily cannot be read.
        foreach (var id in allowed)
            if (!eligible.Any(h => string.Equals(h.HarnessId, id, StringComparison.OrdinalIgnoreCase)))
                eligible.Add(new VaultHarnessChoice(id, KnownHarnesses.GetById(id)?.DisplayName ?? id));
        foreach (var h in eligible.OrderBy(h => h.DisplayName, StringComparer.CurrentCultureIgnoreCase))
            _cardHarnessChoices.Add(new VaultHarnessChoice(h.HarnessId, h.DisplayName)
            {
                IsAllowed = allowed.Contains(h.HarnessId, StringComparer.OrdinalIgnoreCase),
            });
        CardHarnessSwitches.ItemsSource = null;
        CardHarnessSwitches.ItemsSource = _cardHarnessChoices;
        NoCardHarnessesHint.Visibility = _cardHarnessChoices.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    // Edit an existing item: pre-fill the non-secret metadata; secrets stay blank and "leave blank to keep" them.
    private void EditItemClick(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not VaultItemRow row) return;
        if (row.IsPaymentCard) { OpenCardForm(row); return; }
        _editingOriginalName = row.Name;
        _editingEntryId = row.EntryId;
        AddFormTitle.Text = "Edit credential";
        EditKeepHint.Visibility = Visibility.Visible;
        AddOrigins.Text = string.Join(", ", row.OriginList);
        AddName.Text = row.Name;
        AddHarnesses.Text = string.Join(", ", row.HarnessList);
        AddUser.Text = string.Empty; AddPw.Clear(); AddTotp.Text = string.Empty; AddError.Text = string.Empty;
        AddForm.Visibility = Visibility.Visible;
        CardForm.Visibility = Visibility.Collapsed;
        AddButton.Visibility = Visibility.Collapsed;
        AddCardButton.Visibility = Visibility.Collapsed;
        AddOrigins.Focus();
    }

    private void DeleteItemClick(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not VaultItemRow row) return;
        if (MessageBox.Show($"Delete the credential \"{row.Name}\"? This can't be undone.",
                "TraceBrake — Vault", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;
        try { _vault.Delete(row.Name); }
        catch (Exception ex) { MessageBox.Show(ex.Message, "TraceBrake — Vault", MessageBoxButton.OK, MessageBoxImage.Warning); return; }
        Log($"Vault item '{row.Name}' deleted.");
        if (string.Equals(_editingOriginalName, row.Name, StringComparison.OrdinalIgnoreCase))
        {
            if (row.IsPaymentCard) CloseCardForm(); else CloseAddForm();
        }
        PopulateItems();
    }

    private void CancelAddClick(object sender, RoutedEventArgs e) => CloseAddForm();

    private void CancelCardClick(object sender, RoutedEventArgs e) => CloseCardForm();

    private void GeneratePwClick(object sender, RoutedEventArgs e) => AddPw.Password = VaultPasswordGenerator.Generate(20);

    private void SaveItemClick(object sender, RoutedEventArgs e)
    {
        AddError.Text = string.Empty;
        var origins = ParseOrigins(AddOrigins.Text);   // forgiving: a pasted URL or a bare host both reduce to the host
        if (origins.Count == 0) { AddError.Text = "Enter the website this is for (e.g. github.com)."; return; }
        var name = AddName.Text.Trim();
        if (name.Length == 0) name = origins[0];        // default the name to the website

        var entry = new VaultEntry
        {
            EntryId = _editingEntryId ?? string.Empty,
            Kind = VaultEntryKind.Login,
            Name = name,
            Origins = origins,
            Harnesses = SplitCsv(AddHarnesses.Text),
            Username = NullIfBlank(AddUser.Text),
            Password = NullIfBlank(AddPw.Password),
            TotpSeedBase32 = NullIfBlank(AddTotp.Text.Replace(" ", string.Empty)),
        };
        try
        {
            if (_editingOriginalName is { } orig)
            {
                if (!_vault.UpdateItem(orig, entry)) { AddError.Text = "That item no longer exists — close and reopen the list."; return; }
            }
            else _vault.Upsert(entry);
        }
        catch (Exception ex) { AddError.Text = ex.Message; return; }
        Log(_editingOriginalName is null ? $"Vault item '{name}' saved." : $"Vault item '{name}' updated.");
        CloseAddForm();
        PopulateItems();
    }

    private void CloseAddForm()
    {
        AddName.Text = AddOrigins.Text = AddUser.Text = AddTotp.Text = AddHarnesses.Text = string.Empty;
        AddPw.Clear();
        AddError.Text = string.Empty;
        _editingOriginalName = null;
        _editingEntryId = null;
        AddFormTitle.Text = "Add credential";
        EditKeepHint.Visibility = Visibility.Collapsed;
        AddForm.Visibility = Visibility.Collapsed;
        AddButton.Visibility = Visibility.Visible;
        AddCardButton.Visibility = Visibility.Visible;
    }

    private void SaveCardClick(object sender, RoutedEventArgs e)
    {
        CardError.Text = string.Empty;
        var name = CardName.Text.Trim();
        var origins = ParseOrigins(CardOrigins.Text);
        var number = Digits(CardNumber.Password);
        var cvc = Digits(CardSecurityCode.Password);
        var month = CardExpiryMonth.Text.Trim();
        var year = CardExpiryYear.Text.Trim();

        if (name.Length == 0) { CardError.Text = "Enter a nickname for this card."; return; }
        if (origins.Count == 0) { CardError.Text = "Enter at least one checkout website."; return; }
        if (_editingOriginalName is null && (number.Length is < 12 or > 19 || !Foreman.Core.Security.PaymentCardDetection.PassesLuhn(number)))
        { CardError.Text = "Enter a valid card number (12–19 digits)."; return; }
        if (number.Length > 0 && (number.Length is < 12 or > 19 || !Foreman.Core.Security.PaymentCardDetection.PassesLuhn(number)))
        { CardError.Text = "The replacement card number is invalid."; return; }
        if (!int.TryParse(month, out var mm) || mm is < 1 or > 12)
        { CardError.Text = "Expiry month must be between 01 and 12."; return; }
        if (year.Length != 4 || !int.TryParse(year, out var yyyy) || yyyy < DateTime.UtcNow.Year)
        { CardError.Text = "Enter a four-digit expiry year that has not passed."; return; }
        if (yyyy == DateTime.UtcNow.Year && mm < DateTime.UtcNow.Month)
        { CardError.Text = "This card has expired."; return; }
        if (cvc.Length > 0 && cvc.Length is < 3 or > 4)
        { CardError.Text = "Security code must be 3 or 4 digits."; return; }

        var entry = new VaultEntry
        {
            EntryId = _editingEntryId ?? string.Empty,
            Kind = VaultEntryKind.PaymentCard,
            Name = name,
            Origins = origins,
            Harnesses = _cardHarnessChoices.Where(h => h.IsAllowed).Select(h => h.HarnessId).ToList(),
            PaymentCard = new VaultPaymentCard
            {
                CardholderName = NullIfBlank(CardHolder.Text),
                CardNumber = NullIfBlank(number),
                ExpiryMonth = mm.ToString("00"),
                ExpiryYear = yyyy.ToString(),
                SecurityCode = NullIfBlank(cvc),
                BillingAddress = NullIfBlank(CardBillingAddress.Text),
            },
        };
        try
        {
            if (_editingOriginalName is { } original)
            {
                if (!_vault.UpdateItem(original, entry))
                { CardError.Text = "That card no longer exists — close and reopen the list."; return; }
            }
            else _vault.Upsert(entry);
        }
        catch (Exception ex) { CardError.Text = ex.Message; return; }
        Log(_editingOriginalName is null ? $"Payment card '{name}' saved." : $"Payment card '{name}' updated.");
        CloseCardForm();
        PopulateItems();
    }

    private void CloseCardForm()
    {
        CardName.Text = CardHolder.Text = CardExpiryMonth.Text = CardExpiryYear.Text =
            CardBillingAddress.Text = CardOrigins.Text = string.Empty;
        CardNumber.Clear();
        CardSecurityCode.Clear();
        CardError.Text = string.Empty;
        _cardHarnessChoices.Clear();
        CardHarnessSwitches.ItemsSource = null;
        _editingOriginalName = null;
        _editingEntryId = null;
        CardForm.Visibility = Visibility.Collapsed;
        AddButton.Visibility = Visibility.Visible;
        AddCardButton.Visibility = Visibility.Visible;
    }

    private static string Digits(string? value) =>
        new((value ?? string.Empty).Where(char.IsAsciiDigit).ToArray());

    private static List<string> SplitCsv(string? s) =>
        (s ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

    // Forgiving website input: each comma-separated entry may be a full URL or a bare host; reduce each to a bare,
    // lowercase host (so "https://github.com/login", "github.com", and "GitHub.com" all become "github.com").
    private static List<string> ParseOrigins(string? raw)
    {
        var result = new List<string>();
        foreach (var part in (raw ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var host = NormalizeToHost(part);
            if (host.Length > 0 && !result.Contains(host, StringComparer.OrdinalIgnoreCase)) result.Add(host);
        }
        return result;
    }

    private static string NormalizeToHost(string s)
    {
        s = s.Trim();
        if (Uri.TryCreate(s, UriKind.Absolute, out var u) && !string.IsNullOrEmpty(u.Host)) return u.Host.ToLowerInvariant();
        if (Uri.TryCreate("https://" + s, UriKind.Absolute, out var u2) && !string.IsNullOrEmpty(u2.Host)) return u2.Host.ToLowerInvariant();
        return s.ToLowerInvariant();
    }

    private static string? NullIfBlank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s;

    private static void Log(string msg) =>
        EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman.Vault", msg));

    /// <summary>Display row for the items list — names/origins/which-fields/ACL only, no secret values.</summary>
    public sealed class VaultItemRow
    {
        public string Name { get; init; } = string.Empty;
        public string Origins { get; init; } = string.Empty;
        public string Fields { get; init; } = string.Empty;
        public string Acl { get; init; } = string.Empty;
        public string ReferenceHint { get; init; } = string.Empty;
        // Raw lists carried for the Edit form to pre-fill (no secret VALUES — only origins + the agent ACL).
        public IReadOnlyList<string> OriginList { get; init; } = [];
        public IReadOnlyList<string> HarnessList { get; init; } = [];
        public string EntryId { get; init; } = string.Empty;
        public bool IsPaymentCard { get; init; }
        public string? CardholderName { get; init; }
        public string? CardExpiryMonth { get; init; }
        public string? CardExpiryYear { get; init; }
        public string? BillingAddress { get; init; }

        public static VaultItemRow From(Foreman.Core.Vault.VaultItemInfo i)
        {
            var fields = new List<string>();
            if (i.IsPaymentCard)
            {
                fields.Add(i.CardLastFour is null ? "payment card" : $"card •••• {i.CardLastFour}");
                if (i.HasCardSecurityCode) fields.Add("security code");
            }
            else
            {
                if (i.HasUsername) fields.Add("username");
                if (i.HasPassword) fields.Add("password");
                if (i.HasTotp) fields.Add("2FA");
            }
            return new VaultItemRow
            {
                Name = i.Name,
                Origins = string.Join(", ", i.Origins),
                Fields = fields.Count > 0 ? string.Join(" · ", fields) : "(no fields)",
                Acl = i.Harnesses.Count > 0 ? "agents: " + string.Join(", ", i.Harnesses) : "operator only",
                ReferenceHint = i.IsPaymentCard && i.Origins.Count > 0 && i.EntryId.Length > 0
                    ? $"ref: {{{{vault:{i.Origins[0]}/{i.EntryId}/cardnumber}}}}"
                    : string.Empty,
                OriginList = i.Origins,
                HarnessList = i.Harnesses,
                EntryId = i.EntryId,
                IsPaymentCard = i.IsPaymentCard,
                CardholderName = i.CardholderName,
                CardExpiryMonth = i.CardExpiryMonth,
                CardExpiryYear = i.CardExpiryYear,
                BillingAddress = i.BillingAddress,
            };
        }
    }

    public sealed class VaultHarnessChoice(string harnessId, string displayName)
    {
        public string HarnessId { get; } = harnessId;
        public string DisplayName { get; } = displayName;
        public bool IsAllowed { get; set; }
    }
}
