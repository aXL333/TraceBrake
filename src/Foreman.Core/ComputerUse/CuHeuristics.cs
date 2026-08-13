using System.Text.RegularExpressions;

namespace Foreman.Core.ComputerUse;

/// <summary>
/// CU-specific deterministic checks the generic command pattern library doesn't cover — the highest-value
/// browser/desktop threats judged directly from the structured action. Returns the concern, or null when clean.
/// </summary>
public static class CuHeuristics
{
    private const string Src = "fast-path:cu";

    // javascript:/data:/vbscript:/file: "navigations" are local exfil or script injection, never a normal page visit.
    private static readonly Regex DangerousScheme = new(
        @"^\s*(?:javascript|data|vbscript|file)\s*:",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(50));

    // Desktop (Slice 2): a resolved control label that commits something irreversible/consequential -> Hold for the
    // operator. Deliberately broad; an over-Hold is safe (operator clears it), an under-Hold lets the AI commit.
    private static readonly Regex SensitiveControl = new(
        @"\b(confirm|send|delete|transfer|allow|yes|run\s*anyway|save\s*as|pay|approve|grant|install|uninstall|purchase|buy)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(50));

    // Consent / credential / file surfaces a #32770 dialog hosts that the OPERATOR must drive, never the AI -> Block.
    private static readonly Regex ConsentText = new(
        @"(save\s*as|\bopen\b|credential|password|sign\s*in|user\s*name|consent|run\s*as\s*admin)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(50));

    public static CuVerdict? Evaluate(CuAction a)
    {
        // Reference policies follow the data, not a conventional verb or argument name. Future executor verbs
        // therefore cannot create sibling paths around operator approval.
        if (a.Args.Values.Any(Foreman.Core.Vault.VaultReference.HasPaymentCardReference))
            return CuVerdict.Hold(Src,
                "payment-card data release requires explicit operator approval",
                final: true);

        if (a.Args.Values.Any(v => Foreman.Core.Vault.VaultReference.Tokens(v)
                .Any(t => Foreman.Core.Vault.VaultReference.TrySignup(t, out _))))
            return CuVerdict.Hold(Src,
                "agent self-signup creates a NEW saved credential — operator approval required before it can be filled",
                final: true);

        if (string.Equals(a.Verb, "type", StringComparison.OrdinalIgnoreCase))
        {
            // An AI typing into a password / credential field is a prohibited action — hold for the operator to do it.
            var field = a.Arg("fieldType");
            if (field.Contains("password", StringComparison.OrdinalIgnoreCase)
                || field.Contains("credential", StringComparison.OrdinalIgnoreCase))
                return CuVerdict.Hold(Src,
                    "typing into a password/credential field — an agent must not enter credentials");
        }

        // Dangerous navigation schemes.
        if (string.Equals(a.Verb, "navigate", StringComparison.OrdinalIgnoreCase))
        {
            var url = a.Arg("url");
            try
            {
                if (DangerousScheme.IsMatch(url))
                    return CuVerdict.Block(Src, $"navigation to a dangerous URL scheme: {Trim(url)}");
            }
            catch (RegexMatchTimeoutException) { /* treat as no match */ }
        }

        // Desktop (Slice 2 / INV-1): judge the RESOLVED target, never a bare coordinate. An unidentifiable or
        // sensitive/consent target can never auto-Allow. Applies to state-changing verbs (a read/move is a peek).
        if (a.Modality == CuModality.Desktop && CuVerbs.IsStateChanging(a.Verb))
        {
            var label = a.Arg("targetLabel");

            // UAC / a #32770 dialog hosting Save/Open/credential text -> the operator must do this -> hard Block.
            if (IsConsentSurface(a.Arg("windowClass"), a.Arg("windowTitle")))
                return CuVerdict.Block(Src,
                    $"desktop action targets a consent/credential surface ('{Trim(a.Arg("windowTitle"))}') — the operator must do this, not the AI");

            // A sensitive/consequential control label -> Hold for the operator.
            try
            {
                if (!string.IsNullOrWhiteSpace(label) && SensitiveControl.IsMatch(label))
                    return CuVerdict.Hold(Src, $"desktop action targets a sensitive control: '{Trim(label)}'");
            }
            catch (RegexMatchTimeoutException) { /* fall through */ }

            // No resolved target -> TraceBrake cannot identify what is being acted on -> Hold (never auto-Allow).
            if (string.IsNullOrWhiteSpace(label))
                return CuVerdict.Hold(Src,
                    "desktop action has no resolved target — cannot identify the control; held for operator review");
        }

        return null;
    }

    private static bool IsConsentSurface(string windowClass, string windowTitle)
    {
        if (windowTitle.Contains("User Account Control", StringComparison.OrdinalIgnoreCase)) return true;
        if (string.Equals(windowClass, "#32770", StringComparison.OrdinalIgnoreCase))
        {
            try { return ConsentText.IsMatch(windowTitle); }
            catch (RegexMatchTimeoutException) { return true; }   // fail closed: unparseable title -> treat as consent
        }
        return false;
    }

    private static string Trim(string s) => s.Length <= 80 ? s : s[..80] + "…";
}
