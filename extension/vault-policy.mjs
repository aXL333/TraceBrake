// Pure vault-fill policy shared by the MV3 worker and bypass tests.
export const vaultTokenRe = () =>
    /\{\{vault:([A-Za-z0-9.\-]+(?::\d+)?)\/(?:([A-Za-z0-9_-]{6,64})\/)?([A-Za-z]+)\}\}/g;

export function vaultRefs(value) {
    const refs = [];
    const seen = new Set();
    for (const m of String(value).matchAll(vaultTokenRe())) {
        if (seen.has(m[0])) continue;
        seen.add(m[0]);
        refs.push({ token: m[0], entryId: m[2] || null, field: String(m[3] || '').toLowerCase() });
    }
    return refs;
}

function needsPasswordField(refs) {
    return refs.some((r) => r.field === 'password' || r.field === 'signup');
}

function paymentAutocomplete(refs) {
    const names = {
        cardholdername: 'cc-name',
        cardnumber: 'cc-number',
        cardexpirymonth: 'cc-exp-month',
        cardexpiryyear: 'cc-exp-year',
        cardsecuritycode: 'cc-csc',
        billingaddress: 'billing street-address|street-address|billing address-line1|address-line1',
    };
    const hits = refs.map((r) => names[r.field]).filter(Boolean);
    return hits.length === 1 && refs.length === 1 ? hits[0] : (hits.length > 0 ? '__invalid__' : null);
}

export function buildVaultFillPolicy(refs, expectedOrigin) {
    if (refs.length === 0) return {};
    const requiredAutocomplete = paymentAutocomplete(refs);
    return {
        requireSelector: true,
        // Card policy wins for a mixed list; "__invalid__" fails before any reference can resolve.
        requirePasswordField: requiredAutocomplete ? false : needsPasswordField(refs),
        requiredAutocomplete,
        expectedOrigin,
    };
}
