/**
 * TraceBrake — extension service worker.
 *
 * Bridges the browser to the LOCAL TraceBrake desktop app over loopback HTTP (never the network). Two phases:
 *   1. Pairing (one-time): the user clicks "Pair browser extension" in TraceBrake → TraceBrake shows a short code →
 *      the user types it on the options page → we prove we hold it via a challenge/response (the code never
 *      crosses the wire) → TraceBrake allow-lists our origin and hands back a scoped bearer token.
 *   2. Connected: we poll /health for liveness and call the MCP endpoint (with the token) for status/alerts,
 *      feed the side panel, surface the Ask-Harness inbox, and act as the executor for TraceBrake's audited
 *      browser-use (BU) broker.
 *
 * The extension has host_permissions for 127.0.0.1/localhost, so the service worker can fetch the loopback
 * server cross-origin without CORS. Nothing here ever talks to a remote host.
 *
 * (LiveWeave, the local page builder, now lives in its own extension — `extension-liveweave/`.)
 */
import { loadSettings, saveSettings, onSettingsChanged } from './settings.js';
import { callMcpTool, openMcpSession } from './mcp-client.js';
import { vaultTokenRe, vaultRefs, buildVaultFillPolicy } from './vault-policy.mjs';

let cfg = { host: '127.0.0.1', port: 54321, token: '', pairedOrigin: '', harnessId: 'browser-extension' };
let connected = false;
let lastStatus = null;          // last foreman_status payload (or null)
let lastAsks = [];              // pending Ask-Harness requests scoped to this extension
let lastMcpError = null;
let lastMcpAuthProblem = null;  // actionable repair state for stale/denied extension tokens
let sidePanelPort = null;
let pollTimer = null;
let mcpSession = null;
let pinnedTab = null;           // operator's shared-attention pin (tab id) set by pressing the toolbar icon; null = none
let lastReportedPin = null;     // last pin value pushed to TraceBrake, so we re-report changes (incl. clears) exactly once
const POLL_MS = 5000;

// Persist the pin to session storage so a service-worker restart reloads it (in bootstrap) instead of dropping to
// null — otherwise the broker would keep a stale pin while we resolved actions against the active tab.
function persistPin() { try { chrome.storage.session.set({ pinnedTab }); } catch { /* session storage unavailable */ } }

// Visible pin indicator on the toolbar icon (per-tab badge), so pressing the icon gives instant feedback even
// before the TraceBrake round-trip: a badge on the pinned tab, cleared on the previously-pinned one.
function updatePinBadge(prevTab, newTab) {
    try {
        if (prevTab != null && prevTab !== newTab) chrome.action.setBadgeText({ tabId: prevTab, text: '' });
        if (newTab != null) {
            chrome.action.setBadgeText({ tabId: newTab, text: '📌' });   // 📌
            try { chrome.action.setBadgeBackgroundColor({ tabId: newTab, color: '#C8A24B' }); } catch { /* ok */ }
        }
    } catch { /* action badge unavailable */ }
}

const base = () => `http://${cfg.host}:${cfg.port}`;
const selfOrigin = () => `chrome-extension://${chrome.runtime.id}`;

// ── Pairing ────────────────────────────────────────────────────────────────

async function hmacHex(key, message) {
    const enc = new TextEncoder();
    const k = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', k, enc.encode(message));
    return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

async function pair(code) {
    const clean = (code || '').trim().toUpperCase();
    if (!clean) return { ok: false, error: 'Enter the code shown in TraceBrake.' };
    try {
        const cr = await fetch(`${base()}/pair/challenge`);
        if (cr.status === 409) return { ok: false, error: 'No pairing window is open. Click "Pair browser extension" in TraceBrake first.' };
        if (!cr.ok) return { ok: false, error: `TraceBrake returned ${cr.status} for the challenge.` };
        const { challenge } = await cr.json();

        const response = await hmacHex(clean, challenge);
        const done = await fetch(`${base()}/pair/complete`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ response, origin: selfOrigin(), harnessId: 'browser-extension' }),
        });
        const body = await done.json().catch(() => ({}));
        if (!done.ok || !body.ok) return { ok: false, error: body.reason || `Pairing failed (${done.status}).` };

        cfg = { ...cfg, token: body.token || '', pairedOrigin: body.origin || selfOrigin(), harnessId: body.harnessId || 'browser-extension' };
        await saveSettings({ token: cfg.token, pairedOrigin: cfg.pairedOrigin, harnessId: cfg.harnessId });
        mcpSession = null;
        lastMcpError = null;
        lastMcpAuthProblem = null;
        await refresh();
        return { ok: true };
    } catch (e) {
        return { ok: false, error: `Could not reach TraceBrake at ${base()} — is it running? (${e})` };
    }
}

// ── Connection / status ──────────────────────────────────────────────────────

async function checkHealth() {
    try {
        const r = await fetch(`${base()}/health`);
        return r.ok;
    } catch { return false; }
}

async function ensureMcpSession() {
    if (!cfg.token) return null;
    if (mcpSession) return mcpSession;
    mcpSession = await openMcpSession(base(), cfg.token);
    return mcpSession;
}

function describeMcpFailure(e) {
    const status = Number(e?.status) || null;
    const body = String(e?.body || '').trim();
    let detail = String(e?.message || e || '').trim();
    if (body) {
        try {
            const parsed = JSON.parse(body);
            detail = parsed?.error ? String(parsed.error) : body;
        } catch {
            detail = body;
        }
    }

    if (status === 401) {
        return {
            kind: 'auth',
            code: 'token-rejected',
            status,
            title: 'Saved browser token was rejected',
            message: 'TraceBrake is running, but it rejected the token this extension stored when it paired. In TraceBrake, open Connect agent -> Pair browser extension, then enter the new code in this extension.',
            detail,
        };
    }

    if (status === 403) {
        return {
            kind: 'auth',
            code: 'origin-denied',
            status,
            title: 'Browser extension is not allowed',
            message: 'TraceBrake is running, but this extension origin is not allowed to call MCP. Pair the extension again so TraceBrake can allow-list this browser profile.',
            detail,
        };
    }

    return {
        kind: 'error',
        code: status ? `http-${status}` : 'mcp-error',
        status,
        title: 'MCP request failed',
        message: detail || 'TraceBrake did not accept the MCP request.',
        detail,
    };
}

// Single place that opens (or reuses) the MCP session and calls a tool. On any failure it drops the cached
// session so the next call reopens — TraceBrake uses short-lived per-request sessions, so a stale id is expected.
async function mcpCall(name, args = {}) {
    if (!cfg.token) return null;
    try {
        const session = await ensureMcpSession();
        return await callMcpTool(session, name, args);
    } catch (e) {
        mcpSession = null;
        const problem = describeMcpFailure(e);
        lastMcpError = problem.detail || problem.message;
        if (problem.kind === 'auth') lastMcpAuthProblem = problem;
        return null;
    }
}

// Reply to one Ask-Harness prompt. Surfaced to the side panel; returns {ok} so the UI can confirm.
async function replyAsk(requestId, response) {
    if (!requestId || !response?.trim()) return { ok: false, error: 'Empty reply.' };
    const r = await mcpCall('reply_to_ask_harness_request', { requestId, response: response.trim() });
    const ok = r && r.accepted !== false && !r.error;
    // NB: caller posts the ask-reply-result FIRST, then refreshes — so the panel's "✓ Reply sent"
    // confirmation lands before the status rebuild removes the (now answered) card.
    return ok ? { ok: true } : { ok: false, error: (r && (r.reason || r.error)) || lastMcpError || 'Reply was not accepted.' };
}

// ── Browser use (BU) — executor for TraceBrake's audited cu_* broker ───────────────
// TraceBrake AUDITS every action (and holds risky ones for operator approval) BEFORE it reaches here; this
// extension is only the executor for actions TraceBrake already APPROVED. Two capability tiers:
//   Bounded (tabs API only): navigate (new tab), goto (same tab), back/forward (tab history), read (tab metadata).
//   Broad (per-site grant): click / type / scroll via chrome.scripting on a page the operator EXPLICITLY allowed
//     (the "Browser fill access" panel; chrome.permissions.contains is re-checked here, fail-closed). `type` may
//     carry {{vault:...}} references — resolved at this last moment via cu_resolve_vault (the submitting agent
//     never sees the value), all-or-nothing, and the plaintext is never logged or echoed back. screenshot is a
//     separate future slice and still returns the bounded-mode error.

// Resolve which tab an action acts on: an explicit args.tabId wins; else the operator's pinned focus; else the
// active tab. So when a tab is pinned, an action with NO tabId runs IN the pinned tab and can never silently drift.
async function resolveTargetTab(args) {
    const explicit = args.tabId;
    if (explicit !== undefined && explicit !== null && String(explicit) !== '') {
        const s = String(explicit).trim();
        // Only a clean base-10 integer names a tab, matching the broker's canonical parse. Reject 0x2A / 1e3 /
        // trailing-garbage so the executor never acts on a tab the broker reasoned about differently.
        if (!/^\d+$/.test(s)) return null;
        return parseInt(s, 10);
    }
    if (pinnedTab != null) return pinnedTab;
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab?.id ?? null;
}

// ── Broad-mode fill (click / type / scroll) ─────────────────────────────────────
// Every scripting injection is fail-closed behind a per-site operator grant: we re-check
// chrome.permissions.contains for the TARGET TAB'S REAL origin (from chrome.tabs.get, never from agent args), so
// the agent can never make us touch a site the operator didn't allow in the "Browser fill access" panel.

// Resolve every {{vault:...}} token in `value` to its real secret via cu_resolve_vault, bound to this action and
// the live tab host. All-or-nothing and fail-closed: if ANY token won't resolve, nothing is filled and the error
// carries NO secret. The resolved values exist only in the returned string (typed into the page, then dropped) —
// they are never logged, never put in cu_complete_action, never returned to the submitting agent.
async function resolveVaultTokens(actionId, executionToken, value, liveOrigin, argumentKey, refs = vaultRefs(value)) {
    const tokens = refs.map((r) => r.token);
    if (tokens.length === 0) return { ok: true, value };          // plain text — no vault round-trip
    if (!actionId) return { ok: false, error: 'Vault reference present but the action has no id to bind to.' };
    const map = new Map();
    for (const tok of tokens) {
        const r = await mcpCall('cu_resolve_vault', { actionId, executionToken, reference: tok, liveOrigin, argumentKey });
        if (!r || r.ok !== true || typeof r.value !== 'string')
            return { ok: false, error: (r && r.reason) || 'A vault reference could not be resolved.' };
        map.set(tok, r.value);
    }
    // Single pass over the ORIGINAL string so a resolved secret that happens to contain a {{vault:}}-shaped
    // substring is never itself re-substituted.
    const filled = String(value).replace(vaultTokenRe(), (m) => (map.has(m) ? map.get(m) : m));
    map.clear();
    return { ok: true, value: filled };
}

// The per-site gate: resolve the tab's REAL origin and confirm the operator granted it. Returns the bare host as
// `liveOrigin` for cu_resolve_vault's domain-binding. http(s) only (mirrors the grant UI's https-only pattern;
// chrome://, file://, etc. are never fillable and can't be granted anyway).
async function fillGate(tab) {
    if (!tab || tab.id == null) return { ok: false, error: 'No tab to act on.' };
    let u;
    try { u = new URL(tab.url || ''); } catch { return { ok: false, error: 'That tab has no fillable page URL.' }; }
    if (u.protocol !== 'https:' && u.protocol !== 'http:')
        return { ok: false, error: `TraceBrake fills only http(s) pages, not '${u.protocol}'.` };
    const pattern = `${u.protocol}//${u.hostname}/*`;
    let granted = false;
    try { granted = await chrome.permissions.contains({ origins: [pattern] }); } catch { granted = false; }
    if (!granted)
        return { ok: false, error: `TraceBrake isn't allowed to act on ${u.hostname}. Open the side panel and click "Allow TraceBrake on the current site" first.` };
    return { ok: true, host: u.hostname, origin: u.origin };
}

// A claimed action is not standing authority. Panic, expiry, driver revocation, or an operator decision can void its
// owner-bound lease after polling. Fail CLOSED on any missing/ambiguous response and re-check both global panic and
// this exact action lease immediately before every browser effect.
async function ensureCuActionLive(act) {
    const actionId = typeof act?.actionId === 'string' ? act.actionId.trim() : '';
    const executionToken = typeof act?.executionToken === 'string' ? act.executionToken.trim() : '';
    if (!actionId || !/^[0-9a-f]{64}$/i.test(executionToken))
        return { ok: false, error: 'Action has no valid execution lease.' };
    const panic = await mcpCall('computer_use_status');
    if (!panic || panic.halted !== false)
        return { ok: false, error: panic?.halted ? 'Computer use was halted by the operator.' : 'Could not verify panic state.' };
    const status = await mcpCall('cu_action_status', { actionId, executionToken });
    if (!status || status.found !== true || String(status.state || '').toLowerCase() !== 'executing')
        return { ok: false, error: (status && status.reason) || 'Action execution lease is no longer live.' };
    return { ok: true };
}

// ── Functions injected into the page (ISOLATED world; must be fully self-contained, no closures) ──
// Each returns ONLY structural info (tag/name) — never the typed value — so nothing sensitive flows back out.

function injInspectFillTarget(selector, policy) {
    function inspect() {
        const p = policy || {};
        if (p.expectedOrigin && String(location.origin).toLowerCase() !== String(p.expectedOrigin).toLowerCase())
            return { ok: false, error: 'Vault fill target origin changed before injection.' };
        if (p.requireSelector && !selector)
            return { ok: false, error: 'Vault fills require a CSS selector; focused-element fallback is disabled for secrets.' };
        const el = selector ? document.querySelector(selector) : document.activeElement;
        if (!el) return { ok: false, error: selector ? `No element matches '${selector}'.` : 'No focused element to type into.' };
        const tag = (el.tagName || '').toLowerCase();
        if (p.requirePasswordField) {
            const type = String(el.getAttribute && el.getAttribute('type') || 'text').toLowerCase();
            if (tag !== 'input' || type !== 'password')
                return { ok: false, error: 'Vault password fills require a selector that matches an input[type=password] field.' };
        } else if (p.requiredAutocomplete) {
            if (p.requiredAutocomplete === '__invalid__')
                return { ok: false, error: 'A payment-card fill must contain exactly one card field reference.' };
            if (tag !== 'input' && tag !== 'textarea')
                return { ok: false, error: 'Payment-card data may only be filled into a form input.' };
            const ac = String(el.getAttribute && el.getAttribute('autocomplete') || '').trim().toLowerCase();
            const accepted = String(p.requiredAutocomplete).split('|');
            if (!accepted.includes(ac))
                return { ok: false, error: `Payment-card field requires autocomplete="${p.requiredAutocomplete}".` };
        } else if (tag !== 'input' && tag !== 'textarea' && !el.isContentEditable) {
            return { ok: false, error: `<${tag}> is not a fillable field.` };
        }
        if (el.disabled || el.readOnly) return { ok: false, error: 'The target field is disabled or read-only.' };
        const style = typeof getComputedStyle === 'function' ? getComputedStyle(el) : null;
        if (style && (style.display === 'none' || style.visibility === 'hidden'))
            return { ok: false, error: 'The target field is not visible.' };
        if (typeof el.getClientRects === 'function' && el.getClientRects().length === 0)
            return { ok: false, error: 'The target field is not visible.' };
        return { ok: true, tag, name: el.getAttribute && el.getAttribute('name') || null };
    }
    try { return inspect(); }
    catch (e) { return { ok: false, error: String((e && e.message) || e) }; }
}

function injFill(selector, value, policy) {
    try {
        function inspect() {
            const p = policy || {};
            if (p.expectedOrigin && String(location.origin).toLowerCase() !== String(p.expectedOrigin).toLowerCase())
                return { ok: false, error: 'Vault fill target origin changed before injection.' };
            if (p.requireSelector && !selector)
                return { ok: false, error: 'Vault fills require a CSS selector; focused-element fallback is disabled for secrets.' };
            const target = selector ? document.querySelector(selector) : document.activeElement;
            if (!target) return { ok: false, error: selector ? `No element matches '${selector}'.` : 'No focused element to type into.' };
            const targetTag = (target.tagName || '').toLowerCase();
            if (p.requirePasswordField) {
                const type = String(target.getAttribute && target.getAttribute('type') || 'text').toLowerCase();
                if (targetTag !== 'input' || type !== 'password')
                    return { ok: false, error: 'Vault password fills require a selector that matches an input[type=password] field.' };
            } else if (p.requiredAutocomplete) {
                if (p.requiredAutocomplete === '__invalid__')
                    return { ok: false, error: 'A payment-card fill must contain exactly one card field reference.' };
                if (targetTag !== 'input' && targetTag !== 'textarea')
                    return { ok: false, error: 'Payment-card data may only be filled into a form input.' };
                const ac = String(target.getAttribute && target.getAttribute('autocomplete') || '').trim().toLowerCase();
                const accepted = String(p.requiredAutocomplete).split('|');
                if (!accepted.includes(ac))
                    return { ok: false, error: `Payment-card field requires autocomplete="${p.requiredAutocomplete}".` };
            } else if (targetTag !== 'input' && targetTag !== 'textarea' && !target.isContentEditable) {
                return { ok: false, error: `<${targetTag}> is not a fillable field.` };
            }
            if (target.disabled || target.readOnly) return { ok: false, error: 'The target field is disabled or read-only.' };
            const style = typeof getComputedStyle === 'function' ? getComputedStyle(target) : null;
            if (style && (style.display === 'none' || style.visibility === 'hidden'))
                return { ok: false, error: 'The target field is not visible.' };
            if (typeof target.getClientRects === 'function' && target.getClientRects().length === 0)
                return { ok: false, error: 'The target field is not visible.' };
            return { ok: true, el: target, tag: targetTag };
        }

        const checked = inspect();
        if (!checked.ok) return checked;
        const el = checked.el;
        const tag = checked.tag;
        if (el.isContentEditable) {
            el.focus();
            el.textContent = value;
            el.dispatchEvent(new InputEvent('input', { bubbles: true }));
            return { ok: true, tag, name: el.getAttribute && el.getAttribute('name') || null };
        }
        if (tag !== 'input' && tag !== 'textarea')
            return { ok: false, error: `<${tag}> is not a fillable field.` };
        el.focus();
        // Use the native value setter so framework-controlled inputs (React/Vue) observe the change.
        const proto = tag === 'textarea' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
        const setter = Object.getOwnPropertyDescriptor(proto, 'value');
        if (setter && setter.set) setter.set.call(el, value); else el.value = value;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
        return { ok: true, tag, name: el.getAttribute('name') || null };
    } catch (e) { return { ok: false, error: String((e && e.message) || e) }; }
}

function injClick(selector) {
    try {
        const el = document.querySelector(selector);
        if (!el) return { ok: false, error: `No element matches '${selector}'.` };
        if (typeof el.scrollIntoView === 'function') el.scrollIntoView({ block: 'center' });
        if (typeof el.click === 'function') el.click(); else return { ok: false, error: 'Element is not clickable.' };
        return { ok: true, tag: (el.tagName || '').toLowerCase() };
    } catch (e) { return { ok: false, error: String((e && e.message) || e) }; }
}

function injScroll(selector, dx, dy) {
    try {
        const target = selector ? document.querySelector(selector) : null;
        if (target && typeof target.scrollBy === 'function') target.scrollBy(dx, dy);
        else window.scrollBy(dx, dy);
        return { ok: true };
    } catch (e) { return { ok: false, error: String((e && e.message) || e) }; }
}

async function executeCuAction(act) {
    const verb = String(act.verb || '').toLowerCase();
    const args = act.args || {};
    switch (verb) {
        case 'navigate': {
            const url = String(args.url || '');
            // Scheme-gate to http(s) (rejects javascript:/data:/file:/chrome:/about:), then confirm it parses.
            // Defense-in-depth even though TraceBrake already audited the action upstream.
            if (!/^https?:\/\//i.test(url)) return { ok: false, error: 'navigate requires an http(s) url.' };
            try { new URL(url); } catch { return { ok: false, error: 'navigate requires a valid url.' }; }
            const live = await ensureCuActionLive(act);
            if (!live.ok) return live;
            const tab = await chrome.tabs.create({ url, active: true });
            return { ok: true, result: { tabId: tab.id ?? null, url } };
        }
        case 'list_tabs':
        case 'tabs': {
            // Enumerate every window / group / tab so the driver can target one by name ("use my Gmail tab").
            const wins = await chrome.windows.getAll({ populate: true });
            let groups = [];
            try { groups = await chrome.tabGroups.query({}); } catch { /* tabGroups perm absent */ }
            const groupName = (gid) => groups.find((g) => g.id === gid)?.title ?? null;
            const tabs = [];
            for (const w of wins) for (const t of (w.tabs || [])) {
                tabs.push({
                    tabId: t.id, windowId: w.id, title: t.title ?? '', url: t.url ?? '',
                    active: !!t.active, pinned: !!t.pinned,
                    group: (t.groupId != null && t.groupId > -1) ? (groupName(t.groupId) || `group ${t.groupId}`) : null,
                    isAttentionPin: t.id === pinnedTab,
                });
            }
            return { ok: true, result: { tabs, pinnedTab, windowCount: wins.length } };
        }
        case 'read': {
            const tabId = await resolveTargetTab(args);
            if (tabId == null) return { ok: false, error: 'No tab to read.' };
            const tab = await chrome.tabs.get(tabId).catch(() => null);
            if (!tab) return { ok: false, error: `Tab ${tabId} not found.` };
            // Bounded: tab metadata only. Page CONTENT (DOM/text) needs scripting (broad mode).
            return { ok: true, result: { tabId, url: tab.url ?? '', title: tab.title ?? '' } };
        }
        case 'goto': {
            // Navigate the TARGET tab (explicit/pinned/active) in place, vs 'navigate' which opens a new one.
            const url = String(args.url || '');
            if (!/^https?:\/\//i.test(url)) return { ok: false, error: 'goto requires an http(s) url.' };
            try { new URL(url); } catch { return { ok: false, error: 'goto requires a valid url.' }; }
            const tabId = await resolveTargetTab(args);
            if (tabId == null) return { ok: false, error: 'No tab to navigate.' };
            const live = await ensureCuActionLive(act);
            if (!live.ok) return live;
            const updated = await chrome.tabs.update(tabId, { url });
            return { ok: true, result: { tabId: updated?.id ?? tabId, url } };
        }
        case 'back':
        case 'forward': {
            // Tab history navigation via the tabs API (no scripting). Back from a fresh tab is a no-op (no history).
            const tabId = await resolveTargetTab(args);
            if (tabId == null) return { ok: false, error: 'No tab.' };
            const live = await ensureCuActionLive(act);
            if (!live.ok) return live;
            if (verb === 'back') await chrome.tabs.goBack(tabId);
            else await chrome.tabs.goForward(tabId);
            return { ok: true, result: { tabId, action: verb } };
        }
        case 'type': {
            const tabId = await resolveTargetTab(args);
            if (tabId == null) return { ok: false, error: 'No tab to type into.' };
            const tab = await chrome.tabs.get(tabId).catch(() => null);
            const gate = await fillGate(tab);
            if (!gate.ok) return gate;
            const argumentKey = args.value !== undefined ? 'value' : 'text';
            const rawValue = String(args[argumentKey] ?? '');
            const refs = vaultRefs(rawValue);
            const selector = typeof args.selector === 'string' && args.selector.trim() ? args.selector.trim() : null;
            const fillPolicy = buildVaultFillPolicy(refs, gate.origin);
            if (refs.length > 0) {
                const [pre] = await chrome.scripting.executeScript({
                    target: { tabId },
                    func: injInspectFillTarget,
                    args: [selector, fillPolicy],
                });
                const checked = pre && pre.result;
                if (!checked || !checked.ok)
                    return { ok: false, error: (checked && checked.error) || 'Vault fill target could not be verified.' };
            }
            // Resolve {{vault:...}} at the last moment, bound to this action + the live host (all-or-nothing).
            const resolved = await resolveVaultTokens(act.actionId, act.executionToken, rawValue, gate.host, argumentKey, refs);
            if (!resolved.ok) return { ok: false, error: resolved.error };   // carries no secret
            let value = resolved.value;
            let res;
            try {
                const live = await ensureCuActionLive(act);
                if (!live.ok) return live;
                [res] = await chrome.scripting.executeScript({ target: { tabId }, func: injFill, args: [selector, value, fillPolicy] });
            }
            finally { value = ''; }   // drop the plaintext from the worker as soon as it's handed to the page
            const out = res && res.result;
            if (!out || !out.ok) return { ok: false, error: (out && out.error) || 'Could not fill the field.' };
            return { ok: true, result: { tabId, selector, tag: out.tag, name: out.name } };   // never the value
        }
        case 'click': {
            const selector = typeof args.selector === 'string' && args.selector ? args.selector : null;
            if (!selector) return { ok: false, error: 'click requires a CSS selector (args.selector).' };
            const tabId = await resolveTargetTab(args);
            if (tabId == null) return { ok: false, error: 'No tab to click in.' };
            const tab = await chrome.tabs.get(tabId).catch(() => null);
            const gate = await fillGate(tab);
            if (!gate.ok) return gate;
            const live = await ensureCuActionLive(act);
            if (!live.ok) return live;
            const [res] = await chrome.scripting.executeScript({ target: { tabId }, func: injClick, args: [selector] });
            const out = res && res.result;
            if (!out || !out.ok) return { ok: false, error: (out && out.error) || 'Could not click the element.' };
            return { ok: true, result: { tabId, selector, tag: out.tag } };
        }
        case 'scroll': {
            const tabId = await resolveTargetTab(args);
            if (tabId == null) return { ok: false, error: 'No tab to scroll.' };
            const tab = await chrome.tabs.get(tabId).catch(() => null);
            const gate = await fillGate(tab);
            if (!gate.ok) return gate;
            const dx = Number(args.dx ?? 0) || 0;
            const dy = Number(args.dy ?? args.amount ?? 0) || 0;
            const selector = typeof args.selector === 'string' && args.selector ? args.selector : null;
            const live = await ensureCuActionLive(act);
            if (!live.ok) return live;
            const [res] = await chrome.scripting.executeScript({ target: { tabId }, func: injScroll, args: [selector, dx, dy] });
            const out = res && res.result;
            if (!out || !out.ok) return { ok: false, error: (out && out.error) || 'Could not scroll.' };
            return { ok: true, result: { tabId, dx, dy } };
        }
        case 'screenshot':
            return { ok: false, error: `'screenshot' is a separate capability slice and is not enabled in this build.` };
        default:
            return { ok: false, error: `Unsupported browser-use verb '${verb}'.` };
    }
}

async function pollCu() {
    if (!cfg.token || !connected || lastMcpAuthProblem) return;
    // One claim per poll bounds the unavoidable check→browser-API race to the single action already starting. A panic
    // can therefore never leave four more pre-claimed side effects sitting in this worker's batch.
    const batch = await mcpCall('cu_poll_actions', { limit: 1 });
    const actions = Array.isArray(batch?.actions) ? batch.actions : [];
    for (const act of actions) {
        let result;
        // This extension executes BROWSER actions only. No desktop executor exists yet, so all cu actions are
        // browser; when the desktop sidecar lands, cu_poll_actions should filter by modality so we never claim a
        // desktop action we cannot run.
        if (String(act.modality || '').toLowerCase() !== 'browser') {
            result = { ok: false, error: 'Browser extension cannot execute non-browser actions.' };
        } else {
            try {
                const live = await ensureCuActionLive(act);
                result = live.ok ? await executeCuAction(act) : live;
            }
            catch (e) { result = { ok: false, error: String(e?.message || e) }; }
        }
        await mcpCall('cu_complete_action', {
            actionId: act.actionId,
            executionToken: act.executionToken,
            ok: !!result.ok,
            resultJson: result.ok ? JSON.stringify(result.result ?? result) : null,
            error: result.ok ? null : (result.error || 'Browser-use action failed.'),
        });
    }
}

// Tell TraceBrake which tab the operator pinned as shared attention, so the broker holds off-focus state changes.
async function reportAttention() {
    if (lastMcpAuthProblem) return;
    await mcpCall('cu_set_attention', { tabId: pinnedTab == null ? '' : String(pinnedTab) });
}

async function refresh() {
    connected = await checkHealth();
    lastMcpError = null;
    lastMcpAuthProblem = null;
    lastStatus = null;
    lastAsks = [];
    if (connected && cfg.token)
        lastStatus = await mcpCall('foreman_status');
    // Re-assert the pin each cycle so it survives a TraceBrake restart, and push a CLEAR exactly once when it goes to
    // null, so a restarted worker (or an unpin) always reconciles the broker to our true state before pollCu runs.
    if (connected && !lastMcpAuthProblem && (pinnedTab != null || lastReportedPin != null)) {
        await reportAttention();
        lastReportedPin = pinnedTab;
    }
    if (!lastMcpAuthProblem)
        await pollCu();
    // The inbox is scoped to THIS extension's harness ("browser-extension") by the token — it only ever shows
    // prompts TraceBrake routed to us, never a sibling's. Empty until orchestration routes work to the browser.
    if (connected && cfg.token && !lastMcpAuthProblem) {
        const asks = await mcpCall('list_ask_harness_requests', { includeAnswered: false, limit: 10 });
        lastAsks = Array.isArray(asks?.requests) ? asks.requests : [];
    }
    broadcast();
}

function startPolling() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(refresh, POLL_MS);
    refresh();
}

// ── Side panel plumbing ──────────────────────────────────────────────────────

chrome.runtime.onConnect.addListener((port) => {
    if (port.name !== 'foreman-sidepanel') return;
    sidePanelPort = port;
    broadcast();                 // show last-known state immediately…
    refresh();                   // …then pull fresh status + inbox (the SW may have been suspended)
    port.onMessage.addListener(async (msg) => {
        if (msg?.kind === 'pair') {
            const r = await pair(msg.code);
            safePost({ kind: 'pair-result', ...r });
        } else if (msg?.kind === 'refresh') {
            mcpSession = null;
            await refresh();
        } else if (msg?.kind === 'ask-reply') {
            const r = await replyAsk(msg.requestId, msg.response);
            safePost({ kind: 'ask-reply-result', requestId: msg.requestId, ...r });   // confirm first…
            if (r.ok) await refresh();                                                // …then drop the answered card
        }
    });
    port.onDisconnect.addListener(() => { if (sidePanelPort === port) sidePanelPort = null; });
});

function broadcast() {
    safePost({
        kind: 'status',
        connected,
        paired: !!cfg.token,
        verified: !!cfg.token && connected && !!lastStatus,
        base: base(),
        harnessId: cfg.harnessId,
        status: lastStatus,
        asks: lastAsks,
        mcpError: lastMcpError,
        authProblem: lastMcpAuthProblem,
        pinnedTab,                 // shared-attention pin so the panel can show "Claude's attention: this tab"
    });
}

function safePost(message) {
    if (!sidePanelPort) return;
    try { sidePanelPort.postMessage(message); }
    catch { sidePanelPort = null; }
    finally { try { void chrome.runtime.lastError; } catch { /* ok */ } }
}

// Pressing the pinned toolbar icon toggles the shared-attention pin on that tab (press again = unpin, press a
// DIFFERENT tab = move the pin), reports it to TraceBrake, and opens the side panel. openPanelOnActionClick MUST be
// false here — otherwise Chrome opens the panel itself and never fires onClicked, so we'd never see the press.
chrome.action.onClicked.addListener((tab) => {
    // sidePanel.open() MUST run synchronously in the click's user-gesture turn. Calling it after an `await`
    // (e.g. reportAttention) makes Chrome reject it ("may only be called in response to a user gesture") and the
    // click looks dead. So open the panel FIRST, then do the pin toggle + async report fire-and-forget.
    if (tab?.windowId !== undefined) { try { chrome.sidePanel.open({ windowId: tab.windowId }); } catch { /* ok */ } }
    if (tab?.id !== undefined && tab.id !== chrome.tabs.TAB_ID_NONE) {
        const prev = pinnedTab;
        pinnedTab = (pinnedTab === tab.id) ? null : tab.id;
        persistPin();
        updatePinBadge(prev, pinnedTab);   // instant visible feedback on the icon, independent of the round-trip
        reportAttention().then(() => { lastReportedPin = pinnedTab; });
        broadcast();
    }
});
try { chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false }); } catch { /* Chrome < 114 */ }

// If the pinned tab closes, drop the pin (and tell TraceBrake) so a stale id can't linger as the "focus".
chrome.tabs.onRemoved.addListener((tabId) => {
    if (pinnedTab === tabId) { pinnedTab = null; persistPin(); reportAttention().then(() => { lastReportedPin = null; }); broadcast(); }
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg?.kind === 'pair') { pair(msg.code).then(sendResponse); return true; }
    return false;
});

// ── Boot ─────────────────────────────────────────────────────────────────────

const KEEPALIVE_ALARM = 'foreman-keepalive';

async function bootstrap() {
    try { cfg = { ...cfg, ...(await loadSettings()) }; } catch { /* defaults */ }
    // Reload the shared-attention pin a prior worker instance saved, so a service-worker restart doesn't silently
    // drop the focus to null (which would let no-tabId actions resolve to the active tab). refresh() then reconciles
    // it to the broker. lastReportedPin stays null so the first refresh re-pushes the reloaded pin.
    try { const s = await chrome.storage.session.get('pinnedTab'); if (s && typeof s.pinnedTab === 'number') pinnedTab = s.pinnedTab; } catch { /* no session storage */ }
    if (pinnedTab != null) updatePinBadge(null, pinnedTab);   // re-show the pin badge after a worker restart
    // MV3 service workers sleep after ~30s idle, which stops the poll loop — so an APPROVED browser-use action
    // would sit unclaimed unless the side panel is open. A periodic alarm wakes the worker (~1 min) to poll
    // cu_poll_actions / status / inbox even when nothing else fires; the 5s interval still drives the awake bursts.
    try { chrome.alarms.create(KEEPALIVE_ALARM, { periodInMinutes: 1 }); } catch { /* alarms unavailable */ }
    startPolling();
}
// Registered at top level so the alarm can WAKE a suspended worker; it then reloads cfg + resumes polling.
chrome.alarms.onAlarm.addListener((alarm) => { if (alarm.name === KEEPALIVE_ALARM) bootstrap(); });
onSettingsChanged(async () => {
    try {
        cfg = { ...cfg, ...(await loadSettings()) };
        mcpSession = null;
        lastMcpError = null;
        lastMcpAuthProblem = null;
    } catch { /* keep */ }
});
chrome.runtime.onStartup.addListener(bootstrap);
chrome.runtime.onInstalled.addListener(bootstrap);
bootstrap();
