/**
 * TraceBrake LiveWeave — extension service worker.
 *
 * Bridges the browser to the LOCAL TraceBrake desktop app over loopback HTTP (never the network). Pairs as the
 * `liveweave` harness (closed-loop challenge/response; the code never crosses the wire), then polls TraceBrake's
 * `liveweave_*` broker and renders TraceBrake-brokered edits into `liveweave.html` — a local, extension-owned
 * canvas. A page snapshot is read only after the operator invokes the action on that tab and chooses Edit.
 *
 * Split out from the TraceBrake extension so the page-builder feature lives on its own, with its own
 * pairing/token, separate from the safety watchdog arm.
 */
import { loadSettings, saveSettings, onSettingsChanged } from './settings.js';
import { callMcpTool, openMcpSession } from './mcp-client.js';
import { canvasNeedsReload, canvasRuntimeReady } from './canvas-runtime.mjs';
import { canvasRuntimeStateFromPorts, createAsyncDeadlineGate } from './service-worker-state.mjs';
import {
    boundedScan,
    canvasFromProject,
    capStructure,
    createProject,
    markProjectSaved,
    readProjectSource,
    replaceProjectSource,
    searchProjectSource,
    updateProjectFromCanvas,
} from './project-model.mjs';
import {
    getActiveProject,
    getProject,
    listProjects,
    putProject,
    setActiveProjectId,
} from './project-store.js';

const EXTENSION_VERSION = chrome.runtime.getManifest().version;
let cfg = { host: '127.0.0.1', port: 54321, token: '', pairedOrigin: '', harnessId: 'liveweave', liveweaveDriver: '' };
let connected = false;
let lastMcpError = null;
const sidePanelPorts = new Set();   // every open side panel (a 2nd window used to orphan the 1st)
const canvasPortStates = new Map(); // every canvas tab and its independent runtime-version handshake
let pollTimer = null;
let needsPair = false;       // set when the token is rejected (401/403) — stop polling a dead token, prompt re-pair
let mcpSession = null;
const cmdLog = [];           // recent commands {action, ok, error, ts} for the side-panel log (in-memory; resets on SW restart)
let captureCandidate = null; // set only by an explicit toolbar action; activeTab access is tied to that gesture
let currentProjectSummary = null;
let selectionModeRequested = false;
let currentNanoStatus = 'unknown';

function setSelectionModeRequested(enabled) {
    selectionModeRequested = !!enabled;
    const message = { kind: 'selection-mode', enabled: selectionModeRequested };
    for (const port of [...canvasPortStates.keys()]) postTo(port, message);
    for (const panel of [...sidePanelPorts]) postTo(panel, message);
}

const canvasRuntimeState = () => canvasRuntimeStateFromPorts(canvasPortStates, EXTENSION_VERSION);
const canvasIsReady = () => canvasRuntimeReady(canvasRuntimeState());

async function waitForCanvasReady(timeoutMs = 2500) {
    const deadline = Date.now() + timeoutMs;
    while (!canvasIsReady() && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 50));
    }
    return canvasIsReady();
}

function logCommand(action, result) {
    cmdLog.push({ action, ok: !!result?.ok, error: result?.ok ? null : (result?.error || null), ts: Date.now() });
    if (cmdLog.length > 25) cmdLog.shift();
}

// MV3 reliability: a service worker is torn down after ~30s idle, which kills setInterval — so agent commands
// would silently stall until something woke the worker. Two mechanisms cover this: a chrome.alarms heartbeat that
// WAKES the worker to poll even when it's suspended (durable, ~30s floor), plus a fast interval that runs while an
// extension page (side panel or canvas) holds a port open and keeps the worker alive (responsive during building).
const FAST_POLL_MS = 3000;
const POLL_ALARM = 'liveweave-poll';
const POLL_ALARM_PERIOD_MIN = 0.5;   // idle heartbeat. Chrome 120+ honours a 30s floor; older clamps sub-1-min to
                                     // 60s. Sub-minute responsiveness comes from FAST_POLL while a page holds a port.
const POLL_RUN_TIMEOUT_MS = 45_000;
const pollGate = createAsyncDeadlineGate(POLL_RUN_TIMEOUT_MS);

const base = () => `http://${cfg.host}:${cfg.port}`;
const selfOrigin = () => `chrome-extension://${chrome.runtime.id}`;

async function loopbackFetch(url, options = {}, timeoutMs = 10_000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error(`Loopback request timed out after ${timeoutMs} ms.`)), timeoutMs);
    try { return await fetch(url, { ...options, signal: controller.signal }); }
    finally { clearTimeout(timer); }
}
const safeOrigin = (value) => {
    try { return new URL(String(value || '')).origin.slice(0, 500); }
    catch { return ''; }
};

// ── Pairing ────────────────────────────────────────────────────────────────

async function hmacHex(key, message) {
    const enc = new TextEncoder();
    const k = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', k, enc.encode(message));
    return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

async function pair(code, liveweaveDriver = cfg.liveweaveDriver) {
    const clean = (code || '').trim().toUpperCase();
    if (!clean) return { ok: false, error: 'Enter the code shown in TraceBrake.' };
    try {
        const cr = await loopbackFetch(`${base()}/pair/challenge`);
        if (cr.status === 409) return { ok: false, error: 'No pairing window is open. Click "Pair browser extension" in TraceBrake first.' };
        if (!cr.ok) return { ok: false, error: `TraceBrake returned ${cr.status} for the challenge.` };
        const { challenge } = await cr.json();

        const response = await hmacHex(clean, challenge);
        const done = await loopbackFetch(`${base()}/pair/complete`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ response, origin: selfOrigin(), harnessId: 'liveweave' }),
        });
        const body = await done.json().catch(() => ({}));
        if (!done.ok || !body.ok) return { ok: false, error: body.reason || `Pairing failed (${done.status}).` };

        cfg = { ...cfg, token: body.token || '', pairedOrigin: body.origin || selfOrigin(), harnessId: 'liveweave', liveweaveDriver: liveweaveDriver || '' };
        await saveSettings({ token: cfg.token, pairedOrigin: cfg.pairedOrigin, harnessId: 'liveweave', liveweaveDriver: cfg.liveweaveDriver });
        mcpSession = null;
        needsPair = false;   // fresh token — resume polling
        await refresh();
        return { ok: true };
    } catch (e) {
        return { ok: false, error: `Could not reach TraceBrake at ${base()} — is it running? (${e})` };
    }
}

// ── Connection / status ──────────────────────────────────────────────────────

async function checkHealth() {
    try {
        const r = await loopbackFetch(`${base()}/health`);
        return r.ok;
    } catch { return false; }
}

async function ensureMcpSession() {
    if (!cfg.token) return null;
    if (mcpSession) return mcpSession;
    mcpSession = await openMcpSession(base(), cfg.token);
    return mcpSession;
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
        lastMcpError = String(e?.message || e);
        if (e?.authFailed) needsPair = true;   // revoked/rotated token — stop hammering it, prompt re-pair
        return null;
    }
}

// ── LiveWeave canvas ───────────────────────────────────────────────────────

const DEFAULT_CANVAS = {
    title: 'LiveWeave Canvas',
    html: '<main style="font-family: system-ui, sans-serif; padding: 32px;"><h1>LiveWeave Canvas</h1><p>Ready for TraceBrake-brokered edits.</p></main>',
    css: '',
    projectId: '',
    sourceUrl: '',
    revision: 0,
    dirty: false,
    updatedAt: '',
};

async function readCanvas() {
    const s = await chrome.storage.local.get({ liveweaveCanvas: DEFAULT_CANVAS, liveweaveHistory: [], liveweaveRedo: [] });
    return {
        canvas: { ...DEFAULT_CANVAS, ...(s.liveweaveCanvas || {}) },
        history: Array.isArray(s.liveweaveHistory) ? s.liveweaveHistory : [],
        redo: Array.isArray(s.liveweaveRedo) ? s.liveweaveRedo : [],
    };
}

function summarizeProject(project) {
    if (!project) return null;
    return {
        id: project.id,
        title: project.title,
        sourceUrl: project.source?.url || '',
        sourceKind: project.source?.kind || 'blank',
        warningCount: Array.isArray(project.warnings) ? project.warnings.length : 0,
        revision: Number(project.revision || 0),
        dirty: !!project.dirty,
        updatedAt: project.updatedAt || '',
        savedAt: project.savedAt || '',
    };
}

// Single-flight the first-run project creation. getActiveProject → (create + put + setActiveProjectId) is a
// check-then-act sequence that yields at every await, so two concurrent callers on a fresh install (e.g. an
// SSE-brokered apply racing an operator-side saveCanvas) would BOTH see no active project and BOTH mint a
// fresh UUID — leaving an orphan project and a canvas whose revision no longer matches activeProjectId, which
// then surfaces as spurious revision_conflict on the next patch. Share one creation across concurrent callers.
let _ensureActiveInflight = null;
async function ensureActiveProject(canvas) {
    const existing = await getActiveProject();
    if (existing) return existing;
    if (_ensureActiveInflight) return _ensureActiveInflight;   // another caller is already creating it — join them
    _ensureActiveInflight = (async () => {
        // Re-check inside the critical section: a prior in-flight creation may have landed while we awaited above.
        const raced = await getActiveProject();
        if (raced) return raced;
        const project = createProject({ title: canvas.title, html: canvas.html, css: canvas.css, kind: 'blank' });
        await putProject(project);
        await setActiveProjectId(project.id);
        return project;
    })().finally(() => { _ensureActiveInflight = null; });
    return _ensureActiveInflight;
}

async function publishProject(project, { resetHistory = false, open = true } = {}) {
    await putProject(project);
    await setActiveProjectId(project.id);
    currentProjectSummary = summarizeProject(project);
    const canvas = canvasFromProject(project);
    const patch = { liveweaveCanvas: canvas };
    if (resetHistory) {
        patch.liveweaveHistory = [];
        patch.liveweaveRedo = [];
    }
    await chrome.storage.local.set(patch);
    if (open) await openLiveWeaveCanvas({ active: false });
    broadcastProjectChanged(project);
    return canvas;
}

async function saveCanvas(canvas, pushHistory = true, clearRedo = true) {
    const prior = await readCanvas();
    const active = await ensureActiveProject(prior.canvas);
    const changed = active.title !== canvas.title || active.html !== canvas.html || active.css !== canvas.css;
    const project = updateProjectFromCanvas(active, { ...DEFAULT_CANVAS, ...canvas });
    await putProject(project);
    currentProjectSummary = summarizeProject(project);
    const next = { ...DEFAULT_CANVAS, ...canvasFromProject(project), updatedAt: new Date().toISOString() };
    const patch = { liveweaveCanvas: next };
    if (pushHistory && changed) patch.liveweaveHistory = [...prior.history.slice(-9), prior.canvas];
    if (clearRedo && changed) patch.liveweaveRedo = [];   // a fresh edit invalidates the redo stack (standard undo/redo)
    await chrome.storage.local.set(patch);
    // Ensure the canvas exists so the edit is visible, but DON'T steal focus on every brokered micro-edit (a burst
    // of agent commands used to yank the tab forward up to 5x per poll). The canvas re-renders live from storage;
    // explicit user actions (start_builder, side-panel "Open canvas") are the ones that raise it.
    await openLiveWeaveCanvas({ active: false });
    broadcastProjectChanged(project);
    return next;
}

// Track our OWN canvas tab by id (persisted — the service worker is ephemeral) instead of querying tabs by URL.
// chrome.tabs.get/update/create all work without the broad "tabs" permission (which grants read across every tab
// and contradicted this extension's "does not drive arbitrary tabs" scope); querying by URL needed it.
async function openLiveWeaveCanvas({ active = false } = {}) {
    const url = chrome.runtime.getURL('liveweave.html');
    const { liveweaveTabId } = await chrome.storage.local.get({ liveweaveTabId: null });
    if (liveweaveTabId != null) {
        let tab = null;
        try {
            tab = await chrome.tabs.get(liveweaveTabId);          // rejects if the tab was closed
        } catch {
            await chrome.storage.local.remove('liveweaveTabId');
        }
        if (tab) {
            const stale = canvasNeedsReload(canvasRuntimeState());
            if (stale) {
                try { await chrome.tabs.reload(liveweaveTabId); }
                catch { tab = await chrome.tabs.update(liveweaveTabId, { url, active }); }
            }
            if (active) {
                if (tab.windowId != null && chrome.windows?.update) {
                    await chrome.windows.update(tab.windowId, { focused: true }).catch(() => {});
                }
                await chrome.tabs.update(liveweaveTabId, { active: true });
            }
            return { tabId: liveweaveTabId, created: false, reloaded: stale };
        }
    }
    const tab = await chrome.tabs.create({ url, active });
    if (tab?.id != null) await chrome.storage.local.set({ liveweaveTabId: tab.id });
    return { tabId: tab?.id ?? null, created: true, reloaded: false };
}

// Forget the tracked tab when it's closed, so the next open cleanly recreates instead of racing a stale id.
chrome.tabs.onRemoved.addListener(async (tabId) => {
    const { liveweaveTabId } = await chrome.storage.local.get({ liveweaveTabId: null });
    if (liveweaveTabId === tabId) await chrome.storage.local.remove('liveweaveTabId');
    if (captureCandidate?.tabId === tabId) {
        captureCandidate = null;
        await chrome.storage.session.remove('liveweaveCaptureCandidate');
        broadcast();
    }
});

function capturablePage(tab) {
    const url = String(tab?.url || '');
    let reason = '';
    if (!url) reason = 'Click the LiveWeave toolbar icon on the page you want to edit.';
    else if (!/^https?:/i.test(url) && !/^file:/i.test(url)) reason = 'Chrome internal, extension, and browser-owned pages cannot be imported.';
    return {
        tabId: tab?.id ?? null,
        windowId: tab?.windowId ?? null,
        title: String(tab?.title || 'Current page'),
        url,
        available: !reason,
        reason,
    };
}

async function rememberCaptureCandidate(tab) {
    captureCandidate = capturablePage(tab);
    await chrome.storage.session.set({ liveweaveCaptureCandidate: captureCandidate });
    broadcast();
}

async function refreshCaptureCandidate() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
        // chrome.tabs.query can return an id but mask url/title when the panel itself was opened without a fresh
        // activeTab grant. Do not erase the stronger candidate recorded by action.onClicked for the same tab.
        if (tab?.id === captureCandidate?.tabId && !tab.url && captureCandidate.url) return captureCandidate;
        await rememberCaptureCandidate(tab || null);
    } catch {
        await rememberCaptureCandidate(null);
    }
    return captureCandidate;
}

async function importCaptureCandidate() {
    const page = captureCandidate;
    if (!page?.available || page.tabId == null) {
        return { ok: false, code: 'no_page_access', error: page?.reason || 'Open LiveWeave from the page you want to edit.' };
    }
    let result;
    try {
        const execution = await chrome.scripting.executeScript({
            target: { tabId: page.tabId },
            files: ['capture-page.js'],
        });
        result = execution?.[0]?.result;
    } catch (e) {
        return {
            ok: false,
            code: 'capture_denied',
            error: `Could not read this tab. Click the LiveWeave toolbar icon on it and try again. (${String(e?.message || e)})`,
        };
    }
    if (!result?.ok) return result || { ok: false, code: 'capture_failed', error: 'The page returned no capture result.' };

    const project = createProject({
        title: result.title,
        html: result.html,
        css: result.css,
        sourceUrl: result.url,
        warnings: result.warnings,
        kind: 'imported',
    });
    const canvas = await publishProject(project, { resetHistory: true, open: false });
    // Keep focus on the source page so the side panel can enter editor mode. The preview is created in the
    // background and receives live updates; the operator raises it explicitly with the Preview button.
    await openLiveWeaveCanvas({ active: false });
    return { ok: true, project, canvas, stats: result.stats || {} };
}

async function createBlankProject(title = 'Untitled LiveWeave Page') {
    const project = createProject({
        title,
        html: '<main class="lw-blank"><h1>Start building</h1><p>Edit the HTML and CSS from the LiveWeave side panel.</p></main>',
        css: 'body{margin:0;font-family:system-ui,sans-serif}.lw-blank{padding:48px;max-width:720px;margin:auto}',
        kind: 'blank',
    });
    await publishProject(project, { resetHistory: true });
    return project;
}

async function operatorRequest(action, params = {}) {
    switch (action) {
        case 'get_state': {
            const { liveweaveAgentEdit = null } = await chrome.storage.local.get({ liveweaveAgentEdit: null });
            return { ok: true, project: await getActiveProject(), projects: await listProjects(), page: captureCandidate, agentEdit: liveweaveAgentEdit };
        }
        case 'refresh_page':
            return { ok: true, page: await refreshCaptureCandidate() };
        case 'import_page':
            return importCaptureCandidate();
        case 'new_project': {
            const project = await createBlankProject(String(params.title || 'Untitled LiveWeave Page'));
            return { ok: true, project };
        }
        case 'activate_project': {
            const project = await getProject(String(params.projectId || ''));
            if (!project) return { ok: false, code: 'not_found', error: 'LiveWeave project not found.' };
            await publishProject(project, { resetHistory: true });
            return { ok: true, project };
        }
        case 'update_source': {
            const project = await getActiveProject();
            if (!project) return { ok: false, code: 'no_project', error: 'No LiveWeave project is active.' };
            if (Number(params.expectedRevision) !== Number(project.revision)) {
                return { ok: false, code: 'revision_conflict', error: 'The project changed while you were editing.', project };
            }
            const file = String(params.file || '').toLowerCase();
            if (!['html', 'css'].includes(file)) return { ok: false, code: 'bad_file', error: "file must be 'html' or 'css'." };
            const { canvas } = await readCanvas();
            const next = await saveCanvas({ ...canvas, [file]: String(params.value ?? '') });
            return { ok: true, project: await getActiveProject(), canvas: next };
        }
        case 'set_element_style': {
            const path = safeSelector(String(params.path || ''));
            const styles = safeDeclarations(String(params.styles || ''));
            if (!path || styles == null) return { ok: false, code: 'bad_style', error: 'A valid selector and plain CSS declarations are required.' };
            const { canvas } = await readCanvas();
            const next = await saveCanvas({ ...canvas, css: upsertMarked(canvas.css || '', `lw:s:${path}`, `${path}{${styles}}`) });
            return { ok: true, project: await getActiveProject(), canvas: next, path };
        }
        case 'clear_element_style': {
            const path = safeSelector(String(params.path || ''));
            if (!path) return { ok: false, code: 'bad_selector', error: 'A valid selector is required.' };
            const { canvas } = await readCanvas();
            const next = await saveCanvas({ ...canvas, css: removeMarked(canvas.css || '', `lw:s:${path}`) });
            return { ok: true, project: await getActiveProject(), canvas: next, path };
        }
        case 'set_element_text':
        case 'duplicate_element':
        case 'remove_element': {
            const path = safeSelector(String(params.path || ''));
            if (!path) return { ok: false, code: 'bad_selector', error: 'A valid selector is required.' };
            const { canvas } = await readCanvas();
            const op = action === 'set_element_text' ? 'set_text' : action;
            const dom = await domOp(op, { html: canvas.html, path, text: params.text ?? '' });
            if (!dom?.ok) return dom || { ok: false, code: 'dom_unavailable', error: 'The LiveWeave DOM helper is unavailable.' };
            const next = await saveCanvas({ ...canvas, html: dom.html });
            return { ok: true, project: await getActiveProject(), canvas: next, path };
        }
        case 'get_element_context': {
            const path = safeSelector(String(params.path || ''));
            if (!path) return { ok: false, code: 'bad_selector', error: 'Pick an element first.' };
            const { canvas } = await readCanvas();
            const context = await domOp('inspect_element', { html: canvas.html, path });
            if (!context?.ok) return context || { ok: false, code: 'dom_unavailable', error: 'Could not inspect the selected element.' };
            return { ok: true, path, outerHtml: context.outerHtml, revision: Number(canvas.revision || 0) };
        }
        case 'apply_nano_patch': {
            const path = safeSelector(String(params.path || ''));
            const hasInner = params.innerHtml !== null && params.innerHtml !== undefined;
            const innerHtml = hasInner ? String(params.innerHtml).slice(0, 40000) : null;
            const styles = safeDeclarations(String(params.styles || '').slice(0, 4000));
            if (!path || styles == null || (!hasInner && !styles)) {
                return { ok: false, code: 'nano_bad_patch', error: 'Nano returned no valid selected-element change.' };
            }
            if (/(?:@import|expression\s*\(|javascript\s*:|url\s*\()/i.test(styles)) {
                return { ok: false, code: 'nano_bad_style', error: 'Nano returned unsafe CSS.' };
            }
            const { canvas } = await readCanvas();
            if (Number(params.expectedRevision) !== Number(canvas.revision)) {
                return { ok: false, code: 'revision_conflict', error: 'The project changed while Nano was working. Pick the element and try again.', project: await getActiveProject() };
            }
            let html = canvas.html;
            if (hasInner) {
                const changed = await domOp('apply_safe_inner', { html, path, inner: innerHtml });
                if (!changed?.ok) return changed || { ok: false, code: 'dom_unavailable', error: 'Could not apply Nano HTML safely.' };
                html = changed.html;
            }
            const css = styles
                ? upsertMarked(canvas.css || '', `lw:s:${path}`, `${path}{${styles}}`)
                : canvas.css;
            const next = await saveCanvas({ ...canvas, html, css });
            return { ok: true, project: await getActiveProject(), canvas: next, path, summary: String(params.summary || 'Element updated with Nano.').slice(0, 500) };
        }
        case 'request_agent_edit': {
            const project = await getActiveProject();
            const path = safeSelector(String(params.path || ''));
            const instruction = String(params.instruction || '').trim().slice(0, 4000);
            const targetHarnessId = String(params.targetHarnessId || '').trim().toLowerCase();
            if (!project) return { ok: false, code: 'no_project', error: 'No LiveWeave project is active.' };
            if (!path || !instruction) return { ok: false, code: 'bad_prompt', error: 'Choose a page or element target and describe the change first.' };
            if (!/^[a-z0-9._:-]{1,80}$/.test(targetHarnessId) || targetHarnessId === 'any' || targetHarnessId === 'liveweave') {
                return { ok: false, code: 'bad_harness', error: 'Choose a specific TraceBrake harness.' };
            }
            if (!cfg.token || !connected) return { ok: false, code: 'foreman_offline', error: 'Pair LiveWeave with TraceBrake before sending an agent edit.' };
            if (cfg.liveweaveDriver !== targetHarnessId) {
                cfg = { ...cfg, liveweaveDriver: targetHarnessId };
                await saveSettings({ liveweaveDriver: targetHarnessId });
                mcpSession = null;
                broadcast();
            }
            const selectionJson = JSON.stringify(params.selection || {}).slice(0, 6000);
            const result = await mcpCall('liveweave_request_edit', {
                targetHarnessId,
                instruction,
                path,
                projectId: project.id,
                projectTitle: project.title,
                projectRevision: Number(project.revision || 0),
                sourceOrigin: project.source?.url ? safeOrigin(project.source.url) : '',
                selectionJson,
            });
            if (!result?.ok) return { ok: false, code: 'agent_request_failed', error: result?.reason || lastMcpError || 'TraceBrake could not queue the edit request.' };
            await chrome.storage.local.set({
                liveweaveAgentEdit: {
                    requestId: result.requestId,
                    targetHarnessId,
                    projectId: project.id,
                    createdAt: new Date().toISOString(),
                },
            });
            return result;
        }
        case 'agent_edit_status': {
            const requestId = String(params.requestId || '').trim();
            if (!requestId) return { ok: false, code: 'missing_request', error: 'No agent edit request is active.' };
            const result = await mcpCall('liveweave_edit_request_result', { requestId });
            if (!result?.found) {
                await chrome.storage.local.remove('liveweaveAgentEdit');
                return { ok: false, code: 'request_not_found', error: result?.reason || lastMcpError || 'TraceBrake could not read the edit request.' };
            }
            if (result.status !== 'pending') await chrome.storage.local.remove('liveweaveAgentEdit');
            return { ok: true, ...result };
        }
        case 'report_nano_status': {
            const value = String(params.value || '').toLowerCase();
            if (!['available', 'downloadable', 'downloading', 'unavailable'].includes(value)) {
                return { ok: false, code: 'bad_nano_status', error: 'Unknown Nano availability state.' };
            }
            currentNanoStatus = value;
            return { ok: true, nanoStatus: currentNanoStatus };
        }
        case 'mark_saved': {
            const project = await getActiveProject();
            if (!project) return { ok: false, code: 'no_project', error: 'No LiveWeave project is active.' };
            const saved = markProjectSaved(project);
            const canvas = await publishProject(saved, { resetHistory: false, open: false });
            return { ok: true, project: saved, canvas };
        }
        case 'open_canvas': {
            const canvas = await openLiveWeaveCanvas({ active: true });
            const canvasConnected = await waitForCanvasReady();
            return {
                ok: canvasConnected,
                canvas,
                canvasConnected,
                extensionVersion: EXTENSION_VERSION,
                error: canvasConnected ? null : 'The preview tab opened but its LiveWeave script did not connect. Reload the extension and try again.',
            };
        }
        case 'start_selection': {
            setSelectionModeRequested(true);
            const canvas = await openLiveWeaveCanvas({ active: true });
            const canvasConnected = await waitForCanvasReady();
            if (!canvasConnected) setSelectionModeRequested(false);
            return {
                ok: canvasConnected,
                canvas,
                canvasConnected,
                selecting: canvasConnected,
                extensionVersion: EXTENSION_VERSION,
                error: canvasConnected ? null : 'Picking could not start because the preview script did not connect. Reload the extension and try again.',
            };
        }
        case 'stop_selection':
            setSelectionModeRequested(false);
            return { ok: true, selecting: false, extensionVersion: EXTENSION_VERSION };
        case 'set_driver': {
            const liveweaveDriver = String(params.value || '').trim().toLowerCase();
            if (liveweaveDriver && liveweaveDriver !== 'any' && !/^[a-z0-9._:-]{1,80}$/.test(liveweaveDriver)) {
                return { ok: false, code: 'bad_harness', error: 'Driver must be a bounded harness id.' };
            }
            cfg = { ...cfg, liveweaveDriver };
            await saveSettings({ liveweaveDriver });
            mcpSession = null;
            await refresh();
            return { ok: true, liveweaveDriver };
        }
        default:
            return { ok: false, code: 'unsupported', error: `Unsupported operator action '${action}'.` };
    }
}

function textParam(params, name, fallback = '') {
    const v = params?.[name];
    return v == null ? fallback : String(v);
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function generatedCanvas(params, current) {
    const instruction = textParam(params, 'instruction', textParam(params, 'prompt', ''));
    const title = textParam(params, 'title', instruction.match(/named\s+([^.,]+)/i)?.[1] || current.title || 'LiveWeave Page');
    const theme = escapeHtml(title);
    const detail = escapeHtml(instruction || `A polished landing page for ${title}.`);
    return {
        title,
        html: `<main class="lw-page"><section class="lw-hero"><p class="lw-kicker">Generated locally</p><h1>${theme}</h1><p>${detail}</p><a href="#details">Explore</a></section><section id="details" class="lw-grid"><article><h2>Fresh offer</h2><p>Clear, conversion-focused copy with a focused call to action.</p></article><article><h2>Designed to scan</h2><p>Responsive sections, readable spacing, and simple visual hierarchy.</p></article><article><h2>Ready to refine</h2><p>Use apply_page or apply_section for exact agent-authored markup.</p></article></section></main>`,
        css: `body{margin:0;font-family:Inter,ui-sans-serif,system-ui,sans-serif;background:#fff8f3;color:#24151f}.lw-hero{min-height:70vh;display:grid;align-content:center;gap:18px;padding:clamp(32px,7vw,96px);background:linear-gradient(135deg,#fff8f3,#fde9ef 52%,#d8f7f2)}.lw-kicker{margin:0;color:#9b2354;font-size:12px;font-weight:850;letter-spacing:.12em;text-transform:uppercase}.lw-hero h1{max-width:10ch;margin:0;font-size:clamp(48px,8vw,104px);line-height:.9}.lw-hero p{max-width:760px;margin:0;color:#553847;font-size:clamp(18px,2vw,23px);line-height:1.5}.lw-hero a{display:inline-flex;width:max-content;align-items:center;min-height:48px;padding:0 22px;border-radius:8px;background:#ef3e6f;color:#fff;font-weight:850;text-decoration:none}.lw-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;padding:clamp(32px,6vw,80px)}.lw-grid article{padding:22px;border-radius:8px;background:#fff;box-shadow:0 18px 40px rgb(83 44 61 / 10%)}@media(max-width:800px){.lw-grid{grid-template-columns:1fr}}`,
    };
}

// ── Offscreen DOM (true CSS-selector targeting; the service worker has no DOM) ─

let offscreenReady = null;
async function ensureOffscreen() {
    if (!chrome.offscreen) return false;   // Chrome < 109 — caller falls back to string handling
    try {
        if (await chrome.offscreen.hasDocument?.()) return true;
        if (!offscreenReady) {
            offscreenReady = chrome.offscreen.createDocument({
                url: 'offscreen.html',
                reasons: ['DOM_PARSER'],
                justification: 'Target and inspect the LiveWeave canvas by CSS selector (the service worker has no DOM).',
            }).catch(() => {}).finally(() => { offscreenReady = null; });
        }
        await offscreenReady;
        return (await chrome.offscreen.hasDocument?.()) ?? true;
    } catch { return false; }
}

// Run a DOM op in the offscreen document; returns its {ok,...} result, or null when offscreen is unavailable so the
// caller can fall back. Command execution is serialized by the poll mutex, so these calls never overlap.
async function domOp(op, payload) {
    if (!(await ensureOffscreen())) return null;
    try { return await chrome.runtime.sendMessage({ target: 'liveweave-offscreen', op, ...payload }); }
    catch { return null; }
}

// ── Command helpers: validation, structure, safe CSS slots ───────────────────

const escapeRe = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const stripOk = ({ ok, ...rest }) => rest;   // drop the transport flag from an inspect result

// Missing/blank required param → a STRUCTURED error the driving agent can branch on, instead of the old silent
// ok:true no-op (apply_page with no html kept the old html; set_style with no styles wrote `sel{}` — both looked
// like success). This is the core agent-feedback contract.
function requireParams(params, names) {
    for (const n of names) {
        const v = params?.[n];
        if (v == null || String(v).trim() === '')
            return { ok: false, code: 'missing_param', field: n, error: `LiveWeave '${n}' is required for this action.` };
    }
    return null;
}

// Structured slots are DATA, not markup. Reject values that would break out of the CSS rule / HTML block they're
// interpolated into (apply_page is the path for raw markup). Returns the cleaned value, or null to reject.
const safeSelector = (path) => {
    const p = String(path || '').trim();
    return !p || /[{}<>]|-->/.test(p) ? null : p;   // real selectors never contain these
};
const safeDeclarations = (styles) => {
    const s = String(styles ?? '');
    return /[{}<]|-->/.test(s) ? null : s;           // a declaration body can't contain braces or tags
};

// Upsert a comment-MARKED single-line CSS rule so repeated set_style/set_background for the same target REPLACE
// their own prior rule (no more stylesheet growing forever) without ever touching the user's apply_page CSS.
function upsertMarked(css, marker, rule) {
    const line = `\n/*${marker}*/${String(rule).replace(/\s*\n\s*/g, ' ')}`;
    const re = new RegExp(`\\n?\\/\\*${escapeRe(marker)}\\*\\/[^\\n]*`);
    return re.test(css || '') ? css.replace(re, line) : `${css || ''}${line}`;
}

// Best-effort structural outline of the stored HTML. The service worker has no DOM, so this is a regex pass — not a
// full parser, but enough for an agent to learn what headings/landmarks/ids exist to target (vs re-reading the raw
// source it already wrote). scan returns this plus the full source; outline returns just this.
function outlineOf(html) {
    const h = String(html || '');
    const headings = [...h.matchAll(/<(h[1-6])\b[^>]*>([\s\S]*?)<\/\1>/gi)]
        .map((m) => ({ level: Number(m[1][1]), text: m[2].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim().slice(0, 120) }));
    const ids = [...h.matchAll(/\bid\s*=\s*["']([^"']+)["']/gi)].map((m) => m[1]);
    const duplicateIds = [...new Set(ids.filter((v, i) => ids.indexOf(v) !== i))];
    const landmarks = [...h.matchAll(/<(header|nav|main|section|article|aside|footer|form)\b/gi)]
        .reduce((acc, m) => { const t = m[1].toLowerCase(); acc[t] = (acc[t] || 0) + 1; return acc; }, {});
    const elementCount = (h.match(/<[a-z][a-z0-9-]*\b/gi) || []).length;
    return { headings, ids, duplicateIds, landmarks, elementCount };
}

async function executeLiveWeaveCommand(cmd) {
    const action = String(cmd.action || '').toLowerCase();
    const params = cmd.parameters || {};
    const { canvas, history, redo } = await readCanvas();
    const sourceProject = {
        id: canvas.projectId || '',
        title: canvas.title,
        html: canvas.html,
        css: canvas.css,
        sourceUrl: canvas.sourceUrl || '',
        revision: Number(canvas.revision || 0),
    };
    // Effect confirmation appended to every successful mutation so the agent can verify the edit actually landed.
    const effect = (c) => ({ appliedTitle: c.title, htmlLength: (c.html || '').length, cssLength: (c.css || '').length });

    switch (action) {
        case 'start_builder':
            await openLiveWeaveCanvas({ active: true });
            return { ok: true, title: canvas.title, opened: true };

        case 'stop_builder': {
            // Truthful stop: close the canvas tab. (Never clearInterval(pollTimer) — polling is the ONLY command
            // channel, so stopping it would strand the extension.) Brokered edits still apply + reopen the canvas.
            const { liveweaveTabId } = await chrome.storage.local.get({ liveweaveTabId: null });
            if (liveweaveTabId != null) { try { await chrome.tabs.remove(liveweaveTabId); } catch { /* already closed */ } }
            return { ok: true, stopped: true, note: 'Canvas tab closed; a later edit reopens it.' };
        }

        case 'new_canvas': {
            const project = await createBlankProject(textParam(params, 'title', 'LiveWeave Canvas'));
            return { ok: true, projectId: project.id, ...effect(canvasFromProject(project)) };
        }

        case 'generate':
            return { ok: true, ...effect(await saveCanvas(generatedCanvas(params, canvas))) };

        case 'template':
            return { ok: true, ...effect(await saveCanvas(generatedCanvas({ ...params, instruction: textParam(params, 'instruction', textParam(params, 'template', 'Template landing page')) }, canvas))) };

        case 'apply_page': {
            const bad = requireParams(params, ['html']);
            if (bad) return bad;
            const c = await saveCanvas({
                title: textParam(params, 'title', canvas.title),
                html: textParam(params, 'html', canvas.html),
                css: textParam(params, 'css', canvas.css),
            });
            return { ok: true, ...effect(c) };
        }

        case 'apply_section': {
            const bad = requireParams(params, ['html']);
            if (bad) return bad;
            const section = textParam(params, 'html');
            const css = textParam(params, 'css');
            const placement = textParam(params, 'placement', 'append').toLowerCase();
            const targetRaw = textParam(params, 'target');
            const target = targetRaw ? safeSelector(targetRaw) : null;
            if (targetRaw && !target) return { ok: false, code: 'bad_selector', error: 'target must be a plain CSS selector.' };
            // Insert into a target container via the offscreen DOM (or at document top level); a real "target not
            // found" is surfaced. Falls back to a document-level sibling concat when offscreen is unavailable.
            const dom = await domOp('apply_section', { html: canvas.html, section, placement, target });
            if (dom?.code === 'not_found') return dom;
            const nextHtml = dom?.ok ? dom.html : (placement === 'prepend' ? `${section}\n${canvas.html}` : `${canvas.html}\n${section}`);
            const c = await saveCanvas({ ...canvas, html: nextHtml, css: css ? `${canvas.css || ''}\n${css}` : canvas.css });
            return { ok: true, placement, target: target || undefined, targeted: !!dom?.ok, ...effect(c) };
        }

        case 'apply_inner': {
            const bad = requireParams(params, ['path', 'html']);
            if (bad) return bad;
            const sel = safeSelector(textParam(params, 'path'));
            if (!sel) return { ok: false, code: 'bad_selector', error: 'path must be a plain CSS selector (no { } < > or -->).' };
            const html = textParam(params, 'html');
            const css = safeDeclarations(textParam(params, 'css')) ?? '';
            // TRUE selector targeting via the offscreen DOM: resolve `sel` and set its innerHTML. A genuine
            // "selector not found" is surfaced to the agent. If offscreen is unavailable, fall back to a delimited,
            // idempotent block per selector (repeats replace, never duplicate).
            const dom = await domOp('apply_inner', { html: canvas.html, path: sel, inner: html });
            if (dom?.code === 'not_found') return dom;
            if (dom?.ok) {
                const c = await saveCanvas({ ...canvas, html: dom.html, css: css ? `${canvas.css || ''}\n${css}` : canvas.css });
                return { ok: true, target: sel, targeted: true, ...effect(c) };
            }
            const open = `<!-- liveweave:begin ${sel} -->`, close = `<!-- liveweave:end ${sel} -->`;
            const block = `\n${open}\n${html}\n${close}`;
            const re = new RegExp(`\\n?${escapeRe(open)}[\\s\\S]*?${escapeRe(close)}`);
            const replaced = re.test(canvas.html);
            const nextHtml = replaced ? canvas.html.replace(re, block) : `${canvas.html}${block}`;
            const c = await saveCanvas({ ...canvas, html: nextHtml, css: css ? `${canvas.css || ''}\n${css}` : canvas.css });
            return { ok: true, target: sel, targeted: false, replaced, note: 'Delimited-block fallback (offscreen DOM unavailable).', ...effect(c) };
        }

        case 'set_style': {
            const bad = requireParams(params, ['path', 'styles']);
            if (bad) return bad;
            const sel = safeSelector(textParam(params, 'path'));
            const body = safeDeclarations(textParam(params, 'styles'));
            if (!sel || body == null) return { ok: false, code: 'bad_slot', error: 'path/styles must be plain CSS (no braces or tags).' };
            const c = await saveCanvas({ ...canvas, css: upsertMarked(canvas.css || '', `lw:s:${sel}`, `${sel}{${body}}`) });
            return { ok: true, selector: sel, ...effect(c) };
        }

        case 'set_background': {
            const value = String(textParam(params, 'value', textParam(params, 'background', '#ffffff')));
            if (/[{}<]/.test(value)) return { ok: false, code: 'bad_slot', error: 'background value must be a plain CSS value.' };
            const c = await saveCanvas({ ...canvas, css: upsertMarked(canvas.css || '', 'lw:bg', `body{background:${value};}`) });
            return { ok: true, ...effect(c) };
        }

        case 'set_text':
        case 'duplicate_element':
        case 'remove_element': {
            const path = safeSelector(textParam(params, 'path'));
            if (!path) return { ok: false, code: 'bad_selector', error: 'path must be a plain CSS selector.' };
            const op = action === 'set_text' ? 'set_text' : action;
            const dom = await domOp(op, { html: canvas.html, path, text: params.text ?? '' });
            if (!dom?.ok) return dom || { ok: false, code: 'dom_unavailable', error: 'The LiveWeave DOM helper is unavailable.' };
            const c = await saveCanvas({ ...canvas, html: dom.html });
            return { ok: true, target: path, ...effect(c) };
        }

        case 'undo': {
            if (history.length === 0) return { ok: false, error: 'Nothing to undo.' };
            const previous = history[history.length - 1];
            // Push the CURRENT canvas onto the redo stack; restore the previous. Route through saveCanvas so
            // updatedAt refreshes, but don't push history or wipe redo.
            await chrome.storage.local.set({ liveweaveHistory: history.slice(0, -1), liveweaveRedo: [...redo.slice(-9), canvas] });
            const c = await saveCanvas(previous, false, false);
            return { ok: true, ...effect(c) };
        }

        case 'redo': {
            if (redo.length === 0) return { ok: false, error: 'Nothing to redo.' };
            const restore = redo[redo.length - 1];
            await chrome.storage.local.set({ liveweaveRedo: redo.slice(0, -1), liveweaveHistory: [...history.slice(-9), canvas] });
            const c = await saveCanvas(restore, false, false);
            return { ok: true, ...effect(c) };
        }

        case 'scan': {   // bounded source preview + structure; large projects continue through read_source
            const dom = await domOp('inspect', { html: canvas.html });
            const structure = dom?.ok ? stripOk(dom) : outlineOf(canvas.html);   // real DOM structure, or regex fallback
            return { ok: true, ...boundedScan(sourceProject, structure) };
        }

        case 'outline': {   // concise structure only — cheap for targeting decisions
            const dom = await domOp('inspect', { html: canvas.html });
            const s = capStructure(dom?.ok ? stripOk(dom) : outlineOf(canvas.html));
            return { ok: true, title: canvas.title, projectId: canvas.projectId || '', revision: canvas.revision || 0,
                     htmlLength: canvas.html.length, cssLength: canvas.css.length, ...s };
        }

        case 'read_source': {
            try {
                return { ok: true, projectId: sourceProject.id, ...readProjectSource(sourceProject, textParam(params, 'file'), params.offset, params.length) };
            } catch (e) {
                return { ok: false, code: 'bad_read', error: String(e?.message || e) };
            }
        }

        case 'search_source': {
            try {
                return { ok: true, projectId: sourceProject.id, ...searchProjectSource(sourceProject, textParam(params, 'query'), textParam(params, 'file'), params.limit) };
            } catch (e) {
                return { ok: false, code: 'bad_search', error: String(e?.message || e) };
            }
        }

        case 'replace_source': {
            const result = replaceProjectSource(sourceProject, {
                file: textParam(params, 'file'),
                start: params.start,
                end: params.end,
                text: params.text ?? '',
                expectedRevision: params.expectedRevision,
            });
            if (!result.ok) return result;
            const next = await saveCanvas({ ...canvas, html: result.project.html, css: result.project.css });
            return { ok: true, file: result.file, start: result.start, end: result.end,
                     insertedLength: result.insertedLength, ...effect(next), revision: next.revision };
        }

        default:
            return { ok: false, error: `Unsupported LiveWeave action '${action}'. Supported: start_builder, stop_builder, new_canvas, generate, template, apply_page, apply_section, apply_inner, set_style, set_background, set_text, duplicate_element, remove_element, undo, redo, scan, outline, read_source, search_source, replace_source.` };
    }
}

function removeMarked(css, marker) {
    const re = new RegExp(`\\n?\\/\\*${escapeRe(marker)}\\*\\/[^\\n]*`);
    return String(css || '').replace(re, '');
}

// Honest on-device model availability (was hardcoded 'unavailable'). Chrome's Prompt API is a document-context
// API, so it is usually absent in the service worker — in which case we correctly report 'unavailable'. If a
// future channel exposes it here (or an offscreen document is added), this reports the real state. Clamped by
// TraceBrake's SanitizeNanoStatus to {available, downloadable, downloading, unavailable}.
async function liveweaveTabInfo() {
    const { canvas } = await readCanvas();
    return {
        url: chrome.runtime.getURL('liveweave.html'),
        title: canvas.title || 'LiveWeave Canvas',
        kind: 'extension-canvas',
        editable: true,
        extensionVersion: EXTENSION_VERSION,
        canvasConnected: canvasIsReady(),
    };
}

async function pollLiveWeave() {
    if (!cfg.token || !connected) return;
    if (needsPair) return; // token rejected — don't hammer a dead token; the operator must re-pair
    const outcome = await pollGate.run(async () => {
        const tabInfoJson = JSON.stringify(await liveweaveTabInfo());
        const batch = await mcpCall('liveweave_poll_commands', {
            limit: 5,
            tabInfoJson,
            nanoStatus: currentNanoStatus,
            driverHarness: cfg.liveweaveDriver || '',
        });
        const commands = Array.isArray(batch?.commands) ? batch.commands : [];
        for (const cmd of commands) {
            let result;
            try {
                result = await executeLiveWeaveCommand(cmd);
            } catch (e) {
                result = { ok: false, error: String(e?.message || e) };
            }
            logCommand(cmd.action, result);
            await mcpCall('liveweave_complete_command', {
                commandId: cmd.commandId,
                ok: !!result.ok,
                resultJson: result.ok ? JSON.stringify(result) : null,
                error: result.ok ? null : (result.error || 'LiveWeave command failed.'),
            });
        }
    });
    if (!outcome.started) return;
    if (outcome.timedOut) {
        const error = `LiveWeave poll exceeded ${Math.round(POLL_RUN_TIMEOUT_MS / 1000)} seconds; the guard was released.`;
        lastMcpError = error;
        logCommand('poll', { ok: false, error });
        return;
    }
    if (outcome.error) throw outcome.error;
}

async function refresh() {
    try {
        connected = await checkHealth();
        lastMcpError = null;
        await pollLiveWeave();
    } catch (e) {
        lastMcpError = String(e?.message || e);
    } finally {
        broadcast();
    }
}

// Fast interval for responsive building. It only runs while the worker is alive; a connected side-panel or canvas
// port keeps it alive, and the chrome.alarms heartbeat below revives polling after the worker is suspended.
function startPolling() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(refresh, FAST_POLL_MS);
    ensurePollAlarm();
}

// Durable heartbeat: an alarm wakes a suspended worker so queued commands still get applied when nobody is looking
// at the canvas. create() is idempotent (same name replaces). Registered from the top-level alarm listener too.
function ensurePollAlarm() {
    try { chrome.alarms.create(POLL_ALARM, { periodInMinutes: POLL_ALARM_PERIOD_MIN }); } catch { /* no alarms API */ }
}

chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm?.name !== POLL_ALARM) return;
    await bootstrap();
    await refresh();
});

// ── Side panel + canvas plumbing ─────────────────────────────────────────────

chrome.runtime.onConnect.addListener((port) => {
    // The canvas page holds a port open while it's up; that keeps the worker alive so the fast interval runs and
    // building stays responsive. We don't need to do anything per-message — just poll on connect and on disconnect
    // fall back to the alarm heartbeat.
    if (port.name === 'foreman-liveweave-canvas') {
        canvasPortStates.set(port, { canvasVersion: '', previewVersion: '' });
        postTo(port, { kind: 'selection-mode', enabled: selectionModeRequested });
        port.onMessage.addListener((msg) => {
            const state = canvasPortStates.get(port);
            if (!state) return;
            if (msg?.kind === 'canvas-ready') {
                state.canvasVersion = String(msg.version || '');
                broadcast();
                return;
            }
            if (msg?.kind === 'preview-loading') {
                state.previewVersion = '';
                broadcast();
                return;
            }
            if (msg?.kind === 'preview-ready') {
                state.previewVersion = String(msg.version || '');
                broadcast();
                return;
            }
            if (msg?.kind === 'selection-mode-changed') {
                setSelectionModeRequested(msg.enabled);
                return;
            }
            if (msg?.kind !== 'preview-selection' || !msg.selection?.path) return;
            setSelectionModeRequested(false);
            const message = { kind: 'preview-selection', selection: msg.selection };
            for (const panel of [...sidePanelPorts]) postTo(panel, message);
        });
        refresh();
        port.onDisconnect.addListener(() => {
            if (canvasPortStates.delete(port)) {
                broadcast();
            }
        });
        return;
    }
    if (port.name !== 'foreman-liveweave-sidepanel') return;
    sidePanelPorts.add(port);    // track ALL open panels (a second browser window used to orphan the first)
    postTo(port, { kind: 'selection-mode', enabled: selectionModeRequested });
    postTo(port, statusMessage());   // show last-known state to THIS panel immediately…
    refresh();                       // …then pull fresh state (the SW may have been suspended)
    port.onMessage.addListener(async (msg) => {
        if (msg?.kind === 'pair') {
            const r = await pair(msg.code, msg.liveweaveDriver);
            postTo(port, { kind: 'pair-result', ...r });   // route the result to the panel that asked
        } else if (msg?.kind === 'refresh') {
            mcpSession = null;
            await refresh();
        } else if (msg?.kind === 'open-canvas') {
            await openLiveWeaveCanvas({ active: true });    // explicit user action — raise the canvas
        } else if (msg?.kind === 'start-selection') {
            setSelectionModeRequested(true);
            await openLiveWeaveCanvas({ active: true });
        } else if (msg?.kind === 'stop-selection') {
            setSelectionModeRequested(false);
        } else if (msg?.kind === 'command') {
            // Operator-driven builder command from the panel (New/Undo/Redo/Clear) — same executor as brokered ones.
            let result;
            try { result = await executeLiveWeaveCommand({ action: msg.action, parameters: msg.parameters || {} }); }
            catch (e) { result = { ok: false, error: String(e?.message || e) }; }
            logCommand(msg.action, result);
            broadcast();
        }
    });
    port.onDisconnect.addListener(() => sidePanelPorts.delete(port));
});

function statusMessage() {
    const runtime = canvasRuntimeState();
    return {
        kind: 'status',
        connected,
        paired: !!cfg.token,
        needsPair,
        base: base(),
        extensionVersion: EXTENSION_VERSION,
        canvasConnected: canvasIsReady(),
        canvasClientVersion: runtime.canvasVersion,
        previewClientVersion: runtime.previewVersion,
        canvasTabCount: canvasPortStates.size,
        liveweaveDriver: cfg.liveweaveDriver || '',
        nanoStatus: currentNanoStatus,
        mcpError: lastMcpError,
        log: cmdLog,
        page: captureCandidate,
        project: currentProjectSummary,
    };
}

function broadcast() {
    const m = statusMessage();
    for (const port of [...sidePanelPorts]) postTo(port, m);
}

function broadcastProjectChanged(project) {
    const message = { kind: 'project-changed', project: summarizeProject(project) };
    for (const port of [...sidePanelPorts]) postTo(port, message);
    broadcast();
}

function postTo(port, message) {
    try { port.postMessage(message); }
    catch { sidePanelPorts.delete(port); }
    finally { try { void chrome.runtime.lastError; } catch { /* ok */ } }
}

chrome.action.onClicked.addListener(async (tab) => {
    // Keep sidePanel.open directly in the action gesture. Awaiting storage first can consume Chrome's transient
    // user activation and leave an already-open panel with no candidate for the newly selected tab.
    captureCandidate = capturablePage(tab);
    broadcast();
    const persist = chrome.storage.session.set({ liveweaveCaptureCandidate: captureCandidate }).catch(() => {});
    const open = tab?.windowId !== undefined
        ? chrome.sidePanel.open({ windowId: tab.windowId }).catch(() => {})
        : Promise.resolve();
    await Promise.all([persist, open]);
});
// Do not enable openPanelOnActionClick. Chrome may consume the action gesture for its automatic panel path,
// bypassing the onClicked handler above before it records the one-tab activeTab grant. The flag is persistent,
// so bootstrap explicitly clears it for users upgrading from the older auto-open implementation.

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg?.kind === 'pair') { pair(msg.code, msg.liveweaveDriver).then(sendResponse); return true; }
    if (msg?.kind === 'operator') {
        const ownPage = sender?.id === chrome.runtime.id && String(sender?.url || '').startsWith(selfOrigin());
        if (!ownPage) {
            sendResponse({ ok: false, code: 'forbidden', error: 'Operator requests are accepted only from LiveWeave extension pages.' });
            return false;
        }
        operatorRequest(String(msg.action || ''), msg.params || {})
            .then(sendResponse)
            .catch((e) => sendResponse({ ok: false, code: 'operator_error', error: String(e?.message || e) }));
        return true;
    }
    return false;
});

// ── Boot ─────────────────────────────────────────────────────────────────────

// Share the actual boot promise across onStartup, onInstalled, top-level boot and an early alarm. A boolean set
// before loadSettings finished let a cold-start alarm run refresh() against the default/empty configuration.
let bootstrapPromise = null;
function bootstrap() {
    if (bootstrapPromise) return bootstrapPromise;
    bootstrapPromise = (async () => {
        try { await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false }); } catch { /* Chrome < 114 */ }
        try { cfg = { ...cfg, ...(await loadSettings()) }; } catch { /* defaults */ }
        try {
            const session = await chrome.storage.session.get({ liveweaveCaptureCandidate: null });
            captureCandidate = session.liveweaveCaptureCandidate || null;
            currentProjectSummary = summarizeProject(await getActiveProject());
        } catch { /* first run or storage unavailable */ }
        startPolling();
        await refresh();
    })();
    return bootstrapPromise;
}
// Only react to REAL settings changes. The canvas + history + tracked tab id also live in storage.local and are
// rewritten on every brokered edit; without this filter each edit reloaded settings and dropped the cached MCP
// session, forcing an extra initialize handshake per command.
const SETTINGS_KEYS = ['host', 'port', 'token', 'pairedOrigin', 'harnessId', 'liveweaveDriver'];
onSettingsChanged(async (changes) => {
    if (changes && !SETTINGS_KEYS.some((k) => k in changes)) return;
    try {
        cfg = { ...cfg, ...(await loadSettings()) };
        mcpSession = null;
    } catch { /* keep */ }
});
chrome.runtime.onStartup.addListener(() => bootstrap());
chrome.runtime.onInstalled.addListener(() => bootstrap());
bootstrap();
