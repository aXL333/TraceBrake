import { exportDocument, slugify } from './project-model.mjs';
import { getProjectHandle, putProjectHandle } from './project-store.js';
import { buildNanoEditPrompt, parseNanoEditResponse } from './nano-model.mjs';

const port = chrome.runtime.connect({ name: 'foreman-liveweave-sidepanel' });
const $ = (id) => document.getElementById(id);

let status = null;
let currentProject = null;
let currentHandle = null;
let activeView = 'design';
let selectedElement = null;
let updateTimer = null;
let updateInFlight = false;
let suppressInput = false;
let toastTimer = null;
let selectionActive = false;
let agentMode = 'foreman';
let agentBusy = false;
let agentRequestId = '';
let agentPollTimer = null;
let agentMessage = '';
let agentMessageBad = false;
let nanoAvailability = 'unknown';
const dirtyStyleFields = new Set();

async function request(action, params = {}) {
    const result = await chrome.runtime.sendMessage({ kind: 'operator', action, params });
    if (!result) throw new Error('LiveWeave service worker returned no response.');
    return result;
}

port.onMessage.addListener((message) => {
    if (message?.kind === 'status') {
        status = message;
        if (nanoAvailability === 'unknown' && ['available', 'downloadable', 'downloading', 'unavailable'].includes(status.nanoStatus)) {
            nanoAvailability = status.nanoStatus;
        }
        renderConnection();
        renderPage();
        renderAgentControls();
    }
    if (message?.kind === 'preview-selection') {
        selectedElement = message.selection;
        selectionActive = false;
        renderSelectionMode();
        switchView('design');
        renderInspector();
    }
    if (message?.kind === 'selection-mode') {
        selectionActive = !!message.enabled;
        renderSelectionMode();
    }
    if (message?.kind === 'project-changed' && currentProject && message.project?.id === currentProject.id &&
        Number(message.project.revision) !== Number(currentProject.revision) && !updateTimer && !updateInFlight) {
        void loadState({ keepView: true });
    }
});

function toast(text, bad = false) {
    const el = $('toast');
    el.textContent = text;
    el.className = bad ? 'bad' : '';
    el.style.display = 'block';
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.style.display = 'none'; }, 2600);
}

function renderSelectionMode() {
    const button = $('pickElement');
    button.textContent = selectionActive ? 'Picking...' : 'Pick';
    button.classList.toggle('active', selectionActive);
    button.setAttribute('aria-pressed', String(selectionActive));
}

function setAgentStatus(message, bad = false) {
    agentMessage = String(message || '');
    agentMessageBad = !!bad;
    renderAgentControls();
}

async function refreshNanoAvailability() {
    try {
        if (typeof globalThis.LanguageModel?.availability === 'function') {
            const availability = await globalThis.LanguageModel.availability();
            nanoAvailability = ['available', 'downloadable', 'downloading', 'unavailable'].includes(availability)
                ? availability
                : availability === 'readily' ? 'available' : availability === 'after-download' ? 'downloadable' : 'unavailable';
        } else {
            const capabilities = await globalThis.ai?.languageModel?.capabilities?.();
            nanoAvailability = capabilities?.available === 'readily'
                ? 'available'
                : capabilities?.available === 'after-download' ? 'downloadable' : 'unavailable';
        }
    } catch {
        nanoAvailability = 'unavailable';
    }
    void request('report_nano_status', { value: nanoAvailability }).catch(() => {});
    renderAgentControls();
}

function beginNanoSession() {
    const options = {
        monitor(monitor) {
            monitor.addEventListener('downloadprogress', (event) => {
                const percent = Math.max(0, Math.min(100, Math.round(Number(event.loaded || 0) * 100)));
                setAgentStatus(`Downloading Nano: ${percent}%`);
            });
        },
    };
    if (typeof globalThis.LanguageModel?.create === 'function') return globalThis.LanguageModel.create(options);
    if (typeof globalThis.ai?.languageModel?.create === 'function') return globalThis.ai.languageModel.create(options);
    throw new Error('Chrome Nano is not available in this browser profile.');
}

function harnessLabel(value) {
    return $('agentHarness').querySelector(`option[value="${CSS.escape(value)}"]`)?.textContent || value;
}

function renderAgentControls() {
    const foreman = agentMode === 'foreman';
    $('agentModeTraceBrake').classList.toggle('active', foreman);
    $('agentModeNano').classList.toggle('active', !foreman);
    $('agentModeTraceBrake').setAttribute('aria-pressed', String(foreman));
    $('agentModeNano').setAttribute('aria-pressed', String(!foreman));
    $('agentHarness').style.display = foreman ? 'block' : 'none';

    const button = $('runAgentEdit');
    const targetPath = selectedElement?.path || 'body';
    $('agentPrompt').placeholder = selectedElement
        ? 'Describe what to improve or change in this element'
        : 'Describe what to create, improve, or change on this page';
    const promptReady = !!$('agentPrompt').value.trim();
    const foremanReady = !!status?.paired && !!status?.connected;
    const nanoReady = ['available', 'downloadable'].includes(nanoAvailability);
    button.disabled = !currentProject || !targetPath || !promptReady || agentBusy || (foreman ? !foremanReady : !nanoReady);
    button.textContent = agentBusy
        ? (foreman ? 'Agent working...' : 'Nano working...')
        : foreman
            ? `Send to ${harnessLabel($('agentHarness').value)}`
            : nanoAvailability === 'downloadable' ? 'Download & run Nano' : 'Run Nano';

    const statusElement = $('agentStatus');
    let message = agentMessage;
    let bad = agentMessageBad;
    if (!message && !foreman && !nanoReady) {
        message = nanoAvailability === 'downloading' ? 'Nano is downloading.' : 'Nano is unavailable in this Chrome profile.';
        bad = nanoAvailability !== 'downloading';
    } else if (!message && foreman && !foremanReady) {
        message = status?.paired ? 'TraceBrake is offline.' : 'Pair LiveWeave with TraceBrake.';
        bad = true;
    }
    statusElement.textContent = message;
    statusElement.classList.toggle('bad', bad);
}

function renderConnection() {
    const badge = $('badge');
    if (!status?.paired) {
        badge.textContent = 'Not paired';
        badge.className = 'bad';
        $('connectionHint').textContent = 'Open extension options to pair with TraceBrake.';
        return;
    }
    if (status.needsPair) {
        badge.textContent = 'Re-pair';
        badge.className = 'bad';
        $('connectionHint').textContent = 'TraceBrake rejected the saved token. Re-pair from extension options.';
        return;
    }
    badge.textContent = status.connected
        ? `Connected${status.extensionVersion ? ` ${status.extensionVersion}` : ''}`
        : 'TraceBrake offline';
    badge.className = status.connected ? 'ok' : '';
    $('driver').value = status.liveweaveDriver || '';
    if ([...$('agentHarness').options].some((option) => option.value === status.liveweaveDriver)) {
        $('agentHarness').value = status.liveweaveDriver;
    }
    const version = status.extensionVersion ? `LiveWeave ${status.extensionVersion}` : 'LiveWeave';
    const canvas = status.canvasConnected ? 'preview connected' : 'preview reconnects on open';
    $('connectionHint').textContent = `${version}; ${canvas}; ${status.base || 'Local TraceBrake'}.`;
}

function renderPage() {
    const page = status?.page;
    $('pageTitle').textContent = page?.title || 'Open LiveWeave on a page';
    $('pageUrl').textContent = page?.url || '';
    $('pageHint').textContent = page?.available
        ? 'Import a rendered snapshot into a visual LiveWeave project. The original tab is not changed.'
        : (page?.reason || 'The one-tab grant ends when you navigate to another site. Click the LiveWeave toolbar icon once on this tab.');
    $('editPage').disabled = !page?.available;
}

function renderProjects(projects) {
    const root = $('projects');
    if (!projects?.length) {
        root.innerHTML = '<p class="hint">No saved projects yet.</p>';
        return;
    }
    root.replaceChildren(...projects.map((project) => {
        const button = document.createElement('button');
        button.className = 'project-row';
        const title = document.createElement('span');
        title.textContent = project.title || 'Untitled project';
        const meta = document.createElement('small');
        meta.textContent = project.dirty ? 'unsaved' : 'saved';
        button.append(title, meta);
        button.addEventListener('click', async () => {
            await flushEditor();
            const result = await request('activate_project', { projectId: project.id });
            if (!result.ok) return toast(result.error || 'Could not open project.', true);
            selectedElement = null;
            await showProject(result.project);
        });
        return button;
    }));
}

function switchView(view) {
    activeView = ['design', 'html', 'css'].includes(view) ? view : 'design';
    $('designWrap').style.display = activeView === 'design' ? 'block' : 'none';
    document.querySelector('.source-wrap').style.display = activeView === 'design' ? 'none' : 'block';
    document.querySelectorAll('[data-view]').forEach((button) => button.classList.toggle('active', button.dataset.view === activeView));
    if (activeView !== 'design') setEditorValue();
    else updateEditorStatus();
}

function setEditorValue() {
    if (!currentProject || activeView === 'design') return;
    suppressInput = true;
    $('source').value = String(currentProject[activeView] || '');
    suppressInput = false;
    updateEditorStatus();
}

function updateEditorStatus(text = '') {
    if (text) {
        $('editorStatus').textContent = text;
    } else if (activeView === 'design') {
        $('editorStatus').textContent = selectedElement
            ? `${selectedElement.path} | revision ${currentProject?.revision || 0}`
            : `Visual editor | revision ${currentProject?.revision || 0}`;
    } else {
        $('editorStatus').textContent = `${activeView.toUpperCase()} | ${$('source').value.length.toLocaleString()} chars | revision ${currentProject?.revision || 0}`;
    }
    $('dirty').textContent = currentProject?.dirty ? ' | unsaved' : '';
}

function projectHost(project) {
    try { return project.source?.url ? new URL(project.source.url).hostname : 'Local project'; }
    catch { return 'Imported project'; }
}

async function showProject(project) {
    currentProject = project;
    currentHandle = await getProjectHandle(project.id).catch(() => null);
    $('projectTitle').textContent = project.title || 'Untitled project';
    $('projectSource').textContent = projectHost(project);
    $('openOriginal').disabled = !project.source?.url;
    $('browseView').style.display = 'none';
    $('editorView').style.display = 'flex';
    const warnings = Array.isArray(project.warnings) ? project.warnings : [];
    $('warningPanel').style.display = warnings.length ? 'block' : 'none';
    $('warningSummary').textContent = `${warnings.length} import warning${warnings.length === 1 ? '' : 's'}`;
    $('warnings').replaceChildren(...warnings.map((warning) => {
        const item = document.createElement('li');
        item.textContent = warning;
        return item;
    }));
    switchView('design');
    renderInspector();
    if (warnings.length) toast(`${warnings.length} import warning(s); external resources stay blocked in preview.`);
}

async function loadState({ keepView = false } = {}) {
    const result = await request('get_state');
    if (!result.ok) throw new Error(result.error || 'Could not load LiveWeave state.');
    renderProjects(result.projects || []);
    if (result.page) {
        status = { ...(status || {}), page: result.page };
        renderPage();
    }
    if (keepView && result.project) await showProject(result.project);
    if (result.agentEdit?.requestId && !agentRequestId) {
        agentBusy = true;
        agentRequestId = result.agentEdit.requestId;
        if ([...$('agentHarness').options].some((option) => option.value === result.agentEdit.targetHarnessId)) {
            $('agentHarness').value = result.agentEdit.targetHarnessId;
        }
        setAgentStatus(`Waiting for ${harnessLabel(result.agentEdit.targetHarnessId || $('agentHarness').value)}...`);
        clearTimeout(agentPollTimer);
        agentPollTimer = setTimeout(() => void pollAgentEdit(), 300);
    }
}

function scheduleUpdate() {
    if (suppressInput || !currentProject || activeView === 'design') return;
    currentProject = { ...currentProject, [activeView]: $('source').value, dirty: true };
    updateEditorStatus('Autosaving locally...');
    clearTimeout(updateTimer);
    updateTimer = setTimeout(() => { updateTimer = null; void flushEditor(); }, 300);
}

async function flushEditor() {
    clearTimeout(updateTimer);
    updateTimer = null;
    if (!currentProject || activeView === 'design') return true;
    const value = $('source').value;
    if (value === String(currentProject[activeView] || '') && !currentProject.dirty) return true;
    updateInFlight = true;
    try {
        const result = await request('update_source', {
            file: activeView,
            value,
            expectedRevision: currentProject.revision,
        });
        if (!result.ok) {
            if (result.code === 'revision_conflict' && result.project) {
                currentProject = result.project;
                setEditorValue();
            }
            toast(result.error || 'Could not update preview.', true);
            return false;
        }
        currentProject = result.project;
        updateEditorStatus('Preview updated');
        return true;
    } finally {
        updateInFlight = false;
    }
}

function rgbToHex(value, fallback = '#000000') {
    if (/^#[0-9a-f]{6}$/i.test(String(value || ''))) return String(value).toLowerCase();
    const match = String(value || '').match(/rgba?\(\s*(\d+)[, ]+\s*(\d+)[, ]+\s*(\d+)/i);
    if (!match) return fallback;
    return `#${[match[1], match[2], match[3]].map((part) => Math.max(0, Math.min(Number(part), 255)).toString(16).padStart(2, '0')).join('')}`;
}

function setColor(colorId, valueId, value, fallback) {
    const hex = rgbToHex(value, fallback);
    $(colorId).value = hex;
    $(valueId).value = hex;
}

function renderInspector() {
    const selected = selectedElement;
    $('inspectorEmpty').style.display = selected ? 'none' : 'block';
    $('inspectorControls').style.display = selected ? 'block' : 'none';
    $('selectedLabel').textContent = selected ? `<${selected.tag}>${selected.id ? ` #${selected.id}` : ''}` : 'No element selected';
    $('selectedPath').textContent = selected?.path || 'Open the preview and pick an element';
    if (!selected) {
        renderAgentControls();
        updateEditorStatus();
        return;
    }
    const styles = selected.styles || {};
    $('elementText').value = selected.text || '';
    $('elementText').disabled = !selected.canEditText;
    $('applyText').disabled = !selected.canEditText;
    setColor('backgroundColor', 'backgroundValue', styles.backgroundColor, '#ffffff');
    setColor('textColor', 'textColorValue', styles.color, '#111111');
    setColor('borderColor', 'borderColorValue', styles.borderColor, '#000000');
    $('fontSize').value = Math.round(Number(styles.fontSize) || 16);
    $('fontWeight').value = ['400', '500', '600', '700', '800'].includes(String(styles.fontWeight)) ? String(styles.fontWeight) : '400';
    $('textAlign').value = ['left', 'center', 'right', 'justify'].includes(styles.textAlign) ? styles.textAlign : 'left';
    $('display').value = ['block', 'inline', 'inline-block', 'flex', 'grid', 'none'].includes(styles.display) ? styles.display : 'block';
    $('padding').value = Math.round(Number(styles.padding) || 0);
    $('margin').value = Math.round(Number(styles.margin) || 0);
    $('elementWidth').value = styles.width || 'auto';
    $('borderRadius').value = Math.round(Number(styles.borderRadius) || 0);
    $('borderWidth').value = Math.round(Number(styles.borderWidth) || 0);
    dirtyStyleFields.clear();
    renderAgentControls();
    updateEditorStatus();
}

async function pollAgentEdit() {
    clearTimeout(agentPollTimer);
    agentPollTimer = null;
    if (!agentRequestId) return;
    try {
        const result = await request('agent_edit_status', { requestId: agentRequestId });
        if (!result.ok) throw new Error(result.error || 'Could not read the agent edit request.');
        if (result.status === 'pending') {
            setAgentStatus(`Waiting for ${harnessLabel(result.targetHarnessId || $('agentHarness').value)}...`);
            agentPollTimer = setTimeout(() => void pollAgentEdit(), 2000);
            return;
        }
        agentBusy = false;
        agentRequestId = '';
        if (result.status === 'answered') {
            setAgentStatus(result.replyText || result.actionTaken || 'Agent completed the request.');
            await loadState({ keepView: true });
        } else {
            setAgentStatus('The agent did not answer before the request expired.', true);
        }
    } catch (error) {
        agentBusy = false;
        agentRequestId = '';
        setAgentStatus(String(error?.message || error), true);
    }
}

async function runAgentEdit() {
    if (!currentProject || agentBusy) return;
    const instruction = $('agentPrompt').value.trim();
    if (!instruction) return;
    const targetPath = selectedElement?.path || 'body';
    const selection = selectedElement || { path: 'body', tag: 'body', scope: 'page', styles: {} };
    agentBusy = true;
    setAgentStatus(agentMode === 'foreman' ? 'Sending through TraceBrake...' : 'Running on-device Nano...');
    let nanoSession = null;
    try {
        if (agentMode === 'nano') {
            // Start create() in the click's user-activation stack. Chrome requires this when Nano must download.
            const sessionPromise = beginNanoSession();
            const contextPromise = request('get_element_context', { path: targetPath });
            const [session, context] = await Promise.all([sessionPromise, contextPromise]);
            nanoSession = session;
            if (!context.ok) throw new Error(context.error || 'Could not inspect the selected element.');
            const prompt = buildNanoEditPrompt({
                instruction,
                path: targetPath,
                outerHtml: context.outerHtml,
                styles: selection.styles,
            });
            const generated = await nanoSession.prompt(prompt);
            const patch = parseNanoEditResponse(generated);
            if (!patch.ok) throw new Error(patch.error || 'Nano returned an invalid edit.');
            const result = await request('apply_nano_patch', {
                path: targetPath,
                innerHtml: patch.innerHtml,
                styles: patch.styles,
                summary: patch.summary,
                expectedRevision: context.revision,
            });
            if (!result.ok) throw new Error(result.error || 'Nano could not edit the element.');
            if (result.project) currentProject = result.project;
            nanoAvailability = 'available';
            agentBusy = false;
            setAgentStatus(result.summary || 'Element updated with Nano.');
            updateEditorStatus('Preview updated by Nano');
            toast('Nano edit applied.');
            return;
        }

        const targetHarnessId = $('agentHarness').value;
        const result = await request('request_agent_edit', {
            targetHarnessId,
            path: targetPath,
            instruction,
            selection,
        });
        if (!result.ok) throw new Error(result.error || 'TraceBrake could not queue the edit request.');
        agentRequestId = result.requestId;
        setAgentStatus(result.delivered === 'sampled' || result.delivered === 'notified'
            ? `Delivered to ${harnessLabel(targetHarnessId)}.`
            : `Queued for ${harnessLabel(targetHarnessId)}.`);
        agentPollTimer = setTimeout(() => void pollAgentEdit(), 1200);
    } catch (error) {
        agentBusy = false;
        agentRequestId = '';
        setAgentStatus(String(error?.message || error), true);
    } finally {
        try { nanoSession?.destroy?.(); } catch { /* best effort */ }
    }
}

async function visualRequest(action, params) {
    if (!selectedElement?.path) return toast('Pick an element first.', true);
    updateInFlight = true;
    try {
        const result = await request(action, { path: selectedElement.path, ...params });
        if (!result.ok) {
            toast(result.error || 'Element update failed.', true);
            return null;
        }
        if (result.project) currentProject = result.project;
        updateEditorStatus('Preview updated');
        return result;
    } finally {
        updateInFlight = false;
    }
}

async function applySelectedStyles() {
    if (!dirtyStyleFields.size) return toast('Change a style control first.');
    const declarations = [];
    const add = (field, css, value) => { if (dirtyStyleFields.has(field)) declarations.push(`${css}:${value}`); };
    add('backgroundColor', 'background-color', $('backgroundValue').value.trim());
    add('textColor', 'color', $('textColorValue').value.trim());
    add('fontSize', 'font-size', `${Number($('fontSize').value) || 0}px`);
    add('fontWeight', 'font-weight', $('fontWeight').value);
    add('textAlign', 'text-align', $('textAlign').value);
    add('display', 'display', $('display').value);
    add('padding', 'padding', `${Number($('padding').value) || 0}px`);
    add('margin', 'margin', `${Number($('margin').value) || 0}px`);
    add('elementWidth', 'width', $('elementWidth').value.trim() || 'auto');
    add('borderRadius', 'border-radius', `${Number($('borderRadius').value) || 0}px`);
    if (dirtyStyleFields.has('borderWidth')) {
        declarations.push(`border-width:${Number($('borderWidth').value) || 0}px`, 'border-style:solid');
    }
    add('borderColor', 'border-color', $('borderColorValue').value.trim());
    const result = await visualRequest('set_element_style', { styles: declarations.join(';') });
    if (result) {
        dirtyStyleFields.clear();
        toast('Element styles applied.');
    }
}

async function chooseHandle(forceNew) {
    if (forceNew || !currentHandle) {
        if (!window.showSaveFilePicker) return null;
        return window.showSaveFilePicker({
            suggestedName: `${slugify(currentProject?.title)}.html`,
            types: [{ description: 'HTML document', accept: { 'text/html': ['.html', '.htm'] } }],
        });
    }
    const permission = await currentHandle.queryPermission?.({ mode: 'readwrite' });
    if (permission === 'granted' || !currentHandle.requestPermission) return currentHandle;
    return (await currentHandle.requestPermission({ mode: 'readwrite' })) === 'granted' ? currentHandle : null;
}

function downloadFallback() {
    const blob = new Blob([exportDocument(currentProject)], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${slugify(currentProject?.title)}.html`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function saveProject(forceNew = false) {
    if (!currentProject) return;
    let handle;
    try { handle = await chooseHandle(forceNew); }
    catch (e) {
        if (e?.name === 'AbortError') return;
        return toast(`Save picker failed: ${String(e?.message || e)}`, true);
    }
    if (!(await flushEditor())) return;
    try {
        if (handle) {
            const writable = await handle.createWritable();
            await writable.write(exportDocument(currentProject));
            await writable.close();
            currentHandle = handle;
            await putProjectHandle(currentProject.id, handle);
        } else {
            downloadFallback();
        }
        const result = await request('mark_saved');
        if (result.ok) currentProject = result.project;
        updateEditorStatus(handle ? 'Saved to file' : 'Downloaded HTML');
        toast(handle ? 'Project saved.' : 'HTML downloaded.');
    } catch (e) {
        toast(`Save failed: ${String(e?.message || e)}`, true);
    }
}

$('refresh').addEventListener('click', async () => {
    port.postMessage({ kind: 'refresh' });
    await request('refresh_page');
    await loadState({ keepView: $('editorView').style.display === 'flex' });
});
$('editPage').addEventListener('click', async () => {
    $('editPage').disabled = true;
    $('editPage').textContent = 'Importing...';
    try {
        const result = await request('import_page');
        if (!result.ok) return toast(result.error || 'Could not import page.', true);
        selectedElement = null;
        await showProject(result.project);
        toast('Page imported. Pick an element to start editing.');
    } finally {
        $('editPage').textContent = 'Edit this page';
        renderPage();
    }
});
$('newProject').addEventListener('click', async () => {
    const result = await request('new_project');
    if (result.ok) {
        selectedElement = null;
        await showProject(result.project);
    } else toast(result.error || 'Could not create project.', true);
});
$('back').addEventListener('click', async () => {
    await flushEditor();
    $('editorView').style.display = 'none';
    $('browseView').style.display = 'block';
    await loadState();
});
$('preview').addEventListener('click', async () => {
    if (!(await flushEditor())) return;
    const result = await request('open_canvas');
    toast(result.ok ? 'Preview opened.' : (result.error || 'Could not open the preview.'), !result.ok);
});
$('pickElement').addEventListener('click', async () => {
    const starting = !selectionActive;
    const result = await request(starting ? 'start_selection' : 'stop_selection');
    if (!result.ok) return toast(result.error || 'Could not change picking mode.', true);
    toast(starting ? 'Click an element in the preview. Press Escape to cancel.' : 'Element picking cancelled.');
});
$('openOriginal').addEventListener('click', () => {
    if (currentProject?.source?.url) chrome.tabs.create({ url: currentProject.source.url });
});
$('save').addEventListener('click', () => void saveProject(false));
$('saveAs').addEventListener('click', () => void saveProject(true));
$('undo').addEventListener('click', () => port.postMessage({ kind: 'command', action: 'undo' }));
$('redo').addEventListener('click', () => port.postMessage({ kind: 'command', action: 'redo' }));
$('driver').addEventListener('change', async () => {
    const result = await request('set_driver', { value: $('driver').value });
    if ([...$('agentHarness').options].some((option) => option.value === result.liveweaveDriver)) {
        $('agentHarness').value = result.liveweaveDriver;
    }
    toast(result.ok ? `Driver set to ${result.liveweaveDriver || 'operator only'}.` : (result.error || 'Could not change driver.'), !result.ok);
    renderAgentControls();
});

$('agentModeTraceBrake').addEventListener('click', () => {
    agentMode = 'foreman';
    setAgentStatus('');
});
$('agentModeNano').addEventListener('click', () => {
    agentMode = 'nano';
    setAgentStatus('');
    void refreshNanoAvailability();
});
$('agentHarness').addEventListener('change', async () => {
    const result = await request('set_driver', { value: $('agentHarness').value });
    if (!result.ok) return setAgentStatus(result.error || 'Could not select the harness.', true);
    $('driver').value = result.liveweaveDriver;
    setAgentStatus('');
});
$('agentPrompt').addEventListener('input', renderAgentControls);
$('runAgentEdit').addEventListener('click', () => void runAgentEdit());

document.querySelectorAll('[data-view]').forEach((button) => button.addEventListener('click', async () => {
    if (button.dataset.view === activeView) return;
    if (!(await flushEditor())) return;
    switchView(button.dataset.view);
}));

$('source').addEventListener('input', scheduleUpdate);
$('source').addEventListener('keydown', (event) => {
    if (event.key === 'Tab') {
        event.preventDefault();
        const editor = event.currentTarget;
        const start = editor.selectionStart;
        editor.setRangeText('  ', start, editor.selectionEnd, 'end');
        scheduleUpdate();
    }
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's') {
        event.preventDefault();
        void saveProject(false);
    }
});

$('applyText').addEventListener('click', async () => {
    const result = await visualRequest('set_element_text', { text: $('elementText').value });
    if (result) {
        selectedElement = { ...selectedElement, text: $('elementText').value };
        toast('Element text updated.');
    }
});
$('applyStyle').addEventListener('click', () => void applySelectedStyles());
$('resetStyle').addEventListener('click', async () => {
    const result = await visualRequest('clear_element_style', {});
    if (result) {
        dirtyStyleFields.clear();
        toast('LiveWeave styles reset. Pick the element again to refresh computed values.');
    }
});
$('duplicateElement').addEventListener('click', async () => {
    const result = await visualRequest('duplicate_element', {});
    if (result) toast('Element duplicated.');
});
$('deleteElement').addEventListener('click', async () => {
    const result = await visualRequest('remove_element', {});
    if (result) {
        selectedElement = null;
        renderInspector();
        toast('Element deleted. Use Undo to restore it.');
    }
});

const styleInputs = {
    fontSize: 'fontSize', fontWeight: 'fontWeight', textAlign: 'textAlign', display: 'display', padding: 'padding',
    margin: 'margin', elementWidth: 'elementWidth', borderRadius: 'borderRadius', borderWidth: 'borderWidth',
    backgroundValue: 'backgroundColor', textColorValue: 'textColor', borderColorValue: 'borderColor',
};
for (const [id, field] of Object.entries(styleInputs)) {
    $(id).addEventListener('input', () => dirtyStyleFields.add(field));
    $(id).addEventListener('change', () => dirtyStyleFields.add(field));
}
for (const [colorId, valueId, field] of [
    ['backgroundColor', 'backgroundValue', 'backgroundColor'],
    ['textColor', 'textColorValue', 'textColor'],
    ['borderColor', 'borderColorValue', 'borderColor'],
]) {
    $(colorId).addEventListener('input', () => {
        $(valueId).value = $(colorId).value;
        dirtyStyleFields.add(field);
    });
}

request('refresh_page')
    .then(() => loadState())
    .catch((e) => toast(String(e?.message || e), true));

renderAgentControls();
void refreshNanoAvailability();
