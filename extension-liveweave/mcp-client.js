/**
 * Minimal MCP streamable-HTTP client for TraceBrake's loopback server.
 * Handles initialize → notifications/initialized → tools/call with SSE or JSON bodies.
 */

const PROTOCOL = '2024-11-05';
const REQUEST_TIMEOUT_MS = 15_000;

async function fetchWithTimeout(url, options = {}, timeoutMs = REQUEST_TIMEOUT_MS) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error(`Loopback MCP request timed out after ${timeoutMs} ms.`)), timeoutMs);
    try {
        return await fetch(url, { ...options, signal: controller.signal });
    } finally {
        clearTimeout(timer);
    }
}

// Tag 401/403 distinctly so the caller can tell a REVOKED/rotated token (needs re-pair) from a transient network
// or 5xx error (keep the token, retry). Otherwise a dead token loops failing polls forever with no signal.
function httpError(status, message) {
    const e = new Error(message);
    if (status === 401 || status === 403) e.authFailed = true;
    return e;
}

export async function openMcpSession(baseUrl, token, clientInfo = { name: 'foreman-liveweave', version: '0.4.2' }) {
    const headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
        'Authorization': `Bearer ${token}`,
    };

    const initRes = await fetchWithTimeout(`${baseUrl}/mcp`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'initialize',
            params: {
                protocolVersion: PROTOCOL,
                capabilities: {},
                clientInfo,
            },
        }),
    });
    if (!initRes.ok) {
        const err = await initRes.text().catch(() => '');
        throw httpError(initRes.status, `initialize failed (${initRes.status}): ${err.slice(0, 160)}`);
    }

    const initMsg = await readJsonRpc(initRes, 1);   // initialize request id is 1
    let sessionId = initRes.headers.get('Mcp-Session-Id')
        ?? initMsg?.result?.sessionId
        ?? initMsg?.result?.serverInfo?.sessionId;
    if (!sessionId) throw new Error('initialize succeeded but no Mcp-Session-Id was returned');

    const sessionHeaders = { ...headers, 'Mcp-Session-Id': sessionId };

    const initializedRes = await fetchWithTimeout(`${baseUrl}/mcp`, {
        method: 'POST',
        headers: sessionHeaders,
        body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} }),
    });
    if (!initializedRes.ok && initializedRes.status !== 202) {
        const err = await initializedRes.text().catch(() => '');
        throw new Error(`notifications/initialized failed (${initializedRes.status}): ${err.slice(0, 160)}`);
    }

    return { baseUrl, headers: sessionHeaders, sessionId, serverInfo: initMsg?.result?.serverInfo };
}

let nextRpcId = 1;   // monotonic request ids so a response can be correlated to its request

export async function callMcpTool(session, name, args = {}) {
    const id = nextRpcId++;
    const res = await fetchWithTimeout(`${session.baseUrl}/mcp`, {
        method: 'POST',
        headers: session.headers,
        body: JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }),
    });
    if (!res.ok) {
        const err = await res.text().catch(() => '');
        throw httpError(res.status, `tools/call ${name} failed (${res.status}): ${err.slice(0, 160)}`);
    }
    const msg = await readJsonRpc(res, id);
    if (msg?.error) throw new Error(msg.error.message || 'tools/call error');
    return unwrapToolResult(msg?.result);
}

async function readJsonRpc(res, wantId) {
    const text = await res.text();
    return parseJsonRpcPayload(text, wantId);
}

export function parseJsonRpcPayload(text, wantId) {
    if (!text?.trim()) return null;

    const ct = text.trim();
    if (ct.startsWith('{') || ct.startsWith('[')) {
        try { return JSON.parse(ct); } catch { /* fall through to SSE */ }
    }

    // Streamable HTTP wraps JSON-RPC in SSE. Per spec, one event's data is ALL its `data:` lines joined with \n,
    // and events are separated by a blank line — so parse per event, not per line. Then prefer the message whose
    // id matches this request (falling back to the last, which preserves behaviour against a single-message server).
    const messages = [];
    for (const block of text.split(/\r?\n\r?\n/)) {
        const data = block.split(/\r?\n/)
            .filter((l) => l.startsWith('data:'))
            .map((l) => l.slice(5).replace(/^ /, ''))
            .join('\n')
            .trim();
        if (!data) continue;
        try { messages.push(JSON.parse(data)); } catch { /* ignore a torn/partial event */ }
    }
    if (wantId !== undefined) {
        const match = messages.find((m) => m && m.id === wantId && (m.result !== undefined || m.error !== undefined));
        if (match) return match;
    }
    return messages.at(-1) ?? null;
}

export function unwrapToolResult(result) {
    if (!result) return null;
    const blocks = result.content;
    if (!Array.isArray(blocks) || blocks.length === 0) return result;

    const textBlock = blocks.find((b) => b?.type === 'text' && typeof b.text === 'string') ?? blocks[0];
    if (textBlock?.text) {
        try { return JSON.parse(textBlock.text); } catch { return textBlock.text; }
    }
    return result;
}
