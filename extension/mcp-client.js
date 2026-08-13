/**
 * Minimal MCP streamable-HTTP client for TraceBrake's loopback server.
 * Handles initialize → notifications/initialized → tools/call with SSE or JSON bodies.
 */

const PROTOCOL = '2024-11-05';

export class McpHttpError extends Error {
    constructor(phase, status, body) {
        const detail = String(body || '').slice(0, 160);
        super(`${phase} failed (${status})${detail ? `: ${detail}` : ''}`);
        this.name = 'McpHttpError';
        this.phase = phase;
        this.status = status;
        this.body = body || '';
    }
}

export async function openMcpSession(baseUrl, token, clientInfo = { name: 'foreman-extension', version: '0.1.0' }) {
    const headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
        'Authorization': `Bearer ${token}`,
    };

    const initRes = await fetch(`${baseUrl}/mcp`, {
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
        throw new McpHttpError('initialize', initRes.status, err);
    }

    const initMsg = await readJsonRpc(initRes);
    let sessionId = initRes.headers.get('Mcp-Session-Id')
        ?? initMsg?.result?.sessionId
        ?? initMsg?.result?.serverInfo?.sessionId;
    if (!sessionId) throw new Error('initialize succeeded but no Mcp-Session-Id was returned');

    const sessionHeaders = { ...headers, 'Mcp-Session-Id': sessionId };

    const initializedRes = await fetch(`${baseUrl}/mcp`, {
        method: 'POST',
        headers: sessionHeaders,
        body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} }),
    });
    if (!initializedRes.ok && initializedRes.status !== 202) {
        const err = await initializedRes.text().catch(() => '');
        throw new McpHttpError('notifications/initialized', initializedRes.status, err);
    }

    return { baseUrl, headers: sessionHeaders, sessionId, serverInfo: initMsg?.result?.serverInfo };
}

export async function callMcpTool(session, name, args = {}) {
    const res = await fetch(`${session.baseUrl}/mcp`, {
        method: 'POST',
        headers: session.headers,
        body: JSON.stringify({
            jsonrpc: '2.0',
            id: Date.now(),
            method: 'tools/call',
            params: { name, arguments: args },
        }),
    });
    if (!res.ok) {
        const err = await res.text().catch(() => '');
        throw new McpHttpError(`tools/call ${name}`, res.status, err);
    }
    const msg = await readJsonRpc(res);
    if (msg?.error) throw new Error(msg.error.message || 'tools/call error');
    return unwrapToolResult(msg?.result);
}

async function readJsonRpc(res) {
    const text = await res.text();
    return parseJsonRpcPayload(text);
}

export function parseJsonRpcPayload(text) {
    if (!text?.trim()) return null;

    const ct = text.trim();
    if (ct.startsWith('{') || ct.startsWith('[')) {
        try { return JSON.parse(ct); } catch { /* fall through to SSE */ }
    }

    // Streamable HTTP wraps JSON-RPC in SSE: "event: message\ndata: {...}"
    const messages = [];
    for (const line of text.split('\n')) {
        const trimmed = line.trim();
        if (trimmed.startsWith('data:')) {
            const payload = trimmed.slice(5).trim();
            if (payload.length === 0) continue;
            try { messages.push(JSON.parse(payload)); } catch { /* ignore partial lines */ }
        }
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
