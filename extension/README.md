# TraceBrake — browser extension

A Manifest V3 extension that links your browser to the **local** TraceBrake desktop app over loopback — the
closed-loop, on-device design in [`../docs/closed-loop-spec.md`](../docs/closed-loop-spec.md). Nothing it does
ever touches the network: it talks only to `http://127.0.0.1:54321`.

> **Status: pairing + status + inbox + on-device Nano + bounded browser use** (alpha). Pairing, `/health`
> liveness, `foreman_status`, the Ask-Harness inbox, on-device Gemini Nano, and the executor for TraceBrake's
> audited `cu_*` browser-use broker (bounded: navigate + read tab metadata) are implemented. Attestation
> (signed-release hash verification at pairing), icons, and broad browser-use mode are the remaining items.
> Reload the unpacked extension after pulling.
>
> **LiveWeave** (the local page builder) has moved to its own extension — `../extension-liveweave/`.

## What it does

- **Pairing** (one-time): proves it holds TraceBrake's on-screen code via a challenge/response (HMAC; the code
  never crosses the wire), then stores the scoped bearer token TraceBrake issues and gets its origin allow-listed.
  The token is scoped to the `browser-extension` harness — the extension only ever sees/acts as itself, never a
  sibling harness's data.
- **Status**: polls `/health`, calls `foreman_status` over MCP, shows a **`🔒 On-device · verified`** badge
  (the loopback handshake is verified; code-signing attestation is a later step) and a structured status grid.
- **Ask-Harness inbox**: lists prompts TraceBrake routed to the browser (`list_ask_harness_requests`, scoped) and
  lets you reply (`reply_to_ask_harness_request`). Empty until orchestration routes work to the browser.
- **On-device AI (Gemini Nano)**: optional, never required. When Chrome's built-in model is present it can draft
  a reply or summarise the status entirely on-device (nothing leaves the machine). Absent/sub-spec browsers show
  `unavailable` and everything else still works (Pillar 1: Nano is the fast lane, not the gate).
- **Browser use (BU)**: the executor for TraceBrake's **audited** computer-use broker. It polls `cu_poll_actions`
  for actions TraceBrake has already audited (and an operator approved, when held), runs them, and reports via
  `cu_complete_action`. **Bounded mode** (current): `navigate` (open a tab) and `read` (active-tab url/title)
  only, which need nothing beyond the existing `tabs` permission. `click`/`type`/`scroll`/`screenshot` need
  `scripting` + host permissions (a future broad-mode operator opt-in) and return a clear error until then.
  TraceBrake audits, holds, and can panic-halt every action; this extension never decides on its own. The executor
  polls every 5s while paired+connected and runs already-approved actions automatically (so up to ~5s latency
  before an approved action starts); a per-operator pause toggle is a planned refinement.

## Load it

1. Build/run TraceBrake (the desktop app) so its MCP server is listening on `127.0.0.1:54321`.
2. Chrome → `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select either:
   - installed release: `%LOCALAPPDATA%\Programs\TraceBrake\extensions\foreman` (an upgraded Foreman alpha may retain
     `%LOCALAPPDATA%\Programs\Foreman\extensions\foreman`); or
   - source checkout: this `extension/` folder.
3. In TraceBrake, open **Connect agent → Pair browser extension** — it shows a code like `ABCDE-FGHJK`.
4. Click the extension's **Details → Extension options**, type the code, hit **Pair**.
5. Open the side panel (click the toolbar icon). It should read **🔒 On-device · verified** with live alert counts.

## Security model (see the whitepaper)

- `host_permissions` are loopback-only (`127.0.0.1`, `localhost`) — the service worker can reach the local
  server without CORS, and can reach nothing else.
- The pairing code is the auth root; it's never sent — only `HMAC(code, nonce)` is. TraceBrake's server validates
  the request **Host** is loopback (DNS-rebinding defence) and the **Origin** is this paired extension.
- The bearer token lives in `chrome.storage.local` (extension-scoped). It is a local secret, as safe as the
  profile holding it.
- Browser use stays bounded by design: TraceBrake gates -> audits -> (holds for operator) -> approves each action
  before it reaches the extension, and the panic halt empties the poll. The extension adds no broad page
  permissions until broad mode is explicitly opted into.

## Files

| File | Role |
|---|---|
| `manifest.json` | MV3 manifest (loopback host_permissions, side panel, options) |
| `mcp-client.js` | streamable-HTTP MCP client (`initialize` → `notifications/initialized` → `tools/call`) |
| `background.js` | service worker: pairing, health poll, MCP session, inbox fetch/reply, `cu_*` browser-use executor, side-panel port |
| `nano.js` | on-device Gemini Nano adapter (availability detection + a constrained `prompt` turn) |
| `settings.js` | `chrome.storage.local` helpers |
| `options.html` / `options.js` | enter the pairing code |
| `sidepanel.html` / `sidepanel.js` | status grid, verified badge, Ask-Harness inbox, on-device summary |

## Roadmap

- **Broad browser-use mode** (operator opt-in): add `scripting` + host permissions so `click`/`type`/`read`
  page content / `screenshot` work on live pages, with a per-origin lease and an in-panel toggle.
- **Browser-use auto-poll pause toggle** (operator setting): pause/resume `cu_poll_actions` polling without
  unpairing, for operators who want execution to be explicitly resumed rather than continuous.
- **Attestation** (closed-loop spec step 4): SignPath-sign the extension, publish `version → hash → signature`,
  and have `TraceBrake.exe` verify the running extension's hash at pairing. Needs SignPath live (#41).
- Icons (toolbar + store).
