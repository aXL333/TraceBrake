# TraceBrake LiveWeave browser extension

LiveWeave 0.4.2 is a Manifest V3 visual website workspace linked to the local TraceBrake desktop app over loopback. It
can start from a blank project or import a rendered page snapshot, lets the operator select the exact rendered
element, and routes a scoped creation, improvement, or rework prompt either to a chosen TraceBrake harness or Chrome's
on-device Nano model. Editing and previewing happen in extension-owned pages; the source tab is never modified.

## Edit an existing page

1. Navigate to an HTTP(S) page.
2. Click the LiveWeave toolbar action. This grants temporary `activeTab` access and opens the side panel.
3. Choose **Edit this page**. LiveWeave captures the rendered DOM and readable author CSS into a new local project.
4. The side panel opens in **Design** mode. Prompt **Agent edit** immediately for whole-page creation/rework, or
   choose **Pick** and click an element to scope the prompt and direct controls to that target. Choose a TraceBrake
   harness for a brokered edit or Nano for a local on-device edit. HTML and CSS remain advanced tabs.
5. Use **Save** / **Save as** to write a self-contained HTML file. Browsers without File System Access support fall
   back to a download.

The import is a rendered snapshot, not the site's original application source. Scripts and inline event handlers
are removed, forms are neutralized, frames are replaced with placeholders, and inaccessible stylesheets are
reported. Browser-owned pages such as `chrome://`, extension pages, and the Chrome PDF viewer cannot be imported.
Navigating to a different origin ends Chrome's temporary one-tab grant; click the LiveWeave toolbar action once on
the new page before importing it.

## Project and preview model

- Projects live in extension-origin IndexedDB and contain HTML, CSS, source metadata, warnings, revision, dirty
  state, and save timestamps.
- The active project is mirrored into `chrome.storage.local` so the preview and service worker receive prompt,
  durable updates.
- The preview is a `sandbox="allow-scripts"` iframe with a strict per-render nonce CSP: only LiveWeave's inspector
  bridge may execute; project scripts and inline handlers do not. Forms, anchors, refresh directives, base changes,
  storage, network, and top navigation are blocked in the preview copy. Stored project source and single-file
  exports are not destructively rewritten, so intentionally authored site behavior remains available outside the
  confined preview. Imported scripts are still removed during capture.
- The preview toolbar provides one-shot element selection, desktop/tablet/mobile frames, Original, Copy, and
  Download. Picking uses a crosshair and proves selector uniqueness, including on pages with duplicate IDs.
- Tablet and Mobile are honest viewport simulations of the imported snapshot. They exercise captured responsive
  CSS, but cannot fetch a server-selected mobile DOM or user-agent variant without Chrome's broad debugger access.
- The visual inspector uses a bounded selector and computed-style snapshot from the sandbox. Mutations run against
  the stored project DOM/CSS, not the temporary preview attributes, and remain undoable.
- A TraceBrake agent edit becomes an audited Ask-Harness request bound to the project id, revision, and selected
  selector. The target harness inspects and edits through `liveweave_command`; the panel polls its reply.
- A Nano edit starts Chrome's on-device Prompt API directly from the operator's button click (preserving Chrome's
  required user activation for a first model download). Its bounded JSON patch is validated and sanitized before
  entering the same project history.

## TraceBrake MCP actions

LiveWeave polls TraceBrake's `liveweave_*` broker and executes these actions:

- Author: `apply_page`, `apply_section`, `apply_inner`, `set_style`, `set_text`, `duplicate_element`,
  `remove_element`, `set_background`, `new_canvas`, `generate`, `template`, `undo`, and `redo`.
- Inspect: `scan` and `outline`.
- Large source: `read_source(file, offset, length)` and `search_source(query, file?, limit?)`.
- Revision-safe editing: `replace_source(file, start, end, text, expectedRevision)`.
- Lifecycle: `start_builder` and `stop_builder`.

`scan` includes complete HTML/CSS only while the combined source is small enough for TraceBrake's bounded command
result. Larger projects return a bounded preview, file lengths, and `truncated: true`; use `read_source` to pull the
rest. `replace_source` refuses stale revisions so side-panel and agent edits cannot silently overwrite one another.

Page import and filesystem save remain operator-only extension actions. Selecting an MCP driver lets that harness
edit the active project after import; it does not let the harness capture arbitrary tabs or choose files.
Changing the selected driver is intentionally seamless: already-issued command result IDs act as 128-bit
capability receipts so the next driver can finish a handoff, while delivery of new commands remains gated to the
currently selected driver.

The extension uses `liveweave_request_edit` and `liveweave_edit_request_result` to originate and track visual edit
requests. Imported markup and computed selection context are explicitly marked as untrusted in both TraceBrake and
Nano prompts.

## Load and pair

1. Run TraceBrake so its MCP server is listening on `127.0.0.1:54321`.
2. Open `chrome://extensions`, enable Developer mode, choose **Load unpacked**, and select either:
   - installed release: `%LOCALAPPDATA%\Programs\TraceBrake\extensions\liveweave` (an upgraded Foreman alpha may retain
     `%LOCALAPPDATA%\Programs\Foreman\extensions\liveweave`); or
   - source checkout: `extension-liveweave/`.
3. In TraceBrake, open **Connect agent -> Pair browser extension**.
4. Open LiveWeave extension options, select a driver harness, enter the code, and pair.
5. Reload the unpacked extension after changing its source files.

## Security boundaries

- Required host permissions remain loopback-only. `activeTab` grants temporary access only after the operator
  invokes the extension on a page; `scripting` runs the isolated capture file in that one tab.
- Pairing proves possession of TraceBrake's on-screen code by HMAC challenge/response; the code is not sent.
- The bearer token and pairing origin remain extension-scoped in `chrome.storage.local`.
- The capture result is capped at 2 MB. TraceBrake command parameters are separately bounded by the broker.
- Imported page content is untrusted. Capture sanitization, preview sandboxing, CSP, source chunking, and
  revision checks remain independent controls.
- Preview-to-toolbar messages carry a fresh random token and readiness is reported only after the nonce-authorized
  inspector runtime completes its handshake; an iframe load or attempted navigation cannot impersonate readiness.

## Files

| File | Role |
|---|---|
| `manifest.json` | Permissions, side panel, options, icons, and service worker |
| `background.js` | Pairing, project orchestration, capture, polling, and builder commands |
| `capture-page.js` | Isolated rendered-page snapshot and sanitization |
| `project-model.mjs` | Pure project, source paging/search/replacement, scan, and export logic |
| `nano-model.mjs` | Bounded Nano prompt and strict JSON edit-response contract |
| `canvas-runtime.mjs` | Versioned preview-toolbar and sandbox readiness contract |
| `project-store.js` | IndexedDB projects, active-project metadata, and file handles |
| `sidepanel.html` / `sidepanel.js` | Import, visual inspector, advanced source tabs, projects, and save workflow |
| `liveweave.html` / `liveweave.js` | Sandboxed responsive preview, selection bridge, and single-file export |
| `offscreen.html` / `offscreen.js` | DOM selector targeting, safe model-patch application, and structural inspection |
| `mcp-client.js` | Streamable HTTP MCP client |
| `settings.js`, `options.html`, `options.js` | Pairing and connection settings |
| `tests/` | Pure source-model tests and controlled HTTP import fixture |
