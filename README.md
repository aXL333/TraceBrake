<p align="center">
  <img src="docs/assets/foreman-social-preview.png" alt="TraceBrake - safety oversight for AI coding agents">
</p>

<h1 align="center">TraceBrake</h1>

<p align="center">
  A Windows safety monitor for AI coding agents: watch risky commands, stuck runs, MCP changes, and use one AI to audit another.
</p>

<p align="center">
  <strong>Built to keep agent work visible, accountable, and reviewable before it burns tokens, CPU, and power.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: GPL-3.0-or-later" src="https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg"></a>
  <a href="https://github.com/aXL333/Foreman/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/aXL333/Foreman/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Windows 10/11" src="https://img.shields.io/badge/Windows-10%2F11-4A90D9">
  <img alt="Status: alpha" src="https://img.shields.io/badge/status-alpha-E8B23C">
</p>

> **Status:** alpha. TraceBrake targets the stable .NET 10 SDK and runs on Windows 10/11 x64. Treat it as safety visibility tooling, not a sandbox or policy enforcement boundary.

> **OpenAI Build Week 2026:** TraceBrake was entered under its original name, **Foreman Agent Safety**, and predates the event. See
> [docs/openai-build-week-2026.md](docs/openai-build-week-2026.md) for the pre-event baseline,
> eligible extension, immutable submission snapshot, Codex collaboration record, and judge testing path.
> Post-deadline security and packaging maintenance is identified separately and is not claimed as
> submission-period work.

## Why TraceBrake Exists

AI coding agents can move quickly across shells, files, credentials, networked tools, and MCP servers. Most of that work is useful. Some of it is surprising, expensive, stuck, or unsafe.

TraceBrake sits in the tray and keeps that work visible. It raises explainable alerts, attributes child processes back to the harness that spawned them, and gives you two response paths:

- **Ask Harness:** ask the offending agent to justify or correct its own action.
- **Send for Audit:** route alarming behavior to a different agent or API for a second opinion, using MCP when a reviewer harness is connected.

That safety loop can also save money. Catching a runaway command or abandoned agent early means fewer wasted tokens, less CPU/GPU churn, and lower power use.

## What TraceBrake Does

- Watches agent process trees, spawned shells, hung children, and orphaned processes.
- Flags risky command patterns: destructive commands, credential access, privilege escalation, network-borne code execution, and Windows defense-evasion or persistence.
- Tracks per-agent behavior and escalates through **Watch -> Alert -> Alarm -> Emergency** as risk accumulates.
- Reads agent MCP configuration and alerts when a new or changed MCP server appears.
- Optionally scans HTTP/SSE MCP tool descriptions for prompt-injection or data-exfiltration wording. This opt-in scan is the only feature that connects to third-party MCP servers; stdio servers are never launched.
- Exposes a local MCP server so agents can check TraceBrake status, pre-flight commands, inspect recent events, and get integration instructions.
- Brokers audited browser and opt-in Android/ADB computer use through one shared, per-harness-authorised `cu_*` surface,
  with device enrolment, fingerprint-bound APK installs, operator holds, and a global panic stop.
- Keeps a searchable/exportable event log and a dashboard for live process, harness, and behavior state.
- Defines a shared-repo harness deconfliction model for leases, handoffs, and Git conflict evidence; see
  [docs/harness-deconfliction.md](docs/harness-deconfliction.md).
- Persists append-order and monotonic-clock metadata for event-log timing integrity; see
  [docs/temporal-truth.md](docs/temporal-truth.md).

## Screenshots

<p align="center">
  <img src="docs/assets/tab-overview.png" width="92%" alt="Overview command center">
</p>
<p align="center"><em>Overview command center — active alerts, agents running, MCP clients, and at-a-glance status lights.</em></p>

<p align="center">
  <img src="docs/assets/tab-processes.png" width="44%" alt="Color-coded process explorer">
  <img src="docs/assets/tab-harnesses.png" width="54%" alt="Per-agent harness monitoring">
</p>
<p align="center"><em>Color-coded process explorer (orphaned = red &middot; hanging = amber &middot; the agent itself = blue) &nbsp;·&nbsp; per-agent monitoring with trust levels and wake-lock status.</em></p>

<p align="center">
  <img src="docs/assets/tab-behavior.png" width="80%" alt="Per-agent behavior and escalation">
</p>
<p align="center"><em>Per-agent behavior &amp; escalation (Watch &rarr; Alert &rarr; Alarm &rarr; Emergency).</em></p>

## Agent Support

Tested on-machine so far:

| ID | Agent | Integration status |
| --- | --- | --- |
| `claude-code` | Claude Code | one-click MCP setup, process/profile detection |
| `codex` | Codex | one-click MCP setup (CLI + Desktop; `bearer_token_env_var`), process/profile detection, Codex TOML MCP inventory |
| `cursor` | Cursor | one-click MCP setup (~/.cursor/mcp.json), process detection confirmed |

Recognized/profiled, but needs broader field testing:

| ID | Agent | Notes |
| --- | --- | --- |
| `opencode` | OpenCode | one-click MCP setup (opencode.json), profile + default audit routing |
| `t3-code` | T3 Code | control-plane profile + default audit routing — see the note below |
| `gemini-cli` | Gemini CLI | one-click MCP setup (~/.gemini/settings.json — note `httpUrl` for streamable HTTP), process classification |
| `amazon-q` | Amazon Q Developer | process classification |
| `aider` | Aider | process classification |
| `github-copilot` | GitHub Copilot CLI | one-click MCP setup (~/.copilot/mcp-config.json), process classification |
| `lm-studio` | LM Studio | one-click MCP setup (~/.lmstudio/mcp.json) via a local `mcp-remote` stdio bridge that forwards the bearer token (works around LM Studio dropping the `Authorization` header on remote MCP servers, [bug #1892](https://github.com/lmstudio-ai/lmstudio-bug-tracker/issues/1892)); needs `npx`/Node |
| `cline` | Cline / Continue / Roo | process classification |

> **T3 Code is a control plane — there's no "T3 auth" to configure.** T3 Code runs an *underlying* agent
> (Claude Code, Codex, OpenCode, …); that underlying agent is what holds the MCP connection and bearer token.
> So connect the underlying agent to TraceBrake (its own card in Connect Agent), not T3 Code directly. TraceBrake
> still monitors T3 Code itself as the control plane. T3 Code's "Connect automatically" just copies the config
> for you to drop into whichever agent it drives.

Anything else can be added in Settings as a custom harness executable name.

## Quick Start

### Install

Download the newest maintained alpha installer and its SHA-256 checksum from
[GitHub Releases](https://github.com/aXL333/Foreman/releases). Releases are self-contained, so users do not need
to rebuild TraceBrake or install the .NET SDK. New installations place program files under
`%LOCALAPPDATA%\Programs\TraceBrake`; mutable settings, vault data, and logs live under
`%LOCALAPPDATA%\TraceBrake`. Existing Foreman installs upgrade under the same stable installer identity, retain
their selected program directory, and atomically migrate their complete data lineage on first TraceBrake launch.

The immutable OpenAI Build Week submission snapshot is
[`v0.1.0-alpha3`](https://github.com/aXL333/Foreman/releases/tag/v0.1.0-alpha3) at commit `c5fd504`.
It remains available as deadline evidence. Later releases are clearly labelled post-submission
maintenance/development builds; use the newest maintained release for hands-on testing and the snapshot when
reviewing what existed at the deadline.

Both unpacked MV3 browser extensions are included with maintained installers:

- TraceBrake safety/browser-use extension: `%LOCALAPPDATA%\Programs\TraceBrake\extensions\foreman`
- LiveWeave page builder: `%LOCALAPPDATA%\Programs\TraceBrake\extensions\liveweave`

In Chrome, open `chrome://extensions`, enable **Developer mode**, select **Load unpacked**, and choose the
relevant folder. An upgraded alpha installation may instead keep these folders under its older install
directory; right-click the TraceBrake shortcut and choose **Open file location** if needed.

The repository can be newer than the most recent installer. To test an unreleased commit or work from source:

```powershell
dotnet build .\Foreman.slnx -c Release
dotnet test .\Foreman.slnx -c Release
dotnet run --project .\src\Foreman.App\Foreman.App.csproj
```

Installer prerequisite:

- Windows 10/11 x64

Building from source additionally requires the stable .NET 10 SDK.

To produce the same self-contained installer payload used by the release workflow:

```powershell
$version = '0.1.0'
dotnet publish .\src\Foreman.App\Foreman.App.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:Version=$version `
  -o publish
# Every helper process is published separately: a self-contained single-file app cannot share its runtime.
dotnet publish .\src\Foreman.EtwSidecar\Foreman.EtwSidecar.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:Version=$version `
  -o publish\sidecar
dotnet publish .\src\Foreman.Guardian\Foreman.Guardian.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:Version=$version `
  -o publish\guardian
dotnet publish .\src\Foreman.CuSidecar\Foreman.CuSidecar.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:Version=$version `
  -o publish\cu-sidecar
dotnet publish .\src\Foreman.CuPilot\Foreman.CuPilot.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:Version=$version `
  -o publish\cu-pilot
Remove-Item publish\Foreman.EtwSidecar.*,publish\Foreman.Guardian.*,publish\Foreman.CuSidecar.*,publish\Foreman.CuPilot.* `
  -ErrorAction SilentlyContinue
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\Copy-ReleaseExtensions.ps1 `
  -PayloadPath publish
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\Test-ReleasePayload.ps1 `
  -PayloadPath publish -ExpectedVersion $version
```

### Start With Windows

Optional: in **Settings → General**, tick **Start TraceBrake when you sign in to Windows**. This adds a per-user `HKCU` Run entry (no admin rights) so the tray app, monitoring, and the MCP server are up before your first agent session. TraceBrake self-heals the entry if you later move the install.

### Connect An Agent

TraceBrake's MCP server listens on `http://localhost:54321/mcp` while the tray app is running. `/mcp` requires a per-install bearer token. `/health` is open for liveness checks.

The easiest path is in the app:

1. Open TraceBrake from the tray or dashboard.
2. Choose **Connect agent**.
3. Use **Connect automatically** for Claude Code or Codex.
4. Restart the agent.

TraceBrake writes only its own user-scope `foreman` MCP entry and saves a backup of the original config first. For Codex, it also adds/updates a marked TraceBrake section in `~/.codex/AGENTS.md` so Codex knows how to receive and answer Ask Harness and audit prompts.

Manual Claude Code setup:

```bash
claude mcp add --transport http foreman http://localhost:54321/mcp \
  --header "Authorization: Bearer <paste-token-from-mcp.token>" \
  --scope user
```

Manual Codex setup in `~/.codex/config.toml`:

```toml
[mcp_servers.foreman]
url = "http://localhost:54321/mcp"
bearer_token_env_var = "FOREMAN_MCP_TOKEN_CODEX"
enabled = true
```

Codex reads the bearer token from that environment variable; its inline `http_headers` Authorization is **ignored** (Codex lists such a server as "Auth: Unsupported"). Set the variable to the token from `mcp.token`, then start Codex in a **new** terminal so it inherits the value:

```bash
setx FOREMAN_MCP_TOKEN_CODEX "<paste-token-from-mcp.token>"
```

Add this marked section to `~/.codex/AGENTS.md` as well, then restart Codex:

```markdown
<!-- foreman-mcp:begin -->
## TraceBrake MCP Monitor

When the `foreman` MCP server is available:

- Identify this agent as `harnessId: "codex"` when TraceBrake tools accept a harness id.
- At the start of a new task, call `report_task_start(taskDescription, harnessId: "codex")`.
- If `foreman_status` or `report_task_start` reports `pendingAskHarnessRequests`, call `list_ask_harness_requests(harnessId: "codex")`.
- For each pending request addressed to Codex (Ask Harness or queued audit prompt), answer with `reply_to_ask_harness_request(requestId, response, actionTaken, harnessId: "codex")`.
- Treat each request as a safety prompt: explain what happened, whether it was expected, and any corrective action you took or recommend.

<!-- foreman-mcp:end -->
```

The token is generated on first run and stored at `%LocalAppData%\TraceBrake\mcp.token` with current-user-only ACLs where Windows allows it. Existing `foreman` MCP server entries and `FOREMAN_MCP_*` token environment variables remain supported compatibility aliases, so connected harnesses do not break during the rename.

### Test The MCP Loop (No Agent Needed)

`Foreman.TestHarness` is a small console client that impersonates a harness and drives the Ask Harness
round-trip end to end, so you can exercise the loop without attaching a real agent. Each tick it prints a
**SITREP** (`foreman_status` + this harness's behaviour metrics) and **ACKs** every pending Ask Harness /
audit request addressed to it. It connects with a real per-harness scoped token minted the same way the app
mints them, so it tests the per-harness identity + caller-scoping path, not just the operator token.

```powershell
dotnet run --project .\src\Foreman.TestHarness\Foreman.TestHarness.csproj -- --harness claude-code
```

Then trigger an alert and click **Ask Harness** (or let an auto-response fire) in the tray, and watch the
harness answer it. Useful flags: `--harness <id>` (codex, cursor, opencode, …), `--once` (single pass),
`--no-ack` (observe only), `--interval <secs>`, `--token <tok>` (use a specific token). `--help` lists them all.

## Privacy And Trust Boundaries

- TraceBrake is local-only. There is no hosted service, account system, or telemetry.
- Process command lines can contain secrets. TraceBrake displays and logs command lines locally, and masks obvious secrets before putting alert prompts on the clipboard.
- TraceBrake is not a sandbox. A same-user local process can still do anything your user account can do.
- The optional ETW network sidecar runs elevated only if you enable **Run elevated for per-process Network**.
- The optional **Hardened Guardian** is the only other component that can run elevated (a LocalSystem service). It is opt-in, off by default, and only signs TraceBrake's own integrity seal — it does not sandbox or enforce policy on agents. Signed builds authenticate callers by verified publisher. Until commercial signing is available, unsigned development builds use an exact TraceBrake.exe path + SHA-256 pin and are labelled development protection rather than a publisher-authenticated boundary.
- The optional MCP tool-description scan can make outbound HTTP/SSE connections to configured third-party MCP servers. It is off by default.

## How It Works

The TraceBrake codebase is split into these main pieces:

- **Foreman.App:** WPF tray app, dashboard, settings, alert detail, and connection UI.
- **Foreman.Monitor:** WMI process create/terminate watcher, process tree tracker, I/O polling, hang/orphan detection, MCP inventory monitor.
- **Foreman.Core:** platform-agnostic models, event bus, heuristic rules, settings, profiles, escalation logic.
- **Foreman.McpServer:** local MCP host, tool registry, bearer-token auth, connected-session tracking.
- **Foreman.Guardian (optional, off by default):** an internally legacy-named LocalSystem Windows service that holds a SYSTEM-scoped key to sign TraceBrake's own tamper-evident event-log/settings seal. Its pipe accepts only the client identity pinned during elevated installation: verified Authenticode publisher for signed builds, or exact path + SHA-256 for explicitly labelled unsigned development builds. Enable/disable from Settings → Hardened Guardian (one UAC prompt); uninstalling TraceBrake runs the administrator-owned copy from Program Files. Re-enabling after signing upgrades the policy to publisher trust, after which same-publisher updates work without re-pinning. This is self-protection for TraceBrake, not agent sandboxing.

The embedded MCP server exposes tools including:

Tools are registered in snake_case (the ModelContextProtocol SDK derives the tool name
from the C# method name), so call them exactly as shown:

| Tool | Purpose |
| --- | --- |
| `foreman_status` | Current health, active alerts, process count, uptime, version |
| `list_connected_mcp_clients` | Debug connected client identities and sampling support |
| `list_monitored_processes` | Agent and child processes TraceBrake is tracking |
| `query_process_detail` | Details for one PID |
| `report_suspicious_command` | Pre-flight a command line |
| `list_recent_events` | Recent event log entries |
| `list_ask_harness_requests` | Receive pending Ask Harness prompts, including queued audit prompts, for a harness |
| `reply_to_ask_harness_request` | Send TraceBrake a reply to a pending Ask Harness or queued audit prompt |
| `request_harness_review` | Send Foreman-mediated mail or a handoff packet to another harness; operator calls may set reviewer context, harness calls are wrapped as attributed untrusted mail |
| `acknowledge_alert` | Acknowledge low/medium alerts; high/critical require the UI |
| `get_behavior_metrics` | Per-harness escalation state |
| `reset_behavior_metrics` | Reset a harness's escalation metrics for a fresh task |
| `report_task_start` | Announce a task boundary |
| `get_my_permissions` | Resolved profile permissions for the calling harness |
| `get_my_instructions` | Self-service house-rules (modalities) for the calling harness |
| `get_integration_instructions` | Harness-specific MCP setup instructions |
| `validate_harness_integration` | Check profile/process/MCP visibility |
| `list_audit_preferences` / `get_audit_route` | Cross-agent audit routing |
| `list_mcp_servers` | Discovered MCP servers across harness configs |
| `list_mcp_tool_findings` | Cached opt-in MCP tool-description findings |
| `scan_repo_for_agent_config` | Vet a repo's agent-config supply chain (`.claude`/`.gemini` hooks, `.cursor` rules, `.vscode` `folderOpen` tasks, `.github/setup.js`, `CLAUDE.md`/`AGENTS.md`) for the "rules file backdoor" planted-trigger class — *before* opening it in an agent |
| `cu_status` | Mediated browser/Android/desktop broker state, panic state, ADB readiness, and held actions |
| `cu_submit` / `cu_action_status` | Submit an audited browser or bounded Android action—including APK install—and retrieve its result |
| `cu_approve` / `cu_reject` | Operator-only decision for actions held by the broker |
| `cu_set_driver` | Operator-only shared harness allow-list for browser and Android computer use |

See [docs/oversight-model.md](docs/oversight-model.md) for the Ask Harness vs Send for Audit model and the MCP supply-chain tiers.

### Android / ADB bridge

TraceBrake includes an opt-in Android Debug Bridge modality inside the same audited `cu_*` broker used for browser
computer use. It is a bounded bridge, not an `adb shell` convenience tool:

- observe-only `devices`, `screenshot`, `ui_dump`, and capped `logcat` actions;
- local `.apk` installation plus `tap`, `type`, `swipe`, and constrained `key` actions that are always held for
  fresh operator approval;
- APK requests are bound to a canonical local path, byte count, and SHA-256 before approval, then the file is pinned
  and verified again immediately before `adb install`; same-path package swaps fail closed;
- an absolute, operator-selected `adb.exe` path — TraceBrake never searches `PATH`; its SHA-256 is sealed at enrolment
  and the binary is write/delete-pinned while TraceBrake is running;
- explicit device-serial enrolment, a fresh device-authorisation check before every scoped action, bounded output and
  command timeouts;
- the existing global panic stop, which rejects queued/in-flight Android work and kills the active adb client;
- the shared driver set plus each harness's **Computer use policy**, so every selected harness can use the unified
  TraceBrake MCP plugin without receiving executor or raw-shell authority.

To arm it, first enable TraceBrake's presence lock, then open **Settings → Computer use**. Select the Android SDK
`platform-tools\adb.exe`, use **Test and list devices**, enter the serials you want to enrol, enable the bridge, and
save. The live broker is revoked and re-armed immediately. Select allowed harnesses under **Connect agent →
Computer-use driver(s)** or the individual harness settings.

Example calls:

```text
cu_submit(modality="android", verb="devices", argsJson="{}")
cu_submit(modality="android", verb="ui_dump", argsJson="{\"serial\":\"emulator-5554\"}")
cu_submit(modality="android", verb="install", argsJson="{\"serial\":\"emulator-5554\",\"apkPath\":\"C:\\builds\\app-debug.apk\",\"replace\":true}")
cu_submit(modality="android", verb="tap", argsJson="{\"serial\":\"emulator-5554\",\"x\":120,\"y\":340}")
```

If exactly one device is enrolled, `serial` may be omitted; TraceBrake stamps that serial into the action before it is
audited. Results are retrieved with `cu_action_status(actionId)`. Screenshots return PNG metadata plus base64 image
data; output and execution time are capped.

## Configuration

Settings live at `%LocalAppData%\TraceBrake\settings.json` and are editable from the Settings window.

| Setting | Default | Purpose |
| --- | --- | --- |
| `McpPort` | `54321` | MCP and health server port |
| `HangThresholdMinutes` | `30` | No-I/O duration before a child is treated as hung |
| `HookJamThresholdMinutes` | `5` | No-I/O duration before a hook is treated as jammed |
| `IoPollerIntervalSeconds` | `30` | I/O sampling interval |
| `MonitorAllProcesses` | `false` | `false` means harness children only |
| `CustomHarnessExes` | `[]` | Extra executable names to treat as agents |
| `DisabledHarnesses` | `[]` | Agents to detect but not alert on |
| `RunElevated` | `false` | Opt-in elevated ETW sidecar for the Network column |
| `ScanMcpTools` | `false` | Opt-in MCP tool-description injection scan |
| `LlmTriage` | enabled | Cross-agent auditor preference routing |
| `ScheduledAudit` | disabled | Optional count/time-based independent cross-harness review with per-harness cooldown |
| `AdbBridge` | disabled | Bounded, presence-enrolled Android/ADB computer-use executor |

## Release Trust

The installer is per-user and requires no admin prompt. `TraceBrake.exe`, its four legacy-compatible helper executables, and the installer are Authenticode-signed via **SignPath Foundation** (free OV signing for open source) when the release workflow is configured for it; signing is opt-in and gated on a repo variable, so until it is wired up, alpha installers ship **unsigned** and the release notes say so automatically. The optional LocalSystem Guardian fails closed in an unsigned Release build; only an explicitly opted-in Debug development build can use the path-and-hash development mode. Either way the release attaches **SHA-256 checksums** and GitHub build-provenance attestations. Note that even when signed, a freshly-published build can still show a SmartScreen "unrecognized app" prompt until Microsoft's reputation system catches up — this is expected for a low-volume tool, which is why the checksums matter. See [CODE_SIGNING.md](CODE_SIGNING.md) for how signing works and how to verify a download, and [docs/release-checklist.md](docs/release-checklist.md) for the maintainer signing setup.

## Roadmap

- Add a full settings UI for LLM triage preferences.
- Add first-class OpenCode/T3 MCP config adapters after more field testing.
- Add native Windows toast notifications in place of tray balloons.
- Continue tuning false positives from real agent workflows.
- Browser extension (alpha): pairs to this machine over loopback for at-a-glance TraceBrake status — connect via **Connect Agent → Pair browser extension**. See [extension/README.md](extension/README.md) and [docs/closed-loop-spec.md](docs/closed-loop-spec.md).

## Contributing

Contributions are welcome under the project's license. See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports go through [SECURITY.md](SECURITY.md), not public issues.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE). Contributions are accepted under the same license.

## Support

TraceBrake is free and GPL. If it helped you keep agent work safer, saved tokens, or trimmed a power bill and you want to chip in, there is a Ko-fi: <https://ko-fi.com/aXL333>.
