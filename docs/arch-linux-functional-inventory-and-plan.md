# Arch Linux functional inventory and integration plan

Status: planning artifact.

Scope: make TraceBrake viable on Arch Linux as a first-class local agent, while preserving the existing Windows tray app and Windows-specific security backend. This is not a promise that Linux can reproduce every Windows signal. It is an inventory of what exists, what is portable, what must be replaced, and the order of work that keeps the port honest.

## Executive view

The right product shape is not "the Windows app runs on Arch." It is "Foreman has a Linux-native agent that shares the same safety model, MCP surface, profiles, event log, and heuristic engine."

The current codebase already has a useful split:

- `Foreman.Core` is `net10.0` and mostly portable.
- `Foreman.McpServer` is mostly portable in concept, but its peer-process binding and token-file protection need Linux implementations.
- `Foreman.Monitor` is Windows-bound because process creation comes from WMI and I/O quietness comes from `kernel32.dll`.
- `Foreman.App` is Windows/WPF-bound and should not be the first Linux target.
- `Foreman.EtwSidecar` is Windows-only by design. Linux needs a separate privileged helper or backend.

The first Arch target should be a headless per-user service:

- binary: `foreman-agent`
- service: `systemd --user` unit
- local endpoint: same loopback `/health` and `/mcp` contract
- data root: XDG-aware, defaulting to `$XDG_STATE_HOME/foreman`, `$XDG_CONFIG_HOME/foreman`, and `$XDG_DATA_HOME/foreman`
- optional privileged observations: separate helper mediated by `polkit`, not always-root main process

## Functional inventory

### Product and UX surface

| Capability | Current implementation | Linux/Arch disposition | Notes |
| --- | --- | --- | --- |
| Tray app, dashboard, settings, alert details | `Foreman.App` WPF, `net10.0-windows10.0.19041.0` | Do not port first | WPF is the wrong first dependency for Arch. Build headless agent and CLI first. |
| Local safety monitor identity | Product metadata, README, MCP key `foreman` | Reuse | Keep MCP server key and command names stable. |
| Browser extension pairing | `extension/`, `/pair/challenge`, `/pair/complete` in MCP host | Mostly reusable | Extension already speaks loopback HTTP. Needs Linux install docs and token-path handling. |
| Connect Agent UI | `ConnectAgentWindow`, registry of harness snippets | Replace with CLI first | Provide `foreman-agent connect codex`, `connect claude-code`, etc. UI can come later. |
| Notifications | Windows toast/tray | Replace | Use CLI status first, then optional desktop notifications through `org.freedesktop.Notifications`. |
| Operator acknowledgement | WPF alert detail plus MCP `AcknowledgeAlert` limits | Keep policy, change UI | High/Critical still require local operator path. On Linux that can be CLI or future UI. |

### MCP and agent contract

| Capability | Current implementation | Linux/Arch disposition | Notes |
| --- | --- | --- | --- |
| `/mcp` over loopback HTTP/SSE | `Foreman.McpServer.McpServerHost` with Kestrel | Reuse with adaptation | Kestrel is portable. Host/origin/token checks are portable. |
| `/health` | unauthenticated liveness endpoint | Reuse | Keep response low-information. |
| Per-install token | `McpAuthToken` writes setup file | Reuse with path/permission changes | Linux should create token files with `0600` and directory `0700`. |
| Per-harness scoped tokens | `MintHarnessToken`, `CallerScope` | Reuse | This is central to Linux too. |
| Peer process binding | `LoopbackPeer.FindOwningPid` plus harness ancestor lookup | Replace backend | Linux can map sockets through `/proc/net/tcp*` and inode ownership, or use `ss`/netlink. Must be tested before enforcement. |
| Ask Harness durable queue | `ForemanState` and MCP tools | Reuse | No platform dependency. |
| Audit routing | `GetAuditRoute`, auditor preferences | Reuse | Mostly Core/MCP logic. |
| MCP inventory | `McpInventoryScanner`, `McpInventoryMonitor` | Extend | Scanner already uses `~/.claude.json` and `~/.codex/config.toml`. Add Gemini, Copilot, OpenCode, LM Studio paths as needed. |
| MCP tool-description scan | `McpToolScanMonitor` | Likely reusable | Network safety controls must be rechecked. It should keep stdio servers non-launched. |

### Detection and policy engine

| Capability | Current implementation | Linux/Arch disposition | Notes |
| --- | --- | --- | --- |
| Pattern library and command analyzer | `Foreman.Core.Heuristics` with embedded JSON rules | Reuse | Already contains `bash`, `sh`, and `wsl` platform labels. Need Linux-specific tuning and tests. |
| Severity and event model | `Foreman.Core.Models`, `Foreman.Core.Events` | Reuse | Event types are platform-neutral enough. |
| Behavior escalation | `BehaviorTracker`, `EscalationThresholds`, trust presets | Reuse | Works if process attribution works. |
| Profile matching and permission violations | `ProfileStore`, `ProfileMatcher`, `ViolationDetector` | Reuse with path updates | Built-in profiles contain Windows paths. Need Linux path conventions and package-manager rules. |
| Emergency rule IDs | `ForemanSettings.EmergencyRuleIds` | Split by platform | Some IDs are Windows-only. Linux needs its own high-confidence emergency set. |
| Secret redaction | `SecretRedactor` | Reuse | Confirm coverage for common Linux env formats and shell history shapes. |
| Agent config scanner | `AgentConfigScanner` | Reuse and expand | Linux repo poisoning is a primary use case. Keep this strong. |

### Process observation

| Capability | Current implementation | Linux/Arch disposition | Notes |
| --- | --- | --- | --- |
| Initial process snapshot | WMI `Win32_Process` query | Replace | Read `/proc/[pid]/stat`, `/proc/[pid]/cmdline`, `/proc/[pid]/exe`, `/proc/[pid]/status`. |
| Process create/exit stream | WMI event watchers | Replace | Start with polling `/proc` every 1-2 seconds. Add netlink connector/eBPF later only if needed. |
| Process tree tracking | `ProcessTreeTracker` | Reuse with cleanup | Core logic is reusable, but Windows system-host stoplist needs Linux equivalent. |
| Harness classification | exe names plus Node/Python markers | Reuse with normalization | Current rules already include non-`.exe` variants for some agents. Expand for Linux launchers and AppImage/electron wrappers. |
| Child command analysis | WMI command line on process creation | Replace source only | Same analyzer once Linux process records exist. |
| PID reuse defense | pid plus start time key | Reuse | Linux can use `/proc/[pid]/stat` starttime ticks converted to a stable key. |
| Kill process/tree | `Process.Kill(entireProcessTree)` with start-time pin | Replace or wrap | Linux needs process group/session-aware termination and start-time verification before kill. |
| Hang/idle detection | I/O counters via `GetProcessIoCounters` | Replace | Linux can read `/proc/[pid]/io` when allowed. Some kernels restrict visibility; degrade explicitly. |
| Orphan detection | process tree tracker on exit | Reuse if exit detection exists | Polling can detect disappeared parents and live children. |

### File, credential, and audit tripwires

| Capability | Current implementation | Linux/Arch disposition | Notes |
| --- | --- | --- | --- |
| Decoy credential placement | `DecoyCredentialPolicy`, gaps-only under home | Reuse with path review | Candidate paths are mostly Linux-native already. |
| Sentinel-in-command detection | `cred-040` style pattern layer | Reuse | This remains the safest first Linux decoy signal. |
| Windows SACL read auditing | elevated ETW sidecar + Security Event 4663 | Cannot port | Linux has no SACL equivalent. Do not claim parity. |
| Linux read auditing | none today | New backend | Options: `auditd`, fanotify, or eBPF. Start optional and explicit. |
| Decoy cleanup safety | sentinel-gated delete | Reuse | Keep gaps-only and sentinel-gated removal. |
| Content-index exclusion | Windows `NotContentIndexed` attribute | Replace or drop | Linux indexers vary. Prefer bait-path selection and allowlists. |

### Network, power, and privileged signals

| Capability | Current implementation | Linux/Arch disposition | Notes |
| --- | --- | --- | --- |
| Per-PID network rates | elevated ETW sidecar | Replace | Linux options: `/proc/[pid]/net`, cgroup accounting, eBPF, or netlink. Per-process accuracy is non-trivial. |
| Wake requests | Windows power probe in sidecar | Drop for MVP | Linux power blockers are not core to agent safety. Revisit later through systemd inhibitor state if valuable. |
| Privileged helper lifecycle | `ElevatedSidecarController`, UAC, named pipe, nonce | Replace | Linux should use `polkit` and a narrow helper protocol. Main agent remains user-level. |
| Privileged helper cleanup | sidecar reverts SACL/auditpol | Required for Linux helper too | Helper must clean audit rules/watches on exit and package removal. |

### Persistence, settings, and logs

| Capability | Current implementation | Linux/Arch disposition | Notes |
| --- | --- | --- | --- |
| Settings file | `%LocalAppData%/Foreman/settings.json` | Adapt | Use XDG config path. Support migration only if running under WSL is later supported. |
| Profiles directory | `%LocalAppData%/Foreman/profiles` | Adapt | Use XDG config/data path. |
| MCP seen-set | `%LocalAppData%/Foreman/mcp-seen*.json` | Adapt | Use XDG state path. |
| Event log persistence | JSONL with tamper-evident chain | Reuse | Linux path and file permissions need work. |
| TPM-sealed log head plan | Windows-oriented future work | New backend | Linux TPM2 can be supported later with `tpm2-tss`; not MVP. |
| Startup registration | HKCU Run | Replace | `systemd --user enable --now foreman-agent.service`. |

### Packaging and distribution

| Capability | Current implementation | Linux/Arch disposition | Notes |
| --- | --- | --- | --- |
| Windows installer | Inno Setup | Separate | Keep Windows installer untouched. |
| Arch install | none | New | Start with `PKGBUILD` and optional AUR-compatible packaging. |
| Runtime dependency | Stable .NET 10 SDK/runtime | Low | A self-contained `linux-x64` publish still avoids relying on distro runtime packaging. |
| Service unit | none | New | User service for normal monitoring. Optional system service/helper only for privileged audit modes. |
| Uninstall hygiene | Windows installer scripts | New | Must remove services, helper policy, state only on explicit purge. |

## Gaps and uncomfortable truths

1. Linux cannot honestly reuse the current Windows monitoring project. `Foreman.Monitor` is not just lightly Windows-tinted; WMI and `kernel32.dll` are central.

2. The WPF app should not drive the port. A Linux GUI first would burn time before the core monitoring story is real.

3. Decoy read auditing is the biggest semantic gap. Sentinel-in-command is portable. Direct read detection needs a Linux-specific backend and will have different false-positive and privilege behavior.

4. Process attribution on Linux is doable, but not free. `/proc` polling is the correct first version because it is simple and debuggable. Stronger event streams can come after the safety model is proven.

5. Peer PID binding is security-sensitive. Implement it in alert-only mode first, like the current Windows setting, until real connector behavior is observed.

6. The current pattern library already includes shell/Linux rules, but the product docs still describe Foreman as Windows-only. That is fine today; the Linux branch should not update public positioning until the agent can pass an end-to-end demo.

7. Arch runtime packaging can lag the current .NET feature band. A self-contained binary remains the pragmatic first package artifact.

## Proposed architecture

### New projects

| Project | Target | Responsibility |
| --- | --- | --- |
| `Foreman.Agent` | `net10.0` | Headless composition root for Linux and future non-Windows agents. Starts monitor, MCP host, logs, and CLI-facing control surface. |
| `Foreman.Platform` | `net10.0` | Small interfaces for process watching, process querying, file permissions, token-file protection, startup registration, notification sink, and optional privileged helpers. |
| `Foreman.Platform.Linux` | `net10.0` | `/proc` process source, XDG paths, Unix permissions, systemd user service support, Linux peer socket lookup. |
| `Foreman.Monitor.Windows` | `net10.0-windows10.0.19041.0` | Home for current WMI/IO polling pieces if `Foreman.Monitor` is split. |
| `Foreman.LinuxHelper` | `net10.0` | Optional privileged helper for auditd/fanotify/eBPF-backed signals. Not in MVP unless required. |
| `Foreman.Cli` | `net10.0` | `status`, `connect`, `doctor`, `service install`, `service remove`, `decoys plant/remove`, `logs tail`. May be merged into `Foreman.Agent` initially. |

### Interfaces to extract first

Keep interfaces boring and close to current behavior:

```csharp
public interface IProcessSnapshotProvider
{
    IReadOnlyList<ProcessRecord> Snapshot();
}

public interface IProcessEventSource : IDisposable
{
    event Action<ProcessRecord> ProcessStarted;
    event Action<int, DateTimeOffset?> ProcessExited;
    void Start();
}

public interface IProcessIoReader
{
    bool TryReadIo(int pid, out ulong readOps, out ulong writeOps, out string? unavailableReason);
}

public interface ILocalPeerResolver
{
    PeerBindingVerdict TryResolve(int remotePort, int localPort, string claimedHarness, out int? pid, out string? harnessId);
}

public interface IForemanPaths
{
    string ConfigDir { get; }
    string StateDir { get; }
    string DataDir { get; }
    string RuntimeDir { get; }
}
```

The goal is not an abstraction framework. The goal is to stop platform facts from leaking into safety policy.

## Detailed plan

### Phase 0 - inventory hardening and baseline checks

Objective: freeze what exists before changing structure.

Tasks:

- Add this document and keep it updated as the Linux work lands.
- Run and record the current Windows baseline before architectural edits:
  - `dotnet restore .\Foreman.slnx`
  - `dotnet test .\Foreman.slnx -c Release --verbosity minimal`
  - `dotnet build .\Foreman.slnx -c Release --verbosity minimal`
- Record current MCP tool list and expected `/health` shape.
- Identify all Windows-only compile references:
  - `System.Management`
  - `kernel32.dll`
  - WPF/WinExe
  - Windows toast package
  - EventLog/ETW/TraceEvent sidecar
  - WebAuthn Windows interop
  - HKCU startup registration

Exit criteria:

- Existing Windows tests still pass.
- This inventory is committed before code movement.
- No Linux promise has been added to README or releases.

### Phase 1 - separate platform seams without changing behavior

Objective: make Windows behavior depend on interfaces while preserving current output.

Tasks:

- Introduce a minimal platform abstraction project.
- Wrap current WMI process watcher behind `IProcessEventSource`.
- Wrap current initial WMI snapshot behind `IProcessSnapshotProvider`.
- Wrap current `GetProcessIoCounters` path behind `IProcessIoReader`.
- Wrap token-file ACL protection behind an `ITokenFileProtector`.
- Wrap startup registration behind an `IStartupRegistration`.
- Keep `Foreman.App` composing the Windows implementations.
- Add tests at the interface boundary using fake providers.

Exit criteria:

- No user-visible Windows behavior changes.
- Existing monitor tests pass.
- New abstractions have tests that prove the monitor can run from fake process events.

### Phase 2 - build headless agent composition

Objective: run Foreman's core safety loop without WPF.

Tasks:

- Add `Foreman.Agent` as a console/headless host.
- Compose:
  - settings load/save
  - pattern library initialization
  - event log persistence
  - monitor service
  - MCP server host
  - MCP inventory monitor
- Provide CLI flags:
  - `--foreground`
  - `--config-dir`
  - `--state-dir`
  - `--mcp-port`
  - `--no-mcp`
- Make `/health` and `ForemanStatus` work without tray dependencies.
- Ensure High/Critical ack remains operator-only. Initially, operator path is CLI only.

Exit criteria:

- `foreman-agent --foreground` runs on Windows using Windows providers.
- MCP tools work without `Foreman.App`.
- No WPF assembly is loaded by the headless agent.

### Phase 3 - Linux `/proc` backend MVP

Objective: observe harness process trees on Arch without privileged dependencies.

Tasks:

- Implement XDG path provider:
  - config: `$XDG_CONFIG_HOME/foreman` or `~/.config/foreman`
  - state: `$XDG_STATE_HOME/foreman` or `~/.local/state/foreman`
  - data: `$XDG_DATA_HOME/foreman` or `~/.local/share/foreman`
  - runtime: `$XDG_RUNTIME_DIR/foreman` if available
- Implement `/proc` scanner:
  - parse `/proc/[pid]/stat` for pid, ppid, start time
  - parse `/proc/[pid]/comm` or `/proc/[pid]/exe` for process name
  - parse `/proc/[pid]/cmdline` for command line
  - handle permission errors as degraded process fields, not crashes
- Implement polling event source:
  - first scan baselines current processes
  - later scans diff pid/starttime keys
  - creates start/exit events
- Implement `/proc/[pid]/io` reader:
  - read `syscr` and `syscw` or equivalent counters
  - mark unavailable when denied by kernel settings
- Add Linux system-host stoplist:
  - `systemd`
  - `systemd --user`
  - `dbus-daemon`
  - `gnome-shell`, `kwin`, `plasmashell`
  - terminal emulators only if proven to cause false ancestry
- Expand harness classifier for Linux command shapes:
  - Node package managers
  - globally installed CLIs
  - AppImage/electron launchers
  - Python virtualenv wrappers
- Add tests using captured `/proc` fixture text.

Exit criteria:

- On Arch, `foreman-agent --foreground` sees Codex/Claude/Gemini processes and children.
- Command-line pattern alerts fire for a child shell command.
- Hang/idle detection degrades clearly if `/proc/[pid]/io` is blocked.
- Existing Windows tests still pass.

### Phase 4 - Linux MCP identity and token hardening

Objective: make the MCP security model credible on Linux.

Tasks:

- Token file permissions:
  - create directories `0700`
  - create token/setup files `0600`
  - refuse to use token files that are group/world readable unless explicitly repaired
- Linux peer PID lookup:
  - map loopback socket ports to socket inode through `/proc/net/tcp` and `/proc/net/tcp6`
  - find owning process by scanning `/proc/[pid]/fd` symlinks for that socket inode
  - bind to harness ancestor through current process tree
- Keep `McpPeerBindingEnforce` default false.
- Publish Critical notice on token/harness mismatch.
- Add `foreman-agent doctor mcp` to show token permissions, port binding, and peer binding support.

Exit criteria:

- Per-harness token scoping works on Linux.
- Peer mismatch produces a clear alert in alert-only mode.
- No connected harness can list sibling processes or sibling events.

### Phase 5 - Arch packaging and service lifecycle

Objective: install, start, stop, upgrade, and remove the agent cleanly.

Tasks:

- Add packaging directory:
  - `packaging/arch/PKGBUILD`
  - `packaging/arch/foreman-agent.service`
  - `packaging/arch/foreman-agent.install`
- Start with self-contained `linux-x64` publish.
- User service:
  - `systemctl --user enable --now foreman-agent.service`
  - environment respects XDG paths
  - logs to journald and Foreman JSONL
- Add CLI service commands:
  - `foreman-agent service install`
  - `foreman-agent service start`
  - `foreman-agent service status`
  - `foreman-agent service stop`
  - `foreman-agent service uninstall`
- Add uninstall behavior:
  - package removal stops service
  - state/config are left intact
  - explicit purge command removes Foreman-owned files only

Exit criteria:

- Fresh Arch VM install works from local package.
- Reinstall preserves token/config.
- Uninstall does not delete user evidence by default.

### Phase 6 - Decoy credentials on Linux

Objective: restore the portable decoy layer first, then add optional read auditing.

Tasks:

- Reuse gaps-only placement and sentinel content.
- Add Linux docs for what paths may be planted.
- Add CLI commands:
  - `foreman-agent decoys plan`
  - `foreman-agent decoys plant`
  - `foreman-agent decoys remove`
  - `foreman-agent decoys status`
- Keep sentinel-in-command alerting as MVP.
- Add explicit status for read-audit support:
  - `unsupported`
  - `available but disabled`
  - `enabled`
  - `degraded`
- Evaluate read-audit backends in order:
  - `auditd` watches for selected bait files
  - fanotify helper
  - eBPF helper
- Do not enable direct read auditing by default.

Exit criteria:

- Plant/remove is safe and sentinel-gated.
- A command that handles a sentinel token produces a Critical alert.
- Documentation says direct-read parity with Windows SACL is not claimed.

### Phase 7 - Optional privileged Linux helper

Objective: add stronger observations without making the main agent privileged.

Tasks:

- Define helper protocol:
  - nonce handshake
  - parent liveness
  - framed JSON messages
  - explicit capability flags
- Use `polkit` for elevation.
- Initial helper capabilities:
  - decoy file read events, if using audit/fanotify/eBPF
  - optional per-process network observations only if accurate enough
- Helper cleanup:
  - remove audit watches on exit
  - remove temporary files
  - report degraded cleanup if cleanup fails
- Add hard denial for helper actions outside Foreman-owned paths unless a policy file explicitly allows them.

Exit criteria:

- Helper can be disabled with no loss to core process/MCP monitoring.
- Helper leaves no audit watches behind after normal exit.
- Crash recovery either cleans stale watches or reports them.

### Phase 8 - Linux user experience

Objective: make the agent usable daily without requiring a GUI.

Tasks:

- CLI:
  - `status`
  - `events`
  - `alerts`
  - `ack`
  - `connect`
  - `profiles`
  - `doctor`
- Desktop notification adapter:
  - use `org.freedesktop.Notifications` if session bus exists
  - fall back to journald/event log only
- Optional TUI or web dashboard after core service is reliable.
- Update README only when:
  - Arch package installs
  - service starts
  - MCP loop works
  - at least one real harness is observed
  - test suite has Linux coverage in CI or documented local validation

Exit criteria:

- A user can install, connect Codex, run a task, see status, and inspect alerts from terminal.
- Desktop notifications are helpful but not required.

## Test strategy

### Unit tests

- `/proc` parser fixtures:
  - normal process
  - command line with null separators
  - process vanished mid-read
  - permission denied
  - reused PID with different start time
- Linux path provider:
  - XDG variables set
  - XDG variables missing
  - runtime dir missing
- token-file permissions:
  - new token file mode
  - world-readable token rejected or repaired
- peer socket resolver:
  - IPv4 loopback
  - IPv6 loopback
  - socket disappears mid-scan
- process tree attribution:
  - harness parent
  - shell child
  - package install subtree
  - stale parent PID

### Integration tests

- Run `foreman-agent --foreground` with fake process source.
- Start local MCP client using per-harness token.
- Verify scoped MCP tools cannot read sibling records.
- Verify Ask Harness queue and reply path.
- Verify event log writes under XDG state path.

### Manual Arch validation

- Fresh Arch VM.
- Install package.
- Start user service.
- Connect Codex.
- Run benign command.
- Run controlled suspicious command pattern.
- Confirm:
  - process tree appears
  - alert appears
  - `ForemanStatus` changes
  - `ListAskHarnessRequests` works
  - uninstall leaves config/state intact

## First implementation backlog

P0:

- Add `Foreman.Platform` with path, token permission, process source, and peer resolver interfaces. **Started:** `Foreman.Platform` now defines the first cross-platform seams.
- Move Windows token ACL protection behind the token permission interface.
- Add tests for platform-neutral monitor composition.

P1:

- Add `Foreman.Agent` headless host.
- Make MCP host and event log start without WPF.
- Add `status` and `doctor` CLI commands.

P2:

- Add `Foreman.Platform.Linux` `/proc` snapshot and polling event source.
- Add Linux harness classification tests.
- Add XDG settings/state paths.

P3:

- Add Arch packaging skeleton and user service.
- Validate install/start/stop on a VM.

P4:

- Add Linux decoy CLI and sentinel-only tripwire.
- Evaluate direct-read audit backend separately.

## Feature-parity tracker

This table should be updated whenever the Windows mainline gains a safety-relevant feature. Linux parity does not always mean identical implementation; it means the Linux agent has an honest equivalent or an explicit unsupported/degraded state.

| Feature | Windows source today | Linux status | Parity rule |
| --- | --- | --- | --- |
| Core command heuristics | `Foreman.Core.Heuristics` and embedded pattern JSON | Reuse | Same rules load on Linux, with platform labels respected and Linux-specific tests added. |
| Behavior escalation | `BehaviorTracker`, `EscalationThresholds` | Reuse | Same escalation math and trust presets. |
| MCP server and tools | `Foreman.McpServer` | Reuse with host adaptation | Tool names and caller scoping remain stable. |
| Per-harness tokens | `McpAuthToken`, `CallerScope` | Reuse with Unix file modes | Token files must be owner-only. |
| Peer PID binding | `LoopbackPeer` on Windows | Not started | Linux must support alert-only mismatch detection before enforcement. |
| Process create/exit | WMI watcher | Started | `/proc` polling is the first portable backend. |
| Initial process snapshot | WMI query | Started | `/proc` snapshot provider parses pid, ppid, command line, executable target, and start time. |
| I/O quietness | `GetProcessIoCounters` | Started | `/proc/[pid]/io` reader uses syscall counters and reports degraded state when unavailable. |
| Decoy placement | `DecoyCredentialPolicy` | Planned reuse | Same gaps-only, sentinel-gated behavior. |
| Direct decoy read audit | Windows SACL/Event 4663 sidecar | Unsupported until helper work | Linux must not claim Windows SACL parity. |
| Per-PID network rates | ETW sidecar | Not started | Optional helper only, and only if attribution is accurate enough. |
| Wake requests | Windows sidecar probe | Not planned for MVP | Explicitly out of Linux MVP unless a user-facing safety case emerges. |
| Tray/dashboard UI | WPF | Not planned for MVP | CLI/headless service first. |
| Startup registration | HKCU Run | Planned | `systemd --user` service. |
| Packaging | Inno Setup | Planned | Distro-portable tar/self-contained publish first, Arch package second. |

## Port progress log

- Added `Foreman.Platform` for portable path, token protection, process observation, and peer resolver contracts.
- Added `Foreman.Platform.Linux` with XDG path resolution, `/proc` stat/cmdline/io parsers, `/proc` snapshot provider, Linux token-file permission helper, and a polling process event source.
- Added `Foreman.Platform.Linux.Tests` with XDG, `/proc` parser, I/O parser, and polling-diff tests.

## Decision record

- Keep Windows app and installer intact while building Linux support.
- Do not claim sandboxing or Windows-equivalent audit semantics.
- Ship headless Arch agent before GUI.
- Use `/proc` polling first for process lifecycle because it is transparent and testable.
- Treat privileged Linux helper as optional and later.
- Keep `foreman` MCP key and tool names stable.
