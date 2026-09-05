> **Foreman Desktop Computer-Use Engine - security-vetted build spec.**
> Generated 2026-06-22 by an 8-agent design + adversarial-review workflow (4 component designers, 3 red-teamers, 1 synthesizer); **26 red-team attacks** folded in as concrete mitigations. Standalone blueprint - another agent can execute it cold.
>
> Components designed:
>  - Desktop Input + Capture Sidecar (mediated-CU Phase 3) - Foreman.CuSidecar (medium-IL process) + CuSidecarController (App) + ICuExecutor desktop impl + DesktopCu IPC contract (Foreman.Core)
>  - One-Window-at-a-Time enforcement for Foreman desktop CU: an HWND-scoped active-CU-window lock mirroring the browser pinned-focus excursion gate, holding off-window state changes, re-gated at delivery, with switches made explicit, audited and HUD-announced.
>  - Shared-Monopilot cursor: re-skin the REAL OS cursor while the AI drives (honest position, not a synthetic sprite), with guaranteed revert even on crash, user<->AI handoff arbitration, and always-obvious ownership. Targets .NET 10 / WPF on Windows 11, plugging into the existing CuBroker / CuPanicState / CuOverlayWindow seams.
>  - Foreman desktop computer-use: ISOLATED-SESSION 2-cursor mode. The AI gets its own Win32 desktop OBJECT (CreateDesktop on Winsta0) with its own cursor and input, driven by SendInput from a desktop-bound executor thread and captured live for the operator via PrintWindow, while the operator keeps the real input desktop. Primary path = separate desktop object (NOT a second login session, VM, or RDP loopback). Fallback = isolated standard-user login session viewed through one embedded RDP-loopback viewer.

---

# Foreman Desktop Computer-Use Engine - Build-Ready Plan

This plan synthesizes the three component designs and folds in **every** red-team mitigation as a concrete requirement. It is grounded in the verified code: `CuBroker.SubmitAsync`/`Claim` (the Allow->Held downgrade at `CuBroker.cs:104`, the delivery re-gate at `:169`, the tabId stamp at `:185`, `OnExecuting` at `:198`), `FastPathAuditor.Project` (`:45`, the empty-projection bug), `AuditPipeline` cadence sampling (`:51`), the `ElevatedSidecarController`/`PipeClientGuard`/`SidecarIntegrity` hardening trio, `CuPanicState`, `PanicController`, and the `EtwSidecar/Program.cs` parent-death loop.

The single biggest correction the red-team forces: **the existing browser CU trust model leans on two factors that BOTH evaporate for desktop CU** - (a) elevation as the unforgeable pipe discriminator (`PipeClientGuard`), gone because the desktop sidecar is medium-IL; (b) the auditor judging a meaningful projection, gone because `FastPathAuditor.Project` returns an empty string for a coordinate-only desktop click. The plan rebuilds both before any input ever fires.

---

## 0. Cross-cutting invariants (apply to every slice)

These are requirements, not aspirations. Each maps to red-team findings.

- **INV-1 (auditor sees what executes).** A desktop click/type is judged on its *resolved semantic target* (UIA element label + control type), not a bare `(x,y)`. The coordinate is re-resolved at delivery; if the element changed, the action **fails**. (Fixes: "auditor judges nothing on a desktop click", "screenshot-elsewhere".)
- **INV-2 (broker is authoritative for the target window).** The bound HWND is operator-set and verified end-to-end via a **shared MMF the sidecar reads itself** - never trusted from the pipe payload alone. (Fixes: "sidecar trusts the handed HWND".)
- **INV-3 (panic is a hard floor, not a polled byte).** Halt = ACL-protected MMF flip + auto-reset event + `BlockInput(TRUE)` + synthetic release-all + `TerminateProcess(sidecarPid)`. One-INPUT-per-batch is a *verified contract invariant*, not a convention. (Fixes: "mid-stream panic race", "unauthenticated panic MMF".)
- **INV-4 (injected != operator, by kernel flag).** `LLMHF_INJECTED` is the **primary** discriminator for "is this the human"; the `dwExtraInfo` magic only sub-classifies *our* injection. No injected event ever grants control or take-back. (Fixes: "forge the magic", "presence root driven by injected input".)
- **INV-5 (sidecar self-reports are verified, not trusted).** Every `ExecuteActionResult` (FinalHwnd/CursorXY/HaltedMidStream) is cross-checked App-side against an independent `GetForegroundWindow`/`GetCursorPos`; mismatch => Fail + High event + auto-halt. Responses are HMAC'd. (Fixes: "sidecar return channel implicitly trusted".)
- **INV-6 (channel binding is cryptographic).** Nonce off argv (inherited handle), challenge-response HMAC handshake, live-image re-verify of the connected PID, owner-only pipe. (Fixes: "dropping elevation removes the discriminator", "integrity-verify TOCTOU".)
- **INV-7 (desktop queue is in-process only).** No MCP `cu_poll_actions` path for Desktop modality. `ByHarness` is overwritten with the authenticated caller id at submit; `["*"]` drivers never extend to Desktop. (Fixes: "in-process pump derives identity from attacker-controlled ByHarness", "network-drainable queue".)
- **INV-8 (HUD is sticky and fail-closed).** The "AI piloting" banner stays up for the *whole turn* (turn-open/turn-close, heartbeat re-assert), not a 6 s auto-hide; if the HUD is not confirmed visible, the pump does **not** deliver the next input. (Fixes: "starve the HUD so piloting is invisible".)
- **INV-9 (Foreman's own UI is input-rejected at the injection layer).** Before every input, resolve the window under the target point; refuse if its root-owner PID == `Environment.ProcessId` or it is shell chrome (`Shell_TrayWnd`, `NotifyIconOverflowWindow`). (Fixes: "AI drives the HUD/tray".)
- **INV-10 (presence-gate the dangerous gestures).** Desktop *bind* and any *auto-grant* go through the same `PresenceGuard` (Windows Hello) as `PanicController.ResumeAsync`. Binding is never a synthesizable click. (Fixes: "fake the operator gesture".)

---

## 1. Sequenced build order (smallest verifiable slice first)

Each slice is independently testable and ends at a green gate. Input injection does **not** appear until Slice 4, after the audit and confinement spine exist.

### Slice 0 - Core seams, no native code, no process
**Build:** `ICuExecutor` + `CuExecResult` (`Foreman.Core/ComputerUse/ICuExecutor.cs`); `CuWindowRef` (`CuWindowRef.cs`); `IDesktopWindowProbe` (`IDesktopWindowProbe.cs`); add `CuIsolationMode { SharedMonopilot, IsolatedDesktop, IsolatedSession }` to `CuAction`. Add `CuVerbs.IsCursorMoving` set `{move, scroll, drag, mouse_move, left_click_drag}`.
**Why first:** pure types + the one-window broker state can be unit-tested with zero Win32.
**Gate (xUnit, no device):** `dotnet test` green; project compiles into the solution.

### Slice 1 - Broker one-window gate (parallel state, not unified)
**Build:** In `CuBroker.cs` add `_activeWindow` (`CuWindowRef?`), `ActiveWindow`, `SetActiveWindow` (bumps `Epoch`, fires `OnWindowSwitch`), `EvaluateWindowExcursion`, `IsOffWindowExcursion`, and the Desktop `args["hwnd"]` delivery stamp - mirroring the tab gate at `:104`/`:169`/`:185`, modality-scoped so Browser and Desktop gates never cross-fire.

Folded mitigations:
- **Cursor-moving verbs run the window gate** even though they stay read-only for the *audit* pipeline (`CuVerbs.IsCursorMoving`). A bare `move`/`scroll` is no longer a confinement hole. (Critical #1.)
- **No `OperatorApproved` skip for raw HWNDs.** Even operator-approved Desktop items re-validate `IsAlive + OwnerPid + Epoch` at delivery; a recycled handle => Held/Failed, never delivered. Approval binds to the full `CuWindowRef` identity. (Critical/High #7.)
- **Panic clears + invalidates the queue.** On `CuPanicState.Changed->halted`, every non-terminal Desktop item -> Rejected ("panic - re-submit"); `OperatorApproved` is cleared on survivors; items carry a panic-epoch and `Claim` refuses any item older than the last Halt. (High #6 panic.)
- **Reject binding Foreman's own windows** (own PID, `CuOverlayWindow`) - surfaced reason, not silent.

**Gate (xUnit):** `CuBrokerWindowGateTests`, `DeliveryRegateTests`, `StampTests`, `RecycledHwndTests`, `ChildWindowTests`, `ModalityScopingTests`, `PanicClearsBindingTests`, `OwnWindowRejectTests`, `SwitchAuditTests` - all green.

### Slice 2 - Auditor honesty for desktop (no device)
**Build:** Extend `FastPathAuditor.Project` to include `targetLabel`, `targetRole`, `x`, `y`. Add a `CuHeuristics` rule firing on sensitive control vocabulary (`Confirm|Send|Delete|Transfer|Allow|Yes|Run anyway|Save As`) and on the **consent-surface deny-list** by window class/title (`#32770` dialog hosting Save/Open/credential text, UAC `consent`). Decouple desktop audit cadence: for Desktop modality `ShouldReview=true` for any resolved-risky target regardless of `EveryNth`; sampling may only skip confirmed read-only no-ops. Add a per-harness token-bucket rate limit in `SubmitAsync` ("action rate exceeds plausible pilot speed" => Held).

Folded mitigations: empty-projection bug closed; auditor-flood/cadence-skip closed; approval-fatigue rate-limited. (Critical #1, Medium #7 auditor flood.)
**Gate (xUnit):** desktop click with `targetLabel="Confirm wire transfer"` => Held; unlabeled custom-canvas click => Held (never auto-Allow); consent-class window => hard Block; burst above human rate => Held.

### Slice 3 - DesktopCuController + sidecar handshake (capture-free, input-free)
**Build:** `Foreman.CuSidecar` project (WinExe, `net10.0-windows10.0.19041.0`, **asInvoker** manifest, permonitorv2 DPI). `Program.cs` connects, does the handshake, idles. `DesktopCuController` hosts the **duplex** owner-only pipe (`PipeDirection.InOut`, the `CreateOwnerOnlyPipe` shape from `ElevatedSidecarController.cs:163` made InOut). `CuSharedPanicFlag` + `ICuPanicSignal` (named MMF + auto-reset `EventWaitHandle`), mirrored from `CuPanicState.Changed`.

Folded mitigations (the trust rebuild, INV-6):
- **Nonce off argv** -> passed via an inherited anonymous-pipe / duplicated inheritable handle (not WMI-readable).
- **Challenge-response:** App sends random challenge; sidecar returns `HMAC(nonce, challenge)`. Replayed scraped nonce on a new connection fails.
- **Live-image verify:** `GetNamedPipeClientProcessId` -> confirm PID == the PID `Process.Start` returned, parent == `Environment.ProcessId`, and `QueryFullProcessImageName` == the exact `SidecarIntegrity.Verify`'d exe. Replace `PipeClientGuard`'s elevation test with this (elevation is gone).
- **TOCTOU close:** open the sidecar exe with `FileShare.Read` and **deny Delete/Write**, hold the handle across `Verify`->`Process.Start`; re-hash the running image's backing file at connect; mismatch => refuse + High event. Prefer install dir the agent cannot write.
- **Panic MMF is one-directional:** DACL grants App FULL, sidecar READ-ONLY (deny write to all but App); tamper canary - if the App reads its own byte changed by another writer => Critical + halt + kill.
- **Authenticated responses:** every sidecar->App frame HMAC'd with the session nonce (INV-5 prerequisite).

**Gate (process test):** `DesktopCuController handshake` - correct challenge-response from our child PID => connected; wrong PID / wrong nonce / replayed nonce => rejected + High event. `SidecarIntegrity` gate: unsigned sidecar => refused before `Process.Start`. Parent-death: kill parent => sidecar exits within one poll tick.

### Slice 4 - SendInput, one input at a time, panic-killable
**Build:** `SendInputExecutor` (sidecar). `CuInputInjector` stamps `dwExtraInfo = 0x464F5245`. `DesktopCuExecutor` (App, `ICuExecutor`) + `CuExecutorPump` (Claim->Execute->Complete loop, in-process only, INV-7). Wire the whole thing behind `settings.CuDesktopEnabled` (off by default).

Folded mitigations:
- **One-INPUT-per-batch is enforced:** the controller rejects/aborts any sidecar frame claiming a multi-event batch; tested invariant, not a convention. (Critical #2.)
- **Panic floor (INV-3):** before *every* `INPUT`, `Volatile.Read` the panic byte + check panic-epoch; on Halt the App also `BlockInput(TRUE)`, sends synthetic release-all (key-up/mouse-up so a half-held drag can't complete), and `TerminateProcess(sidecarPid)`. Memory barrier on the MMF read; monotonic panic-epoch detects a stale read.
- **Bound-window confinement (INV-2):** sidecar reads `boundHwnd` from the **MMF** (extended to `{panicByte, boundHwnd, epoch}`) and **refuses** any `ExecuteActionArgs.BoundHwnd != MMF.boundHwnd`. App's `Win32WindowProbe` (UI thread) is the only writer.
- **Foreground race (INV-9 + High #5):** prefer `PostMessage(WM_KEYDOWN/WM_CHAR)` to the bound window's focused child for keystrokes; where `SendInput` is unavoidable, `AttachThreadInput`+`LockSetForegroundWindow`, verify `GetForegroundWindow()==boundHwnd` immediately **before and after** each single INPUT, and treat any foreground change mid-turn as forced handoff-to-operator. No bare absolute `MOUSEMOVE` - every move resolves to the bound client rect or is rejected.
- **Owned-popup tightening:** read-only/move may hit menu/tooltip classes (`#32768`, `tooltips_class32`, `ComboLBox`) by real class-name check; a **state-changing** verb must match the exact bound HWND, and a *new* non-menu dialog in the bound process is an excursion surfaced to the operator with its text. (Critical #2 child-window, High #5.)
- **INV-9 injection-layer reject** of Foreman/shell windows under the target point.
- **INV-5 verification** of every result App-side; **INV-1** UIA hit-test stamped into the action *before* `SubmitAsync` and re-resolved at delivery.

**Gate (on-device, Win11 2a not relevant - this is the PC):**
- Type into Notepad (bound) while a marker app receives nothing.
- `move`/`scroll` to another window's button is rejected (not clamped-blind).
- Panic mid-`type`+mid-drag: no input lands after halt-epoch; `GetAsyncKeyState` shows no button still down; sidecar terminated.
- `SetForegroundWindow` fails (force via a foreground-lock) => action returns Ok=false "could not confine", no blind inject.
- Sidecar reports FinalHwnd=bound but actually typed elsewhere (fault-injected build) => App cross-check fails => Fail + High + auto-halt.

### Slice 5 - Capture on its OWN pipe, bound to the action
**Build:** `ScreenCapturer` (DXGI Desktop Duplication + GDI BitBlt fallback). **Second, dedicated capture pipe** (primary design, not fallback) so a frame never head-of-line-blocks ExecuteAction/panic. Length-prefixed binary; downscale; JPEG; server-capped frame rate + bytes/sec.

Folded mitigations:
- **Capture bound to the action, not just the window (INV-1):** operator-facing live-view always captures the **full bound-window client rect** (no AI-chosen sub-rect). At execution the App overlays the **audited** target box sourced from the broker's stamped coordinate (`OnExecuting`), not the sidecar's capture metadata. Frames watermarked server-side (title + timestamp + method); stale/replayed frames detectable via monotonic server token. (High #3 screenshot-elsewhere.)
- **Flood defense:** live-view driven by the App at fixed <=2 Hz sampled from the latest frame (also satisfies the photosensitive rule), decoupled from sidecar push; panic never depends on the pipe (MMF + TerminateProcess floor). (High #5 capture flood.)
- **DXGI degradation (Medium #7 blind-approve):** on black/stale frames do **not** offer per-action approval - **halt** the turn; operator must explicitly `SwitchDesktop` to look (audited gesture) or cancel. Repeated degradation => Medium+ alert ("AI manufacturing blindness"). Refuse capture on the secure desktop.

**Gate (on-device):** DXGI path returns frames; forced DXGI failure => method=`gdi`, non-empty; black-frame case => turn halts, operator-look required; capture of a non-bound HWND refused; flood of capture requests does not delay a panic kill (measure).

### Slice 6 - Shared-Monopilot cursor (re-skin, guaranteed revert, arbiter)
**Build:** `CuCursorSidecar` (separate, same hardened handshake as Slice 3 minus elevation), `CuCursorSkin` (`SetSystemCursor`/`SPI_SETCURSORS`), `CuCursorRevertGuard` (4-layer), `CuCursorArbiter` (`WH_MOUSE_LL`/`WH_KEYBOARD_LL` + `GetLastInputInfo`), `ICuCursorController`.

Folded mitigations:
- **INV-4:** `LLMHF_INJECTED` is the primary discriminator; injected input never triggers take-back or hand-here; the magic only marks *our* injection (untagged injection during a turn => "someone else is injecting" alert).
- **Guaranteed revert (4 layers):** IDisposable + `ProcessExit`/`DispatcherUnhandledException`; out-of-process sidecar reverts within ~250 ms of parent death; App re-asserts `SPI_SETCURSORS` on broken pipe; unconditional `SweepStaleSwapOnStartup` every launch. **Breadcrumb is advisory only** - sweep runs regardless of the file (deletion can't suppress heal); breadcrumb dir ACL'd + HMAC'd (forged file => Medium event, not a fake "healed" record). Fallback `SetSystemCursor(IDC_ARROW)` from cached originals if `SPI_SETCURSORS` returns false.
- **Skin gated by broker turn (High #4):** `ApplyAi` only honored while a brokered `Owner==Ai` Desktop turn is live (`OnExecuting`/`OnHandoff`); a swap with no active turn => refused + High event.
- **INV-10:** initial bind + auto-grant presence-gated; middle-click hand-here defaults on, idle auto-grant opt-in with a 1.5 s cancelable countdown.
- Three ownership signals (distinct skin + sticky HUD + <=2 Hz tether dot), all localised.

**Gate (on-device):** revert-on-Dispose; revert-on-crash (kill parent, cursor restored <=2 ticks); startup sweep heals a leaked swap + logs it; physical mouse jiggle takes back mid-AI-turn and holds the queue; injected untagged input does **not** grant control; secure-desktop transition => forced handoff.

### Slice 7 - Isolated-session 2-cursor mode
**Build:** `Foreman.CuDesktop` (CreateDesktop on Winsta0 + `SetThreadDesktop` + `STARTUPINFO.lpDesktop` + PrintWindow capture). `CuDesktopState`, `CuIsolatedViewWindow`, login-session fallback (`IsolatedSessionAccount`) viewed via single RDP-loopback ActiveX bound to 127.0.0.2.

Folded mitigations:
- **SwitchDesktop hijack (Critical #3):** launch the AI app under a **Job Object** with `JOB_OBJECT_UILIMIT_SWITCHDESKTOP` + `UILIMIT_DESKTOP`; DACL the AI desktop to **DENY** `DESKTOP_SWITCHDESKTOP` to the launched token. An unexpected `SwitchDesktop` is a **panic trigger** (loud, OS-event-logged), not a silent re-assert. Hostile-code tasks => prefer login-session fallback (cross-session SwitchDesktop is kernel-blocked).
- **Honest labeling (Medium #8/9):** HUD/docs say **"INPUT-isolated, not data-isolated"**; never call CreateDesktop "isolated session" unqualified. Secret-touching tasks forced to the login-session fallback (separate token/clipboard/HKCU); clear+restore clipboard around the turn; launched app under a restricted token (`CreateRestrictedToken` dropping high-value SIDs).
- Login-session fallback is a **switched single session** (EULA-clean), never concurrent RDP / RDPWrap.

**Gate (on-device):** input isolation (typing in AI desktop, marker on Default gets nothing); PrintWindow of the off-input desktop returns non-black text; SwitchDesktop from inside the AI desktop => panic + re-assert; panic mid-macro => `SetThreadDesktop(null)`+`CloseDesktop`+app-tree kill.

---

## 2. Key interface contracts

```csharp
// Foreman.Core/ComputerUse/ICuExecutor.cs
public enum CuModality2 { /* existing CuModality is reused */ }
public sealed record CuExecResult(bool Ok, object? Result, string? Error);
public interface ICuExecutor {
    CuModality Modality { get; }          // Desktop
    bool IsReady { get; }
    Task<CuExecResult> ExecuteAsync(CuBrokerItem item, CancellationToken ct);
}

// Foreman.Core/ComputerUse/CuWindowRef.cs
public sealed record CuWindowRef(IntPtr Hwnd, int OwnerPid, string ProcessName,
                                 string TitleAtBind, long Epoch) {
    // exact handle AND pid; epoch + IsAlive(probe) checked by caller for recycle defense
    public bool Matches(IntPtr candidate, int candidatePid);
}

// Foreman.Core/ComputerUse/IDesktopWindowProbe.cs  (keeps user32 out of Core)
public interface IDesktopWindowProbe {
    CuWindowRef? CaptureForeground();
    bool IsAlive(CuWindowRef w);
    IntPtr RootOwner(IntPtr hwnd);
}

// CuBroker additions (modality-scoped; mirrors AttentionTab)
public CuWindowRef? ActiveWindow { get; }
public void SetActiveWindow(CuWindowRef? w);                 // bumps Epoch, fires OnWindowSwitch, presence-gated by caller
public Action<CuWindowRef?, CuWindowRef?>? OnWindowSwitch { get; set; }
public Action<CuBrokerItem, bool>? OnHandoff { get; set; }   // cursor owner changes
```

**Desktop IPC (duplex control pipe; capture is a SEPARATE pipe):**
```
DesktopCuRequest  { RequestId, Kind, PayloadB64 }      // Kind  Hello, BindWindow, ExecuteAction, SetCursorSkin, Heartbeat
DesktopCuResponse { RequestId, Kind, Ok, PayloadB64, Error, Hmac }   // Hmac over payload w/ session nonce (INV-5)
ExecuteActionArgs   { ActionId, Verb, Args, BoundHwnd, SessionMode, DryRun }   // BoundHwnd cross-checked vs MMF (INV-2)
ExecuteActionResult { Ok, Error, CursorX, CursorY, FinalHwnd, HaltedMidStream } // App verifies independently (INV-5)
// Capture pipe (own pipe): 4-byte length prefix + raw bytes; CaptureFrameResult { Ok, W, H, Stride, Encoding, Method, Error }
// Shared panic/bind MMF (ACL: App=FULL, sidecar=READ): { byte Panic; long BoundHwnd; long Epoch } + auto-reset EventWaitHandle
```

**Cursor controller:**
```csharp
public enum CuCursorOwner { Operator, Ai, Contested }
public enum CuCursorRole  { Arrow, IBeam, Hand, Busy }   // -> OCR_NORMAL/OCR_IBEAM/OCR_HAND
public interface ICuCursorController {
    CuCursorOwner CurrentOwner { get; }
    void Acquire(CuCursorOwner owner, CuCursorRole role);
    void Release(string reason);
    bool TryBeginAiTurn(string actionId, out string reason);   // only if Owner==Operator, not halted, bound window foreground, AND PresenceGuard-armed
    void EndAiTurn(string actionId);
    event Action<CuCursorOwner, string> OwnerChanged;
}
```

---

## 3. Bounded vs. needs new permissions/elevation

**Stays bounded - no UAC, medium IL, no new OS privilege:**
- `SendInput`, DXGI Desktop Duplication, `PrintWindow`, `SetSystemCursor`/`SPI_SETCURSORS`, `CreateDesktop`/`SetThreadDesktop`, low-level hooks, `BlockInput`, Job Objects with UI limits, MMF/EventWaitHandle, owner-only pipes. All same-user, same-session.
- The desktop and cursor sidecars are **medium IL** (asInvoker). This is deliberate: panic can hard-kill them; isolated-session needs a separate process; smaller attack surface. Foreman keeps its **one elevated component** (the ETW sidecar) unchanged.

**Needs new perms / out of scope for the bounded path:**
- **Login-session fallback** (Slice 7) requires creating a managed **local standard-user account** - an install-time/admin action, gated and optional. It is the only path that needs elevation, and only for *setup*, not runtime.
- **Install location hardening** (TOCTOU mitigation, Slice 3): putting the sidecars in a non-user-writable dir (Program Files / ACL'd) is an installer concern; until then the `FileShare`-deny-Delete + live-image re-verify is the runtime substitute.
- **DESKTOP_SWITCHDESKTOP DACL / restricted token** (Slice 7) needs the token-manipulation APIs but no elevation (same user, same session).
- **Secure desktop / UAC / lock screen**: explicitly **out of confinement** - capture refused, input never driven; a transition there is a forced handoff to operator.

**Residuals to document (cannot be fully eliminated):**
- Single-INPUT latency on panic (mitigated to ~1 input + `BlockInput` + process kill).
- CreateDesktop is **input-isolated, not data-isolated** (shared clipboard/HKCU/files) - routed honestly and to the login-session fallback for secret-touching tasks.
- A same-user attacker with a kernel driver could forge `LLMHF_INJECTED`; out of the stated threat model (user-mode agents).

---

## 4. Verification ladder (what "done" means)

xUnit gates (Slices 0-2) run in CI on every commit. On-device gates (Slices 4-7) run on the dev PC because they touch the real input desktop, foreground rules, DXGI, and the system cursor - none of which a test can exercise (same lesson as the AAPT/iddb on-device-only crash in memory). The order guarantees the **audit spine (Slice 2) and confinement spine (Slice 1) exist before the first `SendInput` (Slice 4)**, so there is never a window where unaudited or unconfined input is possible.

---

Relevant files (all absolute):
- Broker/auditor edits: `T:/TOOLS/Foreman/src/Foreman.Core/ComputerUse/CuBroker.cs`, `CuAction.cs`, `FastPathAuditor.cs`, `AuditPipeline.cs`
- New Core seams: `T:/TOOLS/Foreman/src/Foreman.Core/ComputerUse/{ICuExecutor,CuWindowRef,IDesktopWindowProbe,ICuCursorController}.cs`, `Foreman.Core/Ipc/Desktop/DesktopCuFrame.cs`, `Foreman.Core/Security/{CuSharedPanicFlag,ICuPanicSignal,CuDesktopState}.cs`
- New sidecars: `T:/TOOLS/Foreman/src/Foreman.CuSidecar/`, `Foreman.CuCursorSidecar/`, `Foreman.CuDesktop/`
- App wiring: `T:/TOOLS/Foreman/src/Foreman.App/ComputerUse/{DesktopCuController,DesktopCuExecutor,CuExecutorPump,Win32WindowProbe,CuCursorArbiter,CuCursorSkin,CuCursorRevertGuard,CuInputInjector,SharedMonopilotCursorController}.cs`, `App.xaml.cs` (~247-282), `CuOverlayWindow.xaml.cs`, `PanicController.cs`
- Trust-root references already in place: `ElevatedSidecarController.cs`, `PipeClientGuard.cs`, `SidecarIntegrity.cs`, `EtwSidecar/Program.cs`

---

## Review amendments (Codex review, 2026-06-23)

A code+spec review surfaced 6 issues. Resolutions (these OVERRIDE the body where they conflict):

1. **2-cursor mode is "2 users, ONE desktop" - NOT two desktops (premise corrected).** The original Slice 7 / isolated-session premise (CreateDesktop so the AI injects into a hidden desktop while the operator keeps using the default one) is INVALID: Windows has a single active *input* desktop; SendInput targets it, and only SwitchDesktop makes another desktop the input one. The operator's intent is two *users* - human + AI - sharing the ONE real desktop, arbitrated. So the "2-cursor" need is an extension of Shared-Monopilot (Slice 6) handoff arbitration, NOT a second desktop. ACTION: drop CreateDesktop as the default 2-cursor path. Hard Windows reality to state honestly: two *simultaneous independent* real cursors on one input desktop is not natively supported (one system cursor per input desktop), so the deliverable is fast turn-taking on the one cursor, not two live pointers. A genuine separate session (login-session / VM / RDP-loopback) is the ONLY path to true parallelism and stays an optional, elevated-setup track - never the default. Slice 7 is rescoped to that optional track; do NOT build the hidden-desktop SendInput path without a spike first proving Win11 can inject into a non-input desktop without switching (it almost certainly cannot).

2. **Desktop CU is rejected over MCP - in-process only [FIXED in code].** cu_submit now refuses modality=desktop ("operator-driven in-process only"), so a harness cannot submit or drain desktop actions and a "*" driver cannot extend to desktop (INV-7). ByHarness is already overwritten with the authenticated caller id at submit. The Slice-4 desktop pump submits to the broker IN-PROCESS only; there is no MCP desktop path.

3. **HUD fail-closed needs an explicit PRE-delivery ack (INV-8 strengthened).** OnExecuting fires best-effort AFTER the move to Executing, so it cannot gate input. ADD a pre-delivery BeforeExecuteAsync / HUD-ack contract: the pump must receive a "HUD confirmed visible" ack BEFORE the first input of a turn; no ack -> no input. Build in Slice 4 (pump) + Slice 6 (HUD heartbeat) - not as a post-hoc callback.

4. **Auditor target = a trusted TargetSnapshot, not a caller label+role (INV-1 strengthened).** targetLabel/targetRole are caller-supplied, localized, duplicable, and spoofable. The App must stamp a TRUSTED snapshot at submit and re-compare at delivery: root HWND + PID + UIA RuntimeId/AutomationId + class + bounding rect + DPI + point hit-test + a capture-region hash. The broker compares the snapshot, never the strings. Build in Slice 2 (projection includes the snapshot) + Slice 4 (re-resolve + compare at delivery).

5. **BlockInput is a short shielded section, never durable state (INV-3 strengthened).** BlockInput(TRUE) on panic risks an operator lockout. Use it ONLY as a try/finally shield around release-all + TerminateProcess (a bounded critical section), check return codes, and run an INDEPENDENT watchdog that unconditionally calls BlockInput(FALSE). Panic must never create a worse failure mode than it prevents.

6. **Doc ASCII-ized [FIXED].** Mojibake / Unicode arrows + comparison glyphs replaced with ASCII; stale "JVM/xUnit" corrected to xUnit (this is a .NET solution). A cold implementer now reads it cleanly.

## Slice 3 handshake review (6-lens red-team workflow, 2026-06-23)

After Slice 3 shipped (`606e282`), a 6-lens adversarial-review workflow (82 agents: pipe-impersonation, handshake-crypto, integrity-TOCTOU, panic-shared-state, lifecycle-DoS, spec-conformance -> 3-skeptic refute-by-default verify -> synthesis) produced 25 raw findings -> 7 survivors. **Verdict: minor hardening recommended before Slice 4.** The three-gate handshake is structurally sound on a SIGNED release build; the gaps below were the real ones.

**FIXED in code (commit after `606e282`):**

- **[HIGH] Unsigned-build integrity waiver + at-rest swap.** `SidecarIntegrity.Decide` returns Trusted for ANY sidecar when Foreman itself is unsigned (dev build), and the sidecar exe sits unlocked while the off-by-default feature is disabled - so a same-user agent could swap in a hostile binary that then passes all three gates (it IS the launched PID; the nonce rides its own argv). Fix: `DesktopCuController.PinBinaryAtRest()` holds a write/delete-denying handle on the staged sidecar for the App's WHOLE lifetime (wired in `App.xaml.cs` regardless of `CuDesktopEnabled`), so the binary cannot be swapped at rest; plus an honest Low notice that on unsigned builds the lock - not Authenticode - is the safeguard. Residual (accepted): a swap BEFORE Foreman starts is uncaught on unsigned builds, but that requires install-dir write access pre-launch = already game-over (the attacker could patch TraceBrake.exe itself). Signed release builds catch even that via the signer match.
- **[LOW] Identity image path via QueryFullProcessImageName + parent-PID check.** `VerifyClientIdentity` now resolves the client image with `QueryFullProcessImageNameW` (kernel path, per INV-6) instead of `Process.MainModule.FileName` (which can fail-close a genuine sidecar across bitness / during startup / under AV), and enforces the spec's parent-PID == Foreman check (`NtQueryInformationProcess`) as defense-in-depth behind the PID pin.
- **[LOW] No per-operation timeouts -> suspend-wedge / orphan / lying IsConnected.** A hostile same-user process could `NtSuspendProcess` the launched child to wedge `RunAsync` (holding exeLock + the sole pipe slot) or pin the single `SendAsync` permit forever. Fix: connect deadline (linked CTS + `CancelAfter`), per-request `SendAsync` deadline that marks the channel dead (clears `_connected`) on timeout, and the child is reaped in `finally` on ANY exit (cancel/timeout/reject/pipe-break) so it never orphans.
- **[INV-5 hygiene] Response MAC now binds Ok/Error + domain separation.** `CuJson.ResponseMac` covers id+kind+**Ok+Error**+payload (a pipe peer can no longer flip the decision bits Slice 4 will trust), and the handshake HMAC is domain-tagged (`CuHandshake.HandshakeMessage` = `cu-handshake-v1|...`) so it can never be confused with a response MAC.

**RESIDUAL carry-forwards Slice 4 MUST close BEFORE it enables input (verify on-device; xUnit cannot exercise these):**

1. **MMF read-only-to-sidecar DACL + tamper canary (the #1 carry-forward).** `CuSharedPanicFlag` uses `MemoryMappedFile.CreateNew` + `new EventWaitHandle` with default same-user-FULL DACLs, so any same-user process can OpenExisting read-write and forge panic/bind/epoch or swallow a wake. Slice 4 MUST hand the sidecar a READ-ONLY duplicated handle (App=FULL, sidecar=READ-ONLY per INV-3) BEFORE the sidecar reads the MMF, and add a tamper canary: the App reads back its own byte; any external change => Critical + halt + kill.
2. **Seqlock reader discipline.** The sidecar's MMF reads of boundHwnd/epoch must use a retry+barrier loop (8-byte cross-process reads are not atomic); reconcile the App's private `_epoch` against the (attacker-writable until DACL'd) MMF epoch so a masked rebind/halt is impossible.
3. **Slice-4 result trust rides the now-authenticated Ok/Error.** The cross-checks (FinalHwnd/CursorXY/HaltedMidStream, INV-5) inherit the extended ResponseMac done here - keep them inside the MAC.
4. **EtwSidecar / Guardian at-rest swap** on unsigned dev is a pre-existing, separate, lower-priority exposure (those are signature-gated + the ETW one is elevated behind UAC) - out of desktop-CU scope, noted for completeness.
5. **Not assessed by this review** (out of the slice's files; need on-device verification): PanicController/CuPanicState internals, the CuBroker one-window gate, FastPathAuditor projection, and the Slice-4 pump/injector. The verification ladder's on-device gates (real connect/suspend timing, foreground/confinement, panic-kill latency) remain mandatory.
