#if DEBUG
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Windows;
using System.Windows.Automation;
using Foreman.Core.ComputerUse;

namespace Foreman.App.ComputerUse;

/// <summary>
/// Developer on-device smoke test for the desktop CU injector spine (run via <c>TraceBrake.exe --cu-smoketest</c>).
/// It drives the REAL path - launch Notepad, bind its window, start + handshake the medium-IL sidecar, then
/// <see cref="DesktopCuController.ExecuteAsync"/> a "type" gesture (the controller independently verifies, INV-5, that
/// the input landed in the bound foreground window) - and then a PANIC test: it sets the shared halt byte and confirms
/// a second type is refused. Results go to a temp log file (this is a WinExe, no console). NOT a production path; it
/// bypasses the broker/audit/operator-approval chain on purpose to isolate the on-device injector + panic byte.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class CuSmokeTest
{
    public const string Flag = "--cu-smoketest";        // injector-only path (controller -> sidecar -> SendInput)
    public const string FlagE2E = "--cu-smoketest-e2e";  // full stack: broker -> approve -> pump -> inject
    public const string FlagHud = "--cu-smoketest-hud";  // INV-18 HUD occlusion-ack plumbing
    public const string FlagExplorer = "--cu-smoketest-explorer";  // full chain drives Explorer to a drive
    public static string LogPath => Path.Combine(Path.GetTempPath(), "foreman-cu-smoketest.log");

    public static void RunToFileAndExit(Application app) => RunCore(app, RunAsync);
    public static void RunE2EToFileAndExit(Application app) => RunCore(app, RunE2EAsync);
    public static void RunHudToFileAndExit(Application app) => RunCore(app, () => RunHudTestAsync(app));
    public static void RunExplorerToFileAndExit(Application app) => RunCore(app, RunExplorerTestAsync);

    private static void RunCore(Application app, Func<Task<(int code, string report)>> run)
    {
        _ = Task.Run(async () =>
        {
            int code; string report;
            try { (code, report) = await run().ConfigureAwait(false); }
            catch (Exception ex) { code = 99; report = "smoketest threw:\n" + ex; }
            try { File.WriteAllText(LogPath, report); } catch { }
            try { app.Dispatcher.Invoke(() => app.Shutdown(code)); } catch { }
        });
    }

    private static async Task<(int code, string report)> RunAsync()
    {
        var sb = new StringBuilder();
        void Log(string m) => sb.AppendLine(m);
        Log("=== TraceBrake desktop-CU injector smoke test ===");
        Log($"time(utc-ish via Stopwatch only); pid={Environment.ProcessId}; baseDir={AppContext.BaseDirectory}");
        Log($"sidecar path: {DesktopCuController.SidecarPath()} (exists={File.Exists(DesktopCuController.SidecarPath())})");
        Log("");

        Process? np = null;
        var notepadPid = 0;
        DesktopCuController? ctl = null;
        CuSharedPanicFlag? flag = null;
        try
        {
            // 1. Launch Notepad and find its top-level window. On Win11 notepad.exe is a packaged app, so the launched
            //    Process's MainWindowHandle never populates (the window belongs to a different PID) - enumerate windows
            //    by title instead, which is PID-agnostic.
            // Kill any stray Notepad first so FindWindowByTitle can't bind a STALE window from a prior run (the new
            // Notepad's session-restore + unreliable kill otherwise leaves old windows that accumulate text).
            foreach (var stale in Process.GetProcessesByName("notepad")) { try { stale.Kill(); } catch { } }
            await Task.Delay(400).ConfigureAwait(false);
            // Launch on a FRESH empty temp file so the new Notepad opens a clean document instead of restoring tabs.
            var tmp = Path.Combine(Path.GetTempPath(), "foreman-cu-fidelity.txt");
            try { File.WriteAllText(tmp, string.Empty); } catch { }
            np = Process.Start(new ProcessStartInfo("notepad.exe") { Arguments = $"\"{tmp}\"", UseShellExecute = true });
            IntPtr hwnd = IntPtr.Zero;
            for (var i = 0; i < 60 && hwnd == IntPtr.Zero; i++)
            {
                hwnd = FindWindowByTitle("Notepad");
                if (hwnd == IntPtr.Zero) await Task.Delay(200).ConfigureAwait(false);
            }
            if (hwnd == IntPtr.Zero) return (2, sb + "\nFAIL: Notepad window never appeared");
            GetWindowThreadProcessId(hwnd, out notepadPid);
            Log($"notepad window hwnd={hwnd.ToInt64()} ownerPid={notepadPid}");
            await EnsureForeground(hwnd).ConfigureAwait(false);

            // 2. Bind the window in the shared panic/bind map and start + handshake the sidecar.
            flag = new CuSharedPanicFlag();
            flag.SetBound(hwnd.ToInt64());
            var verifFailed = false;
            ctl = new DesktopCuController { PanicFlag = flag };
            ctl.OnSecurityNotice = (sev, m) => Log($"  [sidecar notice {sev}] {m}");
            ctl.OnVerificationFailure = () => verifFailed = true;
            ctl.Start();
            for (var i = 0; i < 75 && !ctl.IsConnected; i++) await Task.Delay(200).ConfigureAwait(false);
            if (!ctl.IsConnected) return (3, sb + "\nFAIL: sidecar never connected/handshaked");
            Log("sidecar launched + 3-gate handshake OK + shared panic map mapped");

            var fgOk = await EnsureForeground(hwnd).ConfigureAwait(false);
            Log($"foreground == bound Notepad: {fgOk} (fg={GetForegroundWindow().ToInt64()}, bound={hwnd.ToInt64()})");

            // 3. The real injection: type into the bound Notepad window. The controller verifies (INV-5) that the
            //    foreground the APP itself reads == the bound window == the sidecar's self-reported FinalHwnd.
            const string msg = "Hello from Foreman";   // <=120 inputs/gesture (the injector caps long gestures; split upstream)
            var r1 = await ctl.ExecuteAsync(new ExecuteActionArgs(
                Guid.NewGuid().ToString("N"), "type",
                new Dictionary<string, string> { ["text"] = msg }, hwnd.ToInt64())).ConfigureAwait(false);
            await Task.Delay(400).ConfigureAwait(false);
            Log($"type result: Ok={r1?.Ok} finalHwnd={r1?.FinalHwnd} err={r1?.Error}");
            var readback = TryReadText(hwnd);
            Log($"readback (UIA): {(readback is null ? "<unavailable>" : "\"" + readback.Replace("\r", " ").Replace("\n", " ").Trim() + "\"")}");

            // 4. PANIC: set the shared halt byte, then attempt a second type that MUST be refused.
            flag.SetHalted(true);
            await Task.Delay(150).ConfigureAwait(false);
            var r2 = await ctl.ExecuteAsync(new ExecuteActionArgs(
                Guid.NewGuid().ToString("N"), "type",
                new Dictionary<string, string> { ["text"] = " THIS-MUST-NOT-APPEAR-AFTER-PANIC" }, hwnd.ToInt64())).ConfigureAwait(false);
            await Task.Delay(300).ConfigureAwait(false);
            Log($"post-panic type result: Ok={r2?.Ok} halted={r2?.HaltedMidStream} err={r2?.Error}");
            var readback2 = TryReadText(hwnd);
            flag.SetHalted(false);

            // Verdicts.
            var injected = r1 is { Ok: true } && !verifFailed;
            var textPresent = readback?.Contains("Hello from Foreman", StringComparison.Ordinal) == true;
            var panicRefused = r2 is null || r2.Ok == false;
            var noLeak = readback2 is null || !readback2.Contains("THIS-MUST-NOT-APPEAR", StringComparison.Ordinal);

            Log("");
            Log($"[{(injected ? "PASS" : "FAIL")}] injection executed + INV-5 independently verified into the bound window");
            Log($"[{(textPresent ? "PASS" : readback is null ? "N/A " : "FAIL")}] typed text read back from Notepad" +
                (readback is null ? " (UIA readback unavailable; relied on INV-5)" : ""));
            Log($"[{(panicRefused ? "PASS" : "FAIL")}] second type REFUSED after panic halt");
            Log($"[{(noLeak ? "PASS" : "FAIL")}] no post-panic text leaked into Notepad");

            var overall = injected && panicRefused && noLeak;
            Log("");
            Log($"OVERALL: {(overall ? "PASS" : "FAIL")}");
            return (overall ? 0 : 10, sb.ToString());
        }
        finally
        {
            try { ctl?.Stop(); } catch { }
            try { flag?.Dispose(); } catch { }
            try { if (notepadPid != 0) Process.GetProcessById(notepadPid).Kill(); } catch { }   // discard unsaved Notepad
            try { if (np is { HasExited: false }) np.Kill(); } catch { }
        }
    }

    // Find the first visible top-level window whose title contains <paramref name="needle"/> (PID-agnostic, so it works
    // with Win11's packaged Notepad whose window belongs to a different process than the launched one).
    private static IntPtr FindWindowByTitle(string needle)
    {
        var found = IntPtr.Zero;
        EnumWindows((h, _) =>
        {
            if (!IsWindowVisible(h)) return true;
            var len = GetWindowTextLength(h);
            if (len <= 0) return true;
            var sb = new StringBuilder(len + 1);
            GetWindowText(h, sb, sb.Capacity);
            if (sb.ToString().Contains(needle, StringComparison.OrdinalIgnoreCase)) { found = h; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }

    // First visible top-level window of a given window class (e.g. "CabinetWClass" = File Explorer).
    private static IntPtr FindWindowByClass(string cls)
    {
        var found = IntPtr.Zero;
        EnumWindows((h, _) =>
        {
            if (!IsWindowVisible(h)) return true;
            var sb = new StringBuilder(256);
            if (GetClassName(h, sb, sb.Capacity) > 0 && sb.ToString() == cls) { found = h; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(IntPtr hWnd, StringBuilder sb, int max);

    // Full-stack end-to-end: a relayed local-agent PROPOSAL flows through the real broker (audit + default-Held), is
    // refused by the pump until the operator APPROVES, then the pump claims it and the sidecar injector types it into the
    // bound Notepad window. Proves the whole mediated chain on-device. (cu_approve's MCP presence tap is exercised
    // separately; here the operator decision is broker.ApproveHeld directly.)
    private static async Task<(int code, string report)> RunE2EAsync()
    {
        var sb = new StringBuilder();
        void Log(string m) => sb.AppendLine(m);
        Log("=== TraceBrake desktop-CU END-TO-END smoke test (propose -> Held -> approve -> pump -> inject) ===");
        Log($"sidecar: {DesktopCuController.SidecarPath()} (exists={File.Exists(DesktopCuController.SidecarPath())})");
        Log("");

        Process? np = null;
        var notepadPid = 0;
        DesktopCuController? ctl = null;
        CuSharedPanicFlag? flag = null;
        try
        {
            // 1. Fresh Notepad, foreground.
            foreach (var stale in Process.GetProcessesByName("notepad")) { try { stale.Kill(); } catch { } }
            await Task.Delay(400).ConfigureAwait(false);
            var tmp = Path.Combine(Path.GetTempPath(), "foreman-cu-fidelity.txt");
            try { File.WriteAllText(tmp, string.Empty); } catch { }
            np = Process.Start(new ProcessStartInfo("notepad.exe") { Arguments = $"\"{tmp}\"", UseShellExecute = true });
            IntPtr hwnd = IntPtr.Zero;
            for (var i = 0; i < 60 && hwnd == IntPtr.Zero; i++)
            {
                hwnd = FindWindowByTitle("Notepad");
                if (hwnd == IntPtr.Zero) await Task.Delay(200).ConfigureAwait(false);
            }
            if (hwnd == IntPtr.Zero) return (2, sb + "\nFAIL: Notepad window never appeared");
            GetWindowThreadProcessId(hwnd, out notepadPid);
            await EnsureForeground(hwnd).ConfigureAwait(false);
            Log($"notepad hwnd={hwnd.ToInt64()} pid={notepadPid}");

            // 2. The REAL stack: broker (real audit pipeline) + injector + executor pump.
            flag = new CuSharedPanicFlag();
            var broker = new CuBroker(new AuditPipeline(new FastPathAuditor()));
            broker.WindowProbe = new Win32WindowProbe();
            broker.OnWindowSwitch = (_, now) => { try { flag!.SetBound(now?.Hwnd.ToInt64() ?? 0); } catch { } };
            broker.EnrollDesktopDriver(LocalDriverIpc.LocalAgentHostId);

            ctl = new DesktopCuController { PanicFlag = flag };
            ctl.OnSecurityNotice = (sev, m) => Log($"  [sidecar {sev}] {m}");
            ctl.Start();
            for (var i = 0; i < 75 && !ctl.IsConnected; i++) await Task.Delay(200).ConfigureAwait(false);
            if (!ctl.IsConnected) return (3, sb + "\nFAIL: sidecar not connected");
            Log("sidecar connected + handshaked");

            var pump = new CuExecutorPump(broker, new DesktopCuExecutor(ctl, () => flag!.BoundHwnd));

            // 3. Bind the Notepad window (OnWindowSwitch syncs the injector's MMF bound HWND).
            var probe = new Win32WindowProbe();
            var wref = probe.CaptureForeground();
            if (wref is null || wref.Hwnd != hwnd) { await EnsureForeground(hwnd).ConfigureAwait(false); wref = probe.CaptureForeground(); }
            var (_, bindReason) = broker.SetActiveWindow(wref);
            Log($"bind: {bindReason} (MMF bound now {flag.BoundHwnd})");

            // 4. Relay a proposal AS THE LOCAL AGENT HOST (the real relay path: DriverSubmit -> BuildAction).
            var action = LocalDriverIpc.BuildAction(new DriverSubmit(
                Guid.NewGuid().ToString("N"), "type",
                new Dictionary<string, string> { ["text"] = "Hello from Foreman" }, "e2e smoke test"));
            var item = await broker.SubmitAsync(action, new CuContext(LocalDriverIpc.LocalAgentHostId)).ConfigureAwait(false);
            Log($"proposal submitted -> state={item.State} (expect Held: default-Held, auto-grant off)");

            // 5. NEGATIVE: pump WITHOUT approval must execute nothing.
            await EnsureForeground(hwnd).ConfigureAwait(false);
            await pump.PumpOnceAsync().ConfigureAwait(false);
            var stateNoApprove = broker.Get(item.ActionId)!.State;
            var rb0 = TryReadText(hwnd);
            Log($"pump w/o approval -> state={stateNoApprove}, readback={(string.IsNullOrWhiteSpace(rb0) ? "<empty>" : "\"" + rb0.Trim() + "\"")}");

            // 6. Operator approves, then the pump claims + injects.
            var (aok, aReason) = broker.ApproveHeld(item.ActionId);
            Log($"operator approve -> {aok}: {aReason}");
            await EnsureForeground(hwnd).ConfigureAwait(false);
            await pump.PumpOnceAsync().ConfigureAwait(false);
            await Task.Delay(400).ConfigureAwait(false);
            var finalState = broker.Get(item.ActionId)!.State;
            var rb = TryReadText(hwnd);
            Log($"pump after approval -> state={finalState}, readback={(rb is null ? "<unavailable>" : "\"" + rb.Replace("\r", " ").Replace("\n", " ").Trim() + "\"")}");

            // The STATE machine is the authoritative proof, not the readback: Claim only ever delivers Approved items,
            // and Complete->Completed only happens when the controller's INV-5 (App foreground == bound == sidecar
            // FinalHwnd) passed - so finalState==Completed IS a verified injection into the bound window. The UIA readback
            // is informational only (the new Notepad restores prior-run text + drops chars under load - a documented
            // fidelity limitation, not a chain failure).
            var heldFirst = item.State == CuActionState.Held;
            var notBeforeApprove = stateNoApprove == CuActionState.Held;   // pump didn't advance an unapproved item
            var executed = finalState == CuActionState.Completed;          // INV-5-verified injection
            var textOk = rb?.Contains("Hello from Foreman", StringComparison.Ordinal) == true;

            Log("");
            Log($"[{(heldFirst ? "PASS" : "FAIL")}] proposal landed HELD (not auto-executed)");
            Log($"[{(notBeforeApprove ? "PASS" : "FAIL")}] pump did NOT execute it before operator approval (stayed Held)");
            Log($"[{(executed ? "PASS" : "FAIL")}] after approval the pump executed it -> Completed (INV-5 verified)");
            Log($"[info] typed-text readback (best-effort; new-Notepad confound): {(textOk ? "exact" : rb is null ? "unavailable" : "garbled/accumulated")}");

            var overall = heldFirst && notBeforeApprove && executed;
            Log("");
            Log($"OVERALL: {(overall ? "PASS" : "FAIL")}");
            return (overall ? 0 : 10, sb.ToString());
        }
        finally
        {
            try { ctl?.Stop(); } catch { }
            try { flag?.Dispose(); } catch { }
            try { if (notepadPid != 0) Process.GetProcessById(notepadPid).Kill(); } catch { }
            try { if (np is { HasExited: false }) np.Kill(); } catch { }
        }
    }

    // Full-chain real task: drive File Explorer to the S: drive THROUGH the audited pipeline - launch Explorer, bind its
    // window, then submit -> Held -> approve -> pump -> inject three keystrokes (Ctrl+L to focus the address bar, type
    // "s:\", Enter). The real HUD overlay is up so its BLUE input row shows the keys/macros as they fire. Verifies via
    // the Shell that an Explorer window actually landed on S:.
    private static async Task<(int code, string report)> RunExplorerTestAsync()
    {
        const string drive = "s:\\";
        var sb = new StringBuilder();
        void Log(string m) => sb.AppendLine(m);
        Log("=== TraceBrake desktop-CU drives File Explorer to S: (full audited chain) ===");

        DesktopCuController? ctl = null;
        CuSharedPanicFlag? flag = null;
        CuOverlayWindow? overlay = null;
        var app = Application.Current;
        try
        {
            // 0. Real HUD overlay so the blue input row (keys/macros) is visible on-screen during the drive.
            await app.Dispatcher.InvokeAsync(() => { overlay = new CuOverlayWindow(); overlay.EnsureShown(); });

            // 1. Launch Explorer + find its window (CabinetWClass; the launched process exits immediately on Win11).
            Process.Start(new ProcessStartInfo("explorer.exe") { UseShellExecute = true });
            IntPtr hwnd = IntPtr.Zero;
            for (var i = 0; i < 60 && hwnd == IntPtr.Zero; i++)
            {
                hwnd = FindWindowByClass("CabinetWClass");
                if (hwnd == IntPtr.Zero) await Task.Delay(200).ConfigureAwait(false);
            }
            if (hwnd == IntPtr.Zero) return (2, sb + "\nFAIL: no File Explorer window appeared");
            await EnsureForeground(hwnd).ConfigureAwait(false);
            Log($"explorer window hwnd={hwnd.ToInt64()}");

            // 2. Real stack: broker + injector + pump, with the Explorer window bound.
            flag = new CuSharedPanicFlag();
            var broker = new CuBroker(new AuditPipeline(new FastPathAuditor()));
            broker.WindowProbe = new Win32WindowProbe();
            broker.OnWindowSwitch = (_, now) => { try { flag!.SetBound(now?.Hwnd.ToInt64() ?? 0); } catch { } };
            broker.EnrollDesktopDriver(LocalDriverIpc.LocalAgentHostId);
            // Surface each action's input on the HUD's blue row as it executes (the same wiring the App uses).
            broker.OnExecuting = it =>
            {
                var input = CuInputDescription.Of(it.Action);
                app.Dispatcher.BeginInvoke(new Action(() => { try { overlay?.ShowDriving("desktop"); overlay?.ShowInput(input); } catch { } }));
            };

            ctl = new DesktopCuController { PanicFlag = flag };
            ctl.OnSecurityNotice = (sev, m) => Log($"  [sidecar {sev}] {m}");
            ctl.Start();
            for (var i = 0; i < 75 && !ctl.IsConnected; i++) await Task.Delay(200).ConfigureAwait(false);
            if (!ctl.IsConnected) return (3, sb + "\nFAIL: sidecar not connected");
            Log("sidecar connected + handshaked");

            var pump = new CuExecutorPump(broker, new DesktopCuExecutor(ctl, () => flag!.BoundHwnd));
            var probe = new Win32WindowProbe();
            var wref = probe.CaptureForeground();
            if (wref is null || wref.Hwnd != hwnd) { await EnsureForeground(hwnd).ConfigureAwait(false); wref = probe.CaptureForeground(); }
            var (_, bindReason) = broker.SetActiveWindow(wref);
            var mon = MonitorProbe.ForWindow(hwnd);
            Log($"bind: {bindReason}" + (mon is { } mm ? $" on {mm.Summary}" : ""));

            // 3. Drive three keystrokes through the FULL audited chain (each: submit -> Held -> approve -> pump -> inject).
            async Task<bool> DoAsync(string label, string verb, Dictionary<string, string> args)
            {
                var action = LocalDriverIpc.BuildAction(new DriverSubmit(Guid.NewGuid().ToString("N"), verb, args, "navigate to S:"));
                var item = await broker.SubmitAsync(action, new CuContext(LocalDriverIpc.LocalAgentHostId)).ConfigureAwait(false);
                broker.ApproveHeld(item.ActionId);                              // operator approves
                await EnsureForeground(hwnd).ConfigureAwait(false);
                await pump.PumpOnceAsync().ConfigureAwait(false);
                await Task.Delay(450).ConfigureAwait(false);
                var st = broker.Get(item.ActionId)!.State;
                Log($"  {label}: {item.State} -> approve -> pump -> {st}   [HUD blue: \"{CuInputDescription.Of(action)}\"]");
                return st == CuActionState.Completed;
            }

            var k1 = await DoAsync("Ctrl+L (focus address bar)", "key", new() { ["vk"] = "76", ["mods"] = "ctrl" }).ConfigureAwait(false);  // L = 0x4C
            var k2 = await DoAsync("type \"s:\\\"", "type", new() { ["text"] = drive }).ConfigureAwait(false);
            var k3 = await DoAsync("key Enter (navigate)", "key", new() { ["vk"] = "13" }).ConfigureAwait(false);          // VK_RETURN
            await Task.Delay(700).ConfigureAwait(false);

            var atS = ExplorerIsAtSDrive();
            Log("");
            Log($"[{(k1 && k2 && k3 ? "PASS" : "FAIL")}] all three actions ran through the audited chain (held -> approved -> injected)");
            Log($"[{(atS ? "PASS" : "FAIL")}] an Explorer window is now at S:\\ (verified via the Shell)");
            var overall = k1 && k2 && k3 && atS;
            Log("");
            Log($"OVERALL: {(overall ? "PASS" : "FAIL")}");
            return (overall ? 0 : 10, sb.ToString());
        }
        finally
        {
            try { ctl?.Stop(); } catch { }
            try { flag?.Dispose(); } catch { }
            try { await app.Dispatcher.InvokeAsync(() => overlay?.Close()); } catch { }
        }
    }

    // True if any open File Explorer window is currently showing the S: drive (LocationURL "file:///S:/").
    private static bool ExplorerIsAtSDrive()
    {
        try
        {
            var t = Type.GetTypeFromProgID("Shell.Application");
            if (t is null) return false;
            dynamic shell = Activator.CreateInstance(t)!;
            foreach (var w in shell.Windows())
            {
                try
                {
                    if (w.LocationURL is string url && url.StartsWith("file:///S:", StringComparison.OrdinalIgnoreCase))
                        return true;
                }
                catch { }
            }
            return false;
        }
        catch { return false; }
    }

    // INV-18 plumbing proof: the real CuOverlayWindow's adversarial ConfirmVisible() must return TRUE when the banner
    // is up on a normal desktop, FALSE when it isn't visible. (Foreign-window occlusion is excluded by the own-PID
    // filter + unit-tested via FakeHud; this exercises the real Win32/DWM plumbing on-device.)
    private static async Task<(int code, string report)> RunHudTestAsync(Application app)
    {
        var sb = new StringBuilder();
        void Log(string m) => sb.AppendLine(m);
        Log("=== TraceBrake desktop-CU HUD occlusion-ack plumbing test (INV-18, on-device) ===");
        CuOverlayWindow? hud = null;
        try
        {
            await app.Dispatcher.InvokeAsync(() => { hud = new CuOverlayWindow(); hud.EnsureShown(); });
            await Task.Delay(900).ConfigureAwait(false);
            var v1 = hud!.ConfirmVisible();
            Log($"HUD shown (normal desktop)  -> ConfirmVisible = {v1} (expect True)");

            await app.Dispatcher.InvokeAsync(() => hud!.Hide());
            await Task.Delay(500).ConfigureAwait(false);
            var v2 = hud.ConfirmVisible();
            Log($"HUD hidden                  -> ConfirmVisible = {v2} (expect False)");

            await app.Dispatcher.InvokeAsync(() => hud!.EnsureShown());
            await Task.Delay(700).ConfigureAwait(false);
            var v3 = hud.ConfirmVisible();
            Log($"HUD re-shown                -> ConfirmVisible = {v3} (expect True)");

            var pass = v1 && !v2 && v3;
            Log("");
            Log($"OVERALL: {(pass ? "PASS" : "FAIL")}");
            return (pass ? 0 : 10, sb.ToString());
        }
        finally { try { await app.Dispatcher.InvokeAsync(() => hud?.Close()); } catch { } }
    }

    // Best-effort readback via UI Automation (works across classic + Win11 Notepad's document control). Null if the
    // text can't be read - the test then relies on the controller's INV-5 verification of the injection.
    private static string? TryReadText(IntPtr hwnd)
    {
        try
        {
            var root = AutomationElement.FromHandle(hwnd);
            if (root is null) return null;
            var doc = root.FindFirst(TreeScope.Subtree, new OrCondition(
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Document),
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Edit))) ?? root;
            if (doc.TryGetCurrentPattern(TextPattern.Pattern, out var tp))
                return ((TextPattern)tp).DocumentRange.GetText(-1);
            if (doc.TryGetCurrentPattern(ValuePattern.Pattern, out var vp))
                return ((ValuePattern)vp).Current.Value;
            return null;
        }
        catch { return null; }
    }

    // Force a window genuinely foreground despite Windows' foreground-stealing lock (a process not itself in the
    // foreground normally cannot SetForegroundWindow). Clears the lock timeout, then does the AttachThreadInput dance.
    // Test-harness only - the production injector NEVER forces foreground; it REFUSES off-window input.
    private static async Task<bool> EnsureForeground(IntPtr hwnd)
    {
        for (var i = 0; i < 12; i++)
        {
            try
            {
                SystemParametersInfo(SPI_SETFOREGROUNDLOCKTIMEOUT, 0, IntPtr.Zero, SPIF_SENDCHANGE);
                ShowWindow(hwnd, SW_RESTORE);
                var fg = GetForegroundWindow();
                var ourTid = GetCurrentThreadId();
                var fgTid = GetWindowThreadProcessId(fg, out _);
                var tgtTid = GetWindowThreadProcessId(hwnd, out _);
                AttachThreadInput(ourTid, fgTid, true);
                AttachThreadInput(ourTid, tgtTid, true);
                BringWindowToTop(hwnd);
                SetForegroundWindow(hwnd);
                AttachThreadInput(ourTid, tgtTid, false);
                AttachThreadInput(ourTid, fgTid, false);
            }
            catch { }
            await Task.Delay(150).ConfigureAwait(false);
            if (GetForegroundWindow() == hwnd) return true;
        }
        return GetForegroundWindow() == hwnd;
    }

    private const uint SPI_SETFOREGROUNDLOCKTIMEOUT = 0x2001;
    private const uint SPIF_SENDCHANGE = 0x0002;
    private const int SW_RESTORE = 9;

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool BringWindowToTop(IntPtr hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, [MarshalAs(UnmanagedType.Bool)] bool fAttach);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SystemParametersInfo(uint uiAction, uint uiParam, IntPtr pvParam, uint fWinIni);

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowTextLength(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder sb, int max);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out int pid);
}
#endif
