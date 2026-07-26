using System.ServiceProcess;
using Foreman.Guardian;

// Foreman Guardian (circle-back Phase A) — the OPT-IN LocalSystem authority that holds the event-log head-seal
// key behind the SYSTEM boundary, so a same-user (medium-IL) agent can neither use the key nor forge a seal.
//
// Verbs:
//   --version                      print version and exit
//   --service                      run under the Service Control Manager (LocalSystem) — how it runs in production
//   --install --foreman-pid <pid>  ELEVATED self-install: resolve live Foreman, integrity-gate, install + start
//   --uninstall                    ELEVATED: stop + delete the service, remove its dirs
//   (no verb)                      console host for smoke tests (same authority + authenticated pipe)

if (Has("--version") || Has("-v"))
{
    Console.WriteLine(GuardianAuthority.Version);
    return 0;
}

if (Has("--service"))
{
    ServiceBase.Run(new GuardianService());   // blocks until the SCM stops the service
    return 0;
}

if (Has("--install"))
    return GuardianInstaller.Install(
        ArgInt("--foreman-pid"),
        Console.WriteLine);

if (Has("--uninstall"))
    return GuardianInstaller.Uninstall(Console.WriteLine);

// ── console smoke host ──────────────────────────────────────────────────────────────────────────────
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

using var authority = GuardianAuthority.CreateWithTpmKey();
GuardianClientPolicy consolePolicy;
try
{
    consolePolicy = GuardianClientPolicy.CreateForInstall(ArgValue("--foreman") ?? Environment.ProcessPath);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Cannot create console client policy: {ex.Message}");
    return 2;
}
Console.WriteLine($"Foreman Guardian {GuardianAuthority.Version} — pipe '{GuardianPipeServer.PipeName}', trustMode={consolePolicy.Mode}, headKey={(authority.HeadKeyAvailable ? "available" : "unavailable (no TPM)")} (Ctrl+C to stop).");

var server = new GuardianPipeServer(authority, consolePolicy, Console.WriteLine);
try { await server.RunAsync(cts.Token); }
catch (OperationCanceledException) { /* clean shutdown */ }
return 0;

bool Has(string flag) => args.Any(a => string.Equals(a, flag, StringComparison.OrdinalIgnoreCase));

string? ArgValue(string flag)
{
    for (var i = 0; i < args.Length - 1; i++)
        if (string.Equals(args[i], flag, StringComparison.OrdinalIgnoreCase))
            return args[i + 1];
    return null;
}

int? ArgInt(string flag) => int.TryParse(ArgValue(flag), out var value) ? value : null;
