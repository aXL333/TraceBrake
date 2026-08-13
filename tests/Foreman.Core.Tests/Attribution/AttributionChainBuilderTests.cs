using Foreman.Core.Attribution;
using Foreman.Core.Behavior;
using Foreman.Core.Models;

namespace Foreman.Core.Tests.Attribution;

public sealed class AttributionChainBuilderTests
{
    private static readonly DateTimeOffset T = new(2026, 8, 13, 11, 22, 30, TimeSpan.Zero);

    [Fact]
    public void CommandAlert_UsesTrackedHarnessLineage_AndRedactsCommandSecret()
    {
        var processStart = T.AddMinutes(-2);
        var evt = new CommandAlertEvent(T, ForemanSeverity.High, "powershell.exe (pid 42)", "matched",
            "curl -H \"Authorization: Bearer sk-abc123def456ghi789jkl0\" https://example.test",
            "NET-007", "Remote download", "desc", "guidance", 42) { ProcessStartTime = processStart };
        var process = new ProcessRecord { Pid = 42, ParentPid = 10, StartTime = processStart, Name = "powershell.exe", HarnessType = "codex" };

        var chain = AttributionChainBuilder.Build(evt, pid => pid == 42 ? process : null, _ => null);

        Assert.Equal(
            [AttributionNodeKind.Harness, AttributionNodeKind.Process, AttributionNodeKind.Action,
             AttributionNodeKind.Detector, AttributionNodeKind.Outcome],
            chain.Steps.Select(s => s.Kind));
        Assert.Equal("Codex", chain.Steps[0].Title);
        Assert.Contains("[REDACTED]", chain.Steps[2].Detail);
        Assert.DoesNotContain("sk-abc", chain.Steps[2].Detail);
        Assert.Equal(0, chain.InferredLinks);
    }

    [Fact]
    public void CommandAlert_DoesNotUseRecycledPidProcessAsHistoricalFact()
    {
        var evt = new CommandAlertEvent(T, ForemanSeverity.High, "cmd.exe (pid 42)", "matched",
            "whoami", "PROC-002", "Identity discovery", "", "", 42)
        {
            ProcessStartTime = T.AddHours(-1),
        };
        var recycled = new ProcessRecord
        {
            Pid = 42,
            StartTime = T.AddMinutes(-1),
            Name = "innocent-new-process.exe",
            HarnessType = "cursor",
        };

        var chain = AttributionChainBuilder.Build(evt, _ => recycled, _ => recycled);

        Assert.DoesNotContain(chain.Steps, s => s.Title.Contains("innocent", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(chain.Steps, s => s.Title.Contains("Cursor", StringComparison.OrdinalIgnoreCase));
        Assert.Equal("cmd.exe", chain.Steps[0].Title);
        Assert.Equal(AttributionConfidence.Inferred, chain.Steps[0].RelationshipConfidence);
    }

    [Fact]
    public void CommandAlert_WithExitedProcess_LabelsSourceDerivedProcessAsInferred()
    {
        var evt = new CommandAlertEvent(T, ForemanSeverity.Medium, "pwsh.exe (pid 77)", "matched",
            "Get-Process", "PROC-001", "Process discovery", "", "", 77);

        var chain = AttributionChainBuilder.Build(evt);

        Assert.Equal("pwsh.exe", chain.Steps[0].Title);
        Assert.Equal(AttributionConfidence.Inferred, chain.Steps[0].RelationshipConfidence);
        Assert.Contains("inferred element", chain.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Hang_UsesEventTimeHarnessSpawnerAndIoEvidence()
    {
        var evt = new HangDetectedEvent(T, "watchdog", "silent", 30, "node.exe", 25, 8,
            20, "cmd.exe", 10, "claude-code", "claude.exe");

        var chain = AttributionChainBuilder.Build(evt);

        Assert.Equal("Claude Code", chain.Steps[0].Title);
        Assert.Contains(chain.Steps, s => s.Title == "cmd.exe" && s.Evidence.Contains("event time"));
        Assert.Contains(chain.Steps, s => s.Title == "No I/O detected" && s.Detail.Contains("8 min"));
        Assert.Equal(0, chain.InferredLinks);
    }

    [Fact]
    public void Orphan_ShowsDeadParentAndSurvivingChild()
    {
        var evt = new OrphanDetectedEvent(T, "watchdog", "orphan", 31, "server.exe", 20,
            "node.exe", 14, 10, "codex", "Codex");

        var chain = AttributionChainBuilder.Build(evt);

        Assert.Equal(["Codex", "node.exe", "server.exe", "Orphan alert recorded"],
            chain.Steps.Select(s => s.Title));
        Assert.Contains("exited", chain.Steps[1].Detail);
    }

    [Fact]
    public void PermissionViolation_ShowsAttemptPolicyAndRecordedOutcome()
    {
        var evt = new PermissionViolationEvent(T, "python.exe (pid 9)", "denied", 9,
            "Constrained", "File write", "outside approved workspace");

        var chain = AttributionChainBuilder.Build(evt);

        Assert.Contains(chain.Steps, s => s.Kind == AttributionNodeKind.Action && s.Title == "File write");
        Assert.Contains(chain.Steps, s => s.Kind == AttributionNodeKind.Policy && s.Detail == "Constrained");
        Assert.Equal("Violation recorded", chain.Steps[^1].Title);
    }

    [Fact]
    public void NonzeroExit_ShowsExitCode()
    {
        var evt = new NonzeroExitEvent(T, "build", "failed", 88, "dotnet.exe", 1, null);

        var chain = AttributionChainBuilder.Build(evt);

        Assert.Contains(chain.Steps, s => s.Title == "Non-zero exit" && s.Detail == "Exit code 1");
    }

    [Fact]
    public void Escalation_ShowsAccumulationTriggerAndLevelTransition()
    {
        var evt = new EscalationEvent(T, EscalationLevel.Alarm, EscalationLevel.Alert,
            "codex", "Codex", "threshold crossed", 7, 3, 2, ["network", "credentials"],
            "CRED-001", "Credential access");

        var chain = AttributionChainBuilder.Build(evt);

        Assert.Equal([AttributionNodeKind.Harness, AttributionNodeKind.Detector,
            AttributionNodeKind.Detector, AttributionNodeKind.Outcome], chain.Steps.Select(s => s.Kind));
        Assert.Equal("Alert → Alarm", chain.Steps[^1].Title);
    }

    [Fact]
    public void GenericAndMonitoringEvents_AlwaysReceiveUsefulChains()
    {
        ForemanEvent[] events =
        [
            new InfoEvent(T, "Foreman.Startup", "Dashboard ready"),
            new MonitoringNoticeEvent(T, ForemanSeverity.High, "Foreman.McpInventory", "New server observed"),
        ];

        foreach (var evt in events)
        {
            var chain = AttributionChainBuilder.Build(evt);
            Assert.True(chain.Steps.Count >= 3);
            Assert.Equal(AttributionNodeKind.Outcome, chain.Steps[^1].Kind);
        }
    }

    [Fact]
    public void ResolvedEvent_EndsWithActualResolutionInsteadOfOpenAlert()
    {
        var evt = new InfoEvent(T, "Foreman", "Recovered")
        {
            AutoResolved = true,
            ResolvedReason = "I/O resumed",
        };

        var chain = AttributionChainBuilder.Build(evt);

        Assert.Equal("Auto-resolved", chain.Steps[^1].Title);
        Assert.Equal("I/O resumed", chain.Steps[^1].Detail);
    }
}
