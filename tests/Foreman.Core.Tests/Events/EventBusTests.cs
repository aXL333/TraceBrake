using Foreman.Core.Events;
using Foreman.Core.Models;

namespace Foreman.Core.Tests.Events;

public sealed class EventBusTests
{
    [Fact]
    public void Unsubscribe_HandlerStopsReceivingEvents()
    {
        var bus = new EventBus();   // isolated — not the shared Instance
        var count = 0;
        void Handler(ForemanEvent _) => count++;

        bus.Subscribe(Handler);
        bus.Publish(new InfoEvent(DateTimeOffset.UtcNow, "test", "before"));
        bus.Unsubscribe(Handler);
        bus.Publish(new InfoEvent(DateTimeOffset.UtcNow, "test", "after"));

        Assert.Equal(1, count);
    }

    [Fact]
    public void BoundedHistory_RetainsUnacknowledgedCriticalAheadOfNewNoise()
    {
        var history = new BoundedEventHistory(3);
        var critical = new MonitoringNoticeEvent(
            DateTimeOffset.UnixEpoch, ForemanSeverity.Critical, "test", "do not lose me");
        history.Add(critical);
        history.Add(new InfoEvent(DateTimeOffset.UnixEpoch.AddSeconds(1), "test", "noise 1"));
        history.Add(new InfoEvent(DateTimeOffset.UnixEpoch.AddSeconds(2), "test", "noise 2"));
        history.Add(new InfoEvent(DateTimeOffset.UnixEpoch.AddSeconds(3), "test", "noise 3"));

        Assert.Contains(history.Snapshot(), e => e.Id == critical.Id);
        Assert.Equal(3, history.Snapshot().Count);
    }

    [Fact]
    public void BoundedHistory_EvictsAcknowledgedCriticalBeforeActiveNoise()
    {
        var history = new BoundedEventHistory(2);
        var acknowledged = new MonitoringNoticeEvent(
            DateTimeOffset.UnixEpoch, ForemanSeverity.Critical, "test", "resolved") { Acknowledged = true };
        history.Add(acknowledged);
        history.Add(new MonitoringNoticeEvent(
            DateTimeOffset.UnixEpoch.AddSeconds(1), ForemanSeverity.Medium, "test", "active"));
        history.Add(new MonitoringNoticeEvent(
            DateTimeOffset.UnixEpoch.AddSeconds(2), ForemanSeverity.Medium, "test", "new"));

        Assert.DoesNotContain(history.Snapshot(), e => e.Id == acknowledged.Id);
    }

    [Fact]
    public void BoundedHistory_AgentCriticalFloodCannotDropArrivingHostHigh()
    {
        var history = new BoundedEventHistory(1000);
        for (var i = 0; i < 1_100; i++)
            history.Add(AgentCritical(i));

        var hostHigh = new MonitoringNoticeEvent(
            DateTimeOffset.UtcNow, ForemanSeverity.High, "Foreman.Settings", "genuine host alarm");
        history.Add(hostHigh);

        Assert.Contains(history.Snapshot(), e => e.Id == hostHigh.Id);
        Assert.True(history.Snapshot().Count(e => EventRetentionPolicy.IsAgentReported(e)) <= 250);
    }

    [Fact]
    public void BoundedHistory_ArrivingHostCriticalIsNeverItsOwnEvictionVictim()
    {
        var history = new BoundedEventHistory(2);
        history.Add(new MonitoringNoticeEvent(
            DateTimeOffset.UtcNow, ForemanSeverity.Critical, "Foreman.Guardian", "host one"));
        history.Add(new MonitoringNoticeEvent(
            DateTimeOffset.UtcNow, ForemanSeverity.Critical, "Foreman.Guardian", "host two"));
        var arriving = new MonitoringNoticeEvent(
            DateTimeOffset.UnixEpoch, ForemanSeverity.Critical, "Foreman.Settings", "arriving host");

        history.Add(arriving);

        Assert.Contains(history.Snapshot(), e => e.Id == arriving.Id);
    }

    [Fact]
    public void AttackerControlledMcpFilename_DoesNotChangeHostProvenance()
    {
        var decoyRead = new CommandAlertEvent(
            DateTimeOffset.UnixEpoch, ForemanSeverity.Critical, "MCP.exe (pid 4242)", "decoy read",
            "MCP.exe", "cred-decoy-read", "Decoy read", "desc", "guidance", 4242);

        Assert.False(EventRetentionPolicy.IsAgentReported(decoyRead));

        var history = new BoundedEventHistory(251);
        history.Add(decoyRead);
        for (var i = 0; i < 300; i++) history.Add(AgentCritical(i));
        Assert.Contains(history.Snapshot(), e => e.Id == decoyRead.Id);
    }

    private static CommandAlertEvent AgentCritical(int index) => new(
        DateTimeOffset.UtcNow.AddMilliseconds(index), ForemanSeverity.Critical,
        "MCP.ReportSuspiciousCommand", $"fabricated {index}", "rm -rf /", "del-001", "delete", "test", "none", 0)
        { Origin = EventOrigin.Agent };
}
