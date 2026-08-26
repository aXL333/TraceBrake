using Foreman.McpServer;

namespace Foreman.McpServer.Tests;

public sealed class LiveWeaveBrokerTests
{
    [Fact]
    public void Enqueue_Poll_Complete_RoundTrip()
    {
        var broker = new LiveWeaveBroker();
        broker.SetDriver("codex");
        var id = broker.Enqueue("apply_page", new Dictionary<string, object?> { ["html"] = "<main>x</main>" }, "codex");
        Assert.Equal(32, id.Length);

        var batch = broker.Poll(5);
        Assert.Single(batch);
        Assert.Equal(id, batch[0].CommandId);
        Assert.Equal("apply_page", batch[0].Action);

        var done = broker.Complete(id, true, new { ok = true }, null);
        Assert.True(done.Ok);

        var cmd = broker.GetCommand(id);
        Assert.NotNull(cmd);
        Assert.Equal(LiveWeaveCommandStatus.Completed, cmd!.Status);
        Assert.NotNull(cmd.Result);
    }

    [Fact]
    public void Poll_NoDriver_FailsHarnessCommand()
    {
        var broker = new LiveWeaveBroker();
        var id = broker.Enqueue("apply_page", new Dictionary<string, object?> { ["html"] = "<main>x</main>" }, "codex");

        Assert.Empty(broker.Poll(5));

        var cmd = broker.GetCommand(id);
        Assert.NotNull(cmd);
        Assert.Equal(LiveWeaveCommandStatus.Failed, cmd!.Status);
        Assert.Contains("no harness driver selected", cmd.Error);
    }

    [Fact]
    public void Poll_Is_Empty_When_No_Pending()
    {
        var broker = new LiveWeaveBroker();
        Assert.Empty(broker.Poll(3));
    }

    [Fact]
    public void StaleCommand_NeverDelivered_ExpiresToFailed_SoTheAgentPollStopsHanging()
    {
        var now = DateTimeOffset.UtcNow;
        var broker = new LiveWeaveBroker(() => now);
        broker.SetDriver("codex");
        var id = broker.Enqueue("apply_page", new Dictionary<string, object?> { ["html"] = "<main>x</main>" }, "codex");

        // Extension never polls (closed / unpaired / Foreman was offline). Advance past the stale window.
        now = now.AddMinutes(3);

        var cmd = broker.GetCommand(id);   // the agent's liveweave_command_result path
        Assert.NotNull(cmd);
        Assert.Equal(LiveWeaveCommandStatus.Failed, cmd!.Status);
        Assert.Contains("timed out", cmd.Error);
    }

    [Fact]
    public void StaleDeliveredCommand_BecomesUncertain_AndAcceptsLateCompletion()
    {
        var now = DateTimeOffset.UtcNow;
        var broker = new LiveWeaveBroker(() => now);
        broker.SetDriver("codex");
        var id = broker.Enqueue("apply_page", new Dictionary<string, object?> { ["html"] = "<main>x</main>" }, "codex");

        Assert.Single(broker.Poll(5));     // extension took it (Delivered) but crashes before completing

        now = now.AddMinutes(3);
        var cmd = broker.GetCommand(id);
        Assert.Equal(LiveWeaveCommandStatus.TimedOut, cmd!.Status);
        Assert.Contains("do not resubmit", cmd.Error);

        var late = broker.Complete(id, true, new { ok = true }, null);
        Assert.True(late.Ok);
        Assert.Equal(LiveWeaveCommandStatus.Completed, broker.GetCommand(id)!.Status);
    }

    [Fact]
    public void FreshCommand_WithinWindow_IsNotExpired()
    {
        var now = DateTimeOffset.UtcNow;
        var broker = new LiveWeaveBroker(() => now);
        broker.SetDriver("codex");
        var id = broker.Enqueue("apply_page", new Dictionary<string, object?> { ["html"] = "<main>x</main>" }, "codex");

        now = now.AddSeconds(30);          // still well inside the 2-min window
        var cmd = broker.GetCommand(id);
        Assert.Equal(LiveWeaveCommandStatus.Pending, cmd!.Status);
        Assert.Single(broker.Poll(5));     // and it still delivers normally
    }

    [Fact]
    public void OversizedParameters_RejectedAsFailed_NotQueued()
    {
        var broker = new LiveWeaveBroker();
        broker.SetDriver("codex");
        var huge = new string('x', 300 * 1024);   // > the 256 KB cap
        var id = broker.Enqueue("apply_page", new Dictionary<string, object?> { ["html"] = huge }, "codex");

        var cmd = broker.GetCommand(id);
        Assert.Equal(LiveWeaveCommandStatus.Failed, cmd!.Status);
        Assert.Contains("too large", cmd.Error);
        Assert.Empty(broker.Poll(5));      // never enters the delivery queue
    }

    [Fact]
    public void PerHarnessFlood_RejectsBeyondTheCap()
    {
        var broker = new LiveWeaveBroker();
        broker.SetDriver("codex");
        for (var i = 0; i < 30; i++)       // fill the per-harness pending cap (all stay Pending — driver matches)
            broker.Enqueue("set_background", new Dictionary<string, object?> { ["value"] = "#111" }, "codex");

        var overflow = broker.Enqueue("set_background", new Dictionary<string, object?> { ["value"] = "#222" }, "codex");
        var cmd = broker.GetCommand(overflow);
        Assert.Equal(LiveWeaveCommandStatus.Failed, cmd!.Status);
        Assert.Contains("Too many", cmd.Error);
    }

    [Fact]
    public void DoubleComplete_SecondCallReports_AlreadyCompleted()
    {
        var broker = new LiveWeaveBroker();
        broker.SetDriver("codex");
        var id = broker.Enqueue("apply_page", new Dictionary<string, object?> { ["html"] = "<main>x</main>" }, "codex");
        broker.Poll(5);

        Assert.True(broker.Complete(id, ok: true, result: new { ok = true }, error: null).Ok);
        var second = broker.Complete(id, ok: true, result: new { ok = true }, error: null);
        Assert.False(second.Ok);
        Assert.Contains("already completed", second.Reason);
    }

    [Fact]
    public void Enqueue_SnapshotsMutableParametersBeforeAuditAndDelivery()
    {
        var broker = new LiveWeaveBroker();
        broker.SetDriver("codex");
        var parameters = new Dictionary<string, object?> { ["html"] = "<main>safe</main>" };
        var id = broker.Enqueue("apply_page", parameters, "codex");

        parameters["html"] = "<script>changed-after-enqueue()</script>";

        var delivered = Assert.Single(broker.Poll(1));
        Assert.Equal(id, delivered.CommandId);
        Assert.Contains("safe", delivered.Parameters["html"]!.ToString());
        Assert.DoesNotContain("changed-after-enqueue", delivered.Parameters["html"]!.ToString());
    }
}
