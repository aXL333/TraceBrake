using Foreman.Core.Health;
using Foreman.Core.Models;

namespace Foreman.Core.Tests.Health;

public sealed class SidecarSupervisorTests
{
    // A tiny controllable rig: mutable up/connected flags, a relaunch counter, and a captured notice log.
    private sealed class Rig
    {
        public bool ExpectedUp = true;
        public bool Connected;
        public bool LaunchDeclined;
        public bool LaunchInProgress;
        public bool ThrowOnNotify;
        public bool ThrowOnRelaunch;
        public bool DeclineOnRelaunch;
        public int Relaunches;
        public readonly List<(ForemanSeverity Sev, string Msg)> Notices = [];
        public SidecarSupervisor Make(int maxRelaunch = 2, int graceTicks = 1) => new(
            () => ExpectedUp,
            () => Connected,
            () => LaunchDeclined,
            () =>
            {
                Relaunches++;
                if (DeclineOnRelaunch) LaunchDeclined = true;
                if (ThrowOnRelaunch) throw new InvalidOperationException("relaunch failed");
            },
            (sev, msg) =>
            {
                if (ThrowOnNotify) throw new InvalidOperationException("notice sink failed");
                Notices.Add((sev, msg));
            },
            maxRelaunch, graceTicks,
            () => LaunchInProgress);
    }

    [Fact]
    public void FeatureOff_DoesNothing()
    {
        var rig = new Rig { ExpectedUp = false, Connected = false };
        var sup = rig.Make();
        for (var i = 0; i < 5; i++) sup.Tick();
        Assert.Empty(rig.Notices);
        Assert.Equal(0, rig.Relaunches);
    }

    [Fact]
    public void HealthyAndConnected_NeverAlertsOrRelaunches()
    {
        var rig = new Rig { Connected = true };
        var sup = rig.Make();
        for (var i = 0; i < 10; i++) sup.Tick();
        Assert.Empty(rig.Notices);
        Assert.Equal(0, rig.Relaunches);
    }

    [Fact]
    public void CrashedSidecar_IsRelaunchedBounded_ThenGivesUpWithNotice()
    {
        var rig = new Rig { Connected = true };
        var sup = rig.Make(maxRelaunch: 2, graceTicks: 1);

        sup.Tick();                       // t1: connected → wasConnected
        rig.Connected = false;
        sup.Tick();                       // t2: down, grace → no action
        Assert.Equal(0, rig.Relaunches);
        Assert.Empty(rig.Notices);

        sup.Tick();                       // t3: relaunch #1 + one High "stopped" notice
        sup.Tick();                       // t4: relaunch #2 (no new notice)
        sup.Tick();                       // t5: exhausted → one High "keeps stopping" notice
        sup.Tick();                       // t6: nothing new

        Assert.Equal(2, rig.Relaunches);
        Assert.Equal(2, rig.Notices.Count);
        Assert.All(rig.Notices, n => Assert.Equal(ForemanSeverity.High, n.Sev));
        Assert.Contains("stopped unexpectedly", rig.Notices[0].Msg);
        Assert.Contains("keeps stopping", rig.Notices[1].Msg);
    }

    [Fact]
    public void NeverConnected_AlertsOnce_AndNeverRelaunches()   // declined UAC / missing helper → no UAC-loop
    {
        var rig = new Rig { Connected = false };
        var sup = rig.Make();

        sup.Tick();                       // grace
        Assert.Empty(rig.Notices);
        for (var i = 0; i < 6; i++) sup.Tick();

        Assert.Equal(0, rig.Relaunches);
        var high = Assert.Single(rig.Notices);
        Assert.Equal(ForemanSeverity.High, high.Sev);
        Assert.Contains("isn't running", high.Msg);
    }

    [Fact]
    public void Recovery_EmitsInfo_AndReArmsForTheNextDrop()
    {
        var rig = new Rig { Connected = false };
        var sup = rig.Make(maxRelaunch: 0);   // no auto-relaunch so we can drive the down/up cycle deterministically

        sup.Tick(); sup.Tick();               // grace, then a High down notice
        Assert.Single(rig.Notices);

        rig.Connected = true;
        sup.Tick();                            // reconnect → Info
        Assert.Equal(2, rig.Notices.Count);
        Assert.Equal(ForemanSeverity.Info, rig.Notices[1].Sev);

        // A subsequent drop must be able to alert again (episode state was reset on reconnect).
        rig.Connected = false;
        sup.Tick(); sup.Tick();               // grace, then another High down notice
        Assert.Equal(3, rig.Notices.Count);
        Assert.Equal(ForemanSeverity.High, rig.Notices[2].Sev);
    }

    [Fact]   // was connected, but a settings-toggle re-elevation was DECLINED → NOT a crash: alert once, no relaunch
    public void DeclinedReElevationAfterConnected_IsNotTreatedAsCrash()
    {
        var rig = new Rig { Connected = true };
        var sup = rig.Make(maxRelaunch: 2, graceTicks: 1);

        sup.Tick();                       // connected → wasConnected
        rig.Connected = false;
        rig.LaunchDeclined = true;        // the re-elevation prompt was declined
        sup.Tick();                       // grace
        for (var i = 0; i < 5; i++) sup.Tick();

        Assert.Equal(0, rig.Relaunches);  // crucially: no UAC re-prompt loop
        var high = Assert.Single(rig.Notices);
        Assert.Equal(ForemanSeverity.High, high.Sev);
        Assert.Contains("declined", high.Msg);
    }

    [Fact]
    public void BriefDisconnectWithinGrace_IsRiddenOut_NoRelaunchNoNotice()
    {
        var rig = new Rig { Connected = true };
        var sup = rig.Make(graceTicks: 1);

        sup.Tick();                       // connected → wasConnected
        rig.Connected = false;
        sup.Tick();                       // one down tick (grace) — a toggle-restart's blip
        rig.Connected = true;
        sup.Tick();                       // back up before grace expired

        Assert.Equal(0, rig.Relaunches);
        Assert.Empty(rig.Notices);
    }

    [Fact]
    public void FeatureDisabledMidDownSpell_ResetsCleanly()
    {
        var rig = new Rig { Connected = false };
        var sup = rig.Make();

        sup.Tick(); sup.Tick();           // drives a down notice
        Assert.Single(rig.Notices);

        rig.ExpectedUp = false;
        sup.Tick();                        // feature off → reset, no new notice

        // Re-enable, still down → a fresh episode alerts again (not suppressed by the old _downNotified).
        rig.ExpectedUp = true;
        sup.Tick(); sup.Tick();
        Assert.Equal(2, rig.Notices.Count);
    }

    [Fact]
    public void PendingUacLaunch_DoesNotStackAnotherRelaunch()
    {
        var rig = new Rig { Connected = true };
        var sup = rig.Make(graceTicks: 0);

        sup.Tick();
        rig.Connected = false;
        rig.LaunchInProgress = true;
        for (var i = 0; i < 2; i++) sup.Tick();

        Assert.Equal(0, rig.Relaunches);
        Assert.Empty(rig.Notices);

        rig.LaunchInProgress = false;
        sup.Tick();
        Assert.Equal(1, rig.Relaunches);
    }

    [Fact]
    public void PendingUacLaunch_RemainsOwnedByControllerUntilItActuallyResolves()
    {
        var rig = new Rig { Connected = true, DeclineOnRelaunch = true };
        var sup = rig.Make(maxRelaunch: 1, graceTicks: 0);
        sup.Tick();

        rig.Connected = false;
        rig.LaunchInProgress = true;
        for (var i = 0; i < 20; i++) sup.Tick();

        Assert.Empty(rig.Notices);
        Assert.Equal(0, rig.Relaunches);
        Assert.False(rig.LaunchDeclined);

        rig.LaunchInProgress = false;
        sup.Tick();

        Assert.Equal(1, rig.Relaunches);
        Assert.True(rig.LaunchDeclined);
        var notice = Assert.Single(rig.Notices);
        Assert.Equal(ForemanSeverity.High, notice.Sev);
        Assert.Contains("stopped unexpectedly", notice.Msg);
    }

    [Fact]
    public void ThrowingRelaunchConsumesBudgetAndEventuallyReportsExhaustion()
    {
        var rig = new Rig { Connected = true, ThrowOnRelaunch = true };
        var sup = rig.Make(maxRelaunch: 1, graceTicks: 0);
        sup.Tick();
        rig.Connected = false;

        sup.Tick();
        sup.Tick();

        Assert.Equal(1, rig.Relaunches);
        Assert.Contains(rig.Notices, n => n.Msg.Contains("keeps stopping", StringComparison.Ordinal));
    }

    [Fact]
    public void ThrowingNotice_DoesNotBurnRelaunchWithoutRecovery()
    {
        var rig = new Rig { Connected = true, ThrowOnNotify = true };
        var sup = rig.Make(maxRelaunch: 1, graceTicks: 0);

        sup.Tick();
        rig.Connected = false;
        sup.Tick();

        Assert.Equal(1, rig.Relaunches);
    }

    [Fact]
    public void ExplicitReset_ClearsStateForFastOffOnBetweenTicks()
    {
        var rig = new Rig { Connected = false };
        var sup = rig.Make(graceTicks: 0);
        sup.Tick();
        Assert.Single(rig.Notices);

        // Settings callbacks observe off-to-on even though the periodic Tick never sees ExpectedUp=false.
        sup.ResetEpisode();
        sup.Tick();

        Assert.Equal(2, rig.Notices.Count);
    }
}
