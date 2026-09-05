using Foreman.Core.Alerts;
using Foreman.Core.Behavior;
using Foreman.Core.Events;
using Foreman.Core.Models;

namespace Foreman.Core.Tests.Alerts;

public sealed class HangLearningTests
{
    private static readonly DateTimeOffset T = DateTimeOffset.UnixEpoch.AddDays(100);
    private static readonly HangFeatureSnapshot Features = new(
        1, 30, 60, .5, 10, 20, 3, 1, 2, 0,
        HarnessActivity.Active, 30, 1, true);

    private static HangDetectedEvent Hang() => new(
        T, "Foreman.Monitor", "candidate", 42, "worker.exe", 60, 30,
        40, "shell.exe", 41, "codex", "codex.exe", Features)
        { ProcessStartTime = T.AddHours(-1) };

    [Fact]
    public void BuildRows_UsesOnlyExplicitBinaryOperatorLabelAsGold()
    {
        var hang = Hang();
        var recovered = HangLearning.Outcome(hang, HangOutcomeKind.IoResumed, T.AddMinutes(1), false);
        var unsure = HangLearning.Outcome(hang, HangOutcomeKind.OperatorUnsure, T.AddMinutes(2), true);
        var labelled = HangLearning.Outcome(hang, HangOutcomeKind.OperatorExpectedIdle, T.AddMinutes(3), true);

        var row = Assert.Single(HangLearning.BuildRows([hang, recovered, unsure, labelled]));

        Assert.Equal(0, row.Label);
        Assert.True(row.GoldLabel);
        Assert.Equal(HangOutcomeKind.OperatorExpectedIdle, row.LatestOutcome);
        Assert.Same(Features, row.Features);
    }

    [Fact]
    public void AutomaticRecovery_IsOutcomeButNotTrainingLabel()
    {
        var hang = Hang();
        var recovered = HangLearning.Outcome(hang, HangOutcomeKind.IoResumed, T.AddMinutes(1), false);

        var row = Assert.Single(HangLearning.BuildRows([hang, recovered]));

        Assert.Null(row.Label);
        Assert.False(row.GoldLabel);
        Assert.Equal(HangOutcomeKind.IoResumed, row.LatestOutcome);
    }
}
