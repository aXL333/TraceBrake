namespace Foreman.Monitor.Tests;

public sealed class HarnessAppModelFailurePolicyTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 4, 2, 38, 45, TimeSpan.Zero);

    [Fact]
    public void Parse_ClaudeJobConversionFailure_AttributesPreProcessIncident()
    {
        const string message = "0x80070020: Cannot create the Desktop AppX container for package " +
            "Claude_1.24012.11.0_x64__pzs8sxrjxfjjc because an error was encountered converting the job.";

        var failure = HarnessAppModelFailurePolicy.Parse(215, Now, message);

        Assert.NotNull(failure);
        Assert.Equal("claude-code", failure!.HarnessId);
        Assert.Equal("Claude", failure.HarnessName);
        Assert.Equal("0X80070020", failure.ErrorCode);
        Assert.Equal("Desktop AppX job conversion failed", failure.FailureKind);
        Assert.Equal("Claude_1.24012.11.0_x64__pzs8sxrjxfjjc", failure.PackageFullName);
    }

    [Fact]
    public void Parse_ClaudeRuntimeFailure_HandlesSiblingEvent208()
    {
        const string message = "0x80070020: Cannot create the process for package " +
            "Claude_1.24012.11.0_x64__pzs8sxrjxfjjc because an error was encountered while configuring runtime.";

        var failure = HarnessAppModelFailurePolicy.Parse(208, Now, message);

        Assert.NotNull(failure);
        Assert.Equal("packaged runtime configuration failed", failure!.FailureKind);
    }

    [Theory]
    [InlineData(215, "0x80070020: package Unrelated.Product_1.0_x64__publisher failed converting the job")]
    [InlineData(999, "0x80070020: package Claude_1.0_x64__publisher failed converting the job")]
    [InlineData(215, "unstructured error without a package identity")]
    public void Parse_IgnoresUnrelatedOrUntrustedEvents(int eventId, string message)
        => Assert.Null(HarnessAppModelFailurePolicy.Parse(eventId, Now, message));
}
