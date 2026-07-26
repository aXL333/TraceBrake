using Foreman.Guardian;

namespace Foreman.Guardian.Tests;

/// <summary>
/// Circle-back Phase A, step 6: the guardian's Authenticode gate — used both to authenticate pipe clients (only
/// the same-publisher Foreman may request a seal) and to self-verify before installing as SYSTEM (LPE guard). The
/// pure release and install decisions fail closed for unsigned inputs.
/// </summary>
public sealed class GuardianIntegrityTests
{
    [Fact]
    public void InstallReferenceUnsigned_FailsClosed()
        => Assert.False(GuardianIntegrity.Decide(referenceSigner: null, subjectSigner: "ABC").Trusted);

    [Fact]
    public void SubjectUnsigned_ReferenceSigned_Rejects() // signed release vs an unsigned impostor
        => Assert.False(GuardianIntegrity.Decide(referenceSigner: "ABC", subjectSigner: null).Trusted);

    [Fact]
    public void DifferentPublisher_Rejects()
        => Assert.False(GuardianIntegrity.Decide(referenceSigner: "ABC", subjectSigner: "DEF").Trusted);

    [Fact]
    public void SamePublisher_Allows()
        => Assert.True(GuardianIntegrity.Decide(referenceSigner: "ABC", subjectSigner: "abc").Trusted); // case-insensitive thumbprint

    [Fact]
    public void UnsignedInstall_ArbitraryRootCannotBypassRecordedHklmRoot()
    {
        var result = GuardianIntegrity.DecideForInstall(
            referenceSigner: null,
            subjectSigner: null,
            foremanPath: @"C:\Users\attacker\x\Foreman.exe",
            guardianPath: @"C:\Users\attacker\x\guardian\Foreman.Guardian.exe",
            recordedInstallRoot: @"C:\Users\operator\AppData\Local\Programs\Foreman");

        Assert.False(result.Trusted);
        Assert.Contains("administrator-recorded", result.Reason);
    }

    [Fact]
    public void UnsignedInstall_MissingRecordedRootCannotBeAuthorisedByArgv()
    {
        const string root = @"C:\Foreman-dev";
        var result = GuardianIntegrity.DecideForInstall(
            null, null, root + @"\Foreman.exe", root + @"\guardian\Foreman.Guardian.exe", recordedInstallRoot: null);

        Assert.False(result.Trusted);
        Assert.Contains("argv-independent", result.Reason);
    }

    [Fact]
    public void SignedInstall_MissingRecordedRootCanEstablishAnchor()
    {
        const string root = @"C:\Program Files\Foreman";
        var result = GuardianIntegrity.DecideForInstall(
            "AABB", "aabb", root + @"\Foreman.exe", root + @"\guardian\Foreman.Guardian.exe",
            recordedInstallRoot: null);

        Assert.True(result.Trusted);
    }
}
