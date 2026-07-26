using Foreman.Core.Security;

namespace Foreman.Core.Tests.Security;

public sealed class DecoyAuditEventCorrelatorTests
{
    [Fact]
    public void DeleteAccessFollowedBy4660_ProducesDeletedAlert()
    {
        const string path = @"C:\Users\u\.foreman-decoy";
        var correlator = new DecoyAuditEventCorrelator([path], []);

        var access = correlator.Process(new DecoyAuditAccessEvent(
            4663, path, 4242, @"C:\malware.exe", "0x44",
            DecoyAuditEventCorrelator.Delete));
        var deleted = correlator.Process(new DecoyAuditAccessEvent(
            4660, null, 4242, @"C:\malware.exe", "0x44", 0));

        Assert.Empty(access);
        var alert = Assert.Single(deleted);
        Assert.Equal("deleted", alert.Operation);
        Assert.Equal(path, alert.Path);
    }
}
