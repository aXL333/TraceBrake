using System.Security.Cryptography;
using System.Text.Json;
using Foreman.Core.Security;

namespace Foreman.Core.Tests.Security;

public sealed class ReleasePayloadIntegrityTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "foreman-release-" + Guid.NewGuid().ToString("N"));

    public ReleasePayloadIntegrityTests() => Directory.CreateDirectory(_root);
    public void Dispose() { try { Directory.Delete(_root, true); } catch { } }

    [Fact]
    public void ManifestedTree_Passes_ButRootDllSiblingFails()
    {
        File.WriteAllText(Path.Combine(_root, "TraceBrake.exe"), "release");
        WriteManifest("TraceBrake.exe");
        Assert.True(ReleasePayloadIntegrity.Verify(_root).Trusted);

        File.WriteAllText(Path.Combine(_root, "version.dll"), "planted");
        var result = ReleasePayloadIntegrity.Verify(_root);
        Assert.False(result.Trusted);
        Assert.Contains("tree differs", result.Reason);
    }

    [Fact]
    public void DevelopmentTreeWithoutManifest_IsNotApplicable()
    {
        var result = ReleasePayloadIntegrity.Verify(_root);
        Assert.False(result.Applicable);
        Assert.True(result.Trusted);
    }

    private void WriteManifest(params string[] files)
    {
        var entries = files.Select(path =>
        {
            var bytes = File.ReadAllBytes(Path.Combine(_root, path));
            return new { path = path.Replace('\\', '/'), sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant() };
        });
        File.WriteAllText(
            Path.Combine(_root, ReleasePayloadIntegrity.ManifestFileName),
            JsonSerializer.Serialize(new { schemaVersion = 1, files = entries }));
    }
}
