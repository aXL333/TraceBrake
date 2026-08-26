using Foreman.Vault;

namespace Foreman.Vault.Tests;

public sealed class DepositQueueTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), "foreman-depositq-" + Guid.NewGuid().ToString("N") + ".jsonl");
    public void Dispose() { try { File.Delete(_path); } catch { /* best-effort */ } }

    private static DepositQueue.PendingDeposit Dep(string origin) =>
        new(origin, Username: null, Password: "gen-pw-" + origin, ByHarness: "claude-code", CreatedAtUtc: "2026-06-30T00:00:00Z");

    [Fact]
    public void Enqueue_Drain_RoundTrips()
    {
        var (pub, priv) = DepositCrypto.GenerateKeyPair();
        var q = new DepositQueue(_path);
        Assert.True(q.Enqueue(pub, Dep("a.com")));   // locked-safe: public key only

        var r = q.Drain(priv);
        Assert.Equal(0, r.Failed);
        Assert.Single(r.Deposits);
        Assert.Equal("a.com", r.Deposits[0].Origin);
        Assert.Equal("gen-pw-a.com", r.Deposits[0].Password);
        Assert.Equal("claude-code", r.Deposits[0].ByHarness);
    }

    [Fact]
    public void Multiple_PreservesOrder_AndCount()
    {
        var (pub, priv) = DepositCrypto.GenerateKeyPair();
        var q = new DepositQueue(_path);
        q.Enqueue(pub, Dep("a.com"));
        q.Enqueue(pub, Dep("b.com"));
        q.Enqueue(pub, Dep("c.com"));
        Assert.Equal(3, q.Count);
        var r = q.Drain(priv);
        Assert.Equal(0, r.Failed);
        Assert.Equal(new[] { "a.com", "b.com", "c.com" }, r.Deposits.Select(d => d.Origin));
    }

    [Fact]
    public void Clear_EmptiesQueue()
    {
        var (pub, priv) = DepositCrypto.GenerateKeyPair();
        var q = new DepositQueue(_path);
        q.Enqueue(pub, Dep("a.com"));
        q.Clear();
        Assert.Equal(0, q.Count);
        Assert.Empty(q.Drain(priv).Deposits);
    }

    [Fact]   // wrong key / tamper is COUNTED (Failed), never thrown - so a bad line can't poison the good ones
    public void Drain_WrongPrivateKey_CountedNotThrown()
    {
        var (pub, _) = DepositCrypto.GenerateKeyPair();
        var (_, privOther) = DepositCrypto.GenerateKeyPair();
        var q = new DepositQueue(_path);
        q.Enqueue(pub, Dep("a.com"));
        var r = q.Drain(privOther);
        Assert.Empty(r.Deposits);
        Assert.Equal(1, r.Failed);
    }

    [Fact]   // a single junk line must not DoS the genuine deposits sitting in the same file
    public void Drain_ResilientToJunkLine()
    {
        var (pub, priv) = DepositCrypto.GenerateKeyPair();
        var q = new DepositQueue(_path);
        q.Enqueue(pub, Dep("good.com"));
        File.AppendAllText(_path, "{not a valid envelope}" + Environment.NewLine);   // corruption / attacker append
        q.Enqueue(pub, Dep("good2.com"));

        var r = q.Drain(priv);
        Assert.Equal(1, r.Failed);
        Assert.Equal(new[] { "good.com", "good2.com" }, r.Deposits.Select(d => d.Origin));
    }

    [Fact]   // a flood can't grow the queue without bound while locked (anti review-fatigue)
    public void Enqueue_EnforcesMaxQueuedCap()
    {
        var (pub, _) = DepositCrypto.GenerateKeyPair();
        var q = new DepositQueue(_path);
        for (var i = 0; i < DepositQueue.MaxQueued; i++)
            Assert.True(q.Enqueue(pub, Dep($"s{i}.com")));
        Assert.False(q.Enqueue(pub, Dep("overflow.com")));   // cap hit -> refused, appends nothing
        Assert.Equal(DepositQueue.MaxQueued, q.Count);
    }

    [Fact]
    public void Drain_OversizedForgedLine_IsSkippedWithoutHidingLaterDeposit()
    {
        var (pub, priv) = DepositCrypto.GenerateKeyPair();
        var q = new DepositQueue(_path);
        Assert.True(q.Enqueue(pub, Dep("good.com")));
        var good = File.ReadAllText(_path);
        File.WriteAllText(_path, new string('A', DepositQueue.MaxLineChars + 1) + Environment.NewLine + good);

        var result = q.Drain(priv);

        Assert.Equal(1, result.Failed);
        Assert.Single(result.Deposits);
        Assert.Equal("good.com", result.Deposits[0].Origin);
    }

    [Fact]
    public void OversizedQueueFile_IsTreatedAsFullAndNotReadIntoMemory()
    {
        using (var stream = new FileStream(_path, FileMode.Create, FileAccess.Write, FileShare.None))
            stream.SetLength(DepositQueue.MaxQueueBytes + 1);
        var (pub, priv) = DepositCrypto.GenerateKeyPair();
        var q = new DepositQueue(_path);

        Assert.Equal(DepositQueue.MaxQueued, q.Count);
        Assert.False(q.Enqueue(pub, Dep("blocked.com")));
        var result = q.Drain(priv);
        Assert.Empty(result.Deposits);
        Assert.Equal(1, result.Failed);
    }

    [Fact]
    public void Enqueue_RejectsOversizedAttackerClaims()
    {
        var (pub, _) = DepositCrypto.GenerateKeyPair();
        var q = new DepositQueue(_path);
        var oversized = Dep(new string('x', DepositQueue.MaxClaimChars + 1));

        Assert.False(q.Enqueue(pub, oversized));
        Assert.Equal(0, q.Count);
    }
}
