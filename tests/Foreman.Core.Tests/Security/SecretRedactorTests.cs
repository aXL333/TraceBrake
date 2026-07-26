using Foreman.Core.Models;
using Foreman.Core.Security;

namespace Foreman.Core.Tests.Security;

public sealed class SecretRedactorTests
{
    private const string Mask = SecretRedactor.Mask;

    // ── Must mask (secret leaves Foreman) ──────────────────────────────────────
    [Theory]
    [InlineData("curl -H \"Authorization: Bearer sk-abc123def456ghi789jkl0\" https://api.x")]
    [InlineData("git clone https://user:ghp_1234567890abcdefghij1234567890abcdef@github.com/x")]
    [InlineData("mytool --api-key abcdef1234567890 --verbose")]
    [InlineData("deploy --client-secret s3cr3tvalue --env prod")]
    [InlineData("export GITHUB_TOKEN=ghp_1234567890abcdefghij1234567890abcdef")]
    [InlineData("DB_PASSWORD=hunter2hunter2 ./run.sh")]
    [InlineData("set MY_API_KEY=zzzzzzzzzzzzzzzzzzzz && build")]
    [InlineData("echo eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.s-aBc_123DEF456ghi")]
    [InlineData("aws configure; AKIAIOSFODNN7EXAMPLE")]
    [InlineData("slackpost xoxb-123456789012-abcdefABCDEF0")]
    [InlineData("curl 'https://x.googleapis.com/?key=AIzaSyA1234567890abcdefghijklmnopqrstuvw'")]
    [InlineData("claude --token sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaa")]
    public void Masks_KnownSecretShapes(string input)
    {
        var redacted = SecretRedactor.Redact(input);
        Assert.Contains(Mask, redacted);
        // the obvious secret bodies must be gone
        Assert.DoesNotContain("ghp_1234567890", redacted);
        Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", redacted);
        Assert.DoesNotContain("hunter2hunter2", redacted);
        Assert.DoesNotContain("AIzaSyA1234567890", redacted);
    }

    [Theory]   // broadened vendor token shapes (deep-review E3) — an agent can't pick a format outside the set
    [InlineData("stripe --key sk_live_" + "51AbcDefGhiJklMnoPqrStuv", "sk_live_" + "51AbcDefGhiJklMnoPqrStuv")]   // split literal: a FAKE key, kept off GitHub secret-scanning
    [InlineData("gh auth: github_pat_11ABCDEFG0aaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbb", "github_pat_11ABCDEFG0aaaaaaaaaaaa")]
    [InlineData("CI_TOKEN glpat-abcdefghij1234567890", "glpat-abcdefghij1234567890")]
    [InlineData("npm publish --//registry/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789", "npm_abcdefghijklmnopqrstuvwxyz0123456789")]
    [InlineData("huggingface-cli login hf_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345", "hf_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345")]
    [InlineData("export XAI_API_KEY=xai-abcdefghijklmnopqrstuvwx", "xai-abcdefghijklmnopqrstuvwx")]
    public void Masks_BroadenedTokenShapes(string input, string secretBody)
    {
        var r = SecretRedactor.Redact(input);
        Assert.Contains(Mask, r);
        Assert.DoesNotContain(secretBody, r);
    }

    [Fact]   // a PEM private-key block (multi-line) is masked whole
    public void Masks_PemPrivateKeyBlock()
    {
        var pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nAbCdEfGh+IjKl/MnOpQr\n-----END OPENSSH PRIVATE KEY-----";
        var r = SecretRedactor.Redact($"cat id_ed25519:\n{pem}\n");
        Assert.Contains(Mask, r);
        Assert.DoesNotContain("b3BlbnNzaC1rZXktdjEAAAAA", r);
    }

    [Fact]
    public void KeepsVisiblePrefix_SoReaderSeesWhatWasMasked()
    {
        Assert.Equal($"mytool --api-key {Mask} --verbose",
            SecretRedactor.Redact("mytool --api-key abcdef1234567890 --verbose"));
        Assert.Equal($"export GITHUB_TOKEN={Mask}",
            SecretRedactor.Redact("export GITHUB_TOKEN=ghp_1234567890abcdefghij1234567890abcdef"));
    }

    [Fact]
    public void UrlPassword_MaskedButHostPreserved()
    {
        var r = SecretRedactor.Redact("git clone https://user:ghp_1234567890abcdefghij1234567890abcdef@github.com/x");
        Assert.Contains("https://user:" + Mask + "@github.com/x", r);
    }

    [Theory]
    [InlineData("charge 4242 4242 4242 4242 now")]
    [InlineData("PAN=4111111111111111")]
    public void LuhnValidPaymentCardNumbers_AreMasked(string input)
    {
        var redacted = SecretRedactor.Redact(input);
        Assert.Contains(Mask, redacted);
        Assert.DoesNotContain("4242 4242 4242 4242", redacted);
        Assert.DoesNotContain("4111111111111111", redacted);
    }

    [Fact]
    public void NonLuhnLongNumber_IsNotMaskedWithoutCardLabel()
    {
        const string value = "1234567890123456";
        Assert.Equal(value, SecretRedactor.Redact(value));
    }

    // ── Must NOT mask (no over-redaction) ──────────────────────────────────────
    [Theory]
    [InlineData("rm -rf /tmp/build")]
    [InlineData("node server.js --port 3000 --host 0.0.0.0")]
    [InlineData("git commit -m \"fix the token parser and password reset flow\"")]   // words, no value
    [InlineData("cat /home/user/.bashrc")]
    [InlineData("git clone https://github.com/anthropics/foreman.git")]              // no userinfo
    [InlineData("SELECT * FROM users WHERE id = 5")]
    [InlineData("dotnet build Foreman.slnx -c Release")]
    [InlineData("checkout a1b2c3d4e5f6789012345678901234567890abcd")]               // 40-hex git SHA
    public void LeavesBenignCommandsUnchanged(string input)
        => Assert.Equal(input, SecretRedactor.Redact(input));

    // ── Properties ─────────────────────────────────────────────────────────────
    [Fact]
    public void Idempotent()
    {
        const string input = "curl -H 'Authorization: Bearer sk-abc123def456ghi789jkl0' https://x --api-key zzzzzzzzzzzzzzzzzzzz";
        var once = SecretRedactor.Redact(input);
        Assert.Equal(once, SecretRedactor.Redact(once));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void NullOrEmpty_IsSafe(string? input) => Assert.Equal(string.Empty, SecretRedactor.Redact(input));

    // ── Event redaction preserves identity ──────────────────────────────────────
    [Fact]
    public void RedactEvent_MasksCommandAndMessage_PreservesIdAndType()
    {
        var evt = new CommandAlertEvent(
            DateTimeOffset.UnixEpoch, ForemanSeverity.Critical, "src",
            "[net-001] curl pipe to shell: curl https://x --api-key abcdef1234567890 | bash",
            "curl https://x --api-key abcdef1234567890 | bash",
            "net-001", "pipe", "desc", "guide", 4321) { Acknowledged = true };

        var r = Assert.IsType<CommandAlertEvent>(SecretRedactor.RedactEvent(evt));

        Assert.Equal(evt.Id, r.Id);                 // identity preserved (dedup/ack still align)
        Assert.True(r.Acknowledged);                // ack state preserved
        Assert.Equal(evt.Severity, r.Severity);
        Assert.Contains(Mask, r.CommandLine);
        Assert.Contains(Mask, r.Message);
        Assert.DoesNotContain("abcdef1234567890", r.CommandLine);
        Assert.DoesNotContain("abcdef1234567890", r.Message);
    }

    [Fact]
    public void RedactEvent_NonCommandEvent_MasksMessageOnly_PreservesType()
    {
        var evt = new InfoEvent(DateTimeOffset.UnixEpoch, "src", "token=zzzzzzzzzzzzzzzzzzzz issued");
        var r = Assert.IsType<InfoEvent>(SecretRedactor.RedactEvent(evt));
        Assert.Equal(evt.Id, r.Id);
        Assert.Contains(Mask, r.Message);
    }

    [Fact]   // deep-review E4: PermissionViolationEvent.Detail is persisted, so it must be redacted too
    public void RedactEvent_PermissionViolation_MasksDetailAndMessage()
    {
        var evt = new PermissionViolationEvent(
            DateTimeOffset.UnixEpoch, "src",
            "blocked write to a denied path with GITHUB_TOKEN=ghp_1234567890abcdefghij1234567890abcdef",
            4321, "claude-code-default", "CommandBlocked",
            "cmd: curl https://x --api-key abcdef1234567890");
        var r = Assert.IsType<PermissionViolationEvent>(SecretRedactor.RedactEvent(evt));
        Assert.Equal(evt.Id, r.Id);
        Assert.Contains(Mask, r.Detail);
        Assert.DoesNotContain("abcdef1234567890", r.Detail);
        Assert.DoesNotContain("ghp_1234567890", r.Message);
    }
}
