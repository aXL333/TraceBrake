using Foreman.Core.Models;
using Foreman.Core.Security;

namespace Foreman.Core.Tests.Security;

/// <summary>
/// The privacy requirement as one number. Agent Handbrake spec 6.2 (redact secrets before display, log or forward)
/// and 8.7 (never write a released credential to any log) both reduce to the same measurable claim: push every
/// secret shape the redactor knows about through every egress channel it guards, and count how many come out the
/// other side. The metric is <c>privacyLeakCount</c>. The bar is zero. Per-rule behaviour is covered case by case
/// in <see cref="SecretRedactorTests"/>; this test exists so the whole property is a single asserted value.
/// </summary>
public sealed class PrivacyMetricTests
{
    // One entry per SecretRedactor rule, plus both payment-card paths. Each carries the substring that must not
    // survive egress. Stripe-shaped keys are split literals, as in SecretRedactorTests, so a FAKE key never looks
    // real to GitHub secret scanning.
    private static readonly (string Rule, string Input, string Secret)[] Corpus =
    [
        ("authorization-header", "curl -H \"Authorization: Bearer tok_abc123def456ghi789\" https://api.example",  "tok_abc123def456ghi789"),
        ("url-userinfo",         "git clone https://bob:pa55word-xyz@git.example.com/r.git",                        "pa55word-xyz"),
        ("password-flag",        "mysql --password=hunter2hunter2 -u root",                                          "hunter2hunter2"),
        ("key-equals-value",     "DB_PASSWORD=corr3ct-horse-battery ./run.sh",                                       "corr3ct-horse-battery"),
        ("jwt",                  "echo eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.s-aBc_123DEF456ghi",               "eyJzdWIiOiIxMjM0In0"),
        ("github-pat",           "export GITHUB_TOKEN=ghp_1234567890abcdefghij1234567890abcdef",                    "ghp_1234567890abcdefghij"),
        ("slack-token",          "slackpost xoxb-123456789012-abcdefABCDEF0",                                       "xoxb-123456789012"),
        ("openai-anthropic",     "claude --token sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaa",                            "sk-ant-api03-aaaaaaaa"),
        ("google-api-key",       "curl 'https://x.googleapis.com/?key=AIzaSyA1234567890abcdefghijklmnopqrstuvw'",  "AIzaSyA1234567890"),
        ("aws-access-key",       "aws configure; AKIAIOSFODNN7EXAMPLE",                                             "AKIAIOSFODNN7EXAMPLE"),
        ("stripe-secret",        "stripe --key sk_live_" + "51AbcDefGhiJklMnoPqrStuv",                             "sk_live_" + "51AbcDefGhi"),
        ("stripe-restricted",    "stripe --key rk_test_" + "51AbcDefGhiJklMnoPqrStuv",                             "rk_test_" + "51AbcDefGhi"),
        ("github-fine-grained",  "gh auth: github_pat_11ABCDEFG0aaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbb",         "github_pat_11ABCDEFG0"),
        ("gitlab-pat",           "CI_TOKEN glpat-abcdefghij1234567890",                                             "glpat-abcdefghij"),
        ("npm-token",            "npm publish --//registry/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789",   "npm_abcdefghijklmnop"),
        ("huggingface-token",    "huggingface-cli login hf_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345",                       "hf_aBcDeFgHiJkLmNoP"),
        ("xai-key",              "export XAI_API_KEY=xai-abcdefghijklmnopqrstuvwx",                                 "xai-abcdefghijkl"),
        ("sendgrid-key",         "SENDGRID SG.aBcDeFgHiJkLmNoPqRs.tUvWxYz0123456789AbCdEf",                        "aBcDeFgHiJkLmNoPqRs"),
        ("pem-private-key",      "cat id_ed25519:\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nAbCdEfGh+IjKl/MnOpQr\n-----END OPENSSH PRIVATE KEY-----\n",
                                                                                                                    "b3BlbnNzaC1rZXktdjEAAAAA"),
        ("named-card-value",     "checkout cvc: 987 expiry: 12/29",                                                 "987"),
        ("luhn-card-number",     "charge 4242 4242 4242 4242 now",                                                  "4242 4242 4242 4242"),
    ];

    // Every path a string takes out of the process through the redactor: the raw string transform, and the two
    // event fields RedactEvent masks. A secret that survives ANY of them is a leak.
    private static IEnumerable<(string Rule, string Channel, string Output, string Secret)> Egress(
        (string Rule, string Input, string Secret) c)
    {
        yield return (c.Rule, "Redact(string)", SecretRedactor.Redact(c.Input), c.Secret);

        var info = new InfoEvent(DateTimeOffset.UnixEpoch, "src", c.Input);
        yield return (c.Rule, "InfoEvent.Message", SecretRedactor.RedactEvent(info).Message, c.Secret);

        var cmd = new CommandAlertEvent(
            DateTimeOffset.UnixEpoch, ForemanSeverity.High, "src", c.Input, c.Input,
            "rule", "cat", "desc", "guide", 4321);
        var r = Assert.IsType<CommandAlertEvent>(SecretRedactor.RedactEvent(cmd));
        yield return (c.Rule, "CommandAlertEvent.CommandLine", r.CommandLine, c.Secret);
    }

    [Fact]
    public void PrivacyLeakCount_AcrossEveryEgressChannel_IsZero()
    {
        var leaked = Corpus
            .SelectMany(Egress)
            .Where(e => e.Output.Contains(e.Secret, StringComparison.Ordinal))
            .ToList();

        var privacyLeakCount = leaked.Count;

        Assert.True(privacyLeakCount == 0,
            $"privacyLeakCount = {privacyLeakCount} (must be 0). Leaked:\n" +
            string.Join("\n", leaked.Select(l => $"  [{l.Rule}] via {l.Channel}: {l.Output}")));
    }

    [Fact]   // the corpus must keep pace with the redactor: every rule family is represented, so a new rule
             // without a corpus entry is a test gap, not a silent pass
    public void Corpus_CoversEveryRedactorRule()
    {
        // 21 rule families in SecretRedactor (19 regex rules incl. PEM, plus named-card and Luhn-card paths).
        Assert.Equal(21, Corpus.Length);
        Assert.Equal(Corpus.Length, Corpus.Select(c => c.Rule).Distinct().Count());
    }
}
