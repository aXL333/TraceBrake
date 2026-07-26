using System.Security.Cryptography;
using System.Text;

namespace Foreman.Core.Security;

/// <summary>
/// Decoy ("canary" / honeytoken) credential files. The June-2026 Miasma worm harvests ~130 credential
/// paths; planting believable-but-fake files at the ones you DON'T already use turns the harvester's own
/// enumeration into a near-zero-false-positive tripwire — nothing legitimate ever reads a file you planted
/// as bait.
///
/// Three detection layers stack on these decoys:
///   1. Sentinel-in-command (here, no elevation): each decoy embeds a recognizable sentinel token; if that
///      value ever flows through a monitored command line (echo / upload / base64 staging), rule cred-040
///      fires Critical — the harvester read the bait and is handling it.
///   2. SACL read-auditing (elevated sidecar, separate): a Windows audit ACE on each decoy emits Security
///      Event 4663 on any read, including the payload's direct fopen that no command line shows.
///   3. AWS canarytoken (optional, out-of-band): one decoy can carry a real canarytokens.org AWS key that
///      beacons when the stolen key is USED against AWS.
///
/// Placement is GAPS-ONLY: a decoy is written only where no real file exists, so a working ~/.aws/credentials
/// or ~/.npmrc is never shadowed. A slot occupied by an EXISTING Foreman decoy (sentinel present — a prior
/// install or a diverged settings lineage) is adopted and refreshed rather than skipped, so enabling decoys
/// always ends with the on-disk decoys tracked. Removal only deletes files that still carry the Foreman
/// sentinel, so a real file the user later created in a decoy slot is never destroyed.
/// </summary>
public sealed class DecoyCredentialSettings
{
    /// <summary>Off by default — planting files in the user profile is opt-in.</summary>
    public bool Enabled { get; set; } = false;

    /// <summary>Also enable the elevated SACL read-auditing layer (Security Event 4663). Needs the sidecar.</summary>
    public bool EnableReadAuditing { get; set; } = false;

    /// <summary>Embed a real canarytokens.org / CloudTrail-watched AWS key in the aws-credentials decoy so a USED key beacons.</summary>
    public bool IncludeAwsCanaryToken { get; set; } = false;

    /// <summary>The canarytoken AWS access-key id (user pastes one from canarytokens.org). Not a secret to Foreman — it's bait.</summary>
    public string? AwsCanaryAccessKeyId { get; set; }

    /// <summary>The canarytoken AWS secret. Bait, not a real secret.</summary>
    public string? AwsCanarySecretAccessKey { get; set; }

    /// <summary>Absolute paths Foreman has actually planted, so removal touches only its own decoys.</summary>
    public List<string> PlantedPaths { get; set; } = [];

    /// <summary>
    /// Per-install random sentinel token (B9 polish), generated on first plant and embedded in every decoy
    /// alongside the static marker. The shipped binary reveals only the STATIC sentinel — a signature-based
    /// harvester (e.g. a worm hardcoded to skip "FOREMAN-DECOY-CANARY") can recognise + avoid/scrub that, but it
    /// cannot know THIS install's random token, so when it grabs a decoy the random token still trips cred-040.
    /// Empty until the first plant. (A same-user agent that reads this settings file can still learn it — the
    /// guardian could later hold it SYSTEM-side; this defeats signature harvesters, not per-install recon.)
    /// </summary>
    public string? InstanceSentinel { get; set; }
}

public enum DecoyKind
{
    AwsCredentials,
    SshPrivateKey,
    Npmrc,
    GitCredentials,
    KubeConfig,
    PypiRc,
    NetRc,
    DockerConfig,
    GenericSecret,
}

/// <summary>
/// Whether a decoy sits at a CANONICAL credential path (one that real tools also read — git over HTTPS reads
/// ~/.netrc on every push, npm/node read ~/.npmrc, ssh reads ~/.ssh/id_rsa — so its read-auditing needs the
/// expected-reader allowlist in <see cref="DecoyAuditPolicy"/> to avoid false positives) or is pure BAIT at a
/// path nothing legitimate ever reads (so ANY read is harvester behaviour and it is read-audited
/// image-agnostically). See <see cref="DecoyCredentialPolicy.ReadAuditPaths"/>.
/// </summary>
public enum DecoyRole { Canonical, Bait }

/// <summary>One candidate decoy location, relative to the user's home directory.</summary>
public sealed record DecoySpec(string RelativePath, DecoyKind Kind, DecoyRole Role = DecoyRole.Canonical);

/// <summary>The outcome of planning placements: what to plant vs. what was skipped because a real file exists.</summary>
public sealed record DecoyPlacement(string FullPath, DecoyKind Kind, string Content);

/// <summary>Abstracts the file system so placement/removal is unit-testable without touching disk.</summary>
public interface IDecoyFileSystem
{
    string HomeDirectory { get; }
    bool Exists(string fullPath);
    string ReadAllText(string fullPath);
    void WriteAllText(string fullPath, string content);
    void Delete(string fullPath);
}

/// <summary>Real file system rooted at the current user's profile — the production <see cref="IDecoyFileSystem"/>.</summary>
public sealed class SystemDecoyFileSystem : IDecoyFileSystem
{
    public string HomeDirectory { get; } =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    public bool Exists(string fullPath) => File.Exists(fullPath);
    public string ReadAllText(string fullPath) => File.ReadAllText(fullPath);

    public void WriteAllText(string fullPath, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        File.WriteAllText(fullPath, content);
        ExcludeFromContentIndex(fullPath);
    }

    /// <summary>
    /// Mark a planted decoy <c>NOT_CONTENT_INDEXED</c> so the Windows Search indexer (SearchProtocolHost) does
    /// not crawl its content. Otherwise indexing a home-root bait decoy (secrets.env, credentials.txt, vault.txt)
    /// reads it on the next index pass and trips the image-agnostic read-audit as a false "harvester" hit — the
    /// exact false positive this prevents. It does NOT weaken the tripwire against a real thief: a harvester opens
    /// and reads the file regardless of this attribute. Best-effort; a failure just leaves the indexer-exclusion
    /// belt to <see cref="DecoyAuditPolicy.IsBenignSystemIndexer"/>.
    /// </summary>
    public static void ExcludeFromContentIndex(string fullPath)
    {
        try
        {
            var attrs = File.GetAttributes(fullPath);
            if ((attrs & FileAttributes.NotContentIndexed) == 0)
                File.SetAttributes(fullPath, attrs | FileAttributes.NotContentIndexed);
        }
        catch { /* index-exclusion is best-effort */ }
    }

    public void Delete(string fullPath) => File.Delete(fullPath);
}

/// <summary>
/// Pure policy for decoy placement + believable content generation. No I/O, no elevation — fully testable.
/// </summary>
public static class DecoyCredentialPolicy
{
    /// <summary>
    /// Stable, recognizable sentinel embedded in every Foreman decoy (uses leetspeak zeroes so it never
    /// collides with a real AKIA-key/ghp-token). Detection rule cred-040 matches these; removal verifies a
    /// file still contains <see cref="SentinelMarker"/> before deleting it.
    /// </summary>
    public const string SentinelMarker = "FOREMAN-DECOY-CANARY";
    public const string SentinelAwsKey = "AKIAF0REMANDEC0YAAAA";
    public const string SentinelGitHubToken = "ghp_F0REMANDEC0Y00000000000000000000000000";

    /// <summary>A fresh per-install sentinel (B9 polish): 32 hex chars, no fixed prefix, so the binary reveals no
    /// pattern a signature harvester could match. Stored in <see cref="DecoyCredentialSettings.InstanceSentinel"/>.</summary>
    public static string NewInstanceSentinel() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

    /// <summary>Credential paths the Miasma sweep enumerates — the candidate decoy slots (gaps-only at plant time).</summary>
    public static IReadOnlyList<DecoySpec> Candidates { get; } =
    [
        new(".aws/credentials",      DecoyKind.AwsCredentials),
        new(".ssh/id_rsa",           DecoyKind.SshPrivateKey),
        new(".npmrc",                DecoyKind.Npmrc),
        new(".git-credentials",      DecoyKind.GitCredentials),
        new(".kube/config",          DecoyKind.KubeConfig),
        new(".pypirc",               DecoyKind.PypiRc),
        new(".netrc",                DecoyKind.NetRc),
        new(".docker/config.json",   DecoyKind.DockerConfig),

        // Pure-BAIT decoys: paths NO legitimate tool reads, so any read is harvester behaviour. These are
        // read-audited image-agnostically (no expected-reader allowlist) and restore the direct-fopen
        // tripwire that the canonical paths must give up — git/aws/etc. read those constantly, so auditing
        // them produces guaranteed false positives (see ReadAuditPaths). The .bak/.old siblings sit right
        // next to a real (decoy) credential so a harvester enumerating ~/.aws or ~/.ssh grabs them too; the
        // home-root files catch harvesters that scan $HOME for *.env / secret / cred filenames.
        new(".aws/credentials.bak",  DecoyKind.AwsCredentials, DecoyRole.Bait),
        new(".ssh/id_rsa.old",       DecoyKind.SshPrivateKey,  DecoyRole.Bait),
        new(".npmrc.bak",            DecoyKind.Npmrc,          DecoyRole.Bait),
        new("secrets.env",           DecoyKind.GenericSecret,  DecoyRole.Bait),
        new("credentials.txt",       DecoyKind.GenericSecret,  DecoyRole.Bait),
        new("vault.txt",             DecoyKind.GenericSecret,  DecoyRole.Bait),
    ];

    /// <summary>
    /// Plans which decoys to plant: a candidate is included only when no real file occupies its slot
    /// (gaps-only). <paramref name="exists"/> is injected so this is pure/testable.
    /// </summary>
    public static IReadOnlyList<DecoyPlacement> PlanPlacements(
        string homeDirectory, Func<string, bool> exists, DecoyCredentialSettings settings)
    {
        var placements = new List<DecoyPlacement>();
        foreach (var spec in Candidates)
        {
            var full = JoinHome(homeDirectory, spec.RelativePath);
            if (exists(full)) continue;   // gaps-only: never shadow a real credential file
            placements.Add(new DecoyPlacement(full, spec.Kind, GenerateContent(spec.Kind, settings)));
        }
        return placements;
    }

    /// <summary>Believable, syntactically-valid, NON-functional content for a decoy of the given kind. Carries the
    /// static sentinel (removal gate + baseline detection) AND, when set, the per-install sentinel (B9 polish).</summary>
    public static string GenerateContent(DecoyKind kind, DecoyCredentialSettings settings)
    {
        var awsKey = settings is { IncludeAwsCanaryToken: true, AwsCanaryAccessKeyId.Length: > 0 }
            ? settings.AwsCanaryAccessKeyId!
            : SentinelAwsKey;
        var awsSecret = settings is { IncludeAwsCanaryToken: true, AwsCanarySecretAccessKey.Length: > 0 }
            ? settings.AwsCanarySecretAccessKey!
            : SentinelMarker + "/wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLE";

        var body = kind switch
        {
            // The trailing comment guarantees the sentinel is present even when a real canary key is used
            // for the values, so Remove() can always verify this is Foreman's decoy before deleting it.
            DecoyKind.AwsCredentials =>
                $"[default]\naws_access_key_id = {awsKey}\naws_secret_access_key = {awsSecret}\n# {SentinelMarker}\n",

            DecoyKind.SshPrivateKey =>
                "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
                "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQy\n" +
                "NTUxOQAAACDA000000000000000000000000000000000000000000000000000000000==\n" +
                "-----END OPENSSH PRIVATE KEY-----\n" +
                $"# {SentinelMarker} (decoy; do not use)\n",

            DecoyKind.Npmrc =>
                $"//registry.npmjs.org/:_authToken={SentinelMarker}-npm-0000000000000000\n",

            DecoyKind.GitCredentials =>
                $"https://x-access-token:{SentinelGitHubToken}@github.com\n",

            DecoyKind.KubeConfig =>
                "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://10.0.0.1:6443\n  name: prod\n" +
                "users:\n- name: admin\n  user:\n" +
                $"    token: {SentinelMarker}-kube-0000000000000000000000\n",

            DecoyKind.PypiRc =>
                $"[pypi]\nusername = __token__\npassword = pypi-{SentinelMarker}0000000000000000000000\n",

            DecoyKind.NetRc =>
                $"machine github.com\n  login x-access-token\n  password {SentinelGitHubToken}\n",

            DecoyKind.DockerConfig =>
                "{\n  \"auths\": {\n    \"https://index.docker.io/v1/\": {\n      \"auth\": \"" +
                Convert.ToBase64String(Encoding.ASCII.GetBytes("decoy:" + SentinelMarker)) +
                "\"\n    }\n  },\n  \"_\": \"" + SentinelMarker + "\"\n}\n",

            // Freeform "env/dump" bait for the home-root decoys (secrets.env, credentials.txt, vault.txt) —
            // the shape a careless dev's secrets file or a harvester's staged loot takes. Carries the
            // sentinel so removal stays gated on IsDecoyContent.
            DecoyKind.GenericSecret =>
                $"# {SentinelMarker} (decoy; do not use)\n" +
                $"AWS_SECRET_ACCESS_KEY={SentinelMarker}/wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLE\n" +
                $"DATABASE_URL=postgres://admin:{SentinelMarker}@db.internal:5432/prod\n" +
                $"GITHUB_TOKEN={SentinelGitHubToken}\n" +
                $"API_TOKEN={SentinelMarker}-0000000000000000\n",

            _ => SentinelMarker + "\n",
        };

        // Append the per-install sentinel so a harvester that grabs the decoy carries a token the binary never
        // revealed — even if it scrubbed the known static markers, this still trips cred-040.
        return string.IsNullOrEmpty(settings.InstanceSentinel)
            ? body
            : body + $"# {settings.InstanceSentinel}\n";
    }

    /// <summary>True if the given text is one of Foreman's decoys (carries the sentinel) — gate removal on this.</summary>
    public static bool IsDecoyContent(string? text) =>
        text is not null &&
        (text.Contains(SentinelMarker, StringComparison.Ordinal) ||
         text.Contains(SentinelAwsKey, StringComparison.Ordinal) ||
         text.Contains(SentinelGitHubToken, StringComparison.Ordinal));

    /// <summary>Absolute path of a candidate decoy under the given home directory.</summary>
    public static string FullPath(string home, DecoySpec spec) => JoinHome(home, spec.RelativePath);

    /// <summary>
    /// The subset of <paramref name="plantedPaths"/> that should get an elevated read-audit SACL: every BAIT
    /// decoy (any read = harvester) plus the canonical <c>.npmrc</c> (a foreign reader like powershell still
    /// trips it, while npm/node are filtered by the expected-reader allowlist). The other canonical paths
    /// (<c>.netrc</c>, <c>.git-credentials</c>, <c>.aws/credentials</c>, …) are deliberately NOT read-audited:
    /// legitimate tools read them constantly — git over HTTPS reads <c>~/.netrc</c> on every push, AWS SDKs
    /// read <c>~/.aws/credentials</c> — so auditing them is a guaranteed false-positive source. They keep the
    /// command-line sentinel layer (<c>cred-040</c>) instead. The bait <c>.bak</c>/<c>.old</c> siblings restore
    /// a direct-read tripwire next to each of those paths.
    /// </summary>
    public static IReadOnlyList<string> ReadAuditPaths(string home, IEnumerable<string> plantedPaths)
    {
        var byPath = new Dictionary<string, DecoySpec>(StringComparer.OrdinalIgnoreCase);
        foreach (var spec in Candidates)
            byPath[DecoyAuditPolicy.Normalize(FullPath(home, spec))] = spec;

        var result = new List<string>();
        foreach (var p in plantedPaths)
            if (byPath.TryGetValue(DecoyAuditPolicy.Normalize(p), out var spec)
                && (spec.Role == DecoyRole.Bait || spec.Kind == DecoyKind.Npmrc))
                result.Add(p);
        return result;
    }

    private static string JoinHome(string home, string relative) =>
        Path.Combine(home, relative.Replace('/', Path.DirectorySeparatorChar));
}

/// <summary>Result of a plant operation, for the operator log + the settings record of what to clean up.</summary>
public sealed record DecoyPlantResult(IReadOnlyList<string> Planted, IReadOnlyList<string> SkippedExisting);

/// <summary>
/// Plants and removes decoys using an injected file system. Plant is gaps-only; Remove deletes only files
/// that still carry the Foreman sentinel (so a real file later created in a decoy slot is never destroyed).
/// </summary>
public sealed class DecoyCredentialManager(IDecoyFileSystem fs)
{
    public DecoyPlantResult Plant(DecoyCredentialSettings settings)
    {
        // Mint the per-install sentinel on first plant (B9 polish) so every decoy carries a token unique to this
        // install, not the binary's well-known static marker.
        if (string.IsNullOrEmpty(settings.InstanceSentinel))
            settings.InstanceSentinel = DecoyCredentialPolicy.NewInstanceSentinel();

        var planted = new List<string>();
        var skipped = new List<string>();
        // Iterate candidates directly so a real file in a decoy slot is reported as skipped (gaps-only).
        foreach (var spec in DecoyCredentialPolicy.Candidates)
        {
            var full = DecoyCredentialPolicy.FullPath(fs.HomeDirectory, spec);
            if (fs.Exists(full))
            {
                // A file already occupies the slot. If it is a FOREMAN decoy (carries the sentinel — planted by
                // a previous install, or by another instance whose settings lineage diverged, e.g. a sandboxed
                // launch), ADOPT it: refresh its content under THIS install's sentinel and track it. Otherwise
                // "decoys enabled with decoy files already on disk" silently tracks — and audits — NOTHING.
                // A real user file (no sentinel) stays untouchable: gaps-only stands.
                string existing;
                try { existing = fs.ReadAllText(full); } catch { skipped.Add(full); continue; }
                if (!DecoyCredentialPolicy.IsDecoyContent(existing)) { skipped.Add(full); continue; }
            }
            fs.WriteAllText(full, DecoyCredentialPolicy.GenerateContent(spec.Kind, settings));
            planted.Add(full);
        }
        return new DecoyPlantResult(planted, skipped);
    }

    /// <summary>Removes the recorded decoys — but only files that still contain the Foreman sentinel.</summary>
    public IReadOnlyList<string> Remove(IEnumerable<string> plantedPaths)
    {
        var removed = new List<string>();
        foreach (var path in plantedPaths)
        {
            if (!fs.Exists(path)) continue;
            string text;
            try { text = fs.ReadAllText(path); } catch { continue; }
            if (!DecoyCredentialPolicy.IsDecoyContent(text)) continue;   // not our decoy anymore — leave it
            fs.Delete(path);
            removed.Add(path);
        }
        return removed;
    }

    /// <summary>
    /// Frees a single decoy slot so the user can put REAL credentials there. Sentinel-gated, so it only
    /// ever deletes Foreman's own decoy — if the slot already holds real content it is left untouched.
    /// Returns true when a decoy was actually removed.
    /// </summary>
    public bool Release(string path) => Remove([path]).Contains(path);

    /// <summary>
    /// Re-checks tracked decoys. A slot is "reclaimed" when the file is gone or no longer carries the
    /// sentinel — i.e. the user (or a tool like <c>aws configure</c>) wrote real credentials over it. The
    /// caller stops tracking and auditing reclaimed slots; Foreman NEVER deletes a reclaimed file. Slots
    /// that still carry the sentinel stay decoys. Run on startup and when Settings opens, so a slot the
    /// user repurposed for real credentials silently retires instead of false-alarming on every read.
    /// </summary>
    public RevalidateResult Revalidate(IEnumerable<string> trackedPaths)
    {
        var still = new List<string>();
        var reclaimed = new List<string>();
        var missing = new List<string>();
        foreach (var path in trackedPaths)
        {
            if (!fs.Exists(path)) { reclaimed.Add(path); missing.Add(path); continue; }
            string text;
            try { text = fs.ReadAllText(path); }
            catch { still.Add(path); continue; }                          // unreadable — keep tracking, don't assume
            if (DecoyCredentialPolicy.IsDecoyContent(text)) still.Add(path);
            else reclaimed.Add(path);                                     // real content now lives here — retire, never delete
        }
        return new RevalidateResult(still, reclaimed, missing);
    }
}

/// <summary>
/// Outcome of <see cref="DecoyCredentialManager.Revalidate"/>: which tracked slots are still decoys vs.
/// which were reclaimed (file gone or real credentials written over the decoy — must be untracked, never deleted).
/// </summary>
public sealed record RevalidateResult(
    IReadOnlyList<string> StillDecoys,
    IReadOnlyList<string> Reclaimed,
    IReadOnlyList<string> Missing);
