namespace Foreman.Core.Security;

/// <summary>
/// Pure decision logic for the elevated SACL read-auditing layer: given a Windows Security-log file-access
/// event (Event 4663 — object name + accessing PID + accessing image), decide whether it is a genuine read of
/// a tracked decoy credential worth a Critical alert. Shared by the elevated sidecar (which filters the noisy
/// 4663 stream down to decoy hits before sending anything over the pipe) and the app, and unit-tested here so
/// the sidecar's filter is verified without needing elevation.
///
/// Two correctness points:
///   1. TraceBrake itself reads the decoy files during sentinel re-validation
///      (<see cref="DecoyCredentialManager.Revalidate"/>) and on plant/remove — so the app's own PID (and the
///      sidecar's) MUST be excluded, or TraceBrake would alarm on its own housekeeping.
///   2. A CANONICAL decoy sits at a path real tools also read (git's HTTPS helper reads ~/.netrc and
///      ~/.git-credentials on every push, npm/node read ~/.npmrc, ssh reads ~/.ssh/id_rsa). Reading such a
///      decoy from that path's OWN legitimate tool is normal and is suppressed via <see cref="ExpectedReaders"/>;
///      any OTHER reader (a harvester, powershell, python, or a tool reading a path it doesn't own) still fires.
///      BAIT decoys have no legitimate reader, so they classify to null and any read fires image-agnostically.
/// </summary>
public static class DecoyAuditPolicy
{
    /// <summary>
    /// True when a 4663 read of <paramref name="objectName"/> by <paramref name="subjectPid"/>
    /// (<paramref name="readerImage"/> is the accessing executable) is a real decoy read: the path equals one
    /// of <paramref name="decoyPaths"/>, the reader is not an excluded PID (TraceBrake app + sidecar), and — for a
    /// canonical decoy — the reader is not that path's expected legitimate tool.
    /// </summary>
    public static bool IsDecoyRead(
        string? objectName,
        int subjectPid,
        string? readerImage,
        IReadOnlyCollection<string> decoyPaths,
        IReadOnlyCollection<int> excludedPids)
    {
        if (string.IsNullOrWhiteSpace(objectName)) return false;
        if (excludedPids.Contains(subjectPid)) return false;

        var target = Normalize(objectName);
        var matched = false;
        foreach (var d in decoyPaths)
            if (Normalize(d).Equals(target, StringComparison.OrdinalIgnoreCase)) { matched = true; break; }
        if (!matched) return false;

        // The Windows Search indexer (SearchProtocolHost / SearchIndexer / SearchFilterHost) reads file CONTENT
        // in indexed locations — the user profile included — on every index pass, so it reads a home-root BAIT
        // decoy (secrets.env, vault.txt, …) as routine OS housekeeping, not harvesting. Suppress it, matched
        // PATH-ANCHORED under \Windows\System32\ (not by basename) so a renamed harvester dropped elsewhere
        // can't borrow the exemption — placing a binary in System32 already requires admin. This is the belt to
        // the FILE_ATTRIBUTE_NOT_CONTENT_INDEXED braces set on planted decoys (which stops the indexer at source).
        if (IsBenignSystemIndexer(readerImage)) return false;

        // Suppress a CANONICAL decoy read by that path's own legitimate tool (e.g. git-remote-https reading
        // ~/.netrc on every push). Bait paths classify to null → no allowlist → any read fires.
        var kind = ClassifyCanonical(target);
        if (kind is { } k
            && ExpectedReaders.TryGetValue(k, out var allowed)
            && readerImage is not null
            && allowed.Contains(ImageBasename(readerImage)))
            return false;

        return true;
    }

    /// <summary>
    /// The <see cref="DecoyKind"/> of the CANONICAL decoy at this (already-normalized) path, or null when the
    /// path is a bait decoy or unrecognized — either way meaning "no expected-reader suppression; any read
    /// fires". Matched by relative-path tail so it works without knowing the home directory.
    /// </summary>
    private static DecoyKind? ClassifyCanonical(string normalizedPath)
    {
        foreach (var spec in DecoyCredentialPolicy.Candidates)
        {
            if (spec.Role != DecoyRole.Canonical) continue;
            var relTail = "\\" + spec.RelativePath.Replace('/', '\\');
            if (normalizedPath.EndsWith(relTail, StringComparison.OrdinalIgnoreCase))
                return spec.Kind;
        }
        return null;
    }

    /// <summary>
    /// Per-path legitimate readers. Reading a canonical decoy from one of these images is normal tool
    /// behaviour and is suppressed; everything else fires — shells (powershell/cmd/bash), editors, python on
    /// .pypirc, git on an SSH key, and any binary reading a path it doesn't own. Deliberately tight: broad or
    /// cross-tool readers are NOT listed, so a harvester can't hide behind them. Matched on the bare image
    /// name as emitted in 4663 (includes the .exe extension).
    /// </summary>
    private static readonly Dictionary<DecoyKind, HashSet<string>> ExpectedReaders = new()
    {
        [DecoyKind.NetRc]          = Set("git.exe", "git-remote-https.exe", "git-remote-http.exe", "curl.exe"),
        [DecoyKind.GitCredentials] = Set("git.exe", "git-remote-https.exe", "git-remote-http.exe",
                                         "git-credential-manager.exe", "git-credential-manager-core.exe",
                                         "git-credential-wincred.exe", "git-credential-store.exe"),
        [DecoyKind.SshPrivateKey]  = Set("ssh.exe", "scp.exe", "sftp.exe", "ssh-add.exe", "ssh-keygen.exe", "plink.exe"),
        [DecoyKind.AwsCredentials] = Set("aws.exe"),
        [DecoyKind.Npmrc]          = Set("npm.exe", "node.exe", "npx.exe", "pnpm.exe", "yarn.exe"),
        [DecoyKind.DockerConfig]   = Set("docker.exe", "com.docker.cli.exe",
                                         "docker-credential-desktop.exe", "docker-credential-wincred.exe"),
        [DecoyKind.KubeConfig]     = Set("kubectl.exe", "helm.exe"),
        [DecoyKind.PypiRc]         = Set("twine.exe", "pip.exe"),
    };

    private static HashSet<string> Set(params string[] images) =>
        new(images, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// True when <paramref name="readerImage"/> is the genuine Windows Search indexer content-gathering process
    /// (SearchProtocolHost / SearchIndexer / SearchFilterHost) running from its real System32 path. These crawl
    /// file CONTENT to build the search index and will read a home-root bait decoy on every pass — benign OS
    /// behaviour, not harvesting. Anchored to the REAL System32 by its VOLUME-RELATIVE tail (e.g. \Windows\System32)
    /// so a renamed harvester is NOT exempt no matter where it lives — including a fabricated ...\Windows\System32\
    /// subtree a non-admin can create under their profile or Temp (which an EndsWith(@"\Windows\System32\…") test
    /// would wrongly trust). Only a file actually IN the real System32 has that exact volume-relative tail, and
    /// writing there needs admin (at which point the tripwire is moot anyway). Comparing the volume-relative tail
    /// rather than a full drive path also keeps the \Device\HarddiskVolumeN\… form the real indexer's 4663 emits.
    /// Public for unit-testing.
    /// </summary>
    public static bool IsBenignSystemIndexer(string? readerImage) =>
        IsBenignSystemIndexer(readerImage, System32VolumeRelative);

    /// <summary>
    /// Testable core of <see cref="IsBenignSystemIndexer(string?)"/>: <paramref name="system32VolumeRelative"/> is
    /// the drive-stripped System32 path to anchor on (e.g. <c>\Windows\System32</c>), injected so the exemption
    /// can be verified without depending on where Windows is installed on the test host.
    /// </summary>
    public static bool IsBenignSystemIndexer(string? readerImage, string system32VolumeRelative)
    {
        if (string.IsNullOrWhiteSpace(readerImage) || string.IsNullOrWhiteSpace(system32VolumeRelative)) return false;
        var rel = StripVolume(Normalize(readerImage));
        var anchor = StripVolume(Normalize(system32VolumeRelative)).TrimEnd('\\');
        foreach (var name in SystemIndexerImageNames)
            if (rel.Equals(anchor + "\\" + name, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    // The real System32's volume-relative tail (e.g. "\Windows\System32"), derived from the actual install so a
    // non-standard %SystemRoot% still anchors correctly. Drive-stripped so it matches every 4663 path form.
    private static readonly string System32VolumeRelative =
        StripVolume(Normalize(Environment.GetFolderPath(Environment.SpecialFolder.System)));

    private static readonly string[] SystemIndexerImageNames =
    [
        "SearchProtocolHost.exe",
        "SearchIndexer.exe",
        "SearchFilterHost.exe",
    ];

    /// <summary>
    /// Strips a leading volume designator so paths from any 4663 form compare on their volume-relative tail:
    /// <c>C:\Windows\…</c> → <c>\Windows\…</c>; <c>\Device\HarddiskVolume3\Windows\…</c> → <c>\Windows\…</c>
    /// (the <c>\\?\</c> prefix is already removed by <see cref="Normalize"/>). A path whose volume-relative tail
    /// is <c>\Windows\System32\X</c> can only come from a file in the true System32 — writing there needs admin —
    /// which is exactly the anchor the indexer exemption needs.
    /// </summary>
    private static string StripVolume(string p)
    {
        if (p.Length >= 2 && char.IsLetter(p[0]) && p[1] == ':') return p[2..];          // C:\… → \…
        if (p.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))               // \Device\<vol>\… → \…
        {
            var rest = p[@"\Device\".Length..];
            var slash = rest.IndexOf('\\');
            return slash < 0 ? "\\" : rest[slash..];
        }
        return p;   // already volume-relative (or an unrecognized form — left as-is, so it won't match the anchor)
    }

    /// <summary>
    /// The bare executable name from a 4663 ProcessName. Handles a \\?\ prefix, the \Device\HarddiskVolumeN\…
    /// kernel form, and either separator. (A renamed binary can still spoof this — that is exactly why the
    /// canonical allowlist is paired with image-agnostic bait decoys.)
    /// </summary>
    public static string ImageBasename(string image)
    {
        var p = image.Trim();
        if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) p = p[4..];
        p = p.Replace('/', '\\').TrimEnd('\\');
        var i = p.LastIndexOf('\\');
        return i >= 0 ? p[(i + 1)..] : p;
    }

    /// <summary>Normalises a Windows path for comparison: strips a \\?\ long-path prefix, unifies separators.</summary>
    public static string Normalize(string path)
    {
        var p = path.Trim();
        if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) p = p[4..];
        return p.Replace('/', '\\').TrimEnd('\\');
    }
}
