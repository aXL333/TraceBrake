using System.Text.Json;

namespace Foreman.Core.Profiles;

/// <summary>
/// Loads and watches harness profiles from %LocalAppData%\TraceBrake\profiles\.
/// Also ships a built-in default profile as a fallback.
/// </summary>
public sealed class ProfileStore : IDisposable
{
    // Profiles are same-user writable input. Keep reload work bounded so a hostile harness cannot turn the
    // watcher into an allocation/CPU denial-of-service by dropping thousands of files or one enormous JSON blob.
    public const int MaxUserProfiles = 128;
    public const long MaxProfileBytes = 256 * 1024;
    private const int ReloadDebounceMilliseconds = 250;

    private readonly string _profilesDirectory;
    private readonly Dictionary<string, HarnessProfile> _profiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _builtInNames = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    private FileSystemWatcher? _watcher;
    private Timer? _reloadTimer;
    private bool _disposed;

    private static readonly JsonSerializerOptions _jsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        MaxDepth = 32,
    };

    public ProfileStore(string profilesDirectory)
    {
        _profilesDirectory = profilesDirectory;
    }

    public void Initialize()
    {
        Directory.CreateDirectory(_profilesDirectory);
        LoadAll();
        StartWatcher();
    }

    public HarnessProfile? Get(string name) =>
        WithLock(() => _profiles.TryGetValue(name, out var p) ? p : null);

    public IReadOnlyCollection<HarnessProfile> All => WithLock(() => _profiles.Values.ToArray());

    private void LoadAll()
    {
        lock (_gate)
        {
            _profiles.Clear();

            // embedded built-in profiles
            LoadBuiltIn("claude-code-default");
            LoadBuiltIn("codex-default");
            LoadBuiltIn("t3-code-default");
            LoadBuiltIn("opencode-default");
            LoadBuiltIn("gemini-cli-default");
            LoadBuiltIn("github-copilot-default");
            LoadBuiltIn("lm-studio-default");
            LoadBuiltIn("cursor-default");

            // User profiles are intentionally additive. A same-user harness must not replace an embedded profile
            // by reusing its name, and user-authored profiles never receive alert-suppression authority. Known,
            // reviewed launcher exemptions live in the signed embedded resources / integration registry instead.
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(_profilesDirectory, "*.json")
                    .Order(StringComparer.OrdinalIgnoreCase)
                    .Take(MaxUserProfiles)
                    .ToArray();
            }
            catch { return; }

            foreach (var file in files)
                TryLoadUserFile(file);
        }
    }

    private void LoadBuiltIn(string name)
    {
        var asm = System.Reflection.Assembly.GetExecutingAssembly();
        var res = asm.GetManifestResourceNames()
            .FirstOrDefault(r => r.EndsWith($"{name}.json", StringComparison.OrdinalIgnoreCase));
        if (res is null) return;

        using var stream = asm.GetManifestResourceStream(res)!;
        var profile = JsonSerializer.Deserialize<HarnessProfile>(stream, _jsonOpts);
        if (profile is not null)
        {
            _profiles[profile.Name] = profile;
            _builtInNames.Add(profile.Name);
        }
    }

    private void TryLoadUserFile(string path)
    {
        try
        {
            // Open first, then size/read that exact handle. A separate FileInfo check followed by File.ReadAllText
            // leaves a swap/growth window where a hostile same-user writer can replace the checked file with a huge
            // one and recover the unbounded allocation this limit is meant to prevent.
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length is <= 0 or > MaxProfileBytes) return;
            var bytes = new byte[checked((int)stream.Length)];
            stream.ReadExactly(bytes);
            if (stream.ReadByte() != -1) return; // fail closed if the file grew while its handle was being read
            var profile = JsonSerializer.Deserialize<HarnessProfile>(bytes, _jsonOpts);
            if (profile is null || string.IsNullOrWhiteSpace(profile.Name)) return;
            profile.Name = profile.Name.Trim();
            if (_builtInNames.Contains(profile.Name)) return;

            // System.Text.Json can assign null to non-nullable reference properties. Normalize every section and
            // collection at the trust boundary so a hostile but valid JSON document cannot crash later consumers.
            profile.ProcessMatch ??= new ProcessMatchConfig();
            profile.ProcessMatch.ExecutableNames ??= [];
            profile.ProcessMatch.CommandLineContains ??= [];
            profile.ProcessMatch.ParentExecutableNames ??= [];
            profile.FileSystem ??= new FileSystemConfig();
            profile.FileSystem.AllowedReadPaths ??= [];
            profile.FileSystem.AllowedWritePaths ??= [];
            profile.FileSystem.DeniedPaths ??= [];
            profile.Commands ??= new CommandConfig();
            profile.Commands.BlockedPatterns ??= [];
            profile.ProcessLimits ??= new ProcessLimitsConfig();
            profile.ClaudeCodeIntegration ??= new ClaudeCodeIntegrationConfig();

            // These two fields can suppress command detections. A profile directory writable by the monitored
            // principal is not an authority source, so fail closed and discard them for every disk profile.
            profile.Alerts ??= new AlertConfig();
            profile.Alerts.LauncherSuppressedRuleIds = [];
            profile.Alerts.TrustedHookPathMarkers = [];
            _profiles[profile.Name] = profile;
        }
        catch { /* bad JSON — skip */ }
    }

    private void StartWatcher()
    {
        _watcher = new FileSystemWatcher(_profilesDirectory, "*.json")
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName,
            EnableRaisingEvents = true,
        };

        _reloadTimer = new Timer(_ =>
        {
            lock (_gate)
            {
                if (_disposed) return;
            }
            LoadAll();
        });

        _watcher.Changed += (_, _) => ScheduleReload();
        _watcher.Created += (_, _) => ScheduleReload();
        _watcher.Deleted += (_, _) => ScheduleReload();
        _watcher.Renamed += (_, _) => ScheduleReload();
    }

    private void ScheduleReload()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _reloadTimer?.Change(ReloadDebounceMilliseconds, Timeout.Infinite);
        }
    }

    private T WithLock<T>(Func<T> action)
    {
        lock (_gate) return action();
    }

    public void Dispose()
    {
        lock (_gate) _disposed = true;
        _watcher?.Dispose();
        _reloadTimer?.Dispose();
    }
}
