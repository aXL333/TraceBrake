using System.Text.Json;

namespace Foreman.Core.Profiles;

/// <summary>
/// Loads and watches harness profiles from %LocalAppData%\TraceBrake\profiles\.
/// Also ships a built-in default profile as a fallback.
/// </summary>
public sealed class ProfileStore : IDisposable
{
    private readonly string _profilesDirectory;
    private readonly Dictionary<string, HarnessProfile> _profiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    private FileSystemWatcher? _watcher;

    private static readonly JsonSerializerOptions _jsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
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

            // user profiles from disk (override built-ins by name)
            foreach (var file in Directory.GetFiles(_profilesDirectory, "*.json"))
            {
                TryLoadFile(file);
            }
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
            _profiles[profile.Name] = profile;
    }

    private void TryLoadFile(string path)
    {
        try
        {
            var json = File.ReadAllText(path);
            var profile = JsonSerializer.Deserialize<HarnessProfile>(json, _jsonOpts);
            if (profile is not null && !string.IsNullOrEmpty(profile.Name))
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

        _watcher.Changed += (_, _) => LoadAll();
        _watcher.Created += (_, _) => LoadAll();
        _watcher.Deleted += (_, _) => LoadAll();
    }

    private T WithLock<T>(Func<T> action)
    {
        lock (_gate) return action();
    }

    public void Dispose()
    {
        _watcher?.Dispose();
    }
}
