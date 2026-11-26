using System.Text.Json;
using Microsoft.Extensions.Options;

namespace S1Wazuh;

public sealed class SourceState
{
    public DateTimeOffset? LastTimestamp { get; set; }
    /// <summary>Keys (id|timestamp) already emitted at LastTimestamp (or the whole snapshot when no time filter).</summary>
    public HashSet<string> Keys { get; set; } = new();
}

public sealed class DvState
{
    public DateTimeOffset? LastTo { get; set; }
}

public sealed class StateStore(IOptions<StateOptions> options)
{
    private readonly string _dir = options.Value.Directory;

    public T Load<T>(string name) where T : new()
    {
        var path = Path.Combine(_dir, $"{name}.state.json");
        if (!File.Exists(path)) return new T();
        try { return JsonSerializer.Deserialize<T>(File.ReadAllText(path)) ?? new T(); }
        catch (JsonException) { return new T(); }
    }

    /// <summary>Atomic write: temp file then move.</summary>
    public void Save<T>(string name, T state)
    {
        Directory.CreateDirectory(_dir);
        var path = Path.Combine(_dir, $"{name}.state.json");
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(state));
        File.Move(tmp, path, overwrite: true);
    }
}
