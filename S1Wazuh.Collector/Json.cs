using System.Text.Json.Nodes;

namespace S1Wazuh;

public static class JsonPath
{
    public static JsonNode? Get(JsonNode? node, string path)
    {
        foreach (var seg in path.Split('.'))
        {
            if (node is JsonObject o && o.TryGetPropertyValue(seg, out var child)) node = child;
            else return null;
        }
        return node;
    }

    public static string? GetString(JsonNode? node, string path) => Get(node, path)?.ToString();
}

public static class Envelope
{
    /// <summary>Wraps a raw S1 record so Wazuh rules can key on stable top-level fields.</summary>
    public static string Build(string source, string? id, string? timestamp, JsonNode item, int maxBytes)
    {
        var s1 = (JsonObject)(item.DeepClone());
        var env = new JsonObject
        {
            ["integration"] = "sentinelone",
            ["s1_source"] = source,
            ["s1_id"] = id,
            ["s1_timestamp"] = timestamp,
            ["s1"] = s1,
        };
        var line = env.ToJsonString();
        if (System.Text.Encoding.UTF8.GetByteCount(line) <= maxBytes) return line;

        env["s1_truncated"] = true;
        // Drop the largest top-level fields of the record until the line fits.
        var bySize = s1.Where(p => p.Value is not null)
                       .OrderByDescending(p => p.Value!.ToJsonString().Length)
                       .Select(p => p.Key).ToList();
        foreach (var key in bySize)
        {
            s1.Remove(key);
            line = env.ToJsonString();
            if (System.Text.Encoding.UTF8.GetByteCount(line) <= maxBytes) break;
        }
        return line;
    }
}
