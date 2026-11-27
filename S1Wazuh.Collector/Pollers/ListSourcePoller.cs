using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;
using S1Wazuh.Options;

namespace S1Wazuh.Pollers;

/// <summary>Incrementally polls a cursor-paginated S1 list endpoint (threats, alerts, activities, agents).</summary>
public sealed class ListSourcePoller(
    string name, SourceOptions o, SentinelOneClient client, IEventSink sink, StateStore store,
    IOptions<SentinelOneOptions> s1, IOptions<OutputOptions> output, ILogger log) : ISourcePoller
{
    public string Name => name;
    public int IntervalSeconds => o.IntervalSeconds;

    public async Task RunOnceAsync(CancellationToken ct)
    {
        var state = store.Load<SourceState>(name);
        var since = state.LastTimestamp ?? DateTimeOffset.UtcNow.AddHours(-o.InitialLookbackHours);
        var sorted = o.SortBy is not null;
        var snapshot = o.TimeFilterParam is null;
        var snapshotKeys = new HashSet<string>();
        string? cursor = null;

        var emitted = 0;

        do
        {
            var query = new List<KeyValuePair<string, string>> { new("limit", s1.Value.PageSize.ToString()) };
            query.AddRange(client.ScopeQuery());
            query.AddRange(o.ExtraQuery.Select(kv => new KeyValuePair<string, string>(kv.Key, kv.Value)));

            if (sorted) {
                query.Add(new("sortBy", o.SortBy!));
                query.Add(new("sortOrder", o.SortOrder)); 
            }

            if (!snapshot) 
                query.Add(new(o.TimeFilterParam!, Time.Iso(since)));

            if (cursor is not null)
                query.Add(new("cursor", cursor));

            var resp = await client.GetAsync(o.Path, query, ct);
            var data = resp["data"] as JsonArray ?? [];
            var lines = new List<string>();

            foreach (var item in data)
            {
                if (item is null) 
                    continue;

                var id = JsonPath.GetString(item, o.IdPath);
                var ts = JsonPath.GetString(item, o.TimestampPath);
                var key = $"{id}|{ts}";
                var t = Time.Parse(ts);

                if (snapshot)
                {
                    snapshotKeys.Add(key);
                    if (state.Keys.Contains(key))
                        continue;
                }
                else
                {
                    if (t is not null && t == state.LastTimestamp && state.Keys.Contains(key)) 
                        continue;

                    if (t is not null)
                    {
                        if (state.LastTimestamp is null || t > state.LastTimestamp) 
                        {
                            state.LastTimestamp = t;
                            state.Keys.Clear(); 
                        }

                        if (t == state.LastTimestamp)
                            state.Keys.Add(key);
                    }
                }
                lines.Add(Envelope.Build(name, id, ts, item, output.Value.MaxLineBytes));
            }

            sink.WriteLines(name, lines);
            emitted += lines.Count;
            // Sorted ascending: safe to checkpoint after each page. Otherwise only when the run completes.
            if (sorted && !snapshot) 
                store.Save(name, state);

            cursor = resp["pagination"]?["nextCursor"]?.ToString();
            if (data.Count == 0) 
                break;

        } while (!string.IsNullOrEmpty(cursor));

        if (snapshot) 
            state.Keys = snapshotKeys;

        store.Save(name, state);
        log.LogInformation("{Source}: emitted {Count} new record(s)", name, emitted);
    }
}
