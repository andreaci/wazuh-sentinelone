using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;
using S1Wazuh.Options;

namespace S1Wazuh.Pollers;

/// <summary>Deep Visibility: async query (init → status → events) over non-overlapping time windows.</summary>
public sealed class DeepVisibilityPoller(
    DeepVisibilityOptions o, SentinelOneClient client, IEventSink sink, StateStore store,
    IOptions<SentinelOneOptions> s1, IOptions<OutputOptions> output, ILogger log) : ISourcePoller
{
    private const string Base = "/web/api/v2.1/dv";
    public string Name => "dv";
    public int IntervalSeconds => o.IntervalSeconds;

    public async Task RunOnceAsync(CancellationToken ct)
    {
        var state = store.Load<DvState>(Name);
        var now = DateTimeOffset.UtcNow;
        var from = state.LastTo ?? now.AddHours(-o.InitialLookbackHours);
        var to = now.AddSeconds(-o.EndLagSeconds);
        if (to - from > TimeSpan.FromHours(o.MaxWindowHours)) to = from.AddHours(o.MaxWindowHours);
        if (to <= from) return;

        var body = new JsonObject
        {
            ["query"] = o.Query,
            ["fromDate"] = Time.Iso(from),
            ["toDate"] = Time.Iso(to),
            ["limit"] = o.MaxEventsPerQuery,
            ["queryType"] = new JsonArray("events"),
        };
        if (s1.Value.AccountIds.Length > 0) 
            body["accountIds"] = new JsonArray(s1.Value.AccountIds.Select(a => (JsonNode)a).ToArray());
        if (s1.Value.SiteIds.Length > 0) 
            body["siteIds"] = new JsonArray(s1.Value.SiteIds.Select(a => (JsonNode)a).ToArray());

        var init = await client.PostAsync($"{Base}/init-query", body, ct);
        var queryId = init["data"]?["queryId"]?.ToString()
            ?? throw new InvalidOperationException("Deep Visibility init-query returned no queryId");

        await WaitForQueryAsync(queryId, ct);

        var emitted = 0;
        string? cursor = null;
        do
        {
            var query = new List<KeyValuePair<string, string>> { new("queryId", queryId), new("limit", s1.Value.PageSize.ToString()) };
            if (cursor is not null) 
                query.Add(new("cursor", cursor));

            var resp = await client.GetAsync($"{Base}/events", query, ct);
            var data = resp["data"] as JsonArray ?? [];
            var lines = new List<string>();

            foreach (var item in data)
            {
                if (item is null) 
                    continue;

                lines.Add(Envelope.Build("dv_event", JsonPath.GetString(item, o.IdPath),
                    JsonPath.GetString(item, o.TimestampPath), item, output.Value.MaxLineBytes));
            }

            sink.WriteLines("dv", lines);
            emitted += lines.Count;
            cursor = resp["pagination"]?["nextCursor"]?.ToString();

            if (data.Count == 0)
                break;
        } while (!string.IsNullOrEmpty(cursor));

        if (emitted >= o.MaxEventsPerQuery)
        {
            log.LogWarning("dv: window {From}..{To} hit MaxEventsPerQuery={Max}; events may be missing. Narrow the query or lower MaxWindowHours.",
                from, to, o.MaxEventsPerQuery);
        }

        // Checkpoint only after the whole window was read.
        state.LastTo = to;
        store.Save(Name, state);
        log.LogInformation("dv: emitted {Count} event(s) for {From}..{To}", emitted, Time.Iso(from), Time.Iso(to));
    }

    private async Task WaitForQueryAsync(string queryId, CancellationToken ct)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(o.QueryTimeoutSeconds);
        while (true)
        {
            var st = await client.GetAsync($"{Base}/query-status", [new("queryId", queryId)], ct);
            var data = st["data"];
            var state = data?["responseState"]?.ToString() ?? "";
            var progress = data?["progressStatus"]?.GetValue<int>() ?? 0;

            if (state.StartsWith("FAILED", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"Deep Visibility query {queryId} failed: {state}");

            if (progress >= 100 || state.Equals("FINISHED", StringComparison.OrdinalIgnoreCase)) 
                return;

            if (DateTimeOffset.UtcNow > deadline)
                throw new TimeoutException($"Deep Visibility query {queryId} not finished after {o.QueryTimeoutSeconds}s");

            await Task.Delay(TimeSpan.FromSeconds(o.StatusPollSeconds), ct);
        }
    }
}
