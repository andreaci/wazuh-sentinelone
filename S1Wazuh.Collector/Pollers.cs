using System.Globalization;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace S1Wazuh;

public interface ISourcePoller
{
    string Name { get; }
    int IntervalSeconds { get; }
    Task RunOnceAsync(CancellationToken ct);
}

internal static class Time
{
    public static string Iso(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    public static DateTimeOffset? Parse(string? s) =>
        DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t) ? t : null;
}

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
            if (sorted) { query.Add(new("sortBy", o.SortBy!)); query.Add(new("sortOrder", o.SortOrder)); }
            if (!snapshot) query.Add(new(o.TimeFilterParam!, Time.Iso(since)));
            if (cursor is not null) query.Add(new("cursor", cursor));

            var resp = await client.GetAsync(o.Path, query, ct);
            var data = resp["data"] as JsonArray ?? [];
            var lines = new List<string>();

            foreach (var item in data)
            {
                if (item is null) continue;
                var id = JsonPath.GetString(item, o.IdPath);
                var ts = JsonPath.GetString(item, o.TimestampPath);
                var key = $"{id}|{ts}";
                var t = Time.Parse(ts);

                if (snapshot)
                {
                    snapshotKeys.Add(key);
                    if (state.Keys.Contains(key)) continue;
                }
                else
                {
                    if (t is not null && t == state.LastTimestamp && state.Keys.Contains(key)) continue;
                    if (t is not null)
                    {
                        if (state.LastTimestamp is null || t > state.LastTimestamp) { state.LastTimestamp = t; state.Keys.Clear(); }
                        if (t == state.LastTimestamp) state.Keys.Add(key);
                    }
                }
                lines.Add(Envelope.Build(name, id, ts, item, output.Value.MaxLineBytes));
            }

            sink.WriteLines(name, lines);
            emitted += lines.Count;
            // Sorted ascending: safe to checkpoint after each page. Otherwise only when the run completes.
            if (sorted && !snapshot) store.Save(name, state);

            cursor = resp["pagination"]?["nextCursor"]?.ToString();
            if (data.Count == 0) break;
        } while (!string.IsNullOrEmpty(cursor));

        if (snapshot) state.Keys = snapshotKeys;
        store.Save(name, state);
        log.LogInformation("{Source}: emitted {Count} new record(s)", name, emitted);
    }
}

/// <summary>Unified alerts via GraphQL, incremental on a timestamp field with boundary-key dedupe.</summary>
public sealed class UnifiedAlertPoller(
    UnifiedAlertsOptions o, SentinelOneClient client, IEventSink sink, StateStore store,
    IOptions<SentinelOneOptions> s1, IOptions<OutputOptions> output, ILogger log) : ISourcePoller
{
    private const string Endpoint = "/web/api/v2.1/unifiedalerts/graphql";
    public string Name => "alert";
    public int IntervalSeconds => o.IntervalSeconds;

    public async Task RunOnceAsync(CancellationToken ct)
    {
        var state = store.Load<SourceState>(Name);
        var since = state.LastTimestamp ?? DateTimeOffset.UtcNow.AddHours(-o.InitialLookbackHours);
        var sinceMs = since.ToUnixTimeMilliseconds();
        string? cursor = null;
        var emitted = 0;

        do
        {
            var after = cursor is null ? "" : $", after:{System.Text.Json.JsonSerializer.Serialize(cursor)}";
            var q = $"{{ alerts(first:{s1.Value.PageSize}, viewType:{o.ViewType}{Scope()}, " +
                    $"sorts:[{{by:\"{o.TimeField}\", order:ASC}}], " +
                    $"filters:[{{fieldId:\"{o.TimeField}\", dateTimeRange:{{start:{sinceMs}, startInclusive:true}}}}]{after}) " +
                    $"{{ pageInfo{{hasNextPage endCursor}} edges{{ node{{ {o.Selection} }} }} }} }}";

            var resp = await client.PostAsync(Endpoint, new JsonObject { ["query"] = q }, ct);
            if (resp["errors"] is JsonArray { Count: > 0 } errs)
                throw new InvalidOperationException("Unified alerts GraphQL error: " + errs.ToJsonString());

            var alerts = resp["data"]?["alerts"];
            var edges = alerts?["edges"] as JsonArray ?? [];
            var lines = new List<string>();
            foreach (var edge in edges)
            {
                var item = edge?["node"];
                if (item is null) continue;
                var id = JsonPath.GetString(item, "id");
                var ts = JsonPath.GetString(item, o.TimeField);
                var key = $"{id}|{ts}";
                var t = Time.Parse(ts);
                if (t is not null && t == state.LastTimestamp && state.Keys.Contains(key)) continue;
                if (t is not null)
                {
                    if (state.LastTimestamp is null || t > state.LastTimestamp) { state.LastTimestamp = t; state.Keys.Clear(); }
                    if (t == state.LastTimestamp) state.Keys.Add(key);
                }
                lines.Add(Envelope.Build(Name, id, ts, item, output.Value.MaxLineBytes));
            }

            sink.WriteLines(Name, lines);
            emitted += lines.Count;
            store.Save(Name, state);

            var hasNext = alerts?["pageInfo"]?["hasNextPage"]?.GetValue<bool>() ?? false;
            cursor = hasNext ? alerts?["pageInfo"]?["endCursor"]?.ToString() : null;
            if (edges.Count == 0) break;
        } while (!string.IsNullOrEmpty(cursor));

        log.LogInformation("alert: emitted {Count} new alert(s)", emitted);
    }

    private string Scope() => s1.Value.SiteIds.Length > 0
        ? $", scope:{{scopeType:SITE, scopeIds:[{string.Join(",", s1.Value.SiteIds.Select(i => $"\"{i}\""))}]}}"
        : s1.Value.AccountIds.Length > 0
            ? $", scope:{{scopeType:ACCOUNT, scopeIds:[{string.Join(",", s1.Value.AccountIds.Select(i => $"\"{i}\""))}]}}"
            : "";
}

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
        if (s1.Value.AccountIds.Length > 0) body["accountIds"] = new JsonArray(s1.Value.AccountIds.Select(a => (JsonNode)a).ToArray());
        if (s1.Value.SiteIds.Length > 0) body["siteIds"] = new JsonArray(s1.Value.SiteIds.Select(a => (JsonNode)a).ToArray());

        var init = await client.PostAsync($"{Base}/init-query", body, ct);
        var queryId = init["data"]?["queryId"]?.ToString()
            ?? throw new InvalidOperationException("Deep Visibility init-query returned no queryId");

        await WaitForQueryAsync(queryId, ct);

        var emitted = 0;
        string? cursor = null;
        do
        {
            var query = new List<KeyValuePair<string, string>> { new("queryId", queryId), new("limit", s1.Value.PageSize.ToString()) };
            if (cursor is not null) query.Add(new("cursor", cursor));
            var resp = await client.GetAsync($"{Base}/events", query, ct);
            var data = resp["data"] as JsonArray ?? [];
            var lines = new List<string>();
            foreach (var item in data)
            {
                if (item is null) continue;
                lines.Add(Envelope.Build("dv_event", JsonPath.GetString(item, o.IdPath),
                    JsonPath.GetString(item, o.TimestampPath), item, output.Value.MaxLineBytes));
            }
            sink.WriteLines("dv", lines);
            emitted += lines.Count;
            cursor = resp["pagination"]?["nextCursor"]?.ToString();
            if (data.Count == 0) break;
        } while (!string.IsNullOrEmpty(cursor));

        if (emitted >= o.MaxEventsPerQuery)
            log.LogWarning("dv: window {From}..{To} hit MaxEventsPerQuery={Max}; events may be missing. Narrow the query or lower MaxWindowHours.",
                from, to, o.MaxEventsPerQuery);

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
            if (progress >= 100 || state.Equals("FINISHED", StringComparison.OrdinalIgnoreCase)) return;
            if (DateTimeOffset.UtcNow > deadline)
                throw new TimeoutException($"Deep Visibility query {queryId} not finished after {o.QueryTimeoutSeconds}s");
            await Task.Delay(TimeSpan.FromSeconds(o.StatusPollSeconds), ct);
        }
    }
}
