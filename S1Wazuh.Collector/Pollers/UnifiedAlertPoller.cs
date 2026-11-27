using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;
using S1Wazuh.Options;

namespace S1Wazuh.Pollers;

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
                if (item is null) 
                    continue;

                var id = JsonPath.GetString(item, "id");
                var ts = JsonPath.GetString(item, o.TimeField);
                var key = $"{id}|{ts}";
                var t = Time.Parse(ts);

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

                lines.Add(Envelope.Build(Name, id, ts, item, output.Value.MaxLineBytes));
            }

            sink.WriteLines(Name, lines);
            emitted += lines.Count;
            store.Save(Name, state);

            var hasNext = alerts?["pageInfo"]?["hasNextPage"]?.GetValue<bool>() ?? false;
            cursor = hasNext ? alerts?["pageInfo"]?["endCursor"]?.ToString() : null;
            if (edges.Count == 0) 
                break;

        } while (!string.IsNullOrEmpty(cursor));

        log.LogInformation("alert: emitted {Count} new alert(s)", emitted);
    }

    private string Scope() => s1.Value.SiteIds.Length > 0
        ? $", scope:{{scopeType:SITE, scopeIds:[{string.Join(",", s1.Value.SiteIds.Select(i => $"\"{i}\""))}]}}"
        : s1.Value.AccountIds.Length > 0
            ? $", scope:{{scopeType:ACCOUNT, scopeIds:[{string.Join(",", s1.Value.AccountIds.Select(i => $"\"{i}\""))}]}}"
            : "";
}
