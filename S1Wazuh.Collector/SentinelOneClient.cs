using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;
using S1Wazuh.Options;

namespace S1Wazuh;

public sealed class SentinelOneApiException(HttpStatusCode status, string body)
    : Exception($"SentinelOne API returned {(int)status}: {body}")
{
    public HttpStatusCode Status { get; } = status;
}

public sealed class SentinelOneClient(HttpClient http, IOptions<SentinelOneOptions> options, ILogger<SentinelOneClient> log)
{
    private readonly SentinelOneOptions _o = options.Value;

    public Task<JsonObject> GetAsync(string path, IEnumerable<KeyValuePair<string, string>> query, CancellationToken ct)
    {
        var qs = string.Join("&", query.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
        var url = qs.Length == 0 ? path : $"{path}?{qs}";
        return SendAsync(() => new HttpRequestMessage(HttpMethod.Get, url), ct);
    }

    public Task<JsonObject> PostAsync(string path, JsonObject body, CancellationToken ct) =>
        SendAsync(() => new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
        }, ct);

    /// <summary>Account/site scoping parameters shared by all list endpoints.</summary>
    public IEnumerable<KeyValuePair<string, string>> ScopeQuery()
    {
        if (_o.AccountIds.Length > 0) yield return new("accountIds", string.Join(",", _o.AccountIds));
        if (_o.SiteIds.Length > 0) yield return new("siteIds", string.Join(",", _o.SiteIds));
    }

    private async Task<JsonObject> SendAsync(Func<HttpRequestMessage> make, CancellationToken ct)
    {
        for (var attempt = 0; ; attempt++)
        {
            HttpResponseMessage resp;
            try
            {
                resp = await http.SendAsync(make(), ct);
            }
            catch (Exception ex) when (attempt < _o.MaxRetries && !ct.IsCancellationRequested
                                       && ex is HttpRequestException or TaskCanceledException)
            {
                var d = Backoff(attempt, null);
                log.LogWarning("Request failed ({Msg}); retry {N}/{Max} in {Delay}", ex.Message, attempt + 1, _o.MaxRetries, d);
                await Task.Delay(d, ct);
                continue;
            }

            using (resp)
            {
                if (resp.IsSuccessStatusCode)
                {
                    await using var s = await resp.Content.ReadAsStreamAsync(ct);
                    return (JsonObject)(await JsonNode.ParseAsync(s, cancellationToken: ct))!;
                }

                var retryable = resp.StatusCode == HttpStatusCode.TooManyRequests || (int)resp.StatusCode >= 500;
                if (retryable && attempt < _o.MaxRetries)
                {
                    var d = Backoff(attempt, resp.Headers.RetryAfter?.Delta ??
                        (resp.Headers.RetryAfter?.Date is { } dt ? dt - DateTimeOffset.UtcNow : null));
                    log.LogWarning("HTTP {Status}; retry {N}/{Max} in {Delay}", (int)resp.StatusCode, attempt + 1, _o.MaxRetries, d);
                    await Task.Delay(d, ct);
                    continue;
                }

                var body = await resp.Content.ReadAsStringAsync(ct);
                throw new SentinelOneApiException(resp.StatusCode, body.Length > 500 ? body[..500] : body);
            }
        }
    }

    private TimeSpan Backoff(int attempt, TimeSpan? retryAfter)
    {
        if (retryAfter is { } ra && ra > TimeSpan.Zero) return ra > TimeSpan.FromMinutes(5) ? TimeSpan.FromMinutes(5) : ra;
        var ms = Math.Min(60_000, _o.RetryBaseDelayMs * Math.Pow(2, attempt));
        return TimeSpan.FromMilliseconds(ms + Random.Shared.Next(0, Math.Max(1, _o.RetryBaseDelayMs)));
    }
}
