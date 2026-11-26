using System.Net;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using S1Wazuh;
using Xunit;

namespace S1Wazuh.Tests;

public class PollerTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "s1wazuh-" + Guid.NewGuid().ToString("N"));
    public PollerTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private sealed class FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> f) : HttpMessageHandler
    {
        public List<string> Requests { get; } = new();
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct)
        {
            Requests.Add(r.RequestUri!.PathAndQuery);
            return Task.FromResult(f(r));
        }
    }

    private sealed class MemorySink : IEventSink
    {
        public List<string> Lines { get; } = new();
        public void WriteLines(string source, IReadOnlyList<string> lines) => Lines.AddRange(lines);
    }

    private static HttpResponseMessage Json(string body, HttpStatusCode code = HttpStatusCode.OK) =>
        new(code) { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") };

    private (SentinelOneClient client, IOptions<SentinelOneOptions> opt) MakeClient(FakeHandler h)
    {
        var opt = Options.Create(new SentinelOneOptions { BaseUrl = "https://x.test", ApiToken = "t", RetryBaseDelayMs = 1, MaxRetries = 3, PageSize = 2 });
        var http = new HttpClient(h) { BaseAddress = new Uri("https://x.test/") };
        return (new SentinelOneClient(http, opt, NullLogger<SentinelOneClient>.Instance), opt);
    }

    private ListSourcePoller MakePoller(SentinelOneClient c, IOptions<SentinelOneOptions> opt, MemorySink sink, SourceOptions so) =>
        new("threat", so, c, sink, new StateStore(Options.Create(new StateOptions { Directory = _dir })),
            opt, Options.Create(new OutputOptions()), NullLogger.Instance);

    private static SourceOptions Threats() => new()
    {
        Path = "/web/api/v2.1/threats", TimeFilterParam = "updatedAt__gte", SortBy = "updatedAt",
        IdPath = "id", TimestampPath = "threatInfo.updatedAt",
    };

    [Fact]
    public async Task Paginates_and_dedupes_on_boundary_overlap()
    {
        var page = 0;
        var h = new FakeHandler(r =>
        {
            if (r.RequestUri!.Query.Contains("cursor=c2"))
                return Json("""{"data":[{"id":"3","threatInfo":{"updatedAt":"2026-01-01T00:00:02.000Z"}}],"pagination":{"nextCursor":null}}""");
            page++;
            return page == 1
                ? Json("""{"data":[{"id":"1","threatInfo":{"updatedAt":"2026-01-01T00:00:01.000Z"}},{"id":"2","threatInfo":{"updatedAt":"2026-01-01T00:00:01.000Z"}}],"pagination":{"nextCursor":"c2"}}""")
                // second run: server returns boundary items again (>= filter)
                : Json("""{"data":[{"id":"3","threatInfo":{"updatedAt":"2026-01-01T00:00:02.000Z"}},{"id":"4","threatInfo":{"updatedAt":"2026-01-01T00:00:03.000Z"}}],"pagination":{"nextCursor":null}}""");
        });
        var (c, opt) = MakeClient(h);
        var sink = new MemorySink();
        var p = MakePoller(c, opt, sink, Threats());

        await p.RunOnceAsync(default);
        Assert.Equal(3, sink.Lines.Count);

        await p.RunOnceAsync(default);
        Assert.Equal(4, sink.Lines.Count); // id 3 not re-emitted
        Assert.Contains("\"s1_id\":\"4\"", sink.Lines[3]);
        Assert.Contains("\"integration\":\"sentinelone\"", sink.Lines[0]);
    }

    [Fact]
    public async Task Unified_alerts_graphql_paginates_dedupes_and_sends_filter()
    {
        var bodies = new List<string>();
        var call = 0;
        var h = new FakeHandler(r =>
        {
            bodies.Add(r.Content!.ReadAsStringAsync().Result);
            call++;
            return call switch
            {
                1 => Json("""{"data":{"alerts":{"pageInfo":{"hasNextPage":true,"endCursor":"cur1"},"edges":[{"node":{"id":"a1","updatedAt":"2026-01-01T00:00:01.000Z","severity":"HIGH"}}]}}}"""),
                2 => Json("""{"data":{"alerts":{"pageInfo":{"hasNextPage":false,"endCursor":null},"edges":[{"node":{"id":"a2","updatedAt":"2026-01-01T00:00:02.000Z","severity":"CRITICAL"}}]}}}"""),
                // next run: boundary alert a2 returned again plus a new one
                _ => Json("""{"data":{"alerts":{"pageInfo":{"hasNextPage":false,"endCursor":null},"edges":[{"node":{"id":"a2","updatedAt":"2026-01-01T00:00:02.000Z","severity":"CRITICAL"}},{"node":{"id":"a3","updatedAt":"2026-01-01T00:00:03.000Z","severity":"LOW"}}]}}}"""),
            };
        });
        var (c, opt) = MakeClient(h);
        var sink = new MemorySink();
        var p = new UnifiedAlertPoller(new UnifiedAlertsOptions(), c, sink,
            new StateStore(Options.Create(new StateOptions { Directory = _dir })), opt,
            Options.Create(new OutputOptions()), NullLogger.Instance);

        await p.RunOnceAsync(default);
        Assert.Equal(2, sink.Lines.Count);
        Assert.Contains("after", bodies[1]);
        Assert.Contains("cur1", bodies[1]);
        Assert.Contains("dateTimeRange", bodies[0]);

        await p.RunOnceAsync(default);
        Assert.Equal(3, sink.Lines.Count);
        Assert.Contains("\"s1_source\":\"alert\"", sink.Lines[2]);
    }

    [Fact]
    public async Task Unified_alerts_graphql_errors_throw()
    {
        var h = new FakeHandler(_ => Json("""{"errors":[{"message":"boom"}],"data":null}"""));
        var (c, opt) = MakeClient(h);
        var p = new UnifiedAlertPoller(new UnifiedAlertsOptions(), c, new MemorySink(),
            new StateStore(Options.Create(new StateOptions { Directory = _dir })), opt,
            Options.Create(new OutputOptions()), NullLogger.Instance);
        await Assert.ThrowsAsync<InvalidOperationException>(() => p.RunOnceAsync(default));
    }

    [Fact]
    public async Task Retries_on_429_then_succeeds()
    {
        var n = 0;
        var h = new FakeHandler(_ => ++n < 3 ? Json("{}", HttpStatusCode.TooManyRequests)
            : Json("""{"data":[],"pagination":{}}"""));
        var (c, opt) = MakeClient(h);
        var sink = new MemorySink();
        await MakePoller(c, opt, sink, Threats()).RunOnceAsync(default);
        Assert.Equal(3, h.Requests.Count);
    }

    [Fact]
    public async Task Snapshot_source_emits_only_changed_records()
    {
        var run = 0;
        var h = new FakeHandler(_ => ++run == 1
            ? Json("""{"data":[{"id":"a","updatedAt":"t1"},{"id":"b","updatedAt":"t1"}],"pagination":{}}""")
            : Json("""{"data":[{"id":"a","updatedAt":"t1"},{"id":"b","updatedAt":"t2"}],"pagination":{}}"""));
        var (c, opt) = MakeClient(h);
        var sink = new MemorySink();
        var p = MakePoller(c, opt, sink, new SourceOptions { Path = "/agents", TimeFilterParam = null, IdPath = "id", TimestampPath = "updatedAt" });
        await p.RunOnceAsync(default);
        await p.RunOnceAsync(default);
        Assert.Equal(3, sink.Lines.Count);
    }

    [Fact]
    public void Envelope_truncates_oversized_records_into_a_single_valid_line()
    {
        var big = new JsonObject { ["id"] = "1", ["blob"] = new string('x', 5000), ["small"] = "ok" };
        var line = Envelope.Build("threat", "1", null, big, 1000);
        Assert.DoesNotContain('\n', line);
        var parsed = JsonNode.Parse(line)!;
        Assert.True((bool)parsed["s1_truncated"]!);
        Assert.Equal("ok", (string)parsed["s1"]!["small"]!);
        Assert.True(System.Text.Encoding.UTF8.GetByteCount(line) <= 1000);
    }

    [Fact]
    public void Sink_rotates_by_size()
    {
        var sink = new NdjsonFileSink(Options.Create(new OutputOptions { Directory = _dir, MaxFileSizeMb = 0, RetainedFiles = 2 }));
        sink.WriteLines("x", ["a"]);
        sink.WriteLines("x", ["b"]);
        Assert.True(File.Exists(Path.Combine(_dir, "sentinelone-x.json.1")));
    }
}
