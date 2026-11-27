using System.Net.Http.Headers;
using Microsoft.Extensions.Options;
using S1Wazuh;
using S1Wazuh.Options;
using S1Wazuh.Pollers;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddSystemd();
builder.Services.AddWindowsService(o => o.ServiceName = "s1wazuh");

builder.Services.AddOptions<SentinelOneOptions>().BindConfiguration("SentinelOne")
    .Validate(o => Uri.TryCreate(o.BaseUrl, UriKind.Absolute, out _), "SentinelOne:BaseUrl must be an absolute URL")
    .Validate(o => !string.IsNullOrWhiteSpace(o.ApiToken), "SentinelOne:ApiToken is required (set env SentinelOne__ApiToken)")
    .ValidateOnStart();

builder.Services.AddOptions<OutputOptions>().BindConfiguration("Output");
builder.Services.AddOptions<StateOptions>().BindConfiguration("State");
builder.Services.AddOptions<SourcesOptions>().BindConfiguration("Sources");

builder.Services.AddSingleton<StateStore>();
builder.Services.AddSingleton<IEventSink, NdjsonFileSink>();
builder.Services.AddHttpClient<SentinelOneClient>((sp, http) =>
{
    var o = sp.GetRequiredService<IOptions<SentinelOneOptions>>().Value;
    http.BaseAddress = new Uri(o.BaseUrl.TrimEnd('/') + "/");
    http.Timeout = TimeSpan.FromSeconds(o.HttpTimeoutSeconds);
    http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("ApiToken", o.ApiToken);
});

// One hosted polling loop per enabled source.
var sources = builder.Configuration.GetSection("Sources").Get<SourcesOptions>() ?? new SourcesOptions();
void AddList(string name, SourceOptions o)
{
    if (!o.Enabled) return;
    builder.Services.AddSingleton<IHostedService>(sp => new PollingService(
        new ListSourcePoller(name, o, sp.GetRequiredService<SentinelOneClient>(), sp.GetRequiredService<IEventSink>(),
            sp.GetRequiredService<StateStore>(), sp.GetRequiredService<IOptions<SentinelOneOptions>>(),
            sp.GetRequiredService<IOptions<OutputOptions>>(), sp.GetRequiredService<ILoggerFactory>().CreateLogger($"S1Wazuh.{name}")),
        sp.GetRequiredService<ILoggerFactory>().CreateLogger($"S1Wazuh.{name}")));
}
AddList("threat", sources.Threats);
if (sources.Alerts.Enabled)
{
    builder.Services.AddSingleton<IHostedService>(sp => new PollingService(
        new UnifiedAlertPoller(sources.Alerts, sp.GetRequiredService<SentinelOneClient>(), sp.GetRequiredService<IEventSink>(),
            sp.GetRequiredService<StateStore>(), sp.GetRequiredService<IOptions<SentinelOneOptions>>(),
            sp.GetRequiredService<IOptions<OutputOptions>>(), sp.GetRequiredService<ILoggerFactory>().CreateLogger("S1Wazuh.alert")),
        sp.GetRequiredService<ILoggerFactory>().CreateLogger("S1Wazuh.alert")));
}
AddList("activity", sources.Activities);
AddList("agent", sources.Agents);

if (sources.DeepVisibility.Enabled)
{
    if (string.IsNullOrWhiteSpace(sources.DeepVisibility.Query))
        throw new InvalidOperationException("Sources:DeepVisibility:Query is required when DeepVisibility is enabled");

    builder.Services.AddSingleton<IHostedService>(sp => new PollingService(
        new DeepVisibilityPoller(sources.DeepVisibility, sp.GetRequiredService<SentinelOneClient>(), sp.GetRequiredService<IEventSink>(),
            sp.GetRequiredService<StateStore>(), sp.GetRequiredService<IOptions<SentinelOneOptions>>(),
            sp.GetRequiredService<IOptions<OutputOptions>>(), sp.GetRequiredService<ILoggerFactory>().CreateLogger("S1Wazuh.dv")),
        sp.GetRequiredService<ILoggerFactory>().CreateLogger("S1Wazuh.dv")));
}

await builder.Build().RunAsync();

/// <summary>Runs one poller forever; errors are logged and retried next interval.</summary>
public sealed class PollingService(ISourcePoller poller, ILogger log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stop)
    {
        log.LogInformation("Starting poller {Name} every {S}s", poller.Name, poller.IntervalSeconds);

        while (!stop.IsCancellationRequested)
        {
            try { 
                await poller.RunOnceAsync(stop); 
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) 
            { 
                break; 
            }
            catch (Exception ex) { 
                log.LogError(ex, "Poller {Name} failed; will retry next interval", poller.Name); 
            }

            try { 
                await Task.Delay(TimeSpan.FromSeconds(poller.IntervalSeconds), stop); 
            }
            catch (OperationCanceledException) { 
                break; 
            }
        }
    }
}
