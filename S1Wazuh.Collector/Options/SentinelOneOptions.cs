namespace S1Wazuh.Options;

public sealed class SentinelOneOptions
{
    /// <summary>Prefer the env var SentinelOne__BaseUrl over the config file.</summary>
    public string BaseUrl { get; set; } = "";
    /// <summary>Prefer the env var SentinelOne__ApiToken over the config file.</summary>
    public string ApiToken { get; set; } = "";

    public string[] AccountIds { get; set; } = [];
    public string[] SiteIds { get; set; } = [];
    public int PageSize { get; set; } = 1000;
    public int HttpTimeoutSeconds { get; set; } = 60;
    public int MaxRetries { get; set; } = 5;
    public int RetryBaseDelayMs { get; set; } = 1000;
}
