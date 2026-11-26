namespace S1Wazuh;

public sealed class SentinelOneOptions
{
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

public sealed class OutputOptions
{
    public string Directory { get; set; } = "/var/ossec/logs/sentinelone";
    public int MaxFileSizeMb { get; set; } = 50;
    public int RetainedFiles { get; set; } = 5;
    /// <summary>Wazuh logcollector truncates lines at ~64KB.</summary>
    public int MaxLineBytes { get; set; } = 60000;
}

public sealed class StateOptions
{
    public string Directory { get; set; } = "/var/lib/s1wazuh";
}

/// <summary>A paginated REST list endpoint polled incrementally.</summary>
public class SourceOptions
{
    public bool Enabled { get; set; } = true;
    public int IntervalSeconds { get; set; } = 60;
    public int InitialLookbackHours { get; set; } = 24;
    public string Path { get; set; } = "";
    /// <summary>Query parameter for "items at/after this time". Null = full snapshot each run (changed items only are emitted).</summary>
    public string? TimeFilterParam { get; set; }
    public string? SortBy { get; set; }
    public string SortOrder { get; set; } = "asc";
    public string IdPath { get; set; } = "id";
    public string TimestampPath { get; set; } = "updatedAt";
    public Dictionary<string, string> ExtraQuery { get; set; } = new();
}

/// <summary>Unified Alerts (Singularity Operations Center) via the GraphQL API.</summary>
public sealed class UnifiedAlertsOptions
{
    public bool Enabled { get; set; } = true;
    public int IntervalSeconds { get; set; } = 60;
    public int InitialLookbackHours { get; set; } = 24;
    /// <summary>ALL, ENDPOINT, CLOUD, IDENTITY, THIRD_PARTY, CUSTOM_ALERTS, DLP.</summary>
    public string ViewType { get; set; } = "ALL";
    /// <summary>Field used for the incremental filter and ascending sort.</summary>
    public string TimeField { get; set; } = "updatedAt";
    /// <summary>GraphQL selection set for each alert node; extend it to pull more fields.</summary>
    public string Selection { get; set; } =
        "id externalId name description severity status classification confidenceLevel analystVerdict " +
        "detectionSource{product vendor} detectedAt createdAt updatedAt firstSeenAt lastSeenAt " +
        "storylineId ticketId labels dataSources primaryIndicatorType result " +
        "assets{id name category subcategory osType lastLoggedInUser agentUuid} process{cmdLine parentName}";
}

public sealed class DeepVisibilityOptions
{
    public bool Enabled { get; set; } = false;
    public int IntervalSeconds { get; set; } = 300;
    public int InitialLookbackHours { get; set; } = 1;
    /// <summary>Deep Visibility (PowerQuery-style) filter, e.g. EventType = "Process Creation".</summary>
    public string Query { get; set; } = "";
    public int MaxEventsPerQuery { get; set; } = 20000;
    public int MaxWindowHours { get; set; } = 1;
    public int EndLagSeconds { get; set; } = 60;
    public int QueryTimeoutSeconds { get; set; } = 300;
    public int StatusPollSeconds { get; set; } = 3;
    public string IdPath { get; set; } = "id";
    public string TimestampPath { get; set; } = "createdAt";
}

public sealed class SourcesOptions
{
    public SourceOptions Threats { get; set; } = new();
    public UnifiedAlertsOptions Alerts { get; set; } = new();
    public SourceOptions Activities { get; set; } = new();
    public SourceOptions Agents { get; set; } = new();
    public DeepVisibilityOptions DeepVisibility { get; set; } = new();
}
