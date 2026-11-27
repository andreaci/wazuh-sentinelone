namespace S1Wazuh.Options;

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
