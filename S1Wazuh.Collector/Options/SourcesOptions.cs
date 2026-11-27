namespace S1Wazuh.Options;

public sealed class SourcesOptions
{
    public SourceOptions Threats { get; set; } = new();
    public UnifiedAlertsOptions Alerts { get; set; } = new();
    public SourceOptions Activities { get; set; } = new();
    public SourceOptions Agents { get; set; } = new();
    public DeepVisibilityOptions DeepVisibility { get; set; } = new();
}
