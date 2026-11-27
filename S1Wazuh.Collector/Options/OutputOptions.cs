namespace S1Wazuh.Options;

public sealed class OutputOptions
{
    public string Directory { get; set; } = "/var/ossec/logs/sentinelone";
    public int MaxFileSizeMb { get; set; } = 50;
    public int RetainedFiles { get; set; } = 5;
    /// <summary>Wazuh logcollector truncates lines at ~64KB.</summary>
    public int MaxLineBytes { get; set; } = 60000;
}
