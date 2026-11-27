namespace S1Wazuh.Options;

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
