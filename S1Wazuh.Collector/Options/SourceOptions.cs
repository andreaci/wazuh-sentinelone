namespace S1Wazuh.Options;

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
