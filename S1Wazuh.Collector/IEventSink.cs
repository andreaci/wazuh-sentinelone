namespace S1Wazuh;

public interface IEventSink
{
    /// <summary>Append one NDJSON line to the file for the given source.</summary>
    void WriteLines(string source, IReadOnlyList<string> lines);
}
