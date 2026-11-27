namespace S1Wazuh;

public interface ISourcePoller
{
    string Name { get; }
    int IntervalSeconds { get; }
    Task RunOnceAsync(CancellationToken ct);
}
