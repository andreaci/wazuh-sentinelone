using System.Text;
using Microsoft.Extensions.Options;

namespace S1Wazuh;

public interface IEventSink
{
    /// <summary>Append one NDJSON line to the file for the given source.</summary>
    void WriteLines(string source, IReadOnlyList<string> lines);
}

/// <summary>Appends NDJSON to sentinelone-{source}.json with size-based rotation (.1, .2, ...).</summary>
public sealed class NdjsonFileSink(IOptions<OutputOptions> options) : IEventSink
{
    private readonly OutputOptions _o = options.Value;
    private readonly object _lock = new();

    public void WriteLines(string source, IReadOnlyList<string> lines)
    {
        if (lines.Count == 0) return;
        lock (_lock)
        {
            Directory.CreateDirectory(_o.Directory);
            var path = Path.Combine(_o.Directory, $"sentinelone-{source}.json");
            Rotate(path);
            var sb = new StringBuilder();
            foreach (var l in lines) sb.Append(l).Append('\n');
            using var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            var bytes = new UTF8Encoding(false).GetBytes(sb.ToString());
            fs.Write(bytes);
            fs.Flush(true);
        }
    }

    private void Rotate(string path)
    {
        var fi = new FileInfo(path);
        if (!fi.Exists || fi.Length < _o.MaxFileSizeMb * 1024L * 1024L) return;
        var last = $"{path}.{_o.RetainedFiles}";
        if (File.Exists(last)) File.Delete(last);
        for (var i = _o.RetainedFiles - 1; i >= 1; i--)
            if (File.Exists($"{path}.{i}")) File.Move($"{path}.{i}", $"{path}.{i + 1}");
        File.Move(path, $"{path}.1");
    }
}
