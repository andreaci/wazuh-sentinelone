using System.Text;
using Microsoft.Extensions.Options;
using S1Wazuh.Options;

namespace S1Wazuh;

/// <summary>Appends NDJSON to sentinelone-{source}.json with size-based rotation (.1, .2, ...).</summary>
public sealed class NdjsonFileSink(IOptions<OutputOptions> options) : IEventSink
{
    private readonly OutputOptions _outputOptions = options.Value;
    private readonly object _lock = new();

    public void WriteLines(string source, IReadOnlyList<string> lines)
    {
        if (lines.Count == 0) return;
        lock (_lock)
        {
            Directory.CreateDirectory(_outputOptions.Directory);
            var path = Path.Combine(_outputOptions.Directory, $"sentinelone-{source}.json");
            Rotate(path);

            var sb = new StringBuilder();
            foreach (var l in lines) 
                sb.Append(l).Append('\n');
            
            using var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            var bytes = new UTF8Encoding(false).GetBytes(sb.ToString());
            fs.Write(bytes);
            fs.Flush(true);
        }
    }

    private void Rotate(string path)
    {
        var fi = new FileInfo(path);
        if (!fi.Exists || fi.Length < _outputOptions.MaxFileSizeMb * 1024L * 1024L) 
            return;

        var last = $"{path}.{_outputOptions.RetainedFiles}";
        if (File.Exists(last)) 
            File.Delete(last);

        for (var i = _outputOptions.RetainedFiles - 1; i >= 1; i--)
        {
            if (File.Exists($"{path}.{i}")) 
                File.Move($"{path}.{i}", $"{path}.{i + 1}");
        }

        File.Move(path, $"{path}.1");
    }
}
