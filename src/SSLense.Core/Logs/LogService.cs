using System.Diagnostics;
using SSLense.Core.Config;

namespace SSLense.Core.Logs;

internal sealed class LogService(IFileSystem fileSystem) : ILogService
{
    public async Task<LogSnapshot> ReadCurrentAsync(
        string level,
        int maximumLines = 1000,
        CancellationToken cancellationToken = default)
    {
        if (maximumLines <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumLines));
        }

        var file = fileSystem.GetFiles(AppPaths.LogDirectory, "sslense-*.log")
            .OrderByDescending(Path.GetFileName, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();
        if (file is null)
        {
            return new LogSnapshot(null, []);
        }

        var lines = await fileSystem.ReadAllLinesAsync(file, cancellationToken).ConfigureAwait(false);
        var filtered = lines.Where(line => MatchesLevel(line, level)).TakeLast(maximumLines).ToArray();
        return new LogSnapshot(file, filtered);
    }

    public void OpenLogDirectory()
    {
        fileSystem.CreateDirectory(AppPaths.LogDirectory);
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = AppPaths.LogDirectory,
                UseShellExecute = true
            });
        }
        catch (Exception exception)
        {
            throw new InvalidOperationException(
                $"Could not open the log directory '{AppPaths.LogDirectory}'.",
                exception);
        }
    }

    private static bool MatchesLevel(string line, string level) => level switch
    {
        "Debug" => line.Contains(" DBG]", StringComparison.Ordinal),
        "Information" => line.Contains(" INF]", StringComparison.Ordinal),
        "Warning" => line.Contains(" WRN]", StringComparison.Ordinal),
        "Error" => line.Contains(" ERR]", StringComparison.Ordinal) ||
                   line.Contains(" FTL]", StringComparison.Ordinal),
        _ => true
    };
}
