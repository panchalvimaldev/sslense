namespace SSLense.Core.Logs;

public interface ILogService
{
    Task<LogSnapshot> ReadCurrentAsync(
        string level,
        int maximumLines = 1000,
        CancellationToken cancellationToken = default);

    void OpenLogDirectory();
}
