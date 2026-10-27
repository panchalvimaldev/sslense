namespace SSLense.Core.WindowsServices;

public interface IWindowsServiceManager
{
    Task<WindowsServiceStatus> GetStatusAsync(CancellationToken cancellationToken = default);

    Task InstallAsync(string executablePath, CancellationToken cancellationToken = default);

    Task StartAsync(CancellationToken cancellationToken = default);

    Task StopAsync(CancellationToken cancellationToken = default);

    Task UninstallAsync(CancellationToken cancellationToken = default);
}

public enum WindowsServiceStatus
{
    NotInstalled,
    Stopped,
    Running,
    Pending,
    Unknown
}
