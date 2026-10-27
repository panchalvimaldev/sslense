namespace SSLense.Core.WindowsServices;

public interface IWindowsServiceManager
{
    Task InstallAsync(string executablePath, CancellationToken cancellationToken = default);

    Task UninstallAsync(CancellationToken cancellationToken = default);
}
