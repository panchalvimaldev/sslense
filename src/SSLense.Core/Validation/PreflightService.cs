using System.Security.Principal;
using SSLense.Core.Config;
using SSLense.Core.Iis;

namespace SSLense.Core.Validation;

internal sealed class PreflightService(IIisService iisService, IFileSystem fileSystem) : IPreflightService, IDisposable
{
    private readonly HttpClient _httpClient = new(new HttpClientHandler { AllowAutoRedirect = false })
    {
        Timeout = TimeSpan.FromSeconds(10)
    };

    public async Task<IReadOnlyList<PreflightCheck>> CheckAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(siteName);
        if (hosts.Count == 0)
        {
            throw new ArgumentException("Select at least one host name.", nameof(hosts));
        }

        var results = new List<PreflightCheck>();
        var isAdministrator = OperatingSystem.IsWindows() && new WindowsPrincipal(WindowsIdentity.GetCurrent())
            .IsInRole(WindowsBuiltInRole.Administrator);
        results.Add(new PreflightCheck(
            "Administrator",
            isAdministrator,
            isAdministrator ? "SSLense is elevated." : "Run SSLense as Administrator."));

        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        var site = sites.SingleOrDefault(value => string.Equals(value.Name, siteName, StringComparison.OrdinalIgnoreCase));
        if (site is null)
        {
            results.Add(new PreflightCheck("IIS site", false, $"IIS site '{siteName}' was not found."));
            return results;
        }

        results.Add(new PreflightCheck("IIS site", true, $"IIS site '{site.Name}' was found."));
        foreach (var host in hosts)
        {
            var hasBinding = site.Bindings.Any(binding =>
                string.Equals(binding.Protocol, "http", StringComparison.OrdinalIgnoreCase) &&
                binding.Port == 80 &&
                string.Equals(binding.HostName, host, StringComparison.OrdinalIgnoreCase));
            results.Add(new PreflightCheck(
                $"HTTP binding: {host}",
                hasBinding,
                hasBinding ? "Port 80 binding is configured." : "Add an IIS HTTP binding on port 80 for this host."));

            try
            {
                using var response = await _httpClient.GetAsync(
                        new UriBuilder(Uri.UriSchemeHttp, host, 80).Uri,
                        HttpCompletionOption.ResponseHeadersRead,
                        cancellationToken)
                    .ConfigureAwait(false);
                results.Add(new PreflightCheck(
                    $"HTTP reachability: {host}",
                    true,
                    $"Host responded with HTTP {(int)response.StatusCode}."));
            }
            catch (Exception exception) when (
                exception is HttpRequestException ||
                exception is TaskCanceledException && !cancellationToken.IsCancellationRequested)
            {
                results.Add(new PreflightCheck(
                    $"HTTP reachability: {host}",
                    false,
                    "Could not reach the host on port 80. Check DNS or tunnel routing and the HTTP Host header."));
            }
        }

        if (string.IsNullOrWhiteSpace(site.PhysicalPath))
        {
            results.Add(new PreflightCheck("Challenge folder", false, "The IIS site has no physical root path."));
        }
        else
        {
            var folder = Path.Combine(site.PhysicalPath, ".well-known", "acme-challenge");
            var probe = Path.Combine(folder, $".sslense-write-{Guid.NewGuid():N}");
            try
            {
                fileSystem.CreateDirectory(folder);
                await fileSystem.WriteAllTextAsync(probe, "probe", cancellationToken).ConfigureAwait(false);
                fileSystem.DeleteFile(probe);
                fileSystem.DeleteDirectoryIfEmpty(folder);
                results.Add(new PreflightCheck("Challenge folder", true, "The ACME challenge folder is writable."));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                results.Add(new PreflightCheck(
                    "Challenge folder",
                    false,
                    "The challenge folder is not writable. Check the site path and Administrator permissions."));
            }
            finally
            {
                try { fileSystem.DeleteFile(probe); }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }

        return results;
    }

    public void Dispose() => _httpClient.Dispose();
}
