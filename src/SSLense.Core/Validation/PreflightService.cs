using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.DnsValidation;
using SSLense.Core.Errors;
using SSLense.Core.Iis;

namespace SSLense.Core.Validation;

internal sealed class PreflightService(
    IIisService iisService,
    IFileSystem fileSystem,
    IDnsChallengeService dnsChallenges,
    ISelfHostedChallengeServer? selfHostedServer = null) : IPreflightService, IDisposable
{
    private readonly HttpClient _httpClient = new(new HttpClientHandler { AllowAutoRedirect = false })
    {
        Timeout = TimeSpan.FromSeconds(10)
    };

    public Task<IReadOnlyList<PreflightCheck>> CheckAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        CancellationToken cancellationToken = default) =>
        CheckAsync(siteName, hosts, selfHosted: false, cancellationToken);

    public async Task<IReadOnlyList<PreflightCheck>> CheckAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        bool selfHosted,
        CancellationToken cancellationToken = default)
    {
        if (selfHosted)
        {
            return await CheckSelfHostedAsync(siteName, hosts, cancellationToken).ConfigureAwait(false);
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(siteName);
        if (hosts.Count == 0)
        {
            throw new ArgumentException(ErrorCodes.NoHostNamesGiven.Format("Select at least one host name."), nameof(hosts));
        }

        var results = new List<PreflightCheck>();
        var isAdministrator = WindowsElevation.IsAdministrator();
        results.Add(new PreflightCheck(
            "Administrator",
            isAdministrator,
            isAdministrator ? "SSLense is elevated." : ErrorCodes.NotAdministrator.Format("Run SSLense as Administrator.")));

        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        var site = sites.FindSite(siteName);
        if (site is null)
        {
            results.Add(new PreflightCheck("IIS site", false, ErrorCodes.IisSiteNotFound.Format($"IIS site '{siteName}' was not found.")));
            return results;
        }

        results.Add(new PreflightCheck("IIS site", true, $"IIS site '{site.Name}' was found."));
        foreach (var host in hosts)
        {
            var hasBinding = site.Bindings.Any(binding =>
                string.Equals(binding.Protocol, "http", StringComparison.OrdinalIgnoreCase) &&
                binding.Port == 80 &&
                binding.AnswersFor(host));
            results.Add(new PreflightCheck(
                $"HTTP binding: {host}",
                hasBinding,
                hasBinding ? "Port 80 binding is configured." : ErrorCodes.HostHasNoBinding.Format("Add an IIS HTTP binding on port 80 for this host.")));

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
                    ErrorCodes.ChallengeSelfCheckUnreachable.Format("Could not reach the host on port 80. Check DNS or tunnel routing and the HTTP Host header.")));
            }
        }

        if (string.IsNullOrWhiteSpace(site.PhysicalPath))
        {
            results.Add(new PreflightCheck("Challenge folder", false, ErrorCodes.IisSiteNoPhysicalPath.Format("The IIS site has no physical root path.")));
        }
        else if (IisFolders.IsConfigHistory(site.PhysicalPath))
        {
            results.Add(new PreflightCheck("Challenge folder", false, ErrorCodes.SiteFolderIsIisHistory.Format(
                $"The site's physical path '{site.PhysicalPath}' is IIS's configuration history folder. Give the site its own folder.")));
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
                    ErrorCodes.ChallengeFolderNotWritable.Format("The challenge folder is not writable. Check the site path and Administrator permissions.")));
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

    public async Task<IReadOnlyList<PreflightCheck>> CheckDnsAsync(
        DnsPreflightRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.SiteName);
        if (request.Hosts.Count == 0 && !request.NoSite)
        {
            throw new ArgumentException(ErrorCodes.NoHostNamesGiven.Format("Select at least one host name."), nameof(request));
        }

        var isAdministrator = WindowsElevation.IsAdministrator();
        var results = new List<PreflightCheck>
        {
            new("Administrator", isAdministrator, isAdministrator ? "SSLense is elevated." : ErrorCodes.NotAdministrator.Format("Run SSLense as Administrator."))
        };

        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        if (request.NoSite)
        {
            var taken = sites.Any(value => string.Equals(value.Name, request.SiteName.Trim(), StringComparison.OrdinalIgnoreCase));
            results.Add(new PreflightCheck(
                "Name",
                !taken,
                taken
                    ? ErrorCodes.NameIsIisSite.Format($"'{request.SiteName.Trim()}' is the name of an IIS site. Choose another name for a certificate with no IIS site.")
                    : $"The certificate will be named '{request.SiteName.Trim()}'. Nothing is bound in IIS; deployment steps hand it to its services."));
            IReadOnlyList<string>? noSiteNames;
            try
            {
                noSiteNames = AcmeService.NormalizeCertificateNames(request.CertificateNames, usesDns: true);
            }
            catch (ArgumentException exception)
            {
                results.Add(new PreflightCheck("Certificate names", false, ErrorCodes.InvalidCertificateNames.Format(exception.Message)));
                return results;
            }

            if (noSiteNames is null)
            {
                results.Add(new PreflightCheck("Certificate names", false, ErrorCodes.NoSiteNamesMissing.Format("Enter the names the certificate covers, such as rdp.example.com.")));
                return results;
            }

            results.Add(new PreflightCheck("Certificate names", true, $"The certificate will cover {string.Join(", ", noSiteNames)}."));
            results.Add(await CheckDnsRecordsAsync(request, noSiteNames, cancellationToken).ConfigureAwait(false));
            return results;
        }

        var site = sites.FindSite(request.SiteName);
        if (site is null)
        {
            results.Add(new PreflightCheck("IIS site", false, ErrorCodes.IisSiteNotFound.Format($"IIS site '{request.SiteName}' was not found.")));
            return results;
        }

        results.Add(new PreflightCheck("IIS site", true, $"IIS site '{site.Name}' was found."));

        IReadOnlyList<string> names;
        try
        {
            names = AcmeService.NormalizeCertificateNames(request.CertificateNames, usesDns: true) ?? request.Hosts;
        }
        catch (ArgumentException exception)
        {
            results.Add(new PreflightCheck("Certificate names", false, ErrorCodes.InvalidCertificateNames.Format(exception.Message)));
            return results;
        }

        results.Add(new PreflightCheck("Certificate names", true, $"The certificate will cover {string.Join(", ", names)}."));
        foreach (var host in request.Hosts)
        {
            results.Add(CheckDnsHost(site, host, names));
        }

        results.Add(await CheckDnsRecordsAsync(request, names, cancellationToken).ConfigureAwait(false));
        return results;
    }

    /// <summary>
    /// SSLense answers the challenge: each host needs a binding SSLense manages, and SSLense must be able to answer on
    /// port 80, which is tested by serving a test token and fetching it through each host name.
    /// </summary>
    private async Task<IReadOnlyList<PreflightCheck>> CheckSelfHostedAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(siteName);
        if (hosts.Count == 0)
        {
            throw new ArgumentException(ErrorCodes.NoHostNamesGiven.Format("Select at least one host name."), nameof(hosts));
        }

        var isAdministrator = WindowsElevation.IsAdministrator();
        var results = new List<PreflightCheck>
        {
            new("Administrator", isAdministrator, isAdministrator ? "SSLense is elevated." : ErrorCodes.NotAdministrator.Format("Run SSLense as Administrator."))
        };

        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        var site = sites.FindSite(siteName);
        if (site is null)
        {
            results.Add(new PreflightCheck("IIS site", false, ErrorCodes.IisSiteNotFound.Format($"IIS site '{siteName}' was not found.")));
            return results;
        }

        results.Add(new PreflightCheck("IIS site", true, $"IIS site '{site.Name}' was found."));
        foreach (var host in hosts)
        {
            var hasBinding = site.Bindings.Any(binding =>
                binding.Protocol is "http" or "https" && binding.AnswersFor(host));
            results.Add(new PreflightCheck(
                $"IIS binding: {host}",
                hasBinding,
                hasBinding ? "The binding exists. SSLense answers the challenge itself, so port 80 needs no binding." : ErrorCodes.HostHasNoBinding.Format("Add an IIS HTTP or HTTPS binding for this host.")));
        }

        if (selfHostedServer is null)
        {
            results.Add(new PreflightCheck("Port 80", false, ErrorCodes.SelfHostedPortUnavailable.Format("SSLense cannot answer on port 80 in this process.")));
            return results;
        }

        var token = $"sslense-check-{Guid.NewGuid():N}";
        var expected = Guid.NewGuid().ToString("N");
        IAsyncDisposable serving;
        try
        {
            serving = await selfHostedServer.ServeAsync(new Acme.AcmeHttpChallenge(hosts[0], token, expected), cancellationToken).ConfigureAwait(false);
        }
        catch (SslenseException exception)
        {
            results.Add(new PreflightCheck("Port 80", false, exception.Message));
            return results;
        }

        await using (serving.ConfigureAwait(false))
        {
            results.Add(new PreflightCheck("Port 80", true, "SSLense can answer on port 80 through HTTP.sys, beside IIS."));
            foreach (var host in hosts)
            {
                var name = $"HTTP reachability: {host}";
                try
                {
                    var body = await _httpClient.GetStringAsync(new UriBuilder(Uri.UriSchemeHttp, host, 80, $"/.well-known/acme-challenge/{token}").Uri, cancellationToken)
                        .ConfigureAwait(false);
                    results.Add(body.Trim() == expected
                        ? new PreflightCheck(name, true, "SSLense answered a test challenge through this host name.")
                        : new PreflightCheck(name, false, ErrorCodes.ChallengeSelfCheckContent.Format("Another server answered for this host name on port 80. Check DNS, proxies and NAT.")));
                }
                catch (Exception exception) when (
                    exception is HttpRequestException ||
                    exception is TaskCanceledException && !cancellationToken.IsCancellationRequested)
                {
                    results.Add(new PreflightCheck(name, false,
                        ErrorCodes.ChallengeSelfCheckUnreachable.Format("Could not reach the host on port 80. Check DNS, the firewall and NAT for inbound port 80.")));
                }
            }
        }

        return results;
    }

    private static PreflightCheck CheckDnsHost(IisSite site, string host, IReadOnlyList<string> names)
    {
        var name = $"IIS binding: {host}";
        if (host.Contains('*'))
        {
            return new PreflightCheck(
                name,
                false,
                ErrorCodes.InvalidHostName.Format("SSLense manages IIS bindings for real host names only. Put the wildcard in the certificate names, and choose real host names."));
        }

        if (!site.Bindings.Any(binding =>
                binding.Protocol is "http" or "https" &&
                binding.AnswersFor(host)))
        {
            return new PreflightCheck(name, false, ErrorCodes.HostHasNoBinding.Format("Add an IIS HTTP or HTTPS binding for this host."));
        }

        return CertificateInspector.Covers(names, host)
            ? new PreflightCheck(name, true, "The binding exists, and the certificate names cover it. Port 80 is not needed.")
            : new PreflightCheck(name, false, ErrorCodes.HostNotCovered.Format($"The certificate names {string.Join(", ", names)} do not cover this host."));
    }

    private async Task<PreflightCheck> CheckDnsRecordsAsync(
        DnsPreflightRequest request,
        IReadOnlyList<string> names,
        CancellationToken cancellationToken)
    {
        const string name = "DNS validation";
        try
        {
            await dnsChallenges.CheckBeforeOrderAsync(request.ValidationMethod, names, request.AuthorityId, cancellationToken)
                .ConfigureAwait(false);
            return new PreflightCheck(
                name,
                true,
                request.ValidationMethod == ValidationMethod.Dns01Manual
                    ? "No problem was found with DNS. You will be shown the records to create."
                    : "The DNS provider accepts its token, and no problem was found with DNS.");
        }
        catch (Exception exception) when (exception is InvalidOperationException or HttpRequestException)
        {
            return new PreflightCheck(name, false, ErrorCodes.Unexpected.Format(exception.Message));
        }
    }

    public void Dispose() => _httpClient.Dispose();
}
