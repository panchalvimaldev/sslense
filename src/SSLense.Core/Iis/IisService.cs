using Microsoft.Web.Administration;

namespace SSLense.Core.Iis;

internal sealed class IisService : IIisService
{
    public Task<IReadOnlyList<IisSite>> GetSitesAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("IIS site discovery is only supported on Windows.");
        }

        try
        {
            using var serverManager = new ServerManager();
            var sites = serverManager.Sites
                .Select(MapSite)
                .OrderBy(site => site.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            return Task.FromResult<IReadOnlyList<IisSite>>(sites);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new InvalidOperationException(
                "IIS configuration could not be read. Run SSLense from an Administrator terminal.",
                exception);
        }
        catch (FileNotFoundException exception)
        {
            throw new InvalidOperationException(
                "IIS management components were not found. Install IIS Management Scripts and Tools.",
                exception);
        }
    }

    public Task ConfigureHttpsBindingsAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        string certificateThumbprint,
        string certificateStoreName = "My",
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(siteName);
        ArgumentNullException.ThrowIfNull(hosts);
        ArgumentException.ThrowIfNullOrWhiteSpace(certificateThumbprint);
        ArgumentException.ThrowIfNullOrWhiteSpace(certificateStoreName);
        cancellationToken.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("IIS binding configuration is only supported on Windows.");
        }

        var certificateHash = Convert.FromHexString(NormalizeThumbprint(certificateThumbprint));
        var changes = new List<BindingChange>();
        try
        {
            using (var serverManager = new ServerManager())
            {
                var site = FindSite(serverManager, siteName);
                foreach (var host in hosts)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var binding = FindHttpsBinding(site, host);
                    if (binding is null)
                    {
                        binding = site.Bindings.Add(
                            $"*:443:{host}",
                            certificateHash,
                            certificateStoreName,
                            SslFlags.Sni);
                        changes.Add(new BindingChange(host, WasAdded: true, null, null, SslFlags.None));
                    }
                    else
                    {
                        changes.Add(new BindingChange(
                            host,
                            WasAdded: false,
                            binding.CertificateHash?.ToArray(),
                            binding.CertificateStoreName,
                            binding.SslFlags));
                        binding.CertificateHash = certificateHash;
                        binding.CertificateStoreName = certificateStoreName;
                        binding.SslFlags = SslFlags.Sni;
                    }
                }

                serverManager.CommitChanges();
            }

            using var verificationManager = new ServerManager();
            var verificationSite = FindSite(verificationManager, siteName);
            foreach (var host in hosts)
            {
                var binding = FindHttpsBinding(verificationSite, host)
                    ?? throw new InvalidOperationException(
                        $"HTTPS binding verification failed for '{host}': the binding was not found.");
                if (binding.CertificateHash is null ||
                    !binding.CertificateHash.SequenceEqual(certificateHash) ||
                    !string.Equals(binding.CertificateStoreName, certificateStoreName, StringComparison.OrdinalIgnoreCase) ||
                    (binding.SslFlags & SslFlags.Sni) != SslFlags.Sni)
                {
                    throw new InvalidOperationException(
                        $"HTTPS binding verification failed for '{host}': IIS did not retain the certificate and SNI settings.");
                }
            }

            return Task.CompletedTask;
        }
        catch (Exception exception)
        {
            try
            {
                if (changes.Count > 0)
                {
                    RollBackBindings(siteName, changes);
                }
            }
            catch (Exception rollbackException)
            {
                throw new IisBindingException(
                    "IIS binding configuration failed and the previous bindings could not be fully restored.",
                    previousBindingsRestored: false,
                    new AggregateException(exception, rollbackException));
            }

            if (exception is UnauthorizedAccessException)
            {
                throw new IisBindingException(
                    "IIS bindings could not be changed. Run SSLense from an Administrator terminal.",
                    previousBindingsRestored: true,
                    exception);
            }

            throw new IisBindingException(
                $"Could not configure HTTPS bindings for IIS site '{siteName}'. No existing binding was intentionally removed.",
                previousBindingsRestored: true,
                exception);
        }
    }

    private static IisSite MapSite(Site site)
    {
        var rootApplication = site.Applications.FirstOrDefault(application => application.Path == "/");
        var rootDirectory = rootApplication?.VirtualDirectories.FirstOrDefault(directory => directory.Path == "/");
        var physicalPath = rootDirectory?.PhysicalPath is { } path
            ? Environment.ExpandEnvironmentVariables(path)
            : null;

        var bindings = site.Bindings.Select(MapBinding).ToArray();
        return new IisSite(site.Id, site.Name, site.State.ToString(), physicalPath, bindings);
    }

    private static IisBinding MapBinding(Binding binding)
    {
        var (ipAddress, port, hostName) = ParseBindingInformation(binding.BindingInformation);
        var thumbprint = binding.CertificateHash is { Length: > 0 } hash
            ? Convert.ToHexString(hash)
            : null;

        return new IisBinding(
            binding.Protocol,
            ipAddress,
            port,
            hostName,
            thumbprint,
            binding.CertificateStoreName,
            (binding.SslFlags & SslFlags.Sni) == SslFlags.Sni);
    }

    private static Site FindSite(ServerManager serverManager, string siteName) =>
        serverManager.Sites.FirstOrDefault(site =>
            string.Equals(site.Name, siteName, StringComparison.OrdinalIgnoreCase))
        ?? throw new InvalidOperationException($"IIS site '{siteName}' was not found.");

    private static Binding? FindHttpsBinding(Site site, string host) =>
        site.Bindings.FirstOrDefault(binding =>
        {
            if (!string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var (_, port, bindingHost) = ParseBindingInformation(binding.BindingInformation);
            return port == 443 && string.Equals(bindingHost, host, StringComparison.OrdinalIgnoreCase);
        });

    private static void RollBackBindings(string siteName, IReadOnlyList<BindingChange> changes)
    {
        using var serverManager = new ServerManager();
        var site = FindSite(serverManager, siteName);
        foreach (var change in changes)
        {
            var binding = FindHttpsBinding(site, change.Host);
            if (change.WasAdded)
            {
                if (binding is not null)
                {
                    site.Bindings.Remove(binding);
                }

                continue;
            }

            if (binding is null)
            {
                throw new InvalidOperationException(
                    $"Cannot restore the previous HTTPS binding for '{change.Host}' because it no longer exists.");
            }

            binding.CertificateHash = change.CertificateHash;
            binding.CertificateStoreName = change.CertificateStoreName;
            binding.SslFlags = change.SslFlags;
        }

        serverManager.CommitChanges();
    }

    private static string NormalizeThumbprint(string thumbprint) =>
        string.Concat(thumbprint.Where(Uri.IsHexDigit)).ToUpperInvariant();

    private static (string IpAddress, int Port, string HostName) ParseBindingInformation(string value)
    {
        var hostSeparator = value.LastIndexOf(':');
        var portSeparator = hostSeparator > 0 ? value.LastIndexOf(':', hostSeparator - 1) : -1;
        if (portSeparator < 0 || hostSeparator < 0 ||
            !int.TryParse(value.AsSpan(portSeparator + 1, hostSeparator - portSeparator - 1), out var port))
        {
            throw new InvalidDataException($"IIS returned an invalid binding: '{value}'.");
        }

        return (value[..portSeparator], port, value[(hostSeparator + 1)..]);
    }

    private sealed record BindingChange(
        string Host,
        bool WasAdded,
        byte[]? CertificateHash,
        string? CertificateStoreName,
        SslFlags SslFlags);
}
