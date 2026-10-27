using System.Net.Mail;
using System.Security.Cryptography;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Core.Validation;

namespace SSLense.Core.Acme;

internal sealed class AcmeService : IAcmeService
{
    private readonly IIisService _iisService;
    private readonly IAcmeProtocolClient _protocolClient;
    private readonly IChallengeHandler _challengeHandler;
    private readonly IChallengeProbe _challengeProbe;
    private readonly ICertificateArtifactStore _artifactStore;
    private readonly ICertificateStore _certificateStore;
    private readonly IManagedCertificateStore _managedCertificateStore;

    public AcmeService(
        IIisService iisService,
        IAcmeProtocolClient protocolClient,
        IChallengeHandler challengeHandler,
        IChallengeProbe challengeProbe,
        ICertificateArtifactStore artifactStore,
        ICertificateStore certificateStore,
        IManagedCertificateStore managedCertificateStore)
    {
        _iisService = iisService;
        _protocolClient = protocolClient;
        _challengeHandler = challengeHandler;
        _challengeProbe = challengeProbe;
        _artifactStore = artifactStore;
        _certificateStore = certificateStore;
        _managedCertificateStore = managedCertificateStore;
    }

    public async Task<AcmeIssueResult> IssueAsync(
        AcmeIssueRequest request,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateRequest(request);

        progress?.Report(new ProgressEvent("preflight", "Checking the IIS site and HTTP bindings."));
        var sites = await _iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        var site = sites.SingleOrDefault(candidate =>
            string.Equals(candidate.Name, request.SiteName, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException($"IIS site '{request.SiteName}' was not found.");
        if (string.IsNullOrWhiteSpace(site.PhysicalPath))
        {
            throw new InvalidOperationException($"IIS site '{site.Name}' has no physical root path.");
        }

        var requestedHosts = request.Hosts.Count == 0
            ? site.Bindings
                .Where(binding =>
                    string.Equals(binding.Protocol, "http", StringComparison.OrdinalIgnoreCase) &&
                    binding.Port == 80 &&
                    !string.IsNullOrWhiteSpace(binding.HostName))
                .Select(binding => binding.HostName)
            : request.Hosts;
        var hosts = NormalizeAndValidateHosts(requestedHosts);

        foreach (var host in hosts)
        {
            var hasHttpBinding = site.Bindings.Any(binding =>
                string.Equals(binding.Protocol, "http", StringComparison.OrdinalIgnoreCase) &&
                binding.Port == 80 &&
                string.Equals(NormalizeHost(binding.HostName), host, StringComparison.OrdinalIgnoreCase));
            if (!hasHttpBinding)
            {
                throw new InvalidOperationException(
                    $"Host name '{host}' does not have an HTTP binding on port 80 for IIS site '{site.Name}'.");
            }
        }

        if (!request.Force)
        {
            await ThrowIfAlreadyCoveredAsync(site, hosts, cancellationToken).ConfigureAwait(false);
        }

        progress?.Report(new ProgressEvent("account", "Loading or creating the staging ACME account."));
        IAcmeOrderSession order;
        try
        {
            order = await _protocolClient.CreateOrderAsync(request.Email.Trim(), hosts, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (HttpRequestException exception)
        {
            throw new InvalidOperationException(
                "Could not contact the Let's Encrypt staging service. Check outbound HTTPS, DNS, proxy, and TLS settings.",
                exception);
        }
        if (order.Challenges.Count != hosts.Count)
        {
            throw new InvalidOperationException("The ACME server did not return one HTTP-01 challenge per host.");
        }

        foreach (var challenge in order.Challenges)
        {
            if (!hosts.Contains(NormalizeHost(challenge.Host), StringComparer.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"The ACME server returned an unexpected authorization for '{challenge.Host}'.");
            }

            progress?.Report(new ProgressEvent("challenge", $"Preparing HTTP-01 for {challenge.Host}."));
            await using var cleanup = await _challengeHandler
                .PrepareAsync(site.PhysicalPath, challenge, cancellationToken)
                .ConfigureAwait(false);

            progress?.Report(new ProgressEvent("self-check", $"Checking HTTP access for {challenge.Host}."));
            await _challengeProbe.VerifyAsync(challenge, cancellationToken).ConfigureAwait(false);

            progress?.Report(new ProgressEvent("validation", $"Requesting staging validation for {challenge.Host}."));
            await order.ValidateAsync(challenge, cancellationToken).ConfigureAwait(false);
        }

        progress?.Report(new ProgressEvent("certificate", "Finalizing and downloading the staging certificate."));
        var passwordBytes = RandomNumberGenerator.GetBytes(32);
        CertificateBundle? bundle = null;
        try
        {
            var pfxPassword = Convert.ToBase64String(passwordBytes);
            bundle = await order.FinalizeAsync(hosts[0], pfxPassword, cancellationToken)
                .ConfigureAwait(false);

            progress?.Report(new ProgressEvent("save", "Saving staging certificate artifacts."));
            var artifacts = await _artifactStore
                .SaveAsync(site.Name, hosts, bundle, request.OutputDirectory, cancellationToken)
                .ConfigureAwait(false);

            progress?.Report(new ProgressEvent("install", "Importing the staging certificate into LocalMachine\\My."));
            var installedCertificate = await _certificateStore.ImportPfxAsync(
                    bundle.PfxBytes,
                    pfxPassword,
                    $"SSLense: {hosts[0]} ({DateTimeOffset.UtcNow:yyyy-MM-dd})",
                    cancellationToken)
                .ConfigureAwait(false);
            try
            {
                progress?.Report(new ProgressEvent("binding", "Creating or updating IIS HTTPS bindings with SNI."));
                await _iisService.ConfigureHttpsBindingsAsync(
                        site.Name,
                        hosts,
                        installedCertificate.Thumbprint,
                        "My",
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (IisBindingException exception) when (exception.PreviousBindingsRestored)
            {
                await _certificateStore.RemoveAsync(installedCertificate.Thumbprint, CancellationToken.None)
                    .ConfigureAwait(false);
                throw;
            }
            catch (Exception)
            {
                // Preserve the new certificate when binding state is uncertain; a binding may depend on it.
                throw;
            }

            progress?.Report(new ProgressEvent("state", "Saving the managed certificate record."));
            await _managedCertificateStore.UpsertAsync(
                    new ManagedCertificate(
                        site.Name,
                        hosts,
                        request.Email.Trim(),
                        installedCertificate.Thumbprint,
                        installedCertificate.NotBefore,
                        installedCertificate.NotAfter,
                        request.OutputDirectory,
                        DateTimeOffset.UtcNow,
                        true,
                        "Certificate issued and bound successfully."),
                    CancellationToken.None)
                .ConfigureAwait(false);

            return artifacts with
            {
                CertificateThumbprint = installedCertificate.Thumbprint,
                NotBefore = installedCertificate.NotBefore,
                NotAfter = installedCertificate.NotAfter
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
            if (bundle is not null)
            {
                CryptographicOperations.ZeroMemory(bundle.PfxBytes);
            }
        }
    }

    private async Task ThrowIfAlreadyCoveredAsync(
        IisSite site,
        IReadOnlyList<string> hosts,
        CancellationToken cancellationToken)
    {
        var httpsBindings = hosts
            .Select(host => site.Bindings.SingleOrDefault(binding =>
                string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase) &&
                binding.Port == 443 &&
                string.Equals(NormalizeHost(binding.HostName), host, StringComparison.OrdinalIgnoreCase)))
            .ToArray();
        if (httpsBindings.Any(binding => binding?.CertificateThumbprint is null))
        {
            return;
        }

        var thumbprints = httpsBindings
            .Select(binding => binding!.CertificateThumbprint!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (thumbprints.Length != 1)
        {
            return;
        }

        var certificate = await _certificateStore
            .FindByThumbprintAsync(thumbprints[0], cancellationToken)
            .ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        if (certificate is not null && certificate.HasPrivateKey &&
            certificate.NotBefore <= now && certificate.NotAfter > now)
        {
            throw new InvalidOperationException(
                $"IIS site '{site.Name}' already has a valid certificate for the requested hosts " +
                $"(thumbprint {certificate.Thumbprint}, expires {certificate.NotAfter:yyyy-MM-dd}). " +
                "Use --force to replace it.");
        }
    }

    private static void ValidateRequest(AcmeIssueRequest request)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(request.SiteName);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Email);
        try
        {
            _ = new MailAddress(request.Email.Trim());
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("A valid account email address is required.", nameof(request), exception);
        }

    }

    private static IReadOnlyList<string> NormalizeAndValidateHosts(IEnumerable<string> requestedHosts)
    {
        var hosts = requestedHosts
            .Select(NormalizeHost)
            .Where(host => host.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (hosts.Length == 0)
        {
            throw new InvalidOperationException(
                "No host names were supplied and the IIS site has no named HTTP bindings on port 80.");
        }

        foreach (var host in hosts)
        {
            if (host.Contains('*') || Uri.CheckHostName(host) != UriHostNameType.Dns)
            {
                throw new ArgumentException(
                    $"'{host}' is not a valid DNS host name. HTTP-01 does not support wildcard names.",
                    nameof(requestedHosts));
            }
        }

        return hosts;
    }

    private static string NormalizeHost(string host) => host.Trim().TrimEnd('.').ToLowerInvariant();
}
