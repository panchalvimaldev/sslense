using System.Net.Mail;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.DnsValidation;
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
    private readonly ICertificateOperationLock _operationLock;
    private readonly ICertificateTransactionJournal _transactionJournal;
    private readonly ICertificateAuthorityRegistry _authorities;
    private readonly IDnsChallengeService? _dnsChallenges;

    public AcmeService(
        IIisService iisService,
        IAcmeProtocolClient protocolClient,
        IChallengeHandler challengeHandler,
        IChallengeProbe challengeProbe,
        ICertificateArtifactStore artifactStore,
        ICertificateStore certificateStore,
        IManagedCertificateStore managedCertificateStore,
        ICertificateOperationLock? operationLock = null,
        ICertificateTransactionJournal? transactionJournal = null,
        ICertificateAuthorityRegistry? authorities = null,
        IDnsChallengeService? dnsChallenges = null)
    {
        _iisService = iisService;
        _protocolClient = protocolClient;
        _challengeHandler = challengeHandler;
        _challengeProbe = challengeProbe;
        _artifactStore = artifactStore;
        _certificateStore = certificateStore;
        _managedCertificateStore = managedCertificateStore;
        _operationLock = operationLock ?? new NoOpCertificateOperationLock();
        _transactionJournal = transactionJournal ?? new NoOpCertificateTransactionJournal();
        _authorities = authorities ?? CertificateAuthorityRegistry.BuiltInOnly;
        _dnsChallenges = dnsChallenges;
    }

    public async Task<AcmeIssueResult> IssueAsync(
        AcmeIssueRequest request,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateRequest(request);

        await using var operationLock = await _operationLock
            .AcquireAsync(request.SiteName, cancellationToken)
            .ConfigureAwait(false);
        await EnsureExpectedCertificateAsync(request, cancellationToken).ConfigureAwait(false);
        var authority = await _authorities.GetAsync(request.AuthorityId, cancellationToken).ConfigureAwait(false);
        var environmentName = CertificateAuthorities.Label(authority.Id);
        var usesDns = request.ValidationMethod != ValidationMethod.Http01;

        progress?.Report(new ProgressEvent("preflight", usesDns
            ? "Checking the IIS site and its bindings."
            : "Checking the IIS site and HTTP bindings."));
        var sites = await _iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        var site = sites.SingleOrDefault(candidate =>
            string.Equals(candidate.Name, request.SiteName, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException($"IIS site '{request.SiteName}' was not found.");
        if (!usesDns && string.IsNullOrWhiteSpace(site.PhysicalPath))
        {
            throw new InvalidOperationException($"IIS site '{site.Name}' has no physical root path.");
        }

        // DNS validation never reaches the site, so port 80 is needed only for HTTP-01.
        bool IsUsableBinding(IisBinding binding) => usesDns
            ? string.Equals(binding.Protocol, "http", StringComparison.OrdinalIgnoreCase) ||
              string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase)
            : string.Equals(binding.Protocol, "http", StringComparison.OrdinalIgnoreCase) && binding.Port == 80;

        var requestedHosts = request.Hosts.Count == 0
            ? site.Bindings
                .Where(binding => IsUsableBinding(binding) && !string.IsNullOrWhiteSpace(binding.HostName))
                .Select(binding => binding.HostName)
            : request.Hosts;
        var hosts = NormalizeAndValidateHosts(
            requestedHosts,
            usesDns
                ? "No host names were supplied and the IIS site has no named HTTP or HTTPS bindings."
                : "No host names were supplied and the IIS site has no named HTTP bindings on port 80.");

        foreach (var host in hosts)
        {
            var hasBinding = site.Bindings.Any(binding =>
                IsUsableBinding(binding) &&
                string.Equals(NormalizeHost(binding.HostName), host, StringComparison.OrdinalIgnoreCase));
            if (!hasBinding)
            {
                throw new InvalidOperationException(usesDns
                    ? $"Host name '{host}' does not have an HTTP or HTTPS binding for IIS site '{site.Name}'."
                    : $"Host name '{host}' does not have an HTTP binding on port 80 for IIS site '{site.Name}'.");
            }
        }

        if (!request.Force)
        {
            await ThrowIfAlreadyCoveredAsync(site, hosts, authority, cancellationToken)
                .ConfigureAwait(false);
        }

        var dnsChallenges = usesDns
            ? _dnsChallenges ?? throw new InvalidOperationException("DNS validation is not available.")
            : null;
        if (dnsChallenges is not null)
        {
            progress?.Report(new ProgressEvent("preflight", "Checking the DNS provider and validation records."));
            await dnsChallenges.CheckBeforeOrderAsync(request.ValidationMethod, hosts, cancellationToken)
                .ConfigureAwait(false);
        }

        progress?.Report(new ProgressEvent(
            "account",
            $"Loading or creating the {environmentName} ACME account."));
        IAcmeOrderSession order;
        try
        {
            order = await (usesDns
                    ? _protocolClient.CreateDnsOrderAsync(request.Email.Trim(), hosts, authority, cancellationToken)
                    : _protocolClient.CreateOrderAsync(request.Email.Trim(), hosts, authority, cancellationToken))
                .ConfigureAwait(false);
        }
        catch (HttpRequestException exception)
        {
            throw new InvalidOperationException(
                $"Could not contact the {authority.Name} service. " +
                "Check outbound HTTPS, DNS, proxy, and TLS settings.",
                exception);
        }
        if (dnsChallenges is not null)
        {
            await CompleteDnsChallengesAsync(order, dnsChallenges, hosts, request, environmentName, progress, cancellationToken)
                .ConfigureAwait(false);
        }
        else
        {
            await CompleteHttpChallengesAsync(order, site.PhysicalPath!, hosts, environmentName, progress, cancellationToken)
                .ConfigureAwait(false);
        }

        progress?.Report(new ProgressEvent(
            "certificate",
            $"Finalizing and downloading the {environmentName} certificate."));
        var passwordBytes = RandomNumberGenerator.GetBytes(32);
        CertificateBundle? bundle = null;
        try
        {
            var pfxPassword = Convert.ToBase64String(passwordBytes);
            bundle = await order.FinalizeAsync(hosts[0], pfxPassword, cancellationToken)
                .ConfigureAwait(false);

            progress?.Report(new ProgressEvent(
                "save",
                request.OutputDirectory is null
                    ? "Saving the public certificate. The PFX remains transient."
                    : "Saving the public certificate to the requested output directory. The PFX remains transient."));
            var artifacts = await _artifactStore
                .SaveAsync(site.Name, hosts, bundle, request.OutputDirectory, cancellationToken)
                .ConfigureAwait(false);

            using var publicCertificate = X509Certificate2.CreateFromPem(bundle.CertificatePem);
            var preparedRecord = new ManagedCertificate(
                site.Name,
                hosts,
                request.Email.Trim(),
                publicCertificate.Thumbprint,
                publicCertificate.NotBefore.ToUniversalTime(),
                publicCertificate.NotAfter.ToUniversalTime(),
                request.OutputDirectory,
                DateTimeOffset.UtcNow,
                true,
                "Certificate issued and bound successfully.",
                authority.Id,
                Issuer: publicCertificate.GetNameInfo(X509NameType.SimpleName, forIssuer: true),
                ValidationMethod: request.ValidationMethod);
            var transaction = await _transactionJournal.BeginAsync(
                    preparedRecord,
                    request.ExpectedCurrentThumbprint,
                    CancellationToken.None)
                .ConfigureAwait(false);

            progress?.Report(new ProgressEvent(
                "install",
                $"Importing the {environmentName} certificate into LocalMachine\\My with a non-exportable key."));
            var installedCertificate = await _certificateStore.ImportPfxAsync(
                    bundle.PfxBytes,
                    pfxPassword,
                    $"SSLense: {hosts[0]} ({DateTimeOffset.UtcNow:yyyy-MM-dd})",
                    cancellationToken)
                .ConfigureAwait(false);

            var pendingRecord = preparedRecord with
            {
                Thumbprint = installedCertificate.Thumbprint,
                NotBefore = installedCertificate.NotBefore,
                NotAfter = installedCertificate.NotAfter
            };
            await _transactionJournal.UpdateStageAsync(
                    transaction.Id,
                    CertificateTransactionStage.CertificateImported,
                    CancellationToken.None)
                .ConfigureAwait(false);
            try
            {
                progress?.Report(new ProgressEvent(
                    "binding",
                    "Creating or updating IIS HTTPS bindings with SNI, then confirming over HTTPS that the new certificate is served."));
                await _iisService.ConfigureHttpsBindingsAsync(
                        site.Name,
                        hosts,
                        installedCertificate.Thumbprint,
                        "My",
                        cancellationToken)
                    .ConfigureAwait(false);
                await _transactionJournal.UpdateStageAsync(
                        transaction.Id,
                        CertificateTransactionStage.BindingsUpdated,
                        CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch (IisBindingException exception) when (exception.PreviousBindingsRestored)
            {
                await _certificateStore.RemoveAsync(installedCertificate.Thumbprint, CancellationToken.None)
                    .ConfigureAwait(false);
                await _transactionJournal.CompleteAsync(transaction.Id, CancellationToken.None)
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
                    pendingRecord,
                    CancellationToken.None)
                .ConfigureAwait(false);
            await _transactionJournal.UpdateStageAsync(
                    transaction.Id,
                    CertificateTransactionStage.StateSaved,
                    CancellationToken.None)
                .ConfigureAwait(false);
            await _transactionJournal.CompleteAsync(transaction.Id, CancellationToken.None)
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

    private async Task CompleteHttpChallengesAsync(
        IAcmeOrderSession order,
        string sitePhysicalPath,
        IReadOnlyList<string> hosts,
        string environmentName,
        IProgress<ProgressEvent>? progress,
        CancellationToken cancellationToken)
    {
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
                .PrepareAsync(sitePhysicalPath, challenge, cancellationToken)
                .ConfigureAwait(false);

            progress?.Report(new ProgressEvent("self-check", $"Checking HTTP access for {challenge.Host}."));
            await _challengeProbe.VerifyAsync(challenge, cancellationToken).ConfigureAwait(false);

            progress?.Report(new ProgressEvent(
                "validation",
                $"Requesting {environmentName} validation for {challenge.Host}."));
            await order.ValidateAsync(challenge, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Publishes every record before asking the CA to validate any: a name and its wildcard share one record name, and
    /// propagation takes time per round. The records are removed as soon as validation ends.
    /// </summary>
    private static async Task CompleteDnsChallengesAsync(
        IAcmeOrderSession order,
        IDnsChallengeService dnsChallenges,
        IReadOnlyList<string> names,
        AcmeIssueRequest request,
        string environmentName,
        IProgress<ProgressEvent>? progress,
        CancellationToken cancellationToken)
    {
        foreach (var challenge in order.DnsChallenges)
        {
            if (!names.Contains(NormalizeHost(challenge.Host), StringComparer.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"The ACME server returned an unexpected authorization for '{challenge.Host}'.");
            }
        }

        await using var cleanup = await dnsChallenges
            .PublishAsync(request.ValidationMethod, order.DnsChallenges, request.ConfirmManualDns, progress, cancellationToken)
            .ConfigureAwait(false);
        foreach (var challenge in order.DnsChallenges)
        {
            progress?.Report(new ProgressEvent(
                "validation",
                $"Requesting {environmentName} validation for {challenge.Host}."));
            await order.ValidateAsync(challenge, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task EnsureExpectedCertificateAsync(
        AcmeIssueRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.ExpectedCurrentThumbprint))
        {
            return;
        }

        var current = (await _managedCertificateStore.GetAllAsync(cancellationToken).ConfigureAwait(false))
            .SingleOrDefault(value => string.Equals(
                value.SiteName,
                request.SiteName,
                StringComparison.OrdinalIgnoreCase));
        if (current is null || !string.Equals(
                NormalizeThumbprint(current.Thumbprint),
                NormalizeThumbprint(request.ExpectedCurrentThumbprint),
                StringComparison.Ordinal))
        {
            throw new CertificateStateChangedException(
                $"Certificate state for IIS site '{request.SiteName}' changed while the operation was waiting. " +
                "Refresh status before trying again.");
        }
    }

    private async Task ThrowIfAlreadyCoveredAsync(
        IisSite site,
        IReadOnlyList<string> hosts,
        CertificateAuthority requestedAuthority,
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
            // A certificate from a test CA is untrusted, so it never satisfies a request to a real CA.
            if (!requestedAuthority.IsTest &&
                await IsTestCertificateAsync(site.Name, certificate, cancellationToken).ConfigureAwait(false))
            {
                return;
            }

            throw new InvalidOperationException(
                $"IIS site '{site.Name}' already has a valid certificate for the requested hosts " +
                $"(thumbprint {certificate.Thumbprint}, expires {certificate.NotAfter:yyyy-MM-dd}). " +
                "Use --force to replace it.");
        }
    }

    private async Task<bool> IsTestCertificateAsync(
        string siteName,
        InstalledCertificate certificate,
        CancellationToken cancellationToken)
    {
        // Let's Encrypt marks every staging issuer name with "(STAGING)".
        if (certificate.Issuer?.Contains("(STAGING)", StringComparison.OrdinalIgnoreCase) == true)
        {
            return true;
        }

        var records = await _managedCertificateStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        var record = records.FirstOrDefault(value =>
            string.Equals(value.SiteName, siteName, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(
                NormalizeThumbprint(value.Thumbprint),
                NormalizeThumbprint(certificate.Thumbprint),
                StringComparison.Ordinal));
        if (record is null || record.Source != CertificateSource.Acme)
        {
            return false;
        }

        var authorities = await _authorities.GetAllAsync(cancellationToken).ConfigureAwait(false);
        return authorities.Any(value => value.IsTest && string.Equals(value.Id, record.AuthorityId, StringComparison.OrdinalIgnoreCase));
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

        if (request.ValidationMethod == ValidationMethod.Dns01Manual && request.ConfirmManualDns is null)
        {
            throw new ArgumentException("Manual DNS validation needs someone to create the records.", nameof(request));
        }
    }

    private static IReadOnlyList<string> NormalizeAndValidateHosts(IEnumerable<string> requestedHosts, string noHostsMessage)
    {
        var hosts = requestedHosts
            .Select(NormalizeHost)
            .Where(host => host.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (hosts.Length == 0)
        {
            throw new InvalidOperationException(noHostsMessage);
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

    private static string NormalizeThumbprint(string thumbprint) =>
        string.Concat(thumbprint.Where(Uri.IsHexDigit)).ToUpperInvariant();
}
