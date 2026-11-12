using System.Net.Mail;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Deployment;
using SSLense.Core.DnsValidation;
using SSLense.Core.Iis;
using SSLense.Core.Reminders;
using SSLense.Core.Validation;

namespace SSLense.Core.Acme;

internal sealed partial class AcmeService : IAcmeService
{
    private readonly IIisService _iisService;
    private readonly IAcmeProtocolClient _protocolClient;
    private readonly IChallengeHandler _challengeHandler;
    private readonly IChallengeProbe _challengeProbe;
    private readonly ICertificateArtifactStore _artifactStore;
    private readonly ICertificateStore _certificateStore;
    private readonly IManagedCertificateStore _managedCertificateStore;
    private readonly ICertificateOperationLock _operationLock;
    private readonly IDeploymentRunner? _deployment;
    private readonly ICertificateTransactionJournal _transactionJournal;
    private readonly ICertificateAuthorityRegistry _authorities;
    private readonly IDnsChallengeService? _dnsChallenges;
    private readonly ICertificateAuthorityLock _authorityLock;

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
        IDnsChallengeService? dnsChallenges = null,
        ICertificateAuthorityLock? authorityLock = null,
        IDeploymentRunner? deployment = null)
    {
        _deployment = deployment;
        _authorityLock = authorityLock ?? NoOpCertificateAuthorityLock.Instance;
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

        var lockedSites = await FindSitesToLockAsync(request.SiteName, cancellationToken).ConfigureAwait(false);
        await using var operationLock = await _operationLock
            .AcquireAllAsync(lockedSites, cancellationToken)
            .ConfigureAwait(false);
        var sharedRecord = await FindSharedRecordAsync(request.SiteName, lockedSites, cancellationToken).ConfigureAwait(false);
        await EnsureExpectedCertificateAsync(request, cancellationToken).ConfigureAwait(false);
        // Held until the record is saved, so the CA cannot be removed in between and leave the certificate pointing at
        // nothing. Taken before the CA is read: an issue that waited for a removal finds the CA gone and stops here.
        await using var authorityUse = await _authorityLock.AcquireUseAsync(request.AuthorityId, cancellationToken).ConfigureAwait(false);
        var authority = await _authorities.GetAsync(request.AuthorityId, cancellationToken).ConfigureAwait(false);
        if (!authority.IsTest && !request.AcceptProductionRisk)
        {
            throw new InvalidOperationException(
                $"{authority.Name} issues certificates that browsers trust, and its limits apply. Try the site with a test CA, " +
                "such as Let's Encrypt staging, first. Then confirm with --accept-production-risk, or with the production " +
                "confirmation in the app.");
        }

        var environmentName = CertificateAuthorities.Label(authority.Id);
        var usesDns = request.ValidationMethod != ValidationMethod.Http01;

        progress?.Report(new ProgressEvent("preflight", usesDns
            ? "Checking the IIS site and its bindings."
            : "Checking the IIS site and HTTP bindings."));
        var sites = await _iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        var site = sites.SingleOrDefault(candidate =>
            string.Equals(candidate.Name, request.SiteName, StringComparison.OrdinalIgnoreCase));
        var existingRecord = (await _managedCertificateStore.GetAllAsync(cancellationToken).ConfigureAwait(false))
            .FirstOrDefault(record => string.Equals(record.SiteName, request.SiteName.Trim(), StringComparison.OrdinalIgnoreCase));
        if (request.NoSite)
        {
            // One name never means both a site and a certificate without one.
            if (site is not null || existingRecord is { NoSite: false })
            {
                throw new InvalidOperationException(
                    $"'{request.SiteName.Trim()}' is the name of an IIS site{(site is null ? " that SSLense manages" : "")}. Choose another name for a certificate with no IIS site.");
            }

            if (existingRecord is not null && !request.Force)
            {
                throw new InvalidOperationException(
                    $"'{existingRecord.SiteName}' already has a certificate, which expires on {existingRecord.NotAfter:yyyy-MM-dd}. Use --force to replace it now.");
            }

            site = new IisSite(0, request.SiteName.Trim(), "None", null, []);
        }
        else if (existingRecord is { NoSite: true })
        {
            throw new InvalidOperationException(
                $"'{existingRecord.SiteName}' is a certificate with no IIS site. Renew it with 'SSLense.Cli renew --site \"{existingRecord.SiteName}\"', or remove it first to use the name for a site.");
        }

        if (sharedRecord is null && site is null)
        {
            throw new InvalidOperationException($"IIS site '{request.SiteName}' was not found.");
        }

        if (sharedRecord is not null && !usesDns)
        {
            throw new InvalidOperationException(
                $"The certificate for '{sharedRecord.SiteName}' is shared across several IIS sites, which needs DNS validation.");
        }

        // A deleted site does not hold back the others that share its certificate; the plan below leaves it out.
        site ??= new IisSite(0, sharedRecord!.SiteName, "Missing", null, []);
        if (!usesDns && string.IsNullOrWhiteSpace(site.PhysicalPath))
        {
            throw new InvalidOperationException($"IIS site '{site.Name}' has no physical root path.");
        }

        // DNS validation never reaches the site, so port 80 is needed only for HTTP-01.
        bool IsUsableBinding(IisBinding binding) => usesDns
            ? string.Equals(binding.Protocol, "http", StringComparison.OrdinalIgnoreCase) ||
              string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase)
            : string.Equals(binding.Protocol, "http", StringComparison.OrdinalIgnoreCase) && binding.Port == 80;

        // Without a site there are no bindings to take hosts from: the certificate covers the names given.
        var requestedNames = NormalizeCertificateNames(request.NoSite ? request.CertificateNames ?? request.Hosts : request.CertificateNames, usesDns);
        if (request.NoSite && requestedNames is null)
        {
            throw new ArgumentException("Give the names the certificate covers, such as --names rdp.example.com.", nameof(request));
        }

        var requestedHosts = request.Hosts.Count > 0
            ? request.Hosts
            : sharedRecord?.Hosts ?? site.Bindings
                .Where(binding => IsUsableBinding(binding) && !string.IsNullOrWhiteSpace(binding.HostName))
                .Select(binding => binding.HostName)
                .Where(host => requestedNames is null || CertificateInspector.Covers(requestedNames, host));
        var hosts = request.NoSite ? requestedNames! : NormalizeAndValidateHosts(
            requestedHosts,
            requestedNames is not null
                ? $"No host names were supplied and the IIS site has no named HTTP or HTTPS bindings that {string.Join(", ", requestedNames)} covers."
                : usesDns
                    ? "No host names were supplied and the IIS site has no named HTTP or HTTPS bindings."
                    : "No host names were supplied and the IIS site has no named HTTP bindings on port 80.");
        var names = requestedNames ?? hosts;
        if (hosts.FirstOrDefault(host => !CertificateInspector.Covers(names, host)) is { } uncovered)
        {
            throw new InvalidOperationException(
                $"Host name '{uncovered}' is not covered by the certificate names {string.Join(", ", names)}.");
        }

        foreach (var host in sharedRecord is null && !request.NoSite ? hosts : [])
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

        await ThrowIfWildcardManagedElsewhereAsync(site.Name, names, authority.Id, cancellationToken).ConfigureAwait(false);
        if (!request.Force)
        {
            await ThrowIfAlreadyCoveredAsync(site, hosts, authority, cancellationToken)
                .ConfigureAwait(false);
        }

        var sharedPlan = sharedRecord is null
            ? null
            : await PlanSharedSitesAsync(sharedRecord, hosts, names, sites, progress, cancellationToken).ConfigureAwait(false);

        var dnsChallenges = usesDns
            ? _dnsChallenges ?? throw new InvalidOperationException("DNS validation is not available.")
            : null;
        if (dnsChallenges is not null)
        {
            progress?.Report(new ProgressEvent("preflight", "Checking the DNS provider and validation records."));
            await dnsChallenges.CheckBeforeOrderAsync(request.ValidationMethod, names, authority.Id, cancellationToken)
                .ConfigureAwait(false);
        }

        progress?.Report(new ProgressEvent(
            "account",
            $"Loading or creating the {environmentName} ACME account."));
        IAcmeOrderSession order;
        try
        {
            order = await (usesDns
                    ? _protocolClient.CreateDnsOrderAsync(request.Email.Trim(), names, authority, cancellationToken)
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
            await CompleteDnsChallengesAsync(order, dnsChallenges, names, request, environmentName, progress, cancellationToken)
                .ConfigureAwait(false);
        }
        else
        {
            await CompleteHttpChallengesAsync(order, site.Name, site.PhysicalPath!, hosts, environmentName, progress, cancellationToken)
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
            bundle = await order.FinalizeAsync(names[0], pfxPassword, cancellationToken)
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
                ValidationMethod: request.ValidationMethod,
                CertificateNames: names.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(hosts) ? null : names);
            if (sharedPlan is not null)
            {
                preparedRecord = preparedRecord.WithTargets(sharedPlan.Targets);
            }

            if (request.NoSite)
            {
                preparedRecord = preparedRecord with { NoSite = true, LastRenewalMessage = "Certificate issued. It has no IIS site to bind." };
            }

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
                    $"SSLense: {names[0]} ({DateTimeOffset.UtcNow:yyyy-MM-dd})",
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
            IReadOnlyList<LeftOutSite> leftOut = sharedPlan?.LeftOut ?? [];
            try
            {
                progress?.Report(new ProgressEvent(
                    "binding",
                    "Creating or updating IIS HTTPS bindings with SNI, then confirming over HTTPS that the new certificate is served."));
                if (request.NoSite)
                {
                    // Nothing to bind: deployment steps hand the certificate to the services that use it.
                }
                else if (sharedPlan is null)
                {
                    await _iisService.ConfigureHttpsBindingsAsync(
                            site.Name,
                            hosts,
                            installedCertificate.Thumbprint,
                            "My",
                            cancellationToken)
                        .ConfigureAwait(false);
                }
                else
                {
                    leftOut =
                    [
                        .. leftOut,
                        .. await SharedBindingTransaction
                            .ApplyAsync(
                                _iisService,
                                sharedPlan.Targets.Where(target => target.PendingSince is null).ToArray(),
                                installedCertificate.Thumbprint,
                                sharedPlan.InLastDays,
                                progress,
                                cancellationToken,
                                sitesLeftOut => _transactionJournal.UpdateCertificateAsync(
                                    transaction.Id,
                                    pendingRecord.WithTargets(MarkLeftOut(pendingRecord.AllTargets(), [.. sharedPlan.LeftOut, .. sitesLeftOut])),
                                    CancellationToken.None))
                            .ConfigureAwait(false)
                    ];
                    pendingRecord = pendingRecord.WithTargets(MarkLeftOut(pendingRecord.AllTargets(), leftOut));
                }

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

            var replaced = await FindReplacedCertificateAsync(site.Name).ConfigureAwait(false);
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

            // The certificate is installed, bound, and saved: deployment steps run now, and a failure never undoes that.
            var deployment = await RunDeploymentAsync(site.Name, replaced, leftOut, progress).ConfigureAwait(false);
            if (replaced is not null && deployment?.KeepReplaced != true)
            {
                await RemoveReplacedCertificateAsync(replaced, installedCertificate.Thumbprint, leftOut, progress).ConfigureAwait(false);
            }

            return artifacts with
            {
                CertificateThumbprint = installedCertificate.Thumbprint,
                NotBefore = installedCertificate.NotBefore,
                NotAfter = installedCertificate.NotAfter,
                LeftOutSites = leftOut,
                Deployment = deployment?.Result,
                PreviousCertificateKept = deployment?.KeepReplaced == true
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

    /// <summary>
    /// The thumbprint of the ACME certificate this issue replaces. A certificate from another provider is never removed,
    /// because the administrator paid for it and may want it back. The new certificate is already bound here, so a problem
    /// only means the old one stays in the store.
    /// </summary>
    private async Task<string?> FindReplacedCertificateAsync(string siteName)
    {
        try
        {
            var records = await _managedCertificateStore.GetAllAsync(CancellationToken.None).ConfigureAwait(false);
            return records.FirstOrDefault(value =>
                    value.Source == CertificateSource.Acme &&
                    string.Equals(value.SiteName, siteName, StringComparison.OrdinalIgnoreCase))
                ?.Thumbprint;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private async Task<DeploymentAfterInstall?> RunDeploymentAsync(
        string siteName,
        string? replaced,
        IReadOnlyList<LeftOutSite> leftOut,
        IProgress<ProgressEvent>? progress)
    {
        if (_deployment is null)
        {
            return null;
        }

        try
        {
            return await _deployment
                .RunAfterInstallAsync(siteName, replaced, leftOut.Select(value => value.SiteName).ToArray(), progress, CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            // The steps' state could not be read or saved, so the previous certificate is kept to be safe.
            progress?.Report(new ProgressEvent("deploy", $"The certificate is installed, but its deployment steps could not run: {exception.Message}"));
            return new DeploymentAfterInstall(null, replaced is not null);
        }
    }

    private async Task RemoveReplacedCertificateAsync(

        string oldThumbprint,
        string newThumbprint,
        IReadOnlyList<LeftOutSite> leftOut,
        IProgress<ProgressEvent>? progress)
    {
        try
        {
            if (await ReplacedCertificateCleanup
                    .RemoveIfUnusedAsync(
                        _iisService,
                        _certificateStore,
                        oldThumbprint,
                        newThumbprint,
                        CancellationToken.None,
                        leftOut.Select(site => site.SiteName).ToArray())
                    .ConfigureAwait(false) is { } message)
            {
                progress?.Report(new ProgressEvent("cleanup", $"The new certificate is installed, but {message}"));
            }
        }
        catch (Exception exception)
        {
            progress?.Report(new ProgressEvent(
                "cleanup",
                $"The new certificate is installed, but the old certificate could not be checked for removal: {exception.Message}"));
        }
    }

    private async Task CompleteHttpChallengesAsync(
        IAcmeOrderSession order,
        string siteName,
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
                .PrepareAsync(siteName, sitePhysicalPath, challenge, cancellationToken)
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
            // The CA returns a wildcard's base name with a flag.
            var name = challenge.IsWildcard ? $"*.{NormalizeHost(challenge.Host)}" : NormalizeHost(challenge.Host);
            if (!names.Contains(name, StringComparer.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"The ACME server returned an unexpected authorization for '{name}'.");
            }
        }

        await using var cleanup = await dnsChallenges
            .PublishAsync(request.ValidationMethod, order.DnsChallenges, request.ConfirmManualDns, progress, cancellationToken)
            .ConfigureAwait(false);
        foreach (var challenge in order.DnsChallenges)
        {
            progress?.Report(new ProgressEvent(
                "validation",
                $"Requesting {environmentName} validation for {(challenge.IsWildcard ? "*." : string.Empty)}{challenge.Host}."));
            await order.ValidateAsync(challenge, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Every site whose certificate this issue can change. Taken before anything is read under the locks.</summary>
    private async Task<IReadOnlyList<string>> FindSitesToLockAsync(string siteName, CancellationToken cancellationToken)
    {
        var records = await _managedCertificateStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        ManagedCertificateTargets.ThrowIfAdditionalSite(records, siteName);
        return records.FirstOrDefault(record => string.Equals(record.SiteName, siteName, StringComparison.OrdinalIgnoreCase))
            ?.AllSiteNames() ?? [siteName];
    }

    /// <summary>The site's shared record, read again under the locks, because the sites can change while waiting for them.</summary>
    private async Task<ManagedCertificate?> FindSharedRecordAsync(
        string siteName,
        IReadOnlyList<string> lockedSites,
        CancellationToken cancellationToken)
    {
        var records = await _managedCertificateStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        ManagedCertificateTargets.ThrowIfAdditionalSite(records, siteName);
        var record = records.FirstOrDefault(value => string.Equals(value.SiteName, siteName, StringComparison.OrdinalIgnoreCase));
        if (!(record?.AllSiteNames() ?? [siteName]).ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(lockedSites))
        {
            throw new CertificateStateChangedException(
                $"The sites sharing the certificate for IIS site '{siteName}' changed while the operation was waiting. " +
                "Refresh status before trying again.");
        }

        return record is { } shared && shared.IsShared() ? shared : null;
    }

    /// <summary>
    /// Decides which sites take the new certificate before anything is ordered, so a site that is already broken does not use
    /// up a certificate (docs/design/shared-certificates.md, section 6).
    /// </summary>
    private async Task<SharedPlan> PlanSharedSitesAsync(
        ManagedCertificate record,
        IReadOnlyList<string> firstSiteHosts,
        IReadOnlyList<string> names,
        IReadOnlyList<IisSite> sites,
        IProgress<ProgressEvent>? progress,
        CancellationToken cancellationToken)
    {
        var inLastDays = record.NotAfter - DateTimeOffset.UtcNow <= ManagedCertificateTargets.LeaveOutWindow;
        var targets = record.AllTargets()
            .Select((target, index) => index == 0 ? target with { Hosts = firstSiteHosts } : target)
            .ToArray();
        var leftOut = new List<LeftOutSite>();
        foreach (var target in targets)
        {
            if (target.Hosts.FirstOrDefault(host => !CertificateInspector.Covers(names, host)) is { } uncovered)
            {
                throw new InvalidOperationException(
                    $"Host name '{uncovered}' on IIS site '{target.SiteName}' shares this certificate, but is not covered by the " +
                    $"certificate names {string.Join(", ", names)}. Keep the names, or stop sharing with 'SSLense.Cli share remove --site \"{target.SiteName}\"'.");
            }

            var site = sites.FirstOrDefault(value => string.Equals(value.Name, target.SiteName, StringComparison.OrdinalIgnoreCase));
            if (site is null)
            {
                leftOut.Add(new LeftOutSite(target.SiteName, $"IIS site '{target.SiteName}' no longer exists."));
                continue;
            }

            if (target.Hosts.FirstOrDefault(host => !HasWebBinding(site, host)) is { } unbound)
            {
                leftOut.Add(new LeftOutSite(target.SiteName, $"Host name '{unbound}' no longer has a binding on IIS site '{target.SiteName}'."));
                continue;
            }

            if (site.State != ServedCertificateCheck.StartedState ||
                await _iisService.GetHttpsProblemAsync(site, target.Hosts, cancellationToken).ConfigureAwait(false) is not { } problem)
            {
                continue;
            }

            if (!inLastDays)
            {
                throw new InvalidOperationException(
                    $"IIS site '{target.SiteName}' shares this certificate, but it has a problem: {problem} " +
                    "Nothing was ordered and no site changed. Fix the site, or stop sharing with " +
                    $"'SSLense.Cli share remove --site \"{target.SiteName}\"'.");
            }

            leftOut.Add(new LeftOutSite(target.SiteName, problem));
        }

        if (leftOut.Count == targets.Length)
        {
            throw new InvalidOperationException(
                $"No IIS site can use this certificate, so nothing was ordered: {string.Join(" ", leftOut.Select(site => site.Reason))}");
        }

        foreach (var site in leftOut)
        {
            progress?.Report(new ProgressEvent("preflight", $"IIS site '{site.SiteName}' stays on its previous certificate: {site.Reason}"));
        }

        return new SharedPlan(MarkLeftOut(targets, leftOut), leftOut, inLastDays);
    }

    private static bool HasWebBinding(IisSite site, string host) =>
        site.Bindings.Any(binding =>
            (string.Equals(binding.Protocol, "http", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase)) &&
            string.Equals(NormalizeHost(binding.HostName), host, StringComparison.OrdinalIgnoreCase));

    /// <summary>A site left out keeps the date it first fell behind; every other site is up to date.</summary>
    private static IReadOnlyList<CertificateTarget> MarkLeftOut(
        IReadOnlyList<CertificateTarget> targets,
        IReadOnlyList<LeftOutSite> leftOut) =>
        targets
            .Select(target => target with
            {
                PendingSince = leftOut.Any(site => string.Equals(site.SiteName, target.SiteName, StringComparison.OrdinalIgnoreCase))
                    ? target.PendingSince ?? DateTimeOffset.UtcNow
                    : null
            })
            .ToArray();

    /// <param name="Targets">Every site; those left out have <see cref="CertificateTarget.PendingSince"/> set.</param>
    private sealed record SharedPlan(IReadOnlyList<CertificateTarget> Targets, IReadOnlyList<LeftOutSite> LeftOut, bool InLastDays);

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

    /// <summary>
    /// One wildcard belongs to one IIS site for now. A copy per site is no workaround: renewals of the same names count
    /// toward the CA's weekly limit across all accounts (docs/design/dns-validation.md, section 7).
    /// </summary>
    private async Task ThrowIfWildcardManagedElsewhereAsync(
        string siteName,
        IReadOnlyList<string> names,
        string authorityId,
        CancellationToken cancellationToken)
    {
        var wildcards = names.Where(DnsNames.IsWildcard).ToArray();
        if (wildcards.Length == 0)
        {
            return;
        }

        var records = await _managedCertificateStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        foreach (var record in records.Where(value =>
                     value.Source == CertificateSource.Acme &&
                     string.Equals(value.AuthorityId, authorityId, StringComparison.OrdinalIgnoreCase) &&
                     !string.Equals(value.SiteName, siteName, StringComparison.OrdinalIgnoreCase)))
        {
            var shared = wildcards.FirstOrDefault(name =>
                (record.CertificateNames ?? record.Hosts).Contains(name, StringComparer.OrdinalIgnoreCase));
            if (shared is not null)
            {
                throw new InvalidOperationException(
                    $"'{shared}' is already managed for IIS site '{record.SiteName}'. Issuing a copy per site would use up the " +
                    "certificate authority's weekly limit. Share the certificate instead: " +
                    $"'SSLense.Cli share add --from \"{record.SiteName}\" --to \"{siteName}\"'.");
            }
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

        if (request.NoSite)
        {
            if (request.ValidationMethod == ValidationMethod.Http01)
            {
                throw new ArgumentException(
                    "A certificate with no IIS site needs DNS validation: HTTP validation needs a site to serve the file.", nameof(request));
            }

            if (!NoSiteName().IsMatch(request.SiteName.Trim()))
            {
                throw new ArgumentException(
                    $"'{request.SiteName.Trim()}' cannot name a certificate. Use letters, digits, spaces, dots, hyphens, underscores, and brackets, up to 100 characters.",
                    nameof(request));
            }
        }

        if (request.ValidationMethod == ValidationMethod.Dns01Manual && request.ConfirmManualDns is null)
        {
            throw new ArgumentException("Manual DNS validation needs someone to create the records.", nameof(request));
        }
    }

    [System.Text.RegularExpressions.GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,99}$")]
    private static partial System.Text.RegularExpressions.Regex NoSiteName();

    /// <summary>Null when the request lists no names, so the certificate covers the hosts.</summary>
    internal static IReadOnlyList<string>? NormalizeCertificateNames(IReadOnlyList<string>? requestedNames, bool usesDns)
    {
        var names = (requestedNames ?? [])
            .Select(NormalizeHost)
            .Where(name => name.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (names.Length == 0)
        {
            return null;
        }

        if (!usesDns)
        {
            throw new ArgumentException(
                "Certificate names, including wildcards, need DNS validation. HTTP-01 certificates cover their host names.",
                nameof(requestedNames));
        }

        foreach (var name in names)
        {
            var baseName = DnsNames.IsWildcard(name) ? name[2..] : name;
            if (baseName.Contains('*') ||
                (DnsNames.IsWildcard(name) && !baseName.Contains('.')) ||
                Uri.CheckHostName(baseName) != UriHostNameType.Dns)
            {
                throw new ArgumentException(
                    $"'{name}' is not a valid certificate name. A wildcard covers one level, as in *.example.com.",
                    nameof(requestedNames));
            }

            if (!DnsNames.IsWildcard(name) && CertificateInspector.Covers(names.Where(DnsNames.IsWildcard).ToArray(), name))
            {
                throw new ArgumentException(
                    $"'{name}' is already covered by a wildcard in the same certificate. Remove one of them.",
                    nameof(requestedNames));
            }
        }

        return names;
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
            if (host.Contains('*'))
            {
                throw new ArgumentException(
                    $"'{host}' cannot be used as a host name, because SSLense manages IIS bindings for real host names only. " +
                    "To get a wildcard certificate, use DNS validation, list the wildcard in the certificate names " +
                    "(--names), and list real host names in the hosts (--hosts).",
                    nameof(requestedHosts));
            }

            if (Uri.CheckHostName(host) != UriHostNameType.Dns)
            {
                throw new ArgumentException(
                    $"'{host}' is not a valid DNS host name.",
                    nameof(requestedHosts));
            }
        }

        return hosts;
    }

    private static string NormalizeHost(string host) => host.Trim().TrimEnd('.').ToLowerInvariant();

    private static string NormalizeThumbprint(string thumbprint) =>
        string.Concat(thumbprint.Where(Uri.IsHexDigit)).ToUpperInvariant();
}
