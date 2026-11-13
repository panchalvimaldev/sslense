using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.DnsValidation;
using SSLense.Core.Iis;
using SSLense.Core.Validation;

namespace SSLense.Core.Reminders;

/// <summary>
/// Runs the pre-flight checks ahead of each automatic renewal, so a closed port or a removed binding is found while there
/// is time to fix it (docs/design/proactive-checks.md, section 3). Report-only. The checks run from this server, so a
/// failure means renewal is likely to fail, but a pass does not prove that the CA can reach the site.
/// </summary>
public interface IRenewalReadinessCheck
{
    /// <param name="scheduledRenewals">By site: when each automatic certificate is scheduled to renew.</param>
    Task<ProactiveCheckResult> CheckAsync(
        IReadOnlyList<ManagedCertificate> certificates,
        IReadOnlyDictionary<string, DateTimeOffset> scheduledRenewals,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);
}

internal sealed class RenewalReadinessCheck(
    IPreflightService preflight,
    ICertificateOperationLock operationLock,
    IDnsChallengeService dnsChallenges,
    IIisService? iisService = null) : IRenewalReadinessCheck
{
    /// <summary>Checks start this long before the scheduled renewal, so a certificate far from it causes no daily emails.</summary>
    internal static readonly TimeSpan Window = TimeSpan.FromDays(30);

    public async Task<ProactiveCheckResult> CheckAsync(
        IReadOnlyList<ManagedCertificate> certificates,
        IReadOnlyDictionary<string, DateTimeOffset> scheduledRenewals,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        var problems = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var passed = new List<string>();
        var errors = new List<string>();
        foreach (var certificate in certificates.Where(value =>
                     value.Source == CertificateSource.Acme &&
                     value.ValidationMethod != ValidationMethod.Dns01Manual && // Nothing runs on its own, so nothing to check.
                     !ReminderDigestBuilder.IsMuted(value, now)))
        {
            if (!scheduledRenewals.TryGetValue(certificate.SiteName, out var renewalAt) || renewalAt - now > Window)
            {
                continue;
            }

            // An operation in progress changes bindings and challenge files; this site is looked at again tomorrow.
            await using var siteLock = operationLock.TryAcquireAll(certificate.AllSiteNames());
            if (siteLock is null)
            {
                continue;
            }

            try
            {
                var failed = certificate.ValidationMethod == ValidationMethod.Http01
                    ? (await preflight.CheckAsync(certificate.SiteName, certificate.Hosts, cancellationToken).ConfigureAwait(false))
                        .Where(check => !check.Succeeded)
                        .Select(check => $"'{check.Name}' failed: {check.Message}")
                        .ToArray()
                    : [
                        .. await CheckDnsAsync(certificate, cancellationToken).ConfigureAwait(false),
                        .. await CheckSharedSitesAsync(certificate, cancellationToken).ConfigureAwait(false)
                    ];
                if (failed.Length == 0)
                {
                    passed.Add(certificate.SiteName);
                }
                else
                {
                    problems[certificate.SiteName] = string.Join(" ", failed);
                }
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
            {
                errors.Add($"Could not check renewal readiness for '{certificate.SiteName}': {exception.Message}");
            }
        }

        return new ProactiveCheckResult(problems, passed, errors);
    }

    /// <summary>The site problems that would hold back or leave out a site at renewal (docs/design/shared-certificates.md, section 6).</summary>
    private async Task<string[]> CheckSharedSitesAsync(ManagedCertificate certificate, CancellationToken cancellationToken)
    {
        if (iisService is null || !certificate.IsShared())
        {
            return [];
        }

        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        var failed = new List<string>();
        foreach (var target in certificate.AllTargets())
        {
            var site = sites.FindSite(target.SiteName);
            if (site is null)
            {
                failed.Add($"IIS site '{target.SiteName}' no longer exists, so it will be left out.");
            }
            else if (site.State == ServedCertificateCheck.StartedState &&
                     await iisService.GetHttpsProblemAsync(site, target.Hosts, cancellationToken).ConfigureAwait(false) is { } problem)
            {
                failed.Add($"IIS site '{target.SiteName}' would hold back the renewal: {problem}");
            }
        }

        return [.. failed];
    }

    /// <summary>Changes nothing in DNS. Anything other than a finding, such as a network failure, means the check could not run.</summary>
    private async Task<string[]> CheckDnsAsync(ManagedCertificate certificate, CancellationToken cancellationToken)
    {
        try
        {
            await dnsChallenges.CheckBeforeOrderAsync(
                    certificate.ValidationMethod,
                    certificate.CertificateNames ?? certificate.Hosts,
                    certificate.AuthorityId,
                    cancellationToken)
                .ConfigureAwait(false);
            return [];
        }
        catch (InvalidOperationException exception)
        {
            return [exception.Message];
        }
    }
}
