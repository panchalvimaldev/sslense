using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;

namespace SSLense.Core.Reminders;

/// <summary>
/// Compares the certificate this server really serves with the one SSLense expects
/// (docs/design/proactive-checks.md, section 4). Report-only. It connects from this server, so it shows what IIS serves,
/// not necessarily what visitors receive through a CDN, reverse proxy, or load balancer.
/// </summary>
public interface IServedCertificateCheck
{
    /// <summary>Checks every managed certificate with reminders on, on sites that are started.</summary>
    Task<ProactiveCheckResult> CheckAllAsync(
        IReadOnlyList<ManagedCertificate> certificates,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>Checks one certificate's hosts. Returns what is wrong, or null when all of them serve the expected certificate.</summary>
    Task<string?> CheckAsync(ManagedCertificate certificate, IisSite site, CancellationToken cancellationToken = default);
}

internal sealed class ServedCertificateCheck(
    IIisService iisService,
    ITlsBindingProbe tlsProbe,
    ICertificateStore certificateStore,
    ICertificateOperationLock operationLock) : IServedCertificateCheck
{
    internal const string StartedState = "Started";

    public async Task<ProactiveCheckResult> CheckAllAsync(
        IReadOnlyList<ManagedCertificate> certificates,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        // A certificate with no IIS site is not served by IIS, so there is nothing here to compare.
        var candidates = certificates.Where(value => !value.NoSite && !ReminderDigestBuilder.IsMuted(value, now)).ToArray();
        if (candidates.Length == 0)
        {
            return ProactiveCheckResult.None;
        }

        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        var problems = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var passed = new List<string>();
        var errors = new List<string>();
        foreach (var certificate in candidates)
        {
            if (certificate.IsShared())
            {
                await CheckSharedAsync(certificate, sites, certificates, problems, passed, errors, cancellationToken).ConfigureAwait(false);
                continue;
            }

            var site = sites.FirstOrDefault(value => string.Equals(value.Name, certificate.SiteName, StringComparison.OrdinalIgnoreCase));
            var sharedProblem = DescribeSharing(certificate, sites, certificates);
            if (site is not { State: StartedState })
            {
                if (sharedProblem is not null)
                {
                    problems[certificate.SiteName] = sharedProblem;
                }

                continue;
            }

            // During an install the binding may briefly serve either certificate; this site is looked at again tomorrow.
            await using var siteLock = operationLock.TryAcquire(certificate.SiteName);
            if (siteLock is null)
            {
                continue;
            }

            try
            {
                var served = await CheckAsync(certificate, site, cancellationToken).ConfigureAwait(false);
                if (served is not null || sharedProblem is not null)
                {
                    problems[certificate.SiteName] = string.Join(" ", new[] { served, sharedProblem }.OfType<string>());
                }
                else
                {
                    passed.Add(certificate.SiteName);
                }
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
            {
                errors.Add($"Could not check the served certificate for '{certificate.SiteName}': {exception.Message}");
            }
        }

        return new ProactiveCheckResult(problems, passed, errors);
    }

    /// <summary>Every site of a shared certificate. A site left behind is reported with what it serves, or why it was left out.</summary>
    private async Task CheckSharedAsync(
        ManagedCertificate certificate,
        IReadOnlyList<IisSite> sites,
        IReadOnlyList<ManagedCertificate> certificates,
        Dictionary<string, string> problems,
        List<string> passed,
        List<string> errors,
        CancellationToken cancellationToken)
    {
        await using var siteLocks = operationLock.TryAcquireAll(certificate.AllSiteNames());
        if (siteLocks is null)
        {
            return;
        }

        var found = new List<string>();
        if (DescribeSharing(certificate, sites, certificates) is { } sharing)
        {
            found.Add(sharing);
        }

        foreach (var target in certificate.AllTargets())
        {
            var site = sites.FirstOrDefault(value => string.Equals(value.Name, target.SiteName, StringComparison.OrdinalIgnoreCase));
            if (site is null)
            {
                found.Add($"IIS site '{target.SiteName}' uses this certificate but no longer exists. If it was deleted, run 'SSLense.Cli share remove --site \"{target.SiteName}\"'.");
                continue;
            }

            if (site.State != StartedState)
            {
                continue;
            }

            try
            {
                if (await CheckAsync(certificate with { SiteName = target.SiteName, Hosts = target.Hosts }, site, cancellationToken).ConfigureAwait(false) is { } served)
                {
                    found.Add($"IIS site '{target.SiteName}': {served}");
                }
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
            {
                errors.Add($"Could not check the served certificate for '{target.SiteName}': {exception.Message}");
            }
        }

        if (found.Count > 0)
        {
            problems[certificate.SiteName] = string.Join(" ", found);
        }
        else
        {
            passed.Add(certificate.SiteName);
        }
    }

    public async Task<string?> CheckAsync(ManagedCertificate certificate, IisSite site, CancellationToken cancellationToken = default)
    {
        var problems = new List<string>();
        foreach (var host in certificate.Hosts)
        {
            var bindings = site.Bindings
                .Where(binding =>
                    string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase) &&
                    binding.Port == 443 &&
                    string.Equals(binding.HostName, host, StringComparison.OrdinalIgnoreCase))
                .ToArray();
            if (bindings.Length == 0)
            {
                problems.Add($"{host} has no HTTPS binding on port 443.");
            }

            foreach (var binding in bindings)
            {
                if (await CheckBindingAsync(certificate, host, binding, cancellationToken).ConfigureAwait(false) is { } problem)
                {
                    problems.Add(problem);
                }
            }
        }

        return problems.Count == 0
            ? null
            : $"{string.Join(" ", problems.Distinct())} Check the site's HTTPS binding in IIS.";
    }

    /// <summary>
    /// An administrator may bind an automatic certificate to another site in IIS. Renewal leaves that binding on the old
    /// certificate, so that site would expire without warning unless it is reported.
    /// </summary>
    internal static string? DescribeSharing(
        ManagedCertificate certificate,
        IReadOnlyList<IisSite> sites,
        IReadOnlyList<ManagedCertificate> certificates)
    {
        if (certificate.Source != CertificateSource.Acme)
        {
            return null;
        }

        var expected = Normalize(certificate.Thumbprint);
        var others = sites
            .Where(site =>
                !certificate.ManagesSite(site.Name) &&
                site.Bindings.Any(binding => binding.CertificateThumbprint is { } thumbprint && Normalize(thumbprint) == expected) &&
                !certificates.Any(other =>
                    string.Equals(other.SiteName, site.Name, StringComparison.OrdinalIgnoreCase) &&
                    Normalize(other.Thumbprint) == expected))
            .Select(site => $"'{site.Name}'")
            .ToArray();
        return others.Length == 0
            ? null
            : $"IIS site {string.Join(", ", others)} also uses this certificate, but SSLense does not update that binding when it renews, " +
              $"so it will stop working when the current certificate expires on {certificate.NotAfter:yyyy-MM-dd}. " +
              (certificate.ValidationMethod == ValidationMethod.Http01
                  ? "Give that site its own certificate."
                  : $"To renew it too, run 'SSLense.Cli share add --from \"{certificate.SiteName}\" --to <site>'.");
    }

    private async Task<string?> CheckBindingAsync(
        ManagedCertificate certificate,
        string host,
        IisBinding binding,
        CancellationToken cancellationToken)
    {
        // A wildcard binding also listens on loopback, so the check never leaves this machine.
        var address = binding.IpAddress is "*" or "" ? "127.0.0.1" : binding.IpAddress.Trim('[', ']');
        string served;
        try
        {
            served = Normalize(await tlsProbe.GetServedThumbprintAsync(address, host, 443, cancellationToken).ConfigureAwait(false));
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            return $"{host} did not answer on port 443 ({exception.Message}).";
        }

        var expected = Normalize(certificate.Thumbprint);
        if (string.Equals(served, expected, StringComparison.Ordinal))
        {
            // The probe accepts invalid certificates so it can read them, so a match alone does not mean all is well.
            return certificate.NotAfter <= DateTimeOffset.UtcNow
                ? $"{host} serves the expected certificate, but it expired on {certificate.NotAfter:yyyy-MM-dd}."
                : null;
        }

        var installed = await certificateStore.FindByThumbprintAsync(served, cancellationToken).ConfigureAwait(false);
        var expiry = installed is null
            ? "It is not in this server's certificate store."
            : installed.NotAfter <= DateTimeOffset.UtcNow
                ? $"It expired on {installed.NotAfter:yyyy-MM-dd}."
                : $"It expires on {installed.NotAfter:yyyy-MM-dd}.";
        return $"{host} serves a different certificate from the one SSLense expects: expected {Short(expected)}, served {Short(served)}. {expiry}";
    }

    private static string Normalize(string thumbprint) => thumbprint.Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();

    private static string Short(string thumbprint) => thumbprint.Length <= 8 ? thumbprint : $"{thumbprint[..8]}…";
}
