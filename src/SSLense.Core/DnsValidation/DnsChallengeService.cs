using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Validation;

namespace SSLense.Core.DnsValidation;

internal interface IDnsChallengeService
{
    /// <summary>
    /// Confirms, before an order is created, that every record can be published and that CAA records allow the CA to
    /// issue. Changes nothing in DNS, so the daily readiness checks use it too.
    /// </summary>
    Task CheckBeforeOrderAsync(
        ValidationMethod method,
        IReadOnlyList<string> certificateNames,
        string authorityId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Publishes every record in one batch and waits until they are visible. Disposing the result removes the
    /// records SSLense published; it never throws, because a leftover record must not fail the operation.
    /// </summary>
    Task<IAsyncDisposable> PublishAsync(
        ValidationMethod method,
        IReadOnlyList<AcmeDnsChallenge> challenges,
        ManualDnsConfirmation? confirmManual,
        IProgress<ProgressEvent>? progress,
        CancellationToken cancellationToken);

    /// <summary>Removes records left behind by a process that exited mid-validation. Returns a message for each.</summary>
    Task<IReadOnlyList<string>> CleanUpAbandonedAsync(CancellationToken cancellationToken);
}

internal sealed class DnsChallengeService(
    IConfigStore configStore,
    IEnumerable<IDnsProvider> providers,
    IDnsLookup lookup,
    IDnsChallengeJournal journal,
    DnsPropagationChecker propagation,
    ICertificateAuthorityRegistry? authorities = null,
    ICertificateOperationLock? operationLock = null) : IDnsChallengeService
{
    private readonly ICertificateOperationLock _operationLock = operationLock ?? new NoOpCertificateOperationLock();
    private readonly ICertificateAuthorityRegistry _authorities = authorities ?? CertificateAuthorityRegistry.BuiltInOnly;

    /// <summary>After this long a record that cannot be removed is reported once and no longer retried.</summary>
    private static readonly TimeSpan GiveUpAfter = TimeSpan.FromDays(7);

    public async Task CheckBeforeOrderAsync(
        ValidationMethod method,
        IReadOnlyList<string> certificateNames,
        string authorityId,
        CancellationToken cancellationToken)
    {
        var profiles = method == ValidationMethod.Dns01Provider
            ? await GetProfilesAsync(cancellationToken).ConfigureAwait(false)
            : [];
        var selected = new Dictionary<string, DnsProviderProfile>(StringComparer.OrdinalIgnoreCase);
        var acmeDnsValues = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in certificateNames)
        {
            var record = DnsNames.ChallengeRecord(name);
            var target = await lookup.ResolveCnameAsync(record, cancellationToken).ConfigureAwait(false);
            if (method == ValidationMethod.Dns01Provider)
            {
                ThrowIfAcmeDnsCnameMissing(profiles, record, target);
            }

            await EnsureHasNameServersAsync(target, cancellationToken).ConfigureAwait(false);
            if (method == ValidationMethod.Dns01Provider)
            {
                var profile = SelectProfile(profiles, target);
                selected[profile.Name] = profile;
                if (profile.Provider == DnsProviderType.AcmeDns)
                {
                    acmeDnsValues[profile.Name] = acmeDnsValues.GetValueOrDefault(profile.Name) + 1;
                }
            }
        }

        // An acme-dns account keeps only its two newest values, so a third would push out the first before validation.
        foreach (var (account, count) in acmeDnsValues.Where(value => value.Value > 2))
        {
            throw new InvalidOperationException(
                $"The acme-dns account '{account}' would need {count} values at once, and it keeps only two: enough for a name and its " +
                "wildcard. Give each other name its own acme-dns account, with its own CNAME.");
        }

        foreach (var profile in selected.Values)
        {
            await GetProvider(profile).VerifyAccessAsync(profile, cancellationToken).ConfigureAwait(false);
        }

        // A CA that publishes no CAA identities, and was given none, cannot be checked; the CA still checks CAA itself.
        var authority = await _authorities.GetAsync(authorityId, cancellationToken).ConfigureAwait(false);
        if (authority.CaaIdentities is { Count: > 0 } caDomains)
        {
            foreach (var name in certificateNames)
            {
                await EnsureCaaAllowsAsync(name, caDomains, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task EnsureHasNameServersAsync(string recordName, CancellationToken cancellationToken)
    {
        try
        {
            if ((await lookup.GetAuthoritativeServersAsync(recordName, cancellationToken).ConfigureAwait(false)).Count == 0)
            {
                throw new InvalidOperationException(
                    $"No public name servers were found for '{recordName}'. A public certificate authority can only validate names in public DNS.");
            }
        }
        catch (DnsLookupUnavailableException)
        {
            // Outbound DNS may be blocked on this server, which does not stop the CA from reading the record.
        }
    }

    private async Task EnsureCaaAllowsAsync(string certificateName, IReadOnlyList<string> caDomains, CancellationToken cancellationToken)
    {
        var name = DnsNames.Normalize(certificateName);
        var current = DnsNames.IsWildcard(name) ? name[2..] : name;
        try
        {
            // The closest name with any CAA records decides, whether or not they mention this CA.
            while (current.Contains('.'))
            {
                var records = await lookup.QueryCaaAsync(current, cancellationToken).ConfigureAwait(false);
                if (records.Count > 0)
                {
                    if (CaaPolicy.FindProblem(name, current, records, caDomains) is { } problem)
                    {
                        throw new InvalidOperationException(problem);
                    }

                    return;
                }

                current = current[(current.IndexOf('.') + 1)..];
            }
        }
        catch (DnsLookupUnavailableException)
        {
            // The CA checks CAA itself, so this only loses the early warning.
        }
    }

    public async Task<IAsyncDisposable> PublishAsync(
        ValidationMethod method,
        IReadOnlyList<AcmeDnsChallenge> challenges,
        ManualDnsConfirmation? confirmManual,
        IProgress<ProgressEvent>? progress,
        CancellationToken cancellationToken)
    {
        var records = new List<DnsTxtRecord>(challenges.Count);
        foreach (var challenge in challenges)
        {
            var target = await lookup.ResolveCnameAsync(challenge.RecordName, cancellationToken).ConfigureAwait(false);
            records.Add(new DnsTxtRecord(target, challenge.TxtValue));
        }

        records = records.Distinct().ToList();
        var cleanup = new PublishedRecords(this, journal, progress);
        if (records.Count == 0)
        {
            return cleanup;
        }

        try
        {
            if (method == ValidationMethod.Dns01Manual)
            {
                if (confirmManual is null ||
                    !await confirmManual(records, cancellationToken).ConfigureAwait(false))
                {
                    throw new InvalidOperationException("The DNS records were not confirmed, so the certificate was not requested.");
                }
            }
            else
            {
                await PublishWithProviderAsync(records, cleanup, progress, cancellationToken).ConfigureAwait(false);
            }

            progress?.Report(new ProgressEvent("dns-propagation", "Checking that the DNS records are visible."));
            await propagation.WaitAsync(records, progress, cancellationToken).ConfigureAwait(false);
            return cleanup;
        }
        catch
        {
            await cleanup.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async Task<IReadOnlyList<string>> CleanUpAbandonedAsync(CancellationToken cancellationToken)
    {
        var entries = await journal.GetAbandonedAsync(cancellationToken).ConfigureAwait(false);
        if (entries.Count == 0)
        {
            return [];
        }

        var profiles = await GetProfilesAsync(cancellationToken).ConfigureAwait(false);
        var messages = new List<string>(entries.Count);
        foreach (var entry in entries)
        {
            var profile = profiles.FirstOrDefault(value =>
                string.Equals(value.Name, entry.ProviderName, StringComparison.OrdinalIgnoreCase));
            if (profile is null)
            {
                await journal.CompleteAsync(entry.Id).ConfigureAwait(false);
                messages.Add(
                    $"The DNS TXT record '{entry.RecordName}' from an interrupted validation may remain, because DNS provider " +
                    $"'{entry.ProviderName}' no longer exists. Delete it in your DNS service.");
                continue;
            }

            try
            {
                await GetProvider(profile)
                    .RemoveTxtRecordAsync(profile, entry.RecordName, entry.Value, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception exception) when (
                exception is not OperationCanceledException &&
                DateTimeOffset.UtcNow - entry.CreatedAt > GiveUpAfter)
            {
                await journal.CompleteAsync(entry.Id).ConfigureAwait(false);
                messages.Add(
                    $"The DNS TXT record '{entry.RecordName}' could not be removed for {GiveUpAfter.TotalDays:0} days " +
                    $"({exception.Message}). SSLense will stop trying; delete it in your DNS service.");
                continue;
            }

            await journal.CompleteAsync(entry.Id).ConfigureAwait(false);
            messages.Add(
                $"Removed the DNS TXT record '{entry.RecordName}' left by an interrupted validation " +
                $"started {entry.CreatedAt:yyyy-MM-dd HH:mm} UTC.");
        }

        return messages;
    }

    private async Task PublishWithProviderAsync(
        IReadOnlyList<DnsTxtRecord> records,
        PublishedRecords cleanup,
        IProgress<ProgressEvent>? progress,
        CancellationToken cancellationToken)
    {
        var profiles = await GetProfilesAsync(cancellationToken).ConfigureAwait(false);

        // Before anything changes, so a record without a provider publishes nothing.
        var targets = records.Select(record => (Record: record, Profile: SelectProfile(profiles, record.Name))).ToArray();

        // An acme-dns account keeps only its two newest values, so its use is exclusive until validation ends: another
        // order or a 'dns test' through the same account would otherwise push out a value the CA is about to check.
        var accounts = targets
            .Where(target => target.Profile.Provider == DnsProviderType.AcmeDns)
            .Select(target => AcmeDnsAccountLock.Key(target.Profile))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (accounts.Length > 0)
        {
            var held = _operationLock.TryAcquireAll(accounts);
            if (held is null)
            {
                progress?.Report(new ProgressEvent("dns-publish", "Waiting for another validation through the same acme-dns account to finish."));
                held = await _operationLock.AcquireAllAsync(accounts, cancellationToken).ConfigureAwait(false);
            }

            cleanup.Hold(held);
        }

        var owner = JsonChallengeJournal.CurrentProcess;
        foreach (var (record, profile) in targets)
        {
            var entry = new DnsChallengeEntry(
                Guid.NewGuid(),
                profile.Name,
                record.Name,
                record.Value,
                owner.ProcessId,
                owner.StartedAt,
                DateTimeOffset.UtcNow);

            // Journal first: if the process dies after this point, recovery can still remove the record.
            await journal.RecordAsync(entry, cancellationToken).ConfigureAwait(false);
            cleanup.Add(entry, profile);
            progress?.Report(new ProgressEvent("dns-publish", $"Publishing the TXT record '{record.Name}' with {profile.Name}."));
            await GetProvider(profile)
                .AddTxtRecordAsync(profile, record.Name, record.Value, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async Task<IReadOnlyList<DnsProviderProfile>> GetProfilesAsync(CancellationToken cancellationToken) =>
        (await configStore.LoadAsync(cancellationToken).ConfigureAwait(false)).DnsProviders;

    /// <summary>
    /// A name set up for acme-dns whose CNAME is missing or wrong would reach some other provider, or none, and fail later
    /// with a less useful message. Checked before each order and daily, so a deleted CNAME shows before a renewal fails.
    /// </summary>
    private static void ThrowIfAcmeDnsCnameMissing(IReadOnlyList<DnsProviderProfile> profiles, string record, string target)
    {
        var account = profiles.FirstOrDefault(profile =>
            profile.Provider == DnsProviderType.AcmeDns &&
            profile.AcmeDnsDomain is { } domain &&
            DnsNames.ChallengeRecord(domain) == DnsNames.Normalize(record));
        if (account is not null && DnsNames.Normalize(target) != DnsNames.Normalize(account.ZoneName))
        {
            throw new InvalidOperationException(
                $"'{record}' does not point to the acme-dns account '{account.Name}'. Create this record at your DNS host: {account.AcmeDnsCname}");
        }
    }

    private static DnsProviderProfile SelectProfile(IReadOnlyList<DnsProviderProfile> profiles, string recordName) =>
        DnsNames.SelectProfile(profiles, recordName)
        ?? throw new InvalidOperationException(
            $"No DNS provider manages '{recordName}'. Add one in Settings or with 'SSLense.Cli dns add', delegate the record with a CNAME, " +
            "or use manual DNS validation.");

    private IDnsProvider GetProvider(DnsProviderProfile profile) =>
        providers.FirstOrDefault(provider => provider.Type == profile.Provider)
        ?? throw new InvalidOperationException($"DNS provider type '{profile.Provider}' is not supported by this SSLense version.");

    private sealed class PublishedRecords(
        DnsChallengeService owner,
        IDnsChallengeJournal journal,
        IProgress<ProgressEvent>? progress) : IAsyncDisposable
    {
        private readonly List<(DnsChallengeEntry Entry, DnsProviderProfile Profile)> _entries = [];
        private int _disposed;

        public void Add(DnsChallengeEntry entry, DnsProviderProfile profile) => _entries.Add((entry, profile));

        private IAsyncDisposable? _held;

        /// <summary>Released after the records are removed, when validation is over.</summary>
        public void Hold(IAsyncDisposable held) => _held = held;

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            foreach (var (entry, profile) in _entries)
            {
                try
                {
                    await owner.GetProvider(profile)
                        .RemoveTxtRecordAsync(profile, entry.RecordName, entry.Value, CancellationToken.None)
                        .ConfigureAwait(false);

                    // Only once the record is gone, so a failure above leaves the entry for recovery to retry.
                    await journal.CompleteAsync(entry.Id).ConfigureAwait(false);
                }
                catch (Exception exception)
                {
                    progress?.Report(new ProgressEvent(
                        "dns-cleanup",
                        $"Warning: the TXT record '{entry.RecordName}' could not be removed: {exception.Message} " +
                        "SSLense will try again when it next starts."));
                }
            }

            if (_held is not null)
            {
                await _held.DisposeAsync().ConfigureAwait(false);
            }
        }
    }
}
