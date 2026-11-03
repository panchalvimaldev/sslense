namespace SSLense.Core.DnsValidation;

internal sealed record DnsPropagationOptions
{
    public TimeSpan Timeout { get; init; } = TimeSpan.FromMinutes(5);

    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>A pause after the authoritative servers agree, before the CA is asked to look.</summary>
    public TimeSpan SettleDelay { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>How long to wait instead of checking when DNS cannot be queried from this server.</summary>
    public TimeSpan UncheckedWait { get; init; } = TimeSpan.FromMinutes(2);
}

/// <summary>
/// Waits until every authoritative name server has the records, so failed validations do not use up the CA's rate
/// limit. Authoritative servers are asked directly: an early query to a public resolver could cache "no such record".
/// </summary>
internal sealed class DnsPropagationChecker(IDnsLookup lookup, DnsPropagationOptions? options = null)
{
    private readonly DnsPropagationOptions _options = options ?? new DnsPropagationOptions();

    public async Task WaitAsync(
        IReadOnlyList<DnsTxtRecord> records,
        IProgress<ProgressEvent>? progress,
        CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + _options.Timeout;
        while (true)
        {
            var round = await CheckOnceAsync(records, cancellationToken).ConfigureAwait(false);
            if (round.Unreachable)
            {
                progress?.Report(new ProgressEvent(
                    "dns-propagation",
                    "DNS servers could not be queried from this server, so propagation cannot be checked; outbound port 53 may be blocked. " +
                    $"Waiting {_options.UncheckedWait.TotalMinutes:0.#} minutes before continuing."));
                await Task.Delay(_options.UncheckedWait, cancellationToken).ConfigureAwait(false);
                return;
            }

            if (round.Missing.Count == 0)
            {
                progress?.Report(new ProgressEvent("dns-propagation", "The authoritative name servers have every record."));
                await Task.Delay(_options.SettleDelay, cancellationToken).ConfigureAwait(false);
                return;
            }

            if (DateTimeOffset.UtcNow >= deadline)
            {
                throw new TimeoutException(
                    $"The DNS records did not appear within {_options.Timeout.TotalMinutes:0.#} minutes: {string.Join("; ", round.Missing)}. " +
                    "The certificate authority was not asked to validate. Check the records and try again.");
            }

            progress?.Report(new ProgressEvent("dns-propagation", $"Waiting for DNS: {round.Missing[0]}."));
            await Task.Delay(_options.PollInterval, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<Round> CheckOnceAsync(IReadOnlyList<DnsTxtRecord> records, CancellationToken cancellationToken)
    {
        var missing = new List<string>();
        var answers = 0;
        var queries = 0;
        foreach (var record in records)
        {
            IReadOnlyList<string> servers;
            try
            {
                servers = await lookup.GetAuthoritativeServersAsync(record.Name, cancellationToken).ConfigureAwait(false);
            }
            catch (DnsLookupUnavailableException)
            {
                return new Round(true, []);
            }

            if (servers.Count == 0)
            {
                missing.Add($"no public name servers were found for '{record.Name}'");
                continue;
            }

            foreach (var server in servers)
            {
                queries++;
                var values = await lookup.QueryTxtAsync(server, record.Name, cancellationToken).ConfigureAwait(false);
                if (values is null)
                {
                    missing.Add($"name server {server} did not answer for '{record.Name}'");
                    continue;
                }

                answers++;
                if (!values.Contains(record.Value, StringComparer.Ordinal))
                {
                    missing.Add($"name server {server} does not have the expected value at '{record.Name}'");
                }
            }
        }

        return new Round(queries > 0 && answers == 0, missing);
    }

    private sealed record Round(bool Unreachable, IReadOnlyList<string> Missing);
}
