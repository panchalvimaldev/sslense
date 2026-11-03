using System.Net;
using System.Net.Sockets;
using DnsClient;
using DnsClient.Protocol;

namespace SSLense.Core.DnsValidation;

/// <summary>DNS could not be reached at all, as when a firewall blocks outbound port 53.</summary>
internal sealed class DnsLookupUnavailableException(string message, Exception innerException)
    : Exception(message, innerException);

internal interface IDnsLookup
{
    /// <summary>Follows any CNAME from <paramref name="name"/> and returns the final name.</summary>
    Task<string> ResolveCnameAsync(string name, CancellationToken cancellationToken);

    /// <summary>Addresses of the name servers authoritative for <paramref name="name"/>'s zone; none when it has no public zone.</summary>
    /// <exception cref="DnsLookupUnavailableException">Public DNS could not be reached.</exception>
    Task<IReadOnlyList<string>> GetAuthoritativeServersAsync(string name, CancellationToken cancellationToken);

    /// <summary>The TXT values one server returns for <paramref name="name"/>, or null when it does not answer.</summary>
    Task<IReadOnlyList<string>?> QueryTxtAsync(string serverAddress, string name, CancellationToken cancellationToken);

    /// <summary>The CAA records at exactly <paramref name="name"/>; empty when it has none.</summary>
    /// <exception cref="DnsLookupUnavailableException">Public DNS could not be reached or could not answer.</exception>
    Task<IReadOnlyList<DnsCaaRecord>> QueryCaaAsync(string name, CancellationToken cancellationToken);
}

internal sealed class DnsClientLookup : IDnsLookup
{
    private const int MaxCnameDepth = 8;
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(5);

    // Public resolvers rather than this server's DNS, which on internal networks often differs from what a CA sees.
    private readonly LookupClient _publicResolvers = new(Configure(new LookupClientOptions(NameServer.Cloudflare, NameServer.GooglePublicDns)));

    // Only when the public resolvers are blocked: internal DNS is better than no answer for following a CNAME.
    private readonly Lazy<LookupClient> _systemResolver = new(() => new LookupClient(Configure(new LookupClientOptions())));

    public async Task<string> ResolveCnameAsync(string name, CancellationToken cancellationToken)
    {
        var current = DnsNames.Normalize(name);
        for (var depth = 0; depth < MaxCnameDepth; depth++)
        {
            IDnsQueryResponse response;
            try
            {
                response = await QueryAsync(_publicResolvers, current, QueryType.CNAME, cancellationToken).ConfigureAwait(false);
            }
            catch (DnsLookupUnavailableException)
            {
                try
                {
                    response = await QueryAsync(_systemResolver.Value, current, QueryType.CNAME, cancellationToken).ConfigureAwait(false);
                }
                catch (DnsLookupUnavailableException)
                {
                    return current;
                }
            }

            var target = response.Answers.CnameRecords().FirstOrDefault()?.CanonicalName.Value;
            if (target is null)
            {
                return current;
            }

            current = DnsNames.Normalize(target);
        }

        throw new InvalidOperationException($"'{name}' has too many CNAME steps, or a CNAME loop.");
    }

    public async Task<IReadOnlyList<string>> GetAuthoritativeServersAsync(string name, CancellationToken cancellationToken)
    {
        var current = DnsNames.Normalize(name);
        while (current.Contains('.'))
        {
            var response = await QueryAsync(_publicResolvers, current, QueryType.NS, cancellationToken).ConfigureAwait(false);
            var servers = response.Answers.NsRecords().Select(record => record.NSDName.Value).ToArray();
            if (servers.Length > 0)
            {
                var addresses = new List<string>(servers.Length);
                foreach (var server in servers)
                {
                    if (await GetAddressAsync(server, cancellationToken).ConfigureAwait(false) is { } address)
                    {
                        addresses.Add(address);
                    }
                }

                return addresses.Distinct().ToArray();
            }

            current = current[(current.IndexOf('.') + 1)..];
        }

        return [];
    }

    public async Task<IReadOnlyList<string>?> QueryTxtAsync(string serverAddress, string name, CancellationToken cancellationToken)
    {
        try
        {
            var response = await _publicResolvers.QueryServerAsync(
                    [new NameServer(IPAddress.Parse(serverAddress))],
                    DnsNames.Normalize(name),
                    QueryType.TXT,
                    QueryClass.IN,
                    cancellationToken)
                .ConfigureAwait(false);
            return response.Answers.TxtRecords().Select(record => string.Concat(record.Text)).ToArray();
        }
        catch (Exception exception) when (IsConnectionFailure(exception, cancellationToken))
        {
            return null;
        }
    }

    public async Task<IReadOnlyList<DnsCaaRecord>> QueryCaaAsync(string name, CancellationToken cancellationToken)
    {
        var response = await QueryAsync(_publicResolvers, DnsNames.Normalize(name), QueryType.CAA, cancellationToken).ConfigureAwait(false);
        if (response.HasError && response.Header.ResponseCode != DnsHeaderResponseCode.NotExistentDomain)
        {
            throw new DnsLookupUnavailableException(
                $"DNS could not answer for '{name}': {response.ErrorMessage}",
                new InvalidOperationException(response.ErrorMessage));
        }

        return response.Answers.CaaRecords().Select(record => new DnsCaaRecord(record.Flags, record.Tag, record.Value)).ToArray();
    }

    private async Task<string?> GetAddressAsync(string server, CancellationToken cancellationToken)
    {
        var v4 = await QueryAsync(_publicResolvers, server, QueryType.A, cancellationToken).ConfigureAwait(false);
        if (v4.Answers.ARecords().FirstOrDefault() is { } address)
        {
            return address.Address.ToString();
        }

        var v6 = await QueryAsync(_publicResolvers, server, QueryType.AAAA, cancellationToken).ConfigureAwait(false);
        return v6.Answers.AaaaRecords().FirstOrDefault()?.Address.ToString();
    }

    private static async Task<IDnsQueryResponse> QueryAsync(
        LookupClient client,
        string name,
        QueryType type,
        CancellationToken cancellationToken)
    {
        try
        {
            return await client.QueryAsync(name, type, QueryClass.IN, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (IsConnectionFailure(exception, cancellationToken))
        {
            throw new DnsLookupUnavailableException($"DNS could not be reached: {exception.Message}", exception);
        }
    }

    private static bool IsConnectionFailure(Exception exception, CancellationToken cancellationToken) =>
        exception is DnsResponseException or SocketException or TimeoutException ||
        (exception is OperationCanceledException && !cancellationToken.IsCancellationRequested);

    private static LookupClientOptions Configure(LookupClientOptions options)
    {
        options.UseCache = false;
        options.Timeout = QueryTimeout;
        options.Retries = 1;
        options.ThrowDnsErrors = false;
        return options;
    }
}
