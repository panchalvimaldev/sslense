namespace SSLense.Core.DnsValidation;

/// <summary>
/// A DNS service SSLense can publish validation records with. Providers are compiled in: the service runs as
/// SYSTEM with access to certificates and tokens, so it never loads third-party plugins.
/// </summary>
internal interface IDnsProvider
{
    DnsProviderType Type { get; }

    /// <summary>Confirms the token can read the zone. Changes nothing.</summary>
    Task VerifyAccessAsync(DnsProviderProfile profile, CancellationToken cancellationToken);

    Task AddTxtRecordAsync(DnsProviderProfile profile, string name, string value, CancellationToken cancellationToken);

    /// <summary>Removes only the record with this exact value; other values at the name are kept.</summary>
    Task RemoveTxtRecordAsync(DnsProviderProfile profile, string name, string value, CancellationToken cancellationToken);
}
