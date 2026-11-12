using Certes;
using Certes.Acme;

namespace SSLense.Core.Acme;

internal sealed class CertesAcmeProtocolClient : IAcmeProtocolClient
{
    private readonly IAcmeAccountStore _accountStore;
    private readonly ISecretProtector _protector;
    private readonly HttpClient? _httpClient;

    public CertesAcmeProtocolClient(IAcmeAccountStore accountStore, ISecretProtector protector)
        : this(accountStore, protector, null)
    {
    }

    /// <param name="httpClient">Only for tests against a local CA such as Pebble, whose certificate only they trust.</param>
    internal CertesAcmeProtocolClient(IAcmeAccountStore accountStore, ISecretProtector protector, HttpClient? httpClient)
    {
        _accountStore = accountStore;
        _protector = protector;
        _httpClient = httpClient;
    }

    private IAcmeHttpClient? Http(Uri directoryUri) => _httpClient is null ? null : new AcmeHttpClient(directoryUri, _httpClient);

    public Task<IAcmeOrderSession> CreateOrderAsync(
        string email,
        IReadOnlyList<string> hosts,
        CertificateAuthority authority,
        CancellationToken cancellationToken) =>
        CreateOrderAsync(email, hosts, authority, AcmeOrderOptions.Default, cancellationToken);

    public async Task<IAcmeOrderSession> CreateOrderAsync(
        string email,
        IReadOnlyList<string> hosts,
        CertificateAuthority authority,
        AcmeOrderOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(authority);
        try
        {
            return await CreateOrderCoreAsync(email, hosts, authority, options, cancellationToken).ConfigureAwait(false);
        }
        catch (AcmeRequestException exception) when (IsRateLimited(exception))
        {
            throw ToRateLimitedException(exception, authority);
        }
    }

    public Task<IAcmeOrderSession> CreateDnsOrderAsync(
        string email,
        IReadOnlyList<string> names,
        CertificateAuthority authority,
        CancellationToken cancellationToken) =>
        CreateDnsOrderAsync(email, names, authority, AcmeOrderOptions.Default, cancellationToken);

    public async Task<IAcmeOrderSession> CreateDnsOrderAsync(
        string email,
        IReadOnlyList<string> names,
        CertificateAuthority authority,
        AcmeOrderOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(authority);
        try
        {
            return await CreateDnsOrderCoreAsync(email, names, authority, options, cancellationToken).ConfigureAwait(false);
        }
        catch (AcmeRequestException exception) when (IsRateLimited(exception))
        {
            throw ToRateLimitedException(exception, authority);
        }
    }

    internal static bool IsRateLimited(AcmeRequestException exception) =>
        string.Equals(exception.Error?.Type, AcmeRateLimitedException.ProblemType, StringComparison.OrdinalIgnoreCase);

    internal static AcmeRateLimitedException ToRateLimitedException(
        AcmeRequestException exception,
        CertificateAuthority authority) =>
        new(
            $"The {authority.Name} rate limit was reached: " +
            $"{exception.Error?.Detail ?? exception.Message} " +
            "SSLense will not retry until the next scheduled check. " +
            (authority.Id is CertificateAuthorities.LetsEncryptId or CertificateAuthorities.LetsEncryptStagingId
                ? "See https://letsencrypt.org/docs/rate-limits/ for limits and reset times."
                : "See the certificate authority's documentation for its limits."),
            exception);

    private async Task<IAcmeOrderSession> CreateOrderCoreAsync(
        string email,
        IReadOnlyList<string> hosts,
        CertificateAuthority authority,
        AcmeOrderOptions options,
        CancellationToken cancellationToken)
    {
        var context = await OpenAccountAsync(email, authority, cancellationToken).ConfigureAwait(false);
        var order = await (options.Profile is { } profile
                ? context.NewOrderWithProfile(hosts.ToList(), profile)
                : context.NewOrder(hosts.ToArray()))
            .WaitAsync(cancellationToken)
            .ConfigureAwait(false);
        var authorizations = await order.Authorizations().WaitAsync(cancellationToken).ConfigureAwait(false);
        var challenges = new List<CertesChallenge>(authorizations.Count());
        foreach (var authorization in authorizations)
        {
            var authorizationResource = await authorization.Resource()
                .WaitAsync(cancellationToken)
                .ConfigureAwait(false);
            var challenge = await authorization.Http().WaitAsync(cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidOperationException(
                    $"The ACME server did not offer HTTP-01 for '{authorizationResource.Identifier.Value}'.");
            challenges.Add(new CertesChallenge(
                new AcmeHttpChallenge(
                    authorizationResource.Identifier.Value,
                    challenge.Token,
                    challenge.KeyAuthz),
                authorizationResource.Identifier.Value,
                "HTTP-01",
                authorization,
                challenge));
        }

        return new CertesOrderSession(order, challenges, authority, options);
    }

    private async Task<IAcmeOrderSession> CreateDnsOrderCoreAsync(
        string email,
        IReadOnlyList<string> names,
        CertificateAuthority authority,
        AcmeOrderOptions options,
        CancellationToken cancellationToken)
    {
        var context = await OpenAccountAsync(email, authority, cancellationToken).ConfigureAwait(false);
        var order = await (options.Profile is { } profile
                ? context.NewOrderWithProfile(names.ToList(), profile)
                : context.NewOrder(names.ToArray()))
            .WaitAsync(cancellationToken)
            .ConfigureAwait(false);
        var authorizations = await order.Authorizations().WaitAsync(cancellationToken).ConfigureAwait(false);
        var challenges = new List<CertesChallenge>(authorizations.Count());
        foreach (var authorization in authorizations)
        {
            var authorizationResource = await authorization.Resource()
                .WaitAsync(cancellationToken)
                .ConfigureAwait(false);

            // A reused authorization needs no record, so it changes nothing in DNS.
            if (string.Equals(authorizationResource.Status.ToString(), "Valid", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var host = authorizationResource.Identifier.Value;
            var challenge = await authorization.Dns().WaitAsync(cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidOperationException($"The ACME server did not offer DNS-01 for '{host}'.");
            challenges.Add(new CertesChallenge(
                new AcmeDnsChallenge(
                    host,
                    authorizationResource.Wildcard == true,
                    DnsValidation.DnsNames.ChallengeRecord(host),
                    context.AccountKey.DnsTxt(challenge.Token)),
                host,
                "DNS-01",
                authorization,
                challenge));
        }

        return new CertesOrderSession(order, challenges, authority, options);
    }

    private async Task<AcmeContext> OpenAccountAsync(
        string email,
        CertificateAuthority authority,
        CancellationToken cancellationToken)
    {
        var savedKey = await _accountStore.LoadKeyAsync(authority.Id, cancellationToken).ConfigureAwait(false);
        AcmeContext context;
        if (savedKey is null)
        {
            context = new AcmeContext(authority.DirectoryUri, null, Http(authority.DirectoryUri));
            if (authority.HasExternalAccountBinding)
            {
                // The HMAC key is decrypted only for this request, and binds the new account to the CA account.
                await context.NewAccount([$"mailto:{email}"], true, authority.EabKeyId, UnprotectHmacKey(authority), "HS256")
                    .WaitAsync(cancellationToken)
                    .ConfigureAwait(false);
            }
            else
            {
                await context.NewAccount(email, true)
                    .WaitAsync(cancellationToken)
                    .ConfigureAwait(false);
            }

            await _accountStore.SaveKeyAsync(authority.Id, context.AccountKey.ToPem(), cancellationToken)
                .ConfigureAwait(false);
        }
        else
        {
            context = new AcmeContext(authority.DirectoryUri, KeyFactory.FromPem(savedKey), Http(authority.DirectoryUri));
            await context.Account().WaitAsync(cancellationToken).ConfigureAwait(false);
        }

        return context;
    }

    private string UnprotectHmacKey(CertificateAuthority authority)
    {
        byte[] plaintext;
        try
        {
            plaintext = _protector.Unprotect(Convert.FromBase64String(authority.ProtectedEabHmacKey!));
        }
        catch (Exception exception) when (exception is FormatException or System.Security.Cryptography.CryptographicException or System.ComponentModel.Win32Exception)
        {
            throw new InvalidOperationException(
                $"The EAB key for {authority.Name} cannot be decrypted on this server. Remove the CA and add it again with its EAB credentials.",
                exception);
        }

        try
        {
            return System.Text.Encoding.UTF8.GetString(plaintext);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private sealed record CertesChallenge(
        object Model,
        string Host,
        string Method,
        IAuthorizationContext Authorization,
        IChallengeContext Context);

    internal static IKey NewCertificateKey(CertificateKeyType type) => type switch
    {
        CertificateKeyType.EcdsaP256 => KeyFactory.NewKey(KeyAlgorithm.ES256),
        CertificateKeyType.EcdsaP384 => KeyFactory.NewKey(KeyAlgorithm.ES384),
        CertificateKeyType.Rsa2048 => KeyFactory.NewKey(KeyAlgorithm.RS256, 2048),
        CertificateKeyType.Rsa3072 => KeyFactory.NewKey(KeyAlgorithm.RS256, 3072),
        CertificateKeyType.Rsa4096 => KeyFactory.NewKey(KeyAlgorithm.RS256, 4096),
        _ => throw new ArgumentOutOfRangeException(nameof(type), type, "Unknown key type.")
    };

    private sealed class CertesOrderSession : IAcmeOrderSession
    {
        private readonly IOrderContext _order;
        private readonly IReadOnlyList<CertesChallenge> _challenges;
        private readonly CertificateAuthority _authority;
        private readonly AcmeOrderOptions _options;

        public CertesOrderSession(
            IOrderContext order,
            IReadOnlyList<CertesChallenge> challenges,
            CertificateAuthority authority,
            AcmeOrderOptions options)
        {
            _options = options;
            _order = order;
            _challenges = challenges;
            _authority = authority;
            Challenges = challenges.Select(item => item.Model).OfType<AcmeHttpChallenge>().ToArray();
            DnsChallenges = challenges.Select(item => item.Model).OfType<AcmeDnsChallenge>().ToArray();
        }

        public IReadOnlyList<AcmeHttpChallenge> Challenges { get; }

        public IReadOnlyList<AcmeDnsChallenge> DnsChallenges { get; }

        public Task ValidateAsync(AcmeHttpChallenge challenge, CancellationToken cancellationToken) =>
            ValidateModelAsync(challenge, cancellationToken);

        public Task ValidateAsync(AcmeDnsChallenge challenge, CancellationToken cancellationToken) =>
            ValidateModelAsync(challenge, cancellationToken);

        private async Task ValidateModelAsync(object challenge, CancellationToken cancellationToken)
        {
            try
            {
                await ValidateCoreAsync(challenge, cancellationToken).ConfigureAwait(false);
            }
            catch (AcmeRequestException exception) when (IsRateLimited(exception))
            {
                throw ToRateLimitedException(exception, _authority);
            }
        }

        private async Task ValidateCoreAsync(object challenge, CancellationToken cancellationToken)
        {
            var item = _challenges.Single(candidate => candidate.Model.Equals(challenge));
            await item.Context.Validate().WaitAsync(cancellationToken).ConfigureAwait(false);

            var deadline = DateTimeOffset.UtcNow.AddMinutes(2);
            while (DateTimeOffset.UtcNow < deadline)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var authorization = await item.Authorization.Resource()
                    .WaitAsync(cancellationToken)
                    .ConfigureAwait(false);
                var status = authorization.Status.ToString();
                if (string.Equals(status, "Valid", StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                if (string.Equals(status, "Invalid", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(status, "Deactivated", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(status, "Expired", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(status, "Revoked", StringComparison.OrdinalIgnoreCase))
                {
                    var challengeResource = await item.Context.Resource()
                        .WaitAsync(cancellationToken)
                        .ConfigureAwait(false);
                    var detail = challengeResource.Error?.Detail ?? "The ACME server rejected the authorization.";
                    throw new InvalidOperationException(
                        $"{item.Method} validation failed for '{item.Host}': {detail}");
                }

                await Task.Delay(TimeSpan.FromSeconds(3), cancellationToken).ConfigureAwait(false);
            }

            throw new TimeoutException(
                $"Timed out waiting for {item.Method} validation of '{item.Host}'. " +
                (item.Model is AcmeDnsChallenge
                    ? "Confirm the TXT record is visible in public DNS, then try again."
                    : "Confirm public DNS and inbound port 80 access, then try again."));
        }

        public async Task<CertificateBundle> FinalizeAsync(
            string commonName,
            string pfxPassword,
            CancellationToken cancellationToken)
        {
            try
            {
                return await FinalizeCoreAsync(commonName, pfxPassword, cancellationToken).ConfigureAwait(false);
            }
            catch (AcmeRequestException exception) when (IsRateLimited(exception))
            {
                throw ToRateLimitedException(exception, _authority);
            }
        }

        private async Task<CertificateBundle> FinalizeCoreAsync(
            string commonName,
            string pfxPassword,
            CancellationToken cancellationToken)
        {
            var certificateKey = NewCertificateKey(_options.KeyType);
            var certificate = await _order.Generate(
                    new CsrInfo { CommonName = commonName },
                    certificateKey,
                    _options.PreferredChain)
                .WaitAsync(cancellationToken)
                .ConfigureAwait(false);
            var certificatePem = certificate.ToPem();
            var pfx = certificate.ToPfx(certificateKey)
                .Build($"SSLense: {commonName}", pfxPassword);
            return new CertificateBundle(certificatePem, pfx);
        }
    }
}
