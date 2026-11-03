using Certes;
using Certes.Acme;

namespace SSLense.Core.Acme;

internal sealed class CertesAcmeProtocolClient : IAcmeProtocolClient
{
    private readonly IAcmeAccountStore _accountStore;

    public CertesAcmeProtocolClient(IAcmeAccountStore accountStore)
    {
        _accountStore = accountStore;
    }

    public async Task<IAcmeOrderSession> CreateOrderAsync(
        string email,
        IReadOnlyList<string> hosts,
        CertificateAuthority authority,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authority);
        try
        {
            return await CreateOrderCoreAsync(email, hosts, authority, cancellationToken).ConfigureAwait(false);
        }
        catch (AcmeRequestException exception) when (IsRateLimited(exception))
        {
            throw ToRateLimitedException(exception, authority);
        }
    }

    public async Task<IAcmeOrderSession> CreateDnsOrderAsync(
        string email,
        IReadOnlyList<string> names,
        CertificateAuthority authority,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authority);
        try
        {
            return await CreateDnsOrderCoreAsync(email, names, authority, cancellationToken).ConfigureAwait(false);
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
        CancellationToken cancellationToken)
    {
        var context = await OpenAccountAsync(email, authority, cancellationToken).ConfigureAwait(false);
        var order = await context.NewOrder(hosts.ToArray()).WaitAsync(cancellationToken).ConfigureAwait(false);
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

        return new CertesOrderSession(order, challenges, authority);
    }

    private async Task<IAcmeOrderSession> CreateDnsOrderCoreAsync(
        string email,
        IReadOnlyList<string> names,
        CertificateAuthority authority,
        CancellationToken cancellationToken)
    {
        var context = await OpenAccountAsync(email, authority, cancellationToken).ConfigureAwait(false);
        var order = await context.NewOrder(names.ToArray()).WaitAsync(cancellationToken).ConfigureAwait(false);
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

        return new CertesOrderSession(order, challenges, authority);
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
            context = new AcmeContext(authority.DirectoryUri);
            await context.NewAccount(email, true)
                .WaitAsync(cancellationToken)
                .ConfigureAwait(false);
            await _accountStore.SaveKeyAsync(authority.Id, context.AccountKey.ToPem(), cancellationToken)
                .ConfigureAwait(false);
        }
        else
        {
            context = new AcmeContext(authority.DirectoryUri, KeyFactory.FromPem(savedKey));
            await context.Account().WaitAsync(cancellationToken).ConfigureAwait(false);
        }

        return context;
    }

    private sealed record CertesChallenge(
        object Model,
        string Host,
        string Method,
        IAuthorizationContext Authorization,
        IChallengeContext Context);

    private sealed class CertesOrderSession : IAcmeOrderSession
    {
        private readonly IOrderContext _order;
        private readonly IReadOnlyList<CertesChallenge> _challenges;
        private readonly CertificateAuthority _authority;

        public CertesOrderSession(
            IOrderContext order,
            IReadOnlyList<CertesChallenge> challenges,
            CertificateAuthority authority)
        {
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
            var certificateKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
            var certificate = await _order.Generate(
                    new CsrInfo { CommonName = commonName },
                    certificateKey)
                .WaitAsync(cancellationToken)
                .ConfigureAwait(false);
            var certificatePem = certificate.ToPem();
            var pfx = certificate.ToPfx(certificateKey)
                .Build($"SSLense: {commonName}", pfxPassword);
            return new CertificateBundle(certificatePem, pfx);
        }
    }
}
