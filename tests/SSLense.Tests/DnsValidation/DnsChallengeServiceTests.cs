using SSLense.Core;
using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.DnsValidation;
using Xunit;

namespace SSLense.Tests.DnsValidation;

public sealed class DnsChallengeServiceTests
{
    private static readonly AcmeDnsChallenge Base = new("example.com", false, "_acme-challenge.example.com", "base-value");
    private static readonly AcmeDnsChallenge Wildcard = new("example.com", true, "_acme-challenge.example.com", "wildcard-value");
    private readonly FakeDnsProvider _provider = new();
    private readonly FakeDnsLookup _lookup = new();
    private readonly FakeDnsChallengeJournal _journal = new();
    private readonly List<ProgressEvent> _events = [];

    public DnsChallengeServiceTests()
    {
        // Every server has whatever has been published so far.
        _lookup.Answer = (_, name) => _provider.Records.Where(record => record.Name == name).Select(record => record.Value).ToArray();
    }

    [Fact]
    public async Task Publish_ANameAndItsWildcard_PublishesBothValuesAtTheSameName()
    {
        await using var cleanup = await Service().PublishAsync(
            ValidationMethod.Dns01Provider, [Base, Wildcard], null, Progress(), CancellationToken.None);

        Assert.Equal(
            [("_acme-challenge.example.com", "base-value"), ("_acme-challenge.example.com", "wildcard-value")],
            _provider.Records);
    }

    [Fact]
    public async Task Cleanup_RemovesOnlyWhatWasPublished_AndClearsTheJournal()
    {
        _provider.Records.Add(("_acme-challenge.example.com", "someone-elses-value"));
        var cleanup = await Service().PublishAsync(
            ValidationMethod.Dns01Provider, [Base], null, Progress(), CancellationToken.None);

        await cleanup.DisposeAsync();

        Assert.Equal([("_acme-challenge.example.com", "someone-elses-value")], _provider.Records);
        Assert.Empty(_journal.Entries);
    }

    [Fact]
    public async Task Publish_RecordsTheJournalEntryBeforeAddingTheRecord()
    {
        var addsAtRecordTime = new List<int>();
        _journal.OnRecord = _ => addsAtRecordTime.Add(_provider.Calls.Count(call => call.StartsWith("add", StringComparison.Ordinal)));

        await using var cleanup = await Service().PublishAsync(
            ValidationMethod.Dns01Provider, [Base, Wildcard], null, Progress(), CancellationToken.None);

        Assert.Equal([0, 1], addsAtRecordTime);
        Assert.Equal(2, _journal.Entries.Count);
    }

    [Fact]
    public async Task Publish_FollowsACnameToTheDelegatedZone()
    {
        _lookup.Cnames["_acme-challenge.example.com"] = "example-com.acme.delegated.net";

        await using var cleanup = await Service(Profile("Delegated", "delegated.net")).PublishAsync(
            ValidationMethod.Dns01Provider, [Base], null, Progress(), CancellationToken.None);

        Assert.Equal([("example-com.acme.delegated.net", "base-value")], _provider.Records);
    }

    [Fact]
    public async Task Publish_APartialFailure_RemovesWhatWasPublished()
    {
        _provider.FailAddOn = new InvalidOperationException("provider failed");
        _provider.FailAddForName = "_acme-challenge.www.example.com";
        var www = new AcmeDnsChallenge("www.example.com", false, "_acme-challenge.www.example.com", "www-value");

        await Assert.ThrowsAsync<InvalidOperationException>(() => Service().PublishAsync(
            ValidationMethod.Dns01Provider, [Base, www], null, Progress(), CancellationToken.None));

        Assert.Empty(_provider.Records);
        Assert.Empty(_journal.Entries);
    }

    [Fact]
    public async Task Publish_PropagationTimeout_RemovesTheRecords()
    {
        _lookup.Answer = (_, _) => [];

        await Assert.ThrowsAsync<TimeoutException>(() => Service(timeout: TimeSpan.FromMilliseconds(10)).PublishAsync(
            ValidationMethod.Dns01Provider, [Base], null, Progress(), CancellationToken.None));

        Assert.Empty(_provider.Records);
        Assert.Empty(_journal.Entries);
    }

    [Fact]
    public async Task Publish_ARecordWithoutAProvider_PublishesNothing()
    {
        var other = new AcmeDnsChallenge("other.net", false, "_acme-challenge.other.net", "other-value");

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => Service().PublishAsync(
            ValidationMethod.Dns01Provider, [Base, other], null, Progress(), CancellationToken.None));

        Assert.Contains("_acme-challenge.other.net", exception.Message, StringComparison.Ordinal);
        Assert.Empty(_provider.Calls);
        Assert.Empty(_journal.Entries);
    }

    [Fact]
    public async Task Publish_NoChallenges_ChangesNothingAndSkipsPropagation()
    {
        await using var cleanup = await Service().PublishAsync(
            ValidationMethod.Dns01Provider, [], null, Progress(), CancellationToken.None);

        Assert.Empty(_provider.Calls);
        Assert.Equal(0, _lookup.Rounds);
    }

    [Fact]
    public async Task Cleanup_AFailedRemoval_WarnsAndKeepsTheJournalEntry()
    {
        var cleanup = await Service().PublishAsync(
            ValidationMethod.Dns01Provider, [Base], null, Progress(), CancellationToken.None);
        _provider.FailRemove = new InvalidOperationException("provider failed");

        await cleanup.DisposeAsync();

        Assert.Single(_journal.Entries);
        Assert.Contains(_events, value => value.Step == "dns-cleanup" && value.Message.Contains("try again", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Manual_ShowsTheRecordsAtTheCnameTarget_AndPublishesNothing()
    {
        _lookup.Cnames["_acme-challenge.example.com"] = "target.delegated.net";
        _lookup.Answer = (_, name) => name == "target.delegated.net" ? ["base-value"] : [];
        IReadOnlyList<DnsTxtRecord>? shown = null;

        var cleanup = await Service().PublishAsync(
            ValidationMethod.Dns01Manual,
            [Base],
            (records, _) =>
            {
                shown = records;
                return Task.FromResult(true);
            },
            Progress(),
            CancellationToken.None);
        await cleanup.DisposeAsync();

        Assert.Equal([new DnsTxtRecord("target.delegated.net", "base-value")], shown);
        Assert.Empty(_provider.Calls);
        Assert.Empty(_journal.Entries);
    }

    [Fact]
    public async Task Manual_NotConfirmed_Stops()
    {
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => Service().PublishAsync(
            ValidationMethod.Dns01Manual, [Base], (_, _) => Task.FromResult(false), Progress(), CancellationToken.None));

        Assert.Contains("not confirmed", exception.Message, StringComparison.Ordinal);
        Assert.Equal(0, _lookup.Rounds);
    }

    [Fact]
    public async Task CheckBeforeOrder_VerifiesEachProviderOnce()
    {
        await Service().CheckBeforeOrderAsync(
            ValidationMethod.Dns01Provider, ["example.com", "www.example.com"], CertificateAuthorities.LetsEncryptStagingId, CancellationToken.None);

        Assert.Equal(["verify Main"], _provider.Calls);
    }

    [Fact]
    public async Task CheckBeforeOrder_NoPublicNameServers_IsRefused()
    {
        _lookup.Servers = [];

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => Service().CheckBeforeOrderAsync(
            ValidationMethod.Dns01Manual, ["server.example.com"], CertificateAuthorities.LetsEncryptStagingId, CancellationToken.None));

        Assert.Contains("public name servers", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CheckBeforeOrder_CaaAtAParentBlocksTheCa_IsRefused()
    {
        _lookup.Caa["example.com"] = [new DnsCaaRecord(0, "issue", "other-ca.example")];

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => Service().CheckBeforeOrderAsync(
            ValidationMethod.Dns01Provider, ["shop.example.com"], CertificateAuthorities.LetsEncryptId, CancellationToken.None));

        Assert.Contains("'example.com'", exception.Message, StringComparison.Ordinal);
        Assert.Contains("letsencrypt.org", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CheckBeforeOrder_ClosestCaaDecides_AndParentsAreNotRead()
    {
        _lookup.Caa["shop.example.com"] = [new DnsCaaRecord(0, "issue", "letsencrypt.org")];
        _lookup.Caa["example.com"] = [new DnsCaaRecord(0, "issue", "other-ca.example")];

        await Service().CheckBeforeOrderAsync(
            ValidationMethod.Dns01Provider, ["shop.example.com"], CertificateAuthorities.LetsEncryptId, CancellationToken.None);

        Assert.Equal(["shop.example.com"], _lookup.CaaQueries);
    }

    [Fact]
    public async Task CheckBeforeOrder_Wildcard_ChecksItsBaseNameWithTheWildcardRules()
    {
        _lookup.Caa["example.com"] = [new DnsCaaRecord(0, "issue", "letsencrypt.org"), new DnsCaaRecord(0, "issuewild", ";")];

        await Service().CheckBeforeOrderAsync(
            ValidationMethod.Dns01Provider, ["example.com"], CertificateAuthorities.LetsEncryptId, CancellationToken.None);
        await Assert.ThrowsAsync<InvalidOperationException>(() => Service().CheckBeforeOrderAsync(
            ValidationMethod.Dns01Provider, ["*.example.com"], CertificateAuthorities.LetsEncryptId, CancellationToken.None));
    }

    [Fact]
    public async Task CheckBeforeOrder_DnsBlocked_SkipsTheEarlyChecks()
    {
        _lookup.Unavailable = true;
        _lookup.Caa["example.com"] = [new DnsCaaRecord(0, "issue", ";")];

        await Service().CheckBeforeOrderAsync(
            ValidationMethod.Dns01Provider, ["example.com"], CertificateAuthorities.LetsEncryptId, CancellationToken.None);

        Assert.Equal(["verify Main"], _provider.Calls);
    }

    [Fact]
    public async Task CheckBeforeOrder_CaaUnknownForThisCa_IsNotChecked()
    {
        var custom = new CertificateAuthority("custom-ca", "Custom", new Uri("https://ca.example.net/directory"), IsTest: false);

        await Service(authorities: Authorities(custom)).CheckBeforeOrderAsync(ValidationMethod.Dns01Provider, ["example.com"], "custom-ca", CancellationToken.None);

        Assert.Empty(_lookup.CaaQueries);
    }

    [Fact]
    public async Task CheckBeforeOrder_UsesTheCaaIdentitiesTheCaPublishes()
    {
        var zeroSsl = new CertificateAuthority("zerossl", "ZeroSSL", new Uri("https://acme.zerossl.com/v2/DV90"), IsTest: false, CaaIdentities: ["sectigo.com", "comodoca.com"]);
        _lookup.Caa["example.com"] = [new DnsCaaRecord(0, "issue", "comodoca.com")];

        await Service(authorities: Authorities(zeroSsl)).CheckBeforeOrderAsync(ValidationMethod.Dns01Provider, ["example.com"], "zerossl", CancellationToken.None);

        _lookup.Caa["example.com"] = [new DnsCaaRecord(0, "issue", "letsencrypt.org")];
        var message = (await Assert.ThrowsAsync<InvalidOperationException>(() => Service(authorities: Authorities(zeroSsl))
            .CheckBeforeOrderAsync(ValidationMethod.Dns01Provider, ["example.com"], "zerossl", CancellationToken.None))).Message;
        Assert.Contains("'sectigo.com'", message, StringComparison.Ordinal);
    }

    private static ICertificateAuthorityRegistry Authorities(params CertificateAuthority[] configured) =>
        new CertificateAuthorityRegistry(new FakeConfigStore(new AppConfig { CertificateAuthorities = configured }));

    [Fact]
    public async Task Publish_WildcardAndBaseName_PublishesBothValuesAtOneName()
    {
        await using var cleanup = await Service().PublishAsync(
            ValidationMethod.Dns01Provider,
            [Base, new AcmeDnsChallenge("example.com", true, "_acme-challenge.example.com", "wild-value")],
            null,
            Progress(),
            CancellationToken.None);

        Assert.Equal(2, _provider.Records.Count(record => record.Name == "_acme-challenge.example.com"));
    }

    [Fact]
    public async Task CheckBeforeOrder_NoProvider_ExplainsTheOptions()
    {
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => Service().CheckBeforeOrderAsync(
            ValidationMethod.Dns01Provider, ["other.net"], CertificateAuthorities.LetsEncryptStagingId, CancellationToken.None));

        Assert.Contains("dns add", exception.Message, StringComparison.Ordinal);
        Assert.Contains("CNAME", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CheckBeforeOrder_Manual_NeedsNoProvider()
    {
        await Service().CheckBeforeOrderAsync(ValidationMethod.Dns01Manual, ["other.net"], CertificateAuthorities.LetsEncryptStagingId, CancellationToken.None);

        Assert.Empty(_provider.Calls);
    }

    [Fact]
    public async Task CleanUpAbandoned_RemovesTheExactValue_AndCompletes()
    {
        _provider.Records.Add(("_acme-challenge.example.com", "left-behind"));
        _provider.Records.Add(("_acme-challenge.example.com", "someone-elses-value"));
        _journal.Abandoned.Add(Entry("Main", "left-behind", DateTimeOffset.UtcNow));

        var messages = await Service().CleanUpAbandonedAsync(CancellationToken.None);

        Assert.Single(messages);
        Assert.Equal([("_acme-challenge.example.com", "someone-elses-value")], _provider.Records);
        Assert.Empty(_journal.Abandoned);
    }

    [Fact]
    public async Task CleanUpAbandoned_ProviderRemoved_TellsTheAdministratorAndCompletes()
    {
        _journal.Abandoned.Add(Entry("Gone", "left-behind", DateTimeOffset.UtcNow));

        var messages = await Service().CleanUpAbandonedAsync(CancellationToken.None);

        Assert.Contains("Delete it in your DNS service", Assert.Single(messages), StringComparison.Ordinal);
        Assert.Empty(_journal.Abandoned);
        Assert.Empty(_provider.Calls);
    }

    [Fact]
    public async Task CleanUpAbandoned_RemovalFailing_KeepsARecentEntryForTheNextStart()
    {
        _provider.FailRemove = new InvalidOperationException("provider failed");
        _journal.Abandoned.Add(Entry("Main", "left-behind", DateTimeOffset.UtcNow));

        await Assert.ThrowsAsync<InvalidOperationException>(() => Service().CleanUpAbandonedAsync(CancellationToken.None));

        Assert.Single(_journal.Abandoned);
    }

    [Fact]
    public async Task CleanUpAbandoned_RemovalFailingForAWeek_StopsTrying()
    {
        _provider.FailRemove = new InvalidOperationException("provider failed");
        _journal.Abandoned.Add(Entry("Main", "left-behind", DateTimeOffset.UtcNow.AddDays(-8)));

        var messages = await Service().CleanUpAbandonedAsync(CancellationToken.None);

        Assert.Contains("stop trying", Assert.Single(messages), StringComparison.Ordinal);
        Assert.Empty(_journal.Abandoned);
    }

    private DnsChallengeService Service(DnsProviderProfile? profile = null, TimeSpan? timeout = null, ICertificateAuthorityRegistry? authorities = null) => new(
        new FakeConfigStore(new AppConfig { DnsProviders = [profile ?? Profile("Main", "example.com")] }),
        [_provider],
        _lookup,
        _journal,
        new DnsPropagationChecker(_lookup, new DnsPropagationOptions
        {
            Timeout = timeout ?? TimeSpan.FromSeconds(30),
            PollInterval = TimeSpan.FromMilliseconds(1),
            SettleDelay = TimeSpan.Zero,
            UncheckedWait = TimeSpan.Zero
        }),
        authorities);

    private static DnsProviderProfile Profile(string name, string zone) =>
        new(name, DnsProviderType.Cloudflare, zone, new string('a', 32), "protected");

    private static DnsChallengeEntry Entry(string provider, string value, DateTimeOffset createdAt) =>
        new(Guid.NewGuid(), provider, "_acme-challenge.example.com", value, 1, createdAt, createdAt);

    private ListProgress Progress() => new(_events);

    private sealed class ListProgress(List<ProgressEvent> events) : IProgress<ProgressEvent>
    {
        public void Report(ProgressEvent value) => events.Add(value);
    }
}
