using SSLense.Core;
using SSLense.Core.DnsValidation;
using Xunit;

namespace SSLense.Tests.DnsValidation;

public sealed class DnsPropagationCheckerTests
{
    private static readonly DnsTxtRecord Record = new("_acme-challenge.example.com", "value");
    private readonly FakeDnsLookup _lookup = new();
    private readonly List<ProgressEvent> _events = [];

    [Fact]
    public async Task EveryServerHavingTheValue_Passes()
    {
        _lookup.Answer = (_, _) => ["other", "value"];

        await Checker().WaitAsync([Record], Progress(), CancellationToken.None);

        Assert.Equal(1, _lookup.Rounds);
    }

    [Fact]
    public async Task OneServerBehind_KeepsWaitingUntilItCatchesUp()
    {
        var round = 0;
        _lookup.Answer = (server, _) => server == "192.0.2.2" && ++round < 3 ? [] : ["value"];

        await Checker().WaitAsync([Record], Progress(), CancellationToken.None);

        Assert.Equal(3, _lookup.Rounds);
    }

    [Fact]
    public async Task ValuesAreCaseSensitive()
    {
        _lookup.Answer = (_, _) => ["VALUE"];

        await Assert.ThrowsAsync<TimeoutException>(() =>
            Checker(timeout: TimeSpan.FromMilliseconds(20)).WaitAsync([Record], Progress(), CancellationToken.None));
    }

    [Fact]
    public async Task Timeout_NamesWhatIsMissing_AndSaysTheCaWasNotAsked()
    {
        _lookup.Answer = (server, _) => server == "192.0.2.1" ? ["value"] : [];

        var exception = await Assert.ThrowsAsync<TimeoutException>(() =>
            Checker(timeout: TimeSpan.FromMilliseconds(20)).WaitAsync([Record], Progress(), CancellationToken.None));

        Assert.Contains("192.0.2.2", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("192.0.2.1", exception.Message, StringComparison.Ordinal);
        Assert.Contains("not asked to validate", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OneServerNotAnswering_IsNotTreatedAsBlockedDns()
    {
        _lookup.Answer = (server, _) => server == "192.0.2.1" ? ["value"] : null;

        var exception = await Assert.ThrowsAsync<TimeoutException>(() =>
            Checker(timeout: TimeSpan.FromMilliseconds(20)).WaitAsync([Record], Progress(), CancellationToken.None));

        Assert.Contains("did not answer", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PublicDnsBlocked_WaitsAFixedTimeAndContinues()
    {
        _lookup.Unavailable = true;

        await Checker().WaitAsync([Record], Progress(), CancellationToken.None);

        Assert.Contains(_events, value => value.Message.Contains("port 53", StringComparison.Ordinal));
    }

    [Fact]
    public async Task NoServerAnswering_WaitsAFixedTimeAndContinues()
    {
        _lookup.Answer = (_, _) => null;

        await Checker().WaitAsync([Record], Progress(), CancellationToken.None);

        Assert.Equal(1, _lookup.Rounds);
        Assert.Contains(_events, value => value.Message.Contains("port 53", StringComparison.Ordinal));
    }

    [Fact]
    public async Task NameWithoutPublicServers_FailsWithAnExplanation()
    {
        _lookup.Servers = [];

        var exception = await Assert.ThrowsAsync<TimeoutException>(() =>
            Checker(timeout: TimeSpan.FromMilliseconds(20)).WaitAsync([Record], Progress(), CancellationToken.None));

        Assert.Contains("no public name servers", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Confirm_SaysWhetherTheRecordWasReallySeen_AndDoesNotWaitWhenDnsIsBlocked()
    {
        _lookup.Answer = (_, _) => ["value"];
        Assert.True(await Checker().ConfirmAsync([Record], CancellationToken.None));

        _lookup.Unavailable = true;
        var blocked = new DnsPropagationChecker(_lookup, new DnsPropagationOptions { UncheckedWait = TimeSpan.FromMinutes(10) });
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        Assert.False(await blocked.ConfirmAsync([Record], CancellationToken.None));
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(5), $"Took {stopwatch.Elapsed}.");
    }

    private DnsPropagationChecker Checker(TimeSpan? timeout = null) => new(_lookup, new DnsPropagationOptions
    {
        Timeout = timeout ?? TimeSpan.FromSeconds(30),
        PollInterval = TimeSpan.FromMilliseconds(1),
        SettleDelay = TimeSpan.Zero,
        UncheckedWait = TimeSpan.Zero
    });

    private ImmediateProgress Progress() => new(_events);

    private sealed class ImmediateProgress(List<ProgressEvent> events) : IProgress<ProgressEvent>
    {
        public void Report(ProgressEvent value) => events.Add(value);
    }
}
