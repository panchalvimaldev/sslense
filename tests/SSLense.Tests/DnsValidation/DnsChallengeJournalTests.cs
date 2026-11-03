using SSLense.Core.DnsValidation;
using Xunit;

namespace SSLense.Tests.DnsValidation;

public sealed class DnsChallengeJournalTests
{
    private const string Directory = "C:\\data\\dns-challenges";
    private readonly InMemoryFileSystem _fileSystem = new();

    [Fact]
    public async Task EntryOfAnExitedProcess_IsAbandoned()
    {
        var entry = Entry();
        await Journal(alive: false).RecordAsync(entry, CancellationToken.None);

        Assert.Equal([entry], await Journal(alive: false).GetAbandonedAsync(CancellationToken.None));
    }

    [Fact]
    public async Task EntryOfARunningProcess_IsNotAbandoned()
    {
        await Journal(alive: true).RecordAsync(Entry(), CancellationToken.None);

        Assert.Empty(await Journal(alive: true).GetAbandonedAsync(CancellationToken.None));
    }

    [Fact]
    public async Task CompletedEntry_IsGone()
    {
        var entry = Entry();
        var journal = Journal(alive: false);
        await journal.RecordAsync(entry, CancellationToken.None);

        await journal.CompleteAsync(entry.Id);

        Assert.Empty(await journal.GetAbandonedAsync(CancellationToken.None));
    }

    [Fact]
    public async Task NewerSchema_IsRefused()
    {
        await Journal(alive: false).RecordAsync(Entry() with { SchemaVersion = 99 }, CancellationToken.None);

        await Assert.ThrowsAsync<InvalidDataException>(() => Journal(alive: false).GetAbandonedAsync(CancellationToken.None));
    }

    private JsonDnsChallengeJournal Journal(bool alive) => new(_fileSystem, Directory, (_, _) => alive);

    private static DnsChallengeEntry Entry() => new(
        Guid.NewGuid(),
        "Main",
        "_acme-challenge.example.com",
        "value",
        1234,
        new DateTimeOffset(2026, 11, 3, 9, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2026, 11, 3, 9, 0, 1, TimeSpan.Zero));
}
