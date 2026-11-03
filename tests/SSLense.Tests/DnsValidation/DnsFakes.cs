using SSLense.Core.Config;
using SSLense.Core.DnsValidation;

namespace SSLense.Tests.DnsValidation;

internal sealed class FakeDnsProvider : IDnsProvider
{
    public List<(string Name, string Value)> Records { get; } = [];

    public List<string> Calls { get; } = [];

    public Exception? FailAddOn { get; set; }

    public string? FailAddForName { get; set; }

    public Exception? FailRemove { get; set; }

    public Exception? FailVerify { get; set; }

    public DnsProviderType Type => DnsProviderType.Cloudflare;

    public Task VerifyAccessAsync(DnsProviderProfile profile, CancellationToken cancellationToken)
    {
        Calls.Add($"verify {profile.Name}");
        return FailVerify is null ? Task.CompletedTask : Task.FromException(FailVerify);
    }

    public Task AddTxtRecordAsync(DnsProviderProfile profile, string name, string value, CancellationToken cancellationToken)
    {
        Calls.Add($"add {name} {value}");
        if (FailAddOn is not null && (FailAddForName is null || FailAddForName == name))
        {
            return Task.FromException(FailAddOn);
        }

        Records.Add((name, value));
        return Task.CompletedTask;
    }

    public Task RemoveTxtRecordAsync(DnsProviderProfile profile, string name, string value, CancellationToken cancellationToken)
    {
        Calls.Add($"remove {name} {value}");
        if (FailRemove is not null)
        {
            return Task.FromException(FailRemove);
        }

        Records.Remove((name, value));
        return Task.CompletedTask;
    }
}

internal sealed class FakeDnsLookup : IDnsLookup
{
    public Dictionary<string, string> Cnames { get; } = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<string> Servers { get; set; } = ["192.0.2.1", "192.0.2.2"];

    public bool Unavailable { get; set; }

    /// <summary>Answers for each server and name; null means the server does not answer.</summary>
    public Func<string, string, IReadOnlyList<string>?> Answer { get; set; } = (_, _) => [];

    public int Rounds { get; private set; }

    public Task<string> ResolveCnameAsync(string name, CancellationToken cancellationToken) =>
        Task.FromResult(Cnames.TryGetValue(name, out var target) ? target : name);

    public Task<IReadOnlyList<string>> GetAuthoritativeServersAsync(string name, CancellationToken cancellationToken)
    {
        Rounds++;
        return Unavailable
            ? Task.FromException<IReadOnlyList<string>>(new DnsLookupUnavailableException("blocked", new TimeoutException()))
            : Task.FromResult(Servers);
    }

    public Task<IReadOnlyList<string>?> QueryTxtAsync(string serverAddress, string name, CancellationToken cancellationToken) =>
        Task.FromResult(Answer(serverAddress, name));

    /// <summary>CAA records by the exact name that holds them.</summary>
    public Dictionary<string, IReadOnlyList<DnsCaaRecord>> Caa { get; } = new(StringComparer.OrdinalIgnoreCase);

    public List<string> CaaQueries { get; } = [];

    public Task<IReadOnlyList<DnsCaaRecord>> QueryCaaAsync(string name, CancellationToken cancellationToken)
    {
        CaaQueries.Add(name);
        return Unavailable
            ? Task.FromException<IReadOnlyList<DnsCaaRecord>>(new DnsLookupUnavailableException("blocked", new TimeoutException()))
            : Task.FromResult(Caa.TryGetValue(name, out var records) ? records : (IReadOnlyList<DnsCaaRecord>)[]);
    }
}

internal sealed class FakeDnsChallengeJournal : IDnsChallengeJournal
{
    public List<DnsChallengeEntry> Entries { get; } = [];

    public List<DnsChallengeEntry> Abandoned { get; } = [];

    public Action<DnsChallengeEntry>? OnRecord { get; set; }

    public Task RecordAsync(DnsChallengeEntry entry, CancellationToken cancellationToken)
    {
        OnRecord?.Invoke(entry);
        Entries.Add(entry);
        return Task.CompletedTask;
    }

    public Task CompleteAsync(Guid id)
    {
        Entries.RemoveAll(entry => entry.Id == id);
        Abandoned.RemoveAll(entry => entry.Id == id);
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<DnsChallengeEntry>> GetAbandonedAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<DnsChallengeEntry>>(Abandoned.ToArray());
}

internal sealed class FakeConfigStore(AppConfig? config = null) : IConfigStore
{
    public AppConfig Config { get; private set; } = config ?? new AppConfig();

    public Task<AppConfig> LoadAsync(CancellationToken cancellationToken = default) => Task.FromResult(Config);

    public Task SaveAsync(AppConfig config, CancellationToken cancellationToken = default)
    {
        Config = config;
        return Task.CompletedTask;
    }
}
