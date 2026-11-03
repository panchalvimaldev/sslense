using System.Text.Json;
using SSLense.Core.Config;
using SSLense.Core.Validation;

namespace SSLense.Core.DnsValidation;

/// <summary>One TXT record SSLense is publishing. Recorded before the record is added, removed after it is deleted.</summary>
public sealed record DnsChallengeEntry(
    Guid Id,
    string ProviderName,
    string RecordName,
    string Value,
    int OwnerProcessId,
    DateTimeOffset OwnerProcessStartedAt,
    DateTimeOffset CreatedAt,
    int SchemaVersion = StateSchema.DnsChallenges);

internal interface IDnsChallengeJournal
{
    Task RecordAsync(DnsChallengeEntry entry, CancellationToken cancellationToken);

    Task CompleteAsync(Guid id);

    /// <summary>Entries whose owning process has exited without cleaning up.</summary>
    Task<IReadOnlyList<DnsChallengeEntry>> GetAbandonedAsync(CancellationToken cancellationToken);
}

internal sealed class JsonDnsChallengeJournal : IDnsChallengeJournal
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly IFileSystem _fileSystem;
    private readonly string _directory;
    private readonly Func<int, DateTimeOffset, bool> _isProcessAlive;

    public JsonDnsChallengeJournal(IFileSystem fileSystem)
        : this(fileSystem, AppPaths.DnsChallengeJournalDirectory, JsonChallengeJournal.IsProcessAlive)
    {
    }

    internal JsonDnsChallengeJournal(IFileSystem fileSystem, string directory, Func<int, DateTimeOffset, bool> isProcessAlive)
    {
        _fileSystem = fileSystem;
        _directory = directory;
        _isProcessAlive = isProcessAlive;
    }

    public Task RecordAsync(DnsChallengeEntry entry, CancellationToken cancellationToken)
    {
        _fileSystem.CreateDirectory(_directory);
        return _fileSystem.WriteAllTextAtomicAsync(
            GetPath(entry.Id),
            JsonSerializer.Serialize(entry, SerializerOptions),
            cancellationToken);
    }

    public Task CompleteAsync(Guid id)
    {
        _fileSystem.DeleteFile(GetPath(id));
        _fileSystem.DeleteDirectoryIfEmpty(_directory);
        return Task.CompletedTask;
    }

    public async Task<IReadOnlyList<DnsChallengeEntry>> GetAbandonedAsync(CancellationToken cancellationToken)
    {
        var abandoned = new List<DnsChallengeEntry>();
        foreach (var path in _fileSystem.GetFiles(_directory, "*.json"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            DnsChallengeEntry? entry;
            try
            {
                entry = JsonSerializer.Deserialize<DnsChallengeEntry>(
                    await _fileSystem.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false),
                    SerializerOptions);
            }
            catch (JsonException exception)
            {
                throw new InvalidDataException($"DNS challenge journal entry '{path}' contains invalid JSON.", exception);
            }

            if (entry is null)
            {
                continue;
            }

            StateSchema.EnsureSupported(entry.SchemaVersion, StateSchema.DnsChallenges, path);
            if (!_isProcessAlive(entry.OwnerProcessId, entry.OwnerProcessStartedAt))
            {
                abandoned.Add(entry);
            }
        }

        return abandoned;
    }

    private string GetPath(Guid id) => Path.Combine(_directory, $"{id:N}.json");
}
