using System.Text.Json;

namespace SSLense.Core.Config;

public sealed class JsonManagedCertificateStore : IManagedCertificateStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly IFileSystem _fileSystem;
    private readonly string _statePath;
    private readonly string _lockPath;

    public JsonManagedCertificateStore(IFileSystem fileSystem)
        : this(fileSystem, AppPaths.ManagedCertificatesFile, AppPaths.ManagedCertificatesLockFile)
    {
    }

    public JsonManagedCertificateStore(IFileSystem fileSystem, string statePath, string lockPath)
    {
        _fileSystem = fileSystem ?? throw new ArgumentNullException(nameof(fileSystem));
        _statePath = statePath;
        _lockPath = lockPath;
    }

    public async Task<IReadOnlyList<ManagedCertificate>> GetAllAsync(
        CancellationToken cancellationToken = default)
    {
        await using var fileLock = await _fileSystem
            .AcquireExclusiveFileLockAsync(_lockPath, cancellationToken)
            .ConfigureAwait(false);
        return await ReadUnsafeAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task UpsertAsync(
        ManagedCertificate certificate,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        await using var fileLock = await _fileSystem
            .AcquireExclusiveFileLockAsync(_lockPath, cancellationToken)
            .ConfigureAwait(false);
        var records = (await ReadUnsafeAsync(cancellationToken).ConfigureAwait(false)).ToList();
        records.RemoveAll(value => string.Equals(
            value.SiteName,
            certificate.SiteName,
            StringComparison.OrdinalIgnoreCase));
        records.Add(certificate);
        await WriteUnsafeAsync(records, cancellationToken).ConfigureAwait(false);
    }

    public async Task RecordRenewalFailureAsync(
        string siteName,
        DateTimeOffset attemptedAt,
        string message,
        CancellationToken cancellationToken = default)
    {
        await using var fileLock = await _fileSystem
            .AcquireExclusiveFileLockAsync(_lockPath, cancellationToken)
            .ConfigureAwait(false);
        var records = (await ReadUnsafeAsync(cancellationToken).ConfigureAwait(false)).ToList();
        var index = records.FindIndex(value => string.Equals(
            value.SiteName,
            siteName,
            StringComparison.OrdinalIgnoreCase));
        if (index < 0)
        {
            return;
        }

        records[index] = records[index] with
        {
            LastRenewalAttempt = attemptedAt,
            LastRenewalSucceeded = false,
            LastRenewalMessage = message
        };
        await WriteUnsafeAsync(records, cancellationToken).ConfigureAwait(false);
    }

    private async Task<IReadOnlyList<ManagedCertificate>> ReadUnsafeAsync(
        CancellationToken cancellationToken)
    {
        if (!_fileSystem.FileExists(_statePath))
        {
            return [];
        }

        try
        {
            var json = await _fileSystem.ReadAllTextAsync(_statePath, cancellationToken)
                .ConfigureAwait(false);
            return JsonSerializer.Deserialize<List<ManagedCertificate>>(json, SerializerOptions)
                ?? throw new InvalidDataException($"Managed certificate state '{_statePath}' is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                $"Managed certificate state '{_statePath}' contains invalid JSON.",
                exception);
        }
    }

    private Task WriteUnsafeAsync(
        IReadOnlyList<ManagedCertificate> records,
        CancellationToken cancellationToken) =>
        _fileSystem.WriteAllTextAtomicAsync(
            _statePath,
            JsonSerializer.Serialize(records, SerializerOptions),
            cancellationToken);
}
