using SSLense.Core.Config;
using SSLense.Core.Errors;
using SSLense.Core.Iis;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SSLense.Core.Certificates;

public enum CertificateHistoryKind
{
    Issued = 0,
    Renewed = 1,
    RenewalFailed = 2,
    RolledBack = 3,
    Revoked = 4
}

/// <summary>One thing that happened to a managed certificate, for its timeline (docs/design/history-and-rollback.md).</summary>
/// <param name="RecordId">The managed certificate record, so the timeline survives a rename; empty for a certificate revoked from a file.</param>
/// <param name="Thumbprint">The certificate the event is about: the new one for an issue, renewal or rollback, the revoked one for a revocation.</param>
/// <param name="ReplacedThumbprint">The certificate the site used before, for a renewal or rollback.</param>
public sealed record CertificateHistoryEntry(
    DateTimeOffset At,
    Guid RecordId,
    string Name,
    CertificateHistoryKind Kind,
    string Message,
    string? Thumbprint = null,
    string? ReplacedThumbprint = null,
    DateTimeOffset? NotAfter = null);

/// <summary>Whether the certificate can go back to the one the last renewal replaced, and why not when it cannot.</summary>
public sealed record RollbackOption(bool Available, string Message, string? Thumbprint = null, DateTimeOffset? NotAfter = null);

public sealed record CertificateHistoryView(string Name, IReadOnlyList<CertificateHistoryEntry> Entries, RollbackOption Rollback);

/// <summary>Where the timeline is kept. Recording never fails an operation: see <see cref="CertificateHistoryStoreExtensions.TryAddAsync"/>.</summary>
public interface ICertificateHistoryStore
{
    Task AddAsync(CertificateHistoryEntry entry, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<CertificateHistoryEntry>> GetAllAsync(CancellationToken cancellationToken = default);
}

public static class CertificateHistoryStoreExtensions
{
    /// <summary>Adds an entry, ignoring any failure: the operation it describes already happened.</summary>
    public static async Task TryAddAsync(this ICertificateHistoryStore? store, CertificateHistoryEntry entry)
    {
        if (store is null)
        {
            return;
        }

        try
        {
            await store.AddAsync(entry, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // The log has the same event; a lost history line must not turn a success into a failure.
        }
    }
}

internal sealed class JsonCertificateHistoryStore : ICertificateHistoryStore
{
    /// <summary>The newest entries kept for each certificate; older ones are dropped.</summary>
    internal const int EntriesPerCertificate = 50;

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly IFileSystem _fileSystem;
    private readonly string _path;
    private readonly string _lockPath;

    public JsonCertificateHistoryStore(IFileSystem fileSystem)
        : this(fileSystem, AppPaths.HistoryFile, AppPaths.HistoryLockFile)
    {
    }

    internal JsonCertificateHistoryStore(IFileSystem fileSystem, string path, string lockPath)
    {
        _fileSystem = fileSystem;
        _path = path;
        _lockPath = lockPath;
    }

    public async Task AddAsync(CertificateHistoryEntry entry, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entry);
        await using var fileLock = await _fileSystem.AcquireExclusiveFileLockAsync(_lockPath, cancellationToken).ConfigureAwait(false);
        var entries = (await ReadUnsafeAsync(cancellationToken).ConfigureAwait(false)).ToList();
        entries.Add(entry);
        var kept = entries
            .GroupBy(value => value.RecordId != Guid.Empty ? value.RecordId.ToString() : value.Name.ToUpperInvariant())
            .SelectMany(group => group.OrderByDescending(value => value.At).Take(EntriesPerCertificate))
            .OrderBy(value => value.At)
            .ToArray();
        await _fileSystem.WriteAllTextAtomicAsync(
                _path,
                JsonSerializer.Serialize(new HistoryDocument(StateSchema.History, kept), SerializerOptions),
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<CertificateHistoryEntry>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        await using var fileLock = await _fileSystem.AcquireExclusiveFileLockAsync(_lockPath, cancellationToken).ConfigureAwait(false);
        return await ReadUnsafeAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<IReadOnlyList<CertificateHistoryEntry>> ReadUnsafeAsync(CancellationToken cancellationToken)
    {
        if (!_fileSystem.FileExists(_path))
        {
            return [];
        }

        try
        {
            var json = await _fileSystem.ReadAllTextAsync(_path, cancellationToken).ConfigureAwait(false);
            StateSchema.EnsureSupported(json, StateSchema.History, _path);
            var document = JsonSerializer.Deserialize<HistoryDocument>(json, SerializerOptions);
            if (document is null)
            {
                return [];
            }

            StateSchema.EnsureSupported(document.SchemaVersion, StateSchema.History, _path);
            return document.Entries ?? [];
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(ErrorCodes.DataFileDamaged.Format($"The certificate history '{_path}' contains invalid JSON."), exception);
        }
    }

    private sealed record HistoryDocument(int SchemaVersion, IReadOnlyList<CertificateHistoryEntry>? Entries);
}

/// <summary>
/// The timeline of a managed certificate, and going back to the certificate its last renewal replaced
/// (docs/design/history-and-rollback.md).
/// </summary>
public interface ICertificateHistoryService
{
    Task<CertificateHistoryView> GetAsync(string name, CancellationToken cancellationToken = default);

    /// <summary>Binds the previous certificate to the sites again; the current one is kept, so going forward is a rollback too.</summary>
    /// <returns>What happened, for the administrator.</returns>
    Task<string> RollBackAsync(string name, IProgress<ProgressEvent>? progress = null, CancellationToken cancellationToken = default);
}

internal sealed class CertificateHistoryService(
    IManagedCertificateStore managedStore,
    ICertificateStore certificateStore,
    IIisService iisService,
    ICertificateHistoryStore history,
    ICertificateOperationLock? operationLock = null,
    ICertificateTransactionJournal? journal = null) : ICertificateHistoryService
{
    /// <summary>The longest a rollback holds scheduled renewal, so the service does not replace the certificate again at once.</summary>
    internal static readonly TimeSpan MaximumHold = TimeSpan.FromDays(7);

    private readonly ICertificateOperationLock _operationLock = operationLock ?? new NoOpCertificateOperationLock();
    private readonly ICertificateTransactionJournal _journal = journal ?? new NoOpCertificateTransactionJournal();

    public async Task<CertificateHistoryView> GetAsync(string name, CancellationToken cancellationToken = default)
    {
        var record = await FindAsync(name, cancellationToken).ConfigureAwait(false);
        var entries = await history.GetAllAsync(cancellationToken).ConfigureAwait(false);
        var timeline = entries
            .Where(entry => entry.RecordId == record.Id ||
                            (entry.RecordId == Guid.Empty && string.Equals(entry.Name, record.SiteName, StringComparison.OrdinalIgnoreCase)))
            .OrderByDescending(entry => entry.At)
            .ToArray();
        return new CertificateHistoryView(record.SiteName, timeline, await CheckAsync(record, entries, cancellationToken).ConfigureAwait(false));
    }

    public async Task<string> RollBackAsync(string name, IProgress<ProgressEvent>? progress = null, CancellationToken cancellationToken = default)
    {
        var found = await FindAsync(name, cancellationToken).ConfigureAwait(false);
        await using var locked = await _operationLock.AcquireAllAsync(found.AllSiteNames(), cancellationToken).ConfigureAwait(false);

        // Read again under the lock: a renewal may have finished while this waited.
        var record = await FindAsync(found.SiteName, cancellationToken).ConfigureAwait(false);
        var option = await CheckAsync(record, await history.GetAllAsync(cancellationToken).ConfigureAwait(false), cancellationToken).ConfigureAwait(false);
        if (!option.Available || record.PreviousThumbprint is not { } previous)
        {
            throw new SslenseException(ErrorCodes.RollbackNotAvailable, option.Message);
        }

        using var certificate = await certificateStore.OpenAsync(previous, cancellationToken).ConfigureAwait(false)
            ?? throw new SslenseException(ErrorCodes.RollbackNotAvailable, $"Certificate {previous} is no longer in LocalMachine\\My.");
        var now = DateTimeOffset.UtcNow;
        var notBefore = new DateTimeOffset(certificate.NotBefore.ToUniversalTime());
        var notAfter = new DateTimeOffset(certificate.NotAfter.ToUniversalTime());
        var hold = HoldUntil(now, notBefore, notAfter);
        var message = $"Rolled back to certificate {previous} on {now:yyyy-MM-dd HH:mm} UTC.";
        ManagedCertificate RolledBack(ManagedCertificate value) => value with
        {
            Thumbprint = previous,
            PreviousThumbprint = value.Thumbprint,
            NotBefore = notBefore,
            NotAfter = notAfter,
            Issuer = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: true),
            LastRenewalMessage = message,
            ConsecutiveFailures = 0,
            NextRetryAt = hold
        };

        var rolled = RolledBack(record);
        var transaction = await _journal.BeginAsync(rolled, record.Thumbprint, CancellationToken.None).ConfigureAwait(false);
        await _journal.UpdateStageAsync(transaction.Id, CertificateTransactionStage.CertificateImported, CancellationToken.None).ConfigureAwait(false);
        var targets = rolled.AllTargets().Where(target => target.PendingSince is null).ToArray();
        try
        {
            if (targets.Length == 1)
            {
                progress?.Report(new ProgressEvent("binding", $"Binding certificate {previous} to IIS site '{targets[0].SiteName}' again."));
                await iisService.ConfigureHttpsBindingsAsync(targets[0].SiteName, targets[0].Hosts, previous, "My", cancellationToken).ConfigureAwait(false);
            }
            else if (targets.Length > 1)
            {
                await SharedBindingTransaction.ApplyAsync(iisService, targets, previous, leaveOutFailures: false, progress, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (IisBindingException exception) when (exception.PreviousBindingsRestored)
        {
            // Every site is back on the current certificate, so there is nothing to recover.
            await _journal.CompleteAsync(transaction.Id, CancellationToken.None).ConfigureAwait(false);
            throw;
        }

        await _journal.UpdateStageAsync(transaction.Id, CertificateTransactionStage.BindingsUpdated, CancellationToken.None).ConfigureAwait(false);
        await managedStore.UpdateRecordAsync(record.Id, RolledBack, CancellationToken.None).ConfigureAwait(false);
        await _journal.UpdateStageAsync(transaction.Id, CertificateTransactionStage.StateSaved, CancellationToken.None).ConfigureAwait(false);
        await _journal.CompleteAsync(transaction.Id, CancellationToken.None).ConfigureAwait(false);
        await history.TryAddAsync(new CertificateHistoryEntry(
                now, record.Id, record.SiteName, CertificateHistoryKind.RolledBack, message, previous, record.Thumbprint, notAfter))
            .ConfigureAwait(false);

        return string.Join(" ", new[]
        {
            $"'{record.SiteName}' uses certificate {previous} again, valid until {notAfter:yyyy-MM-dd}. Certificate {record.Thumbprint} is kept, so you can roll forward the same way.",
            hold is { } until
                ? $"Automatic renewal waits until {until:yyyy-MM-dd HH:mm} UTC; fix what was wrong with the new certificate before then, or renew by hand."
                : "This certificate is due for renewal, so the service will renew it at its next check; fix what was wrong with the new certificate first.",
            rolled.DeploymentSteps is { Count: > 0 }
                ? $"Deployment steps were not run. If other services use this certificate, run 'SSLense.Cli deploy run --site \"{record.SiteName}\"'."
                : null
        }.OfType<string>());
    }

    /// <summary>
    /// How long scheduled renewal waits after a rollback: up to <see cref="MaximumHold"/>, and never closer to expiry than
    /// a tenth of the lifetime or two days, whichever is longer. Null when even that is too close.
    /// </summary>
    internal static DateTimeOffset? HoldUntil(DateTimeOffset now, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        var margin = TimeSpan.FromTicks(Math.Max(TimeSpan.FromDays(2).Ticks, (notAfter - notBefore).Ticks / 10));
        var until = new[] { now + MaximumHold, notAfter - margin }.Min();
        return until > now ? until : null;
    }

    private async Task<RollbackOption> CheckAsync(
        ManagedCertificate record,
        IReadOnlyList<CertificateHistoryEntry> entries,
        CancellationToken cancellationToken)
    {
        if (record.Source != CertificateSource.Acme)
        {
            return new RollbackOption(false, $"'{record.SiteName}' is not issued by SSLense, so no previous certificate is kept for it.");
        }

        if (record.NoSite)
        {
            return new RollbackOption(false, $"'{record.SiteName}' has no IIS site to bind a previous certificate to; its deployment steps decide where it is used.");
        }

        if (record.PreviousThumbprint is not { } previous)
        {
            return new RollbackOption(false, $"No previous certificate is kept for '{record.SiteName}'. SSLense keeps the one a renewal replaces while it is still valid.");
        }

        if (entries.Any(entry => entry.Kind == CertificateHistoryKind.Revoked && string.Equals(entry.Thumbprint, previous, StringComparison.OrdinalIgnoreCase)))
        {
            return new RollbackOption(false, $"The previous certificate {previous} was revoked, so browsers would refuse it.");
        }

        using var certificate = await certificateStore.OpenAsync(previous, cancellationToken).ConfigureAwait(false);
        if (certificate is null)
        {
            return new RollbackOption(false, $"The previous certificate {previous} is no longer in LocalMachine\\My.");
        }

        var notAfter = new DateTimeOffset(certificate.NotAfter.ToUniversalTime());
        if (!certificate.HasPrivateKey)
        {
            return new RollbackOption(false, $"The previous certificate {previous} has lost its private key.");
        }

        if (notAfter <= DateTimeOffset.UtcNow.AddDays(1))
        {
            return new RollbackOption(false, $"The previous certificate {previous} expires on {notAfter:yyyy-MM-dd HH:mm} UTC, too soon to go back to.");
        }

        var missing = record.AllTargets()
            .Where(target => target.PendingSince is null)
            .SelectMany(target => target.Hosts)
            .Where(host => !Covers(certificate, host))
            .ToArray();
        if (missing.Length > 0)
        {
            return new RollbackOption(false, $"The previous certificate {previous} does not cover {string.Join(", ", missing)}, which the site now uses.");
        }

        return new RollbackOption(true, $"Certificate {previous}, valid until {notAfter:yyyy-MM-dd}, can be bound again.", previous, notAfter);
    }

    /// <summary>An IIS wildcard host such as <c>*.example.com</c> needs a wildcard name on the certificate.</summary>
    internal static bool Covers(X509Certificate2 certificate, string host)
    {
        try
        {
            return certificate.MatchesHostname(host.StartsWith("*.", StringComparison.Ordinal) ? "sslense-wildcard-check" + host[1..] : host);
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private async Task<ManagedCertificate> FindAsync(string name, CancellationToken cancellationToken)
    {
        var records = await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        return records.FirstOrDefault(value => string.Equals(value.SiteName, name.Trim(), StringComparison.OrdinalIgnoreCase))
            ?? throw ManagedCertificateNotFound.Create(name, records);
    }
}
