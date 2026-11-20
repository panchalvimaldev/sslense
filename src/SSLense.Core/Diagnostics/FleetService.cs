using SSLense.Core.Config;
using SSLense.Core.Errors;
using SSLense.Core.Renewal;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SSLense.Core.Diagnostics;

/// <summary>One certificate as a fleet report shows it: names and dates only, never a key, secret or thumbprint's file.</summary>
public sealed record FleetCertificate(
    string Name,
    IReadOnlyList<string> Hosts,
    DateTimeOffset NotAfter,
    string Authority,
    bool? LastRenewalSucceeded,
    string? LastRenewalMessage,
    int ConsecutiveFailures);

/// <summary>What one server reported: written by its renewal service after every hourly cycle.</summary>
public sealed record FleetReport(
    string Server,
    string Version,
    DateTimeOffset WrittenAt,
    bool? LastCycleSucceeded,
    string? LastCycleMessage,
    IReadOnlyList<FleetCertificate> Certificates,
    int SchemaVersion = FleetService.SchemaVersion);

/// <param name="Stale">No report for longer than <see cref="FleetService.StaleAfter"/>: the server or its service may be down.</param>
/// <param name="Problem">Why the report could not be read, when it could not.</param>
public sealed record FleetServer(string Server, FleetReport? Report, bool Stale, string? Problem);

/// <summary>
/// Several servers from one place, first part (docs/design/fleet.md): each server writes a report to a shared folder,
/// and any of them can read every report. Nothing central renews anything, so a server keeps renewing whatever happens
/// to the folder; who may read it is the share's own Windows permissions.
/// </summary>
public interface IFleetService
{
    Task<string?> GetFolderAsync(CancellationToken cancellationToken = default);

    /// <summary>Sets the shared folder, or turns reports off with null. The folder must be reachable now.</summary>
    Task SetFolderAsync(string? folder, CancellationToken cancellationToken = default);

    /// <summary>Writes this server's report, when a folder is set. Returns where, or null when reports are off.</summary>
    Task<string?> WriteReportAsync(bool? lastCycleSucceeded = null, string? lastCycleMessage = null, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<FleetServer>> ReadAsync(CancellationToken cancellationToken = default);
}

internal sealed class FleetService(IConfigStore configStore, IRenewalService renewalService, IFileSystem fileSystem) : IFleetService
{
    public const int SchemaVersion = 1;

    /// <summary>Three missed hourly cycles.</summary>
    public static readonly TimeSpan StaleAfter = TimeSpan.FromHours(3);

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private static readonly string Version =
        (typeof(FleetService).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown").Split('+')[0];

    internal string ServerName { get; init; } = Environment.MachineName;

    public async Task<string?> GetFolderAsync(CancellationToken cancellationToken = default) =>
        (await configStore.LoadAsync(cancellationToken).ConfigureAwait(false)).FleetFolder;

    public async Task SetFolderAsync(string? folder, CancellationToken cancellationToken = default)
    {
        var value = string.IsNullOrWhiteSpace(folder) ? null : folder.Trim().Trim('"').TrimEnd('\\');
        if (value is not null)
        {
            if (!Path.IsPathFullyQualified(value))
            {
                throw new ArgumentException(ErrorCodes.FleetFolderInvalid.Format($"'{value}' must be a full path, normally a share such as \\\\files\\sslense-fleet."));
            }

            if (!fileSystem.DirectoryExists(value))
            {
                throw new ArgumentException(ErrorCodes.FleetFolderInvalid.Format(
                    $"'{value}' cannot be reached from this server. When the service runs as SYSTEM, give the computer account write access to the share."));
            }
        }

        await configStore.UpdateAsync(config => config with { FleetFolder = value }, cancellationToken).ConfigureAwait(false);
    }

    public async Task<string?> WriteReportAsync(bool? lastCycleSucceeded = null, string? lastCycleMessage = null, CancellationToken cancellationToken = default)
    {
        if (await GetFolderAsync(cancellationToken).ConfigureAwait(false) is not { } folder)
        {
            return null;
        }

        var certificates = (await renewalService.GetStatusAsync(cancellationToken).ConfigureAwait(false))
            .Select(status => new FleetCertificate(
                status.SiteName, status.Hosts, status.NotAfter, status.AuthorityName, status.LastRenewalSucceeded, status.LastRenewalMessage, status.ConsecutiveFailures))
            .ToArray();
        var report = new FleetReport(ServerName, Version, DateTimeOffset.UtcNow, lastCycleSucceeded, lastCycleMessage, certificates);
        var path = Path.Combine(folder, $"{ServerName}.json");
        await fileSystem.WriteAllTextAtomicAsync(path, JsonSerializer.Serialize(report, SerializerOptions), cancellationToken).ConfigureAwait(false);
        return path;
    }

    public async Task<IReadOnlyList<FleetServer>> ReadAsync(CancellationToken cancellationToken = default)
    {
        var folder = await GetFolderAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new SslenseException(ErrorCodes.FleetFolderInvalid, "No fleet folder is set. Set one with 'SSLense.Cli fleet folder --path <share>'.");
        var servers = new List<FleetServer>();
        foreach (var path in fileSystem.GetFiles(folder, "*.json").Order(StringComparer.OrdinalIgnoreCase))
        {
            var name = Path.GetFileNameWithoutExtension(path);
            try
            {
                var report = JsonSerializer.Deserialize<FleetReport>(await fileSystem.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false), SerializerOptions)
                    ?? throw new JsonException("The report is empty.");
                servers.Add(report.SchemaVersion > SchemaVersion
                    ? new FleetServer(name, null, false, $"Written by a newer SSLense ({report.Version}); update this server to read it.")
                    : new FleetServer(report.Server, report, DateTimeOffset.UtcNow - report.WrittenAt > StaleAfter, null));
            }
            catch (Exception exception) when (exception is JsonException or IOException or UnauthorizedAccessException)
            {
                servers.Add(new FleetServer(name, null, false, $"The report could not be read: {exception.Message}"));
            }
        }

        return servers;
    }
}
