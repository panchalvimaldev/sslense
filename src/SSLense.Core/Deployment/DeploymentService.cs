using System.Globalization;
using System.Text;
using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.DnsValidation;
using SSLense.Core.Iis;
using SSLense.Core.Notifications;

namespace SSLense.Core.Deployment;

/// <param name="Site">The IIS site whose certificate record gets the step.</param>
/// <param name="Value">The account, the service name, or the script's path.</param>
/// <param name="TimeoutSeconds">For a script, how long it may run; five minutes when left out.</param>
/// <param name="Password">For a PFX or Central Certificate Store export, the password that protects the files.</param>
public sealed record DeploymentStepRequest(string Site, DeploymentStepKind Kind, string Value, int? TimeoutSeconds = null, string? Password = null)
{
    public const int DefaultScriptTimeoutSeconds = 300;
}

/// <param name="Steps">The steps in the order they run.</param>
/// <param name="Pending">True when the steps have not yet succeeded for the certificate in use.</param>
public sealed record DeploymentOverview(
    string Site,
    string Thumbprint,
    IReadOnlyList<DeploymentStep> Steps,
    DeploymentState? State,
    bool Pending);

/// <param name="StepsCompleted">Steps that succeeded in this run, before the one that failed if any.</param>
public sealed record DeploymentRunResult(
    string Site,
    string Thumbprint,
    bool Succeeded,
    int StepsCompleted,
    int StepCount,
    string Message);

/// <summary>
/// Deployment steps: what runs after every install and renewal of a certificate, such as giving an application pool access
/// to its key or restarting a service. See docs/design/deployment-steps.md.
/// </summary>
public interface IDeploymentService
{
    Task<DeploymentStep> AddAsync(DeploymentStepRequest request, CancellationToken cancellationToken = default);

    Task<DeploymentOverview> ListAsync(string site, CancellationToken cancellationToken = default);

    /// <summary>Every certificate with deployment steps.</summary>
    Task<IReadOnlyList<DeploymentOverview>> ListAllAsync(CancellationToken cancellationToken = default);

    /// <summary>Removes a step by its number in <see cref="ListAsync"/>, counting from 1. Returns the removed step.</summary>
    Task<DeploymentStep> RemoveAsync(string site, int number, CancellationToken cancellationToken = default);

    /// <summary>Runs every step now, for the certificate in use.</summary>
    Task<DeploymentRunResult> RunAsync(string site, IProgress<ProgressEvent>? progress = null, CancellationToken cancellationToken = default);

    /// <summary>Runs the steps of every certificate whose steps have not yet succeeded for it. The service calls this every cycle.</summary>
    Task<IReadOnlyList<DeploymentRunResult>> RunPendingAsync(IProgress<ProgressEvent>? progress = null, CancellationToken cancellationToken = default);
}

/// <param name="Result">Null when the certificate has no deployment steps.</param>
/// <param name="KeepReplaced">True when the certificate just replaced must stay, because services may use it until the steps succeed.</param>
internal sealed record DeploymentAfterInstall(DeploymentRunResult? Result, bool KeepReplaced);

/// <summary>Runs deployment steps for an install that already holds the sites' operation locks.</summary>
internal interface IDeploymentRunner
{
    Task<DeploymentAfterInstall> RunAfterInstallAsync(
        string site,
        string? replacedThumbprint,
        IReadOnlyList<string> sitesLeftOut,
        IProgress<ProgressEvent>? progress,
        CancellationToken cancellationToken);
}

internal sealed class DeploymentService : IDeploymentService, IDeploymentRunner
{
    public const int MaxSteps = 20;
    public const int DefaultScriptTimeoutSeconds = DeploymentStepRequest.DefaultScriptTimeoutSeconds;
    public const int MinScriptTimeoutSeconds = 10;
    public const int MaxScriptTimeoutSeconds = 3600;
    private static readonly TimeSpan ServiceTimeout = TimeSpan.FromMinutes(2);

    /// <summary>The first failure is notified, then about once a day while the hourly retries keep failing.</summary>
    private const int NotifyEveryFailures = 24;

    private readonly IManagedCertificateStore _store;
    private readonly IPrivateKeyAccess _keyAccess;
    private readonly IServiceRestarter _services;
    private readonly IDnsScriptStore _scripts;
    private readonly IScriptRunner _runner;
    private readonly IIisService _iis;
    private readonly ICertificateStore _certificates;
    private readonly INotifier? _notifier;
    private readonly ICertificateOperationLock _operationLock;
    private readonly ICertificateExporter? _exporter;
    private readonly ISecretProtector? _protector;

    public DeploymentService(
        IManagedCertificateStore store,
        IPrivateKeyAccess keyAccess,
        IServiceRestarter services,
        IDnsScriptStore scripts,
        IScriptRunner runner,
        IIisService iis,
        ICertificateStore certificates,
        INotifier? notifier = null,
        ICertificateOperationLock? operationLock = null,
        ICertificateExporter? exporter = null,
        ISecretProtector? protector = null)
    {
        _exporter = exporter;
        _protector = protector;
        _store = store;
        _keyAccess = keyAccess;
        _services = services;
        _scripts = scripts;
        _runner = runner;
        _iis = iis;
        _certificates = certificates;
        _notifier = notifier;
        _operationLock = operationLock ?? new NoOpCertificateOperationLock();
    }

    public async Task<DeploymentStep> AddAsync(DeploymentStepRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Value);
        var record = await FindAsync(request.Site, cancellationToken).ConfigureAwait(false);
        if ((record.DeploymentSteps?.Count ?? 0) >= MaxSteps)
        {
            throw new InvalidOperationException($"A certificate can have at most {MaxSteps} deployment steps.");
        }

        if (request.Password is not null && request.Kind is not (DeploymentStepKind.ExportPfx or DeploymentStepKind.CentralStore))
        {
            throw new ArgumentException(request.Kind == DeploymentStepKind.ExportPem
                ? "PEM files take no password: key.pem is written for Administrators and SYSTEM only."
                : "Only a PFX or Central Certificate Store export takes a password.");
        }

        if (request.Kind != DeploymentStepKind.Script && request.TimeoutSeconds is not null)
        {
            throw new ArgumentException("A timeout can only be set for a script step.");
        }

        var id = Guid.NewGuid();
        DeploymentStep step;
        switch (request.Kind)
        {
            case DeploymentStepKind.GrantKeyAccess:
                step = new DeploymentStep(id, request.Kind, _keyAccess.ResolveAccount(request.Value));
                break;
            case DeploymentStepKind.RestartService:
                var name = request.Value.Trim();
                ScServiceRestarter.ValidateName(name);
                if (!await _services.ExistsAsync(name, cancellationToken).ConfigureAwait(false))
                {
                    throw new ArgumentException(
                        $"No Windows service is named '{name}'. Use the service's name, as 'sc.exe query' or the Services console shows it, not its display name.");
                }

                if (string.Equals(name, "SSLense", StringComparison.OrdinalIgnoreCase))
                {
                    throw new ArgumentException("SSLense cannot restart its own service as a deployment step.");
                }

                step = new DeploymentStep(id, request.Kind, name);
                break;
            case DeploymentStepKind.Script:
                var timeout = request.TimeoutSeconds ?? DefaultScriptTimeoutSeconds;
                if (timeout is < MinScriptTimeoutSeconds or > MaxScriptTimeoutSeconds)
                {
                    throw new ArgumentException(
                        $"The timeout must be from {MinScriptTimeoutSeconds} to {MaxScriptTimeoutSeconds} seconds.");
                }

                var sha256 = await _scripts.SaveAsync(ScriptName(id), request.Value, cancellationToken).ConfigureAwait(false);
                step = new DeploymentStep(id, request.Kind, Path.GetFileName(request.Value.Trim().Trim('"')), sha256, timeout);
                break;
            case DeploymentStepKind.ExportPfx or DeploymentStepKind.ExportPem or DeploymentStepKind.CentralStore:
                step = CreateExportStep(record, id, request);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(request), request.Kind, "Unknown deployment step.");
        }

        ManagedCertificate? updated;
        try
        {
            updated = await _store.UpdateRecordAsync(
                    record.Id,
                    current => current with
                    {
                        DeploymentSteps = [.. current.DeploymentSteps ?? [], step],

                        // Steps added now run after the next renewal, or on 'deploy run'. Counting them as pending for
                        // the certificate in use would make the service restart services within the hour, unasked.
                        Deployment = current.Deployment ?? new DeploymentState(CompletedThumbprint: current.Thumbprint)
                    },
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            DeleteScript(step);
            throw;
        }

        if (updated is null)
        {
            DeleteScript(step);
            throw new InvalidOperationException($"The certificate record for '{request.Site}' was removed while the step was added.");
        }

        return step;
    }

    public async Task<DeploymentOverview> ListAsync(string site, CancellationToken cancellationToken = default) =>
        Overview(await FindAsync(site, cancellationToken).ConfigureAwait(false));

    public async Task<IReadOnlyList<DeploymentOverview>> ListAllAsync(CancellationToken cancellationToken = default) =>
        (await _store.GetAllAsync(cancellationToken).ConfigureAwait(false))
            .Where(record => record.HasDeploymentSteps())
            .Select(Overview)
            .ToArray();

    public async Task<DeploymentStep> RemoveAsync(string site, int number, CancellationToken cancellationToken = default)
    {
        var record = await FindAsync(site, cancellationToken).ConfigureAwait(false);
        await using var held = await _operationLock.AcquireAllAsync(record.AllSiteNames(), cancellationToken).ConfigureAwait(false);
        DeploymentStep? removed = null;
        var updated = await _store.UpdateRecordAsync(
                record.Id,
                current =>
                {
                    var steps = current.DeploymentSteps ?? [];
                    if (number < 1 || number > steps.Count)
                    {
                        throw new ArgumentOutOfRangeException(
                            nameof(number),
                            steps.Count == 0
                                ? $"'{current.SiteName}' has no deployment steps."
                                : $"'{current.SiteName}' has deployment steps 1 to {steps.Count}. 'SSLense.Cli deploy list' shows them.");
                    }

                    removed = steps[number - 1];
                    var remaining = steps.Where((_, index) => index != number - 1).ToArray();
                    return current with
                    {
                        DeploymentSteps = remaining.Length == 0 ? null : remaining,
                        Deployment = remaining.Length == 0 ? null : current.Deployment
                    };
                },
                cancellationToken)
            .ConfigureAwait(false);
        if (updated is null || removed is null)
        {
            throw new InvalidOperationException($"The certificate record for '{site}' was removed meanwhile.");
        }

        DeleteScript(removed);

        // With no steps left, nothing can still need a certificate kept for them.
        if (!updated.HasDeploymentSteps() && record.Deployment?.RetainedThumbprint is { } retained)
        {
            await RemoveRetainedAsync(updated, retained, null, cancellationToken).ConfigureAwait(false);
        }

        return removed;
    }

    public async Task<DeploymentRunResult> RunAsync(
        string site,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var record = await FindAsync(site, cancellationToken).ConfigureAwait(false);
        await using var held = await _operationLock.AcquireAllAsync(record.AllSiteNames(), cancellationToken).ConfigureAwait(false);
        record = await FindAsync(site, cancellationToken).ConfigureAwait(false);
        if (!record.HasDeploymentSteps())
        {
            throw new InvalidOperationException(
                $"'{record.SiteName}' has no deployment steps. Add one with 'SSLense.Cli deploy add --site \"{record.SiteName}\"'.");
        }

        return await RunStepsAsync(record, null, notify: false, progress, cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<DeploymentRunResult>> RunPendingAsync(
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var results = new List<DeploymentRunResult>();
        var records = await _store.GetAllAsync(cancellationToken).ConfigureAwait(false);

        // Copies of steps that no longer exist, such as those of a removed certificate. A copy younger than an hour may
        // belong to a step being added right now, whose record is not saved yet.
        _scripts.DeleteUnused(
            records.SelectMany(record => record.DeploymentSteps ?? []).Select(step => ScriptName(step.Id)).ToHashSet(StringComparer.OrdinalIgnoreCase),
            TimeSpan.FromHours(1));

        foreach (var candidate in records.Where(record => record.HasPendingDeployment()))

        {
            cancellationToken.ThrowIfCancellationRequested();

            // An install or renewal in progress runs the steps itself when it finishes.
            await using var held = _operationLock.TryAcquireAll(candidate.AllSiteNames());
            if (held is null)
            {
                continue;
            }

            var record = (await _store.GetAllAsync(cancellationToken).ConfigureAwait(false))
                .FirstOrDefault(value => value.Id == candidate.Id);
            if (record is null || !record.HasPendingDeployment())
            {
                continue;
            }

            results.Add(await RunStepsAsync(record, null, notify: true, progress, cancellationToken).ConfigureAwait(false));
        }

        return results;
    }

    public async Task<DeploymentAfterInstall> RunAfterInstallAsync(
        string site,
        string? replacedThumbprint,
        IReadOnlyList<string> sitesLeftOut,
        IProgress<ProgressEvent>? progress,
        CancellationToken cancellationToken)
    {
        var record = (await _store.GetAllAsync(cancellationToken).ConfigureAwait(false))
            .FirstOrDefault(value => value.ManagesSite(site));
        if (record is null || !record.HasDeploymentSteps())
        {
            return new DeploymentAfterInstall(null, false);
        }

        var deployed = record.Deployment?.CompletedThumbprint;
        var replaced = replacedThumbprint is not null &&
                       !string.Equals(replacedThumbprint, record.Thumbprint, StringComparison.OrdinalIgnoreCase)
            ? replacedThumbprint
            : null;
        var result = await RunStepsAsync(record, replaced, notify: true, progress, cancellationToken).ConfigureAwait(false);
        if (result.Succeeded || replaced is null ||
            !string.Equals(replaced, deployed, StringComparison.OrdinalIgnoreCase))
        {
            // A replaced certificate the steps never completed for was never handed to the services, so it can go.
            return new DeploymentAfterInstall(result, false);
        }

        await _store.UpdateRecordAsync(
                record.Id,
                current => current with
                {
                    Deployment = (current.Deployment ?? new DeploymentState()) with { RetainedThumbprint = replaced }
                },
                CancellationToken.None)
            .ConfigureAwait(false);
        progress?.Report(new ProgressEvent(
            "deploy",
            $"The previous certificate {replaced} is kept while the deployment steps are pending, because services may still use it."));
        return new DeploymentAfterInstall(result, true);
    }

    /// <param name="replaced">The certificate this install replaced, if any; given to scripts when the steps never completed before.</param>
    private async Task<DeploymentRunResult> RunStepsAsync(
        ManagedCertificate record,
        string? replaced,
        bool notify,
        IProgress<ProgressEvent>? progress,
        CancellationToken cancellationToken)
    {
        var steps = record.DeploymentSteps ?? [];
        var state = record.Deployment ?? new DeploymentState();
        var previous = state.CompletedThumbprint is { } completed &&
                       !string.Equals(completed, record.Thumbprint, StringComparison.OrdinalIgnoreCase)
            ? completed
            : replaced ?? state.PreviousThumbprint;

        var done = 0;
        string? error = null;
        foreach (var step in steps)
        {
            cancellationToken.ThrowIfCancellationRequested();
            progress?.Report(new ProgressEvent("deploy", $"Step {done + 1} of {steps.Count}: {step.Describe()}."));
            try
            {
                await RunStepAsync(record, step, previous, cancellationToken).ConfigureAwait(false);
                done++;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                error = $"Step {done + 1} ({step.Describe()}) failed: {exception.Message}";
                progress?.Report(new ProgressEvent("deploy", error));
                break;
            }
        }

        var succeeded = error is null;
        var now = DateTimeOffset.UtcNow;
        var updated = await _store.UpdateRecordAsync(
                record.Id,
                current =>
                {
                    // A record that changed certificate meanwhile is left for the next run.
                    if (!string.Equals(current.Thumbprint, record.Thumbprint, StringComparison.OrdinalIgnoreCase))
                    {
                        return current;
                    }

                    var currentState = current.Deployment ?? new DeploymentState();
                    return current with
                    {
                        Deployment = succeeded
                            ? currentState with
                            {
                                CompletedThumbprint = current.Thumbprint,
                                PreviousThumbprint = previous,
                                LastAttempt = now,
                                LastError = null,
                                ConsecutiveFailures = 0,
                                RetainedThumbprint = null
                            }
                            : currentState with
                            {
                                LastAttempt = now,
                                LastError = error,
                                ConsecutiveFailures = currentState.ConsecutiveFailures + 1
                            }
                    };
                },
                CancellationToken.None)
            .ConfigureAwait(false);

        if (succeeded && state.RetainedThumbprint is { } retained && updated is not null)
        {
            await RemoveRetainedAsync(updated, retained, progress, CancellationToken.None).ConfigureAwait(false);
        }

        var message = succeeded
            ? $"All {steps.Count} deployment step(s) succeeded for certificate {record.Thumbprint}."
            : $"{error} {done} of {steps.Count} step(s) succeeded. The certificate itself is installed; SSLense retries the steps every hour.";
        if (notify)
        {
            await NotifyAsync(record, succeeded, state.ConsecutiveFailures, message, progress).ConfigureAwait(false);
        }

        return new DeploymentRunResult(record.SiteName, record.Thumbprint, succeeded, done, steps.Count, message);
    }

    private async Task RunStepAsync(ManagedCertificate record, DeploymentStep step, string? previous, CancellationToken cancellationToken)
    {
        switch (step.Kind)
        {
            case DeploymentStepKind.GrantKeyAccess:
                await _keyAccess.GrantReadAsync(record.Thumbprint, step.Value, cancellationToken).ConfigureAwait(false);
                break;
            case DeploymentStepKind.RestartService:
                await _services.RestartAsync(step.Value, ServiceTimeout, cancellationToken).ConfigureAwait(false);
                break;
            case DeploymentStepKind.Script:
                await RunScriptAsync(record, step, previous, cancellationToken).ConfigureAwait(false);
                break;
            case DeploymentStepKind.ExportPfx:
                await Exporter().ExportPfxAsync(record.Thumbprint, step.Value, Password(step), cancellationToken).ConfigureAwait(false);
                break;
            case DeploymentStepKind.ExportPem:
                await Exporter().ExportPemAsync(record.Thumbprint, step.Value, cancellationToken).ConfigureAwait(false);
                break;
            case DeploymentStepKind.CentralStore:
                await Exporter()
                    .ExportCentralStoreAsync(record.Thumbprint, record.CertificateNames ?? record.Hosts, step.Value, Password(step), cancellationToken)
                    .ConfigureAwait(false);
                break;
            default:
                throw new InvalidOperationException($"This SSLense version does not know deployment step kind {(int)step.Kind}.");
        }
    }

    private DeploymentStep CreateExportStep(ManagedCertificate record, Guid id, DeploymentStepRequest request)
    {
        if (!record.ExportableKey)
        {
            throw new InvalidOperationException(
                $"The private key of the certificate for '{record.SiteName}' is not exportable, so it cannot be written to files. " +
                "Issue the certificate again with an exportable key: add --exportable-key --force to its 'issue' command, or choose " +
                "Exportable private key in the app.");
        }

        var path = request.Value.Trim().Trim('"');
        if (!Path.IsPathFullyQualified(path))
        {
            throw new ArgumentException($"'{path}' is not a full path. Use one such as D:\\Certs\\shop.pfx or \\\\server\\share\\certs.");
        }

        if (request.Kind == DeploymentStepKind.ExportPfx &&
            !string.Equals(Path.GetExtension(path), ".pfx", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException($"'{path}' must be a .pfx file.");
        }

        string? protectedPassword = null;
        if (request.Kind is DeploymentStepKind.ExportPfx or DeploymentStepKind.CentralStore)
        {
            if (string.IsNullOrEmpty(request.Password))
            {
                throw new ArgumentException("A password is needed to protect the PFX files.");
            }

            var plaintext = Encoding.UTF8.GetBytes(request.Password);
            try
            {
                protectedPassword = Convert.ToBase64String(
                    (_protector ?? throw new InvalidOperationException("Passwords cannot be stored here.")).Protect(plaintext));
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(plaintext);
            }
        }

        return new DeploymentStep(id, request.Kind, Path.GetFullPath(path), ProtectedPassword: protectedPassword);
    }

    private ICertificateExporter Exporter() =>
        _exporter ?? throw new InvalidOperationException("Export is not available in this SSLense process.");

    private string Password(DeploymentStep step)
    {
        if (step.ProtectedPassword is null || _protector is null)
        {
            throw new InvalidOperationException("The step has no password. Remove it and add it again.");
        }

        try
        {
            return Encoding.UTF8.GetString(_protector.Unprotect(Convert.FromBase64String(step.ProtectedPassword)));
        }
        catch (Exception exception) when (exception is FormatException or System.Security.Cryptography.CryptographicException)
        {
            throw new InvalidOperationException(
                "The step's password can no longer be read on this server, for example after the data folder was copied from " +
                "another one. Remove the step and add it again.");
        }
    }

    private async Task RunScriptAsync(
ManagedCertificate record, DeploymentStep step, string? previous, CancellationToken cancellationToken)
    {
        var path = _scripts.GetVerifiedPath(
            ScriptName(step.Id),
            step.ScriptSha256 ?? throw new InvalidOperationException("The step has no script. Remove it and add it again."));
        var timeout = TimeSpan.FromSeconds(step.TimeoutSeconds ?? DefaultScriptTimeoutSeconds);
        var result = await _runner.RunAsync(path, ScriptArguments(record, previous), null, timeout, cancellationToken).ConfigureAwait(false);
        if (result.TimedOut)
        {
            throw new System.TimeoutException(
                $"The script '{step.Value}' did not finish within {timeout.TotalSeconds:0} seconds, so it was stopped." +
                ScriptDnsProvider.Tail(result.Output, null));
        }

        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"The script '{step.Value}' failed (exit code {result.ExitCode})." + ScriptDnsProvider.Tail(result.Output, null));
        }
    }

    /// <summary>The colon form, as for DNS scripts, so no value can be read as another parameter.</summary>
    internal static IReadOnlyList<string> ScriptArguments(ManagedCertificate record, string? previous) =>
    [
        $"-Thumbprint:{record.Thumbprint}",
        .. previous is null ? Array.Empty<string>() : [$"-PreviousThumbprint:{previous}"],
        $"-Hosts:{string.Join(',', record.AllTargets().SelectMany(target => target.Hosts).Distinct(StringComparer.OrdinalIgnoreCase))}",
        $"-NotAfter:{record.NotAfter.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)}",
        $"-Site:{record.SiteName}"
    ];

    private async Task RemoveRetainedAsync(
        ManagedCertificate record,
        string retained,
        IProgress<ProgressEvent>? progress,
        CancellationToken cancellationToken)
    {
        try
        {
            var message = await ReplacedCertificateCleanup
                .RemoveIfUnusedAsync(
                    _iis,
                    _certificates,
                    retained,
                    record.Thumbprint,
                    cancellationToken,
                    record.AllTargets().Where(target => target.PendingSince is not null).Select(target => target.SiteName).ToArray())
                .ConfigureAwait(false);
            if (message is not null)
            {
                progress?.Report(new ProgressEvent("cleanup", $"The deployment steps succeeded, but {message}"));
            }
        }
        catch (Exception exception)
        {
            progress?.Report(new ProgressEvent("cleanup", $"The previous certificate could not be checked for removal: {exception.Message}"));
        }
    }

    private async Task NotifyAsync(
        ManagedCertificate record,
        bool succeeded,
        int failuresBefore,
        string message,
        IProgress<ProgressEvent>? progress)
    {
        var failures = failuresBefore + 1;
        if (_notifier is null || (succeeded && failuresBefore == 0) ||
            (!succeeded && failures != 1 && failures % NotifyEveryFailures != 0))
        {
            return;
        }

        try
        {
            await _notifier.NotifyAsync(
                    succeeded
                        ? new NotificationMessage(
                            NotificationKind.RenewalSuccess,
                            $"SSLense deployment steps succeeded: {record.SiteName}",
                            $"After {failuresBefore} failed attempt(s), the deployment steps for {record.DescribeSites()} succeeded. {message}")
                        : new NotificationMessage(
                            NotificationKind.RenewalFailure,
                            $"SSLense deployment steps failed: {record.SiteName}",
                            $"The certificate for {record.DescribeSites()} is installed and bound in IIS, but its deployment steps failed. {message}"),
                    CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            progress?.Report(new ProgressEvent("notification", $"Notification could not be sent: {exception.Message}"));
        }
    }

    private static DeploymentOverview Overview(ManagedCertificate record) =>
        new(record.SiteName, record.Thumbprint, record.DeploymentSteps ?? [], record.Deployment, record.HasPendingDeployment());

    private async Task<ManagedCertificate> FindAsync(string site, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(site);
        var records = await _store.GetAllAsync(cancellationToken).ConfigureAwait(false);
        return records.FirstOrDefault(record => record.ManagesSite(site))
            ?? throw ManagedCertificateNotFound.Create(site, records);
    }

    private void DeleteScript(DeploymentStep step)
    {
        if (step is { Kind: DeploymentStepKind.Script, ScriptSha256: { } sha256 })
        {
            _scripts.Delete(ScriptName(step.Id), sha256);
        }
    }

    private static string ScriptName(Guid id) => $"step-{id:N}";
}
