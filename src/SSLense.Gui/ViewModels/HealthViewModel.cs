using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using SSLense.Core;
using SSLense.Core.Diagnostics;

namespace SSLense.Gui.ViewModels;

public partial class HealthViewModel : ObservableObject
{
    private readonly IHealthCheckService _healthCheckService;
    private readonly IDiagnosticBundleService _bundleService;
    private readonly ILogger<HealthViewModel> _logger;
    private readonly AsyncRelayCommand _runCommand;
    private readonly AsyncRelayCommand _createBundleCommand;

    [ObservableProperty]
    private bool isBusy;

    [ObservableProperty]
    private string summary = "Run the health check to see whether SSLense can renew your certificates.";

    [ObservableProperty]
    private string? statusMessage;

    [ObservableProperty]
    private string? errorMessage;

    [ObservableProperty]
    private bool redactHosts;

    [ObservableProperty]
    private string? bundlePath;

    public HealthViewModel(
        IHealthCheckService healthCheckService,
        IDiagnosticBundleService bundleService,
        ILogger<HealthViewModel> logger,
        SSLense.Core.Certificates.ICertificateCleanupService? cleanup = null)
    {
        _cleanup = cleanup;
        FindUnusedCommand = new AsyncRelayCommand(FindUnusedAsync, () => !IsBusy && _cleanup is not null);
        RemoveUnusedCommand = new AsyncRelayCommand(RemoveUnusedAsync, () => !IsBusy && _cleanup is not null);
        _healthCheckService = healthCheckService;
        _bundleService = bundleService;
        _logger = logger;
        _runCommand = new AsyncRelayCommand(RunAsync, () => !IsBusy);
        _createBundleCommand = new AsyncRelayCommand(CreateBundleAsync, () => !IsBusy);
        ShowBundleCommand = new RelayCommand(ShowBundle, () => BundlePath is not null);
    }

    public ObservableCollection<HealthCheckRowViewModel> Results { get; } = [];

    public IAsyncRelayCommand RunCommand => _runCommand;

    public IAsyncRelayCommand CreateBundleCommand => _createBundleCommand;

    // Clean-up of unused certificates (docs/design/certificate-cleanup.md).
    private readonly SSLense.Core.Certificates.ICertificateCleanupService? _cleanup;

    public ObservableCollection<UnusedCertificateRow> UnusedCertificates { get; } = [];

    [ObservableProperty] private string cleanupMessage = string.Empty;

    public IAsyncRelayCommand FindUnusedCommand { get; }

    public IAsyncRelayCommand RemoveUnusedCommand { get; }

    private async Task FindUnusedAsync(CancellationToken cancellationToken)
    {
        IsBusy = true;
        ErrorMessage = null;
        try
        {
            UnusedCertificates.Clear();
            foreach (var candidate in await _cleanup!.FindAsync(cancellationToken).ConfigureAwait(true))
            {
                UnusedCertificates.Add(new UnusedCertificateRow(candidate));
            }

            CleanupMessage = UnusedCertificates.Count == 0
                ? "No unused certificates to clean up."
                : $"{UnusedCertificates.Count} unused. Tick the ones to remove; check first that no other service, such as SQL Server or Exchange, uses them.";
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            _logger.LogError(exception, "Could not look for unused certificates");
            ErrorMessage = SSLense.Core.Errors.ErrorCode.Describe(exception);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task RemoveUnusedAsync(CancellationToken cancellationToken)
    {
        var ticked = UnusedCertificates.Where(row => row.IsChecked).Select(row => row.Candidate.Thumbprint).ToArray();
        if (ticked.Length == 0) return;
        IsBusy = true;
        ErrorMessage = null;
        try
        {
            var results = await _cleanup!.RemoveAsync(ticked, cancellationToken).ConfigureAwait(true);
            _logger.LogInformation("Clean-up: {Results}", string.Join(" ", results));
            CleanupMessage = string.Join(Environment.NewLine, results);
            foreach (var row in UnusedCertificates.Where(row => row.IsChecked).ToArray()) UnusedCertificates.Remove(row);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            ErrorMessage = SSLense.Core.Errors.ErrorCode.Describe(exception);
        }
        finally
        {
            IsBusy = false;
        }
    }

    public IRelayCommand ShowBundleCommand { get; }

    partial void OnIsBusyChanged(bool value)
    {
        FindUnusedCommand.NotifyCanExecuteChanged();
        RemoveUnusedCommand.NotifyCanExecuteChanged();
        _runCommand.NotifyCanExecuteChanged();
        _createBundleCommand.NotifyCanExecuteChanged();
    }

    partial void OnBundlePathChanged(string? value) => ShowBundleCommand.NotifyCanExecuteChanged();

    private async Task RunAsync()
    {
        IsBusy = true;
        ErrorMessage = null;
        StatusMessage = "Running checks…";
        try
        {
            var progress = new Progress<ProgressEvent>(value => StatusMessage = value.Message);
            var results = await _healthCheckService.RunAsync(progress).ConfigureAwait(true);
            Results.Clear();
            foreach (var result in results.OrderByDescending(value => value.Status))
            {
                Results.Add(new HealthCheckRowViewModel(result));
            }

            var failures = results.Count(value => value.Status == HealthStatus.Fail);
            var warnings = results.Count(value => value.Status == HealthStatus.Warning);
            Summary = failures > 0
                ? $"{failures} check(s) failed and {warnings} need attention. Problems are listed first."
                : warnings > 0
                    ? $"No failures; {warnings} check(s) need attention."
                    : $"All {results.Count} checks passed.";
            StatusMessage = $"Last run {DateTime.Now:HH:mm:ss}.";
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Health check failed");
            ErrorMessage = SSLense.Core.Errors.ErrorCode.Describe(exception);
            StatusMessage = null;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task CreateBundleAsync()
    {
        IsBusy = true;
        ErrorMessage = null;
        try
        {
            var path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                $"sslense-diagnostics-{DateTime.Now:yyyyMMdd-HHmmss}.zip");
            var progress = new Progress<ProgressEvent>(value => StatusMessage = value.Message);
            var result = await _bundleService
                .CreateAsync(new DiagnosticBundleRequest(path, RedactHosts), progress)
                .ConfigureAwait(true);
            BundlePath = result.Path;
            StatusMessage = $"Diagnostic bundle saved to {result.Path}. Review it before sharing.";
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Failed to create the diagnostic bundle");
            ErrorMessage = SSLense.Core.Errors.ErrorCode.Describe(exception);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void ShowBundle()
    {
        if (BundlePath is null)
        {
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{BundlePath}\"") { UseShellExecute = true });
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Could not open Explorer for the diagnostic bundle");
            ErrorMessage = $"Could not open Explorer: {exception.Message}";
        }
    }
}

public sealed class HealthCheckRowViewModel(HealthCheckResult result)
{
    public string Name { get; } = result.Name;

    public HealthStatus Status { get; } = result.Status;

    // Text label so status never depends on colour alone.
    public string Result { get; } = result.Status switch
    {
        HealthStatus.Pass => "PASS",
        HealthStatus.Warning => "WARN",
        _ => "FAIL"
    };

    public string Message { get; } = result.Message;

    public string Fix { get; } = result.Fix ?? string.Empty;
}

/// <summary>An unused certificate that can be ticked for removal.</summary>
public sealed partial class UnusedCertificateRow(SSLense.Core.Certificates.CleanupCandidate candidate) : ObservableObject
{
    [ObservableProperty] private bool isChecked;

    public SSLense.Core.Certificates.CleanupCandidate Candidate { get; } = candidate;

    public string Title => $"{Candidate.Name} · {Candidate.Issuer} · expires {Candidate.NotAfter.ToLocalTime():dd MMM yyyy}";
}
