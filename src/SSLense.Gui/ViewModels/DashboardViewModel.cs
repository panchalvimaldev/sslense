using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using SSLense.Core;
using SSLense.Core.Diagnostics;
using SSLense.Core.Renewal;

namespace SSLense.Gui.ViewModels;

/// <summary>The Certificates tab: the list of managed certificates, grouped by IIS site, and the selected one.</summary>
public partial class DashboardViewModel : ObservableObject
{
    private readonly IRenewalService _renewalService;
    private readonly IHealthCheckService _healthCheckService;
    private readonly ILogger<DashboardViewModel> _logger;
    private readonly INavigationService _navigation;
    private readonly AsyncRelayCommand _refreshCommand;
    private readonly AsyncRelayCommand _renewAllCommand;
    private readonly RelayCommand _cancelCommand;
    private bool _reloading;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelection), nameof(ShowOverview))]
    private CertificateRowViewModel? selectedCertificate;

    /// <summary>Text typed in the list's filter box, matched against host names and certificate names.</summary>
    [ObservableProperty]
    private string filter = string.Empty;

    [ObservableProperty]
    private bool isBusy;

    [ObservableProperty]
    private string activity = "Ready.";

    [ObservableProperty]
    private string? errorMessage;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasHealthAlert))]
    private string? healthAlertTitle;

    /// <summary>Quick health result for the window header: Checking, Ok, Warning, Fail, or Unknown.</summary>
    [ObservableProperty]
    private string healthState = "Checking";

    [ObservableProperty]
    private string? healthAlertDetails;

    public DashboardViewModel(
        IRenewalService renewalService,
        IHealthCheckService healthCheckService,
        ILogger<DashboardViewModel> logger,
        INavigationService navigation,
        CertificateDetailsViewModel details)
    {
        Details = details;
        _renewalService = renewalService;
        _healthCheckService = healthCheckService;
        _logger = logger;
        _navigation = navigation;
        _refreshCommand = new AsyncRelayCommand(RefreshAsync, CanRun);
        _renewAllCommand = new AsyncRelayCommand(RenewAllAsync, CanRenewAll);
        _cancelCommand = new RelayCommand(Cancel, CanCancel);
        AddCertificateCommand = new RelayCommand(() => _navigation.Navigate("Add certificate"));
        OpenHealthCommand = new RelayCommand(() => _navigation.Navigate("Health"));
        ClearSelectionCommand = new RelayCommand(() => SelectedCertificate = null);
        SelectCommand = new RelayCommand<CertificateRowViewModel>(row => SelectedCertificate = row);
        ProgressLines.CollectionChanged += (_, _) => OnPropertyChanged(nameof(HasProgress));

        CertificatesView = new ListCollectionView(Certificates);
        CertificatesView.GroupDescriptions.Add(new PropertyGroupDescription(nameof(CertificateRowViewModel.GroupName)));
        CertificatesView.SortDescriptions.Add(new SortDescription(nameof(CertificateRowViewModel.IsNoSite), ListSortDirection.Ascending));
        CertificatesView.SortDescriptions.Add(new SortDescription(nameof(CertificateRowViewModel.IisSite), ListSortDirection.Ascending));
        CertificatesView.SortDescriptions.Add(new SortDescription(nameof(CertificateRowViewModel.Title), ListSortDirection.Ascending));
        CertificatesView.Filter = item => item is CertificateRowViewModel row && Matches(row);

        // Renewing, removing or changing a certificate on its own screen changes the list too.
        details.CertificatesChanged += message =>
        {
            if (message is not null) Notice = message;
            _ = _refreshCommand.ExecuteAsync(null);
        };
        DismissNoticeCommand = new RelayCommand(() => Notice = null);
    }

    /// <summary>A result to show above the list, such as after a certificate was removed.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasNotice))]
    private string? notice;

    public bool HasNotice => Notice is not null;

    public IRelayCommand DismissNoticeCommand { get; }

    /// <summary>The selected certificate, shown beside the list.</summary>
    public CertificateDetailsViewModel Details { get; }

    public ObservableCollection<CertificateRowViewModel> Certificates { get; } = [];

    /// <summary>The list as shown: grouped by IIS site, sorted and filtered.</summary>
    public ListCollectionView CertificatesView { get; }

    /// <summary>Certificates that need the administrator, for the summary shown when none is selected.</summary>
    public ObservableCollection<CertificateRowViewModel> NeedsAttention { get; } = [];

    public ObservableCollection<string> ProgressLines { get; } = [];

    public int TotalCount => Certificates.Count;

    public int AttentionCount => NeedsAttention.Count;

    public int AutomaticCount => Certificates.Count(value => value.IsAutomatic);

    public int ByHandCount => Certificates.Count(value => !value.IsAutomatic);

    public bool HasCertificates => Certificates.Count > 0;

    public bool HasNoCertificates => Certificates.Count == 0;

    public bool HasAttention => NeedsAttention.Count > 0;

    public bool AllFine => Certificates.Count > 0 && NeedsAttention.Count == 0;

    public bool HasSelection => SelectedCertificate is not null;

    public bool ShowOverview => SelectedCertificate is null;

    public IAsyncRelayCommand RefreshCommand => _refreshCommand;

    /// <summary>Renews every automatic certificate that is due. Bought ones are installed by the administrator.</summary>
    public IAsyncRelayCommand RenewAllCommand => _renewAllCommand;

    public IRelayCommand CancelCommand => _cancelCommand;

    public IRelayCommand AddCertificateCommand { get; }

    public IRelayCommand OpenHealthCommand { get; }

    public IRelayCommand ClearSelectionCommand { get; }

    /// <summary>Selects a certificate from the summary's "Needs your attention" list.</summary>
    public IRelayCommand<CertificateRowViewModel> SelectCommand { get; }

    public bool HasHealthAlert => HealthAlertTitle is not null;

    public IRelayCommand ClearProgressCommand => new RelayCommand(ProgressLines.Clear);

    public bool HasProgress => ProgressLines.Count > 0;

    public bool ShowActivity => IsBusy || !string.IsNullOrEmpty(ErrorMessage);

    public Task InitializeAsync() => _refreshCommand.ExecuteAsync(null);

    /// <summary>Selects a certificate by its name, as when another screen asks for it.</summary>
    public async Task SelectAsync(string? siteName)
    {
        if (Certificates.Count == 0) await InitializeAsync().ConfigureAwait(true);
        SelectedCertificate = siteName is null
            ? null
            : Certificates.FirstOrDefault(value => string.Equals(value.SiteName, siteName, StringComparison.OrdinalIgnoreCase));
    }

    partial void OnSelectedCertificateChanged(CertificateRowViewModel? value)
    {
        if (_reloading) return;
        if (value is null) Details.Clear();
        else _ = Details.ShowAsync(value);
    }

    partial void OnFilterChanged(string value) => CertificatesView.Refresh();

    partial void OnErrorMessageChanged(string? value) => OnPropertyChanged(nameof(ShowActivity));

    partial void OnIsBusyChanged(bool value)
    {
        OnPropertyChanged(nameof(ShowActivity));
        _refreshCommand.NotifyCanExecuteChanged();
        _renewAllCommand.NotifyCanExecuteChanged();
        _cancelCommand.NotifyCanExecuteChanged();
    }

    private bool Matches(CertificateRowViewModel row)
    {
        var text = Filter.Trim();
        return text.Length == 0
               || row.Hosts.Contains(text, StringComparison.OrdinalIgnoreCase)
               || row.SiteName.Contains(text, StringComparison.OrdinalIgnoreCase);
    }

    private Task RefreshAsync(CancellationToken cancellationToken) =>
        RunOperationAsync("Refreshing managed certificates...", LoadCertificatesAsync, cancellationToken);

    private Task RenewAllAsync(CancellationToken cancellationToken) =>
        RunOperationAsync(
            "Renewing the certificates that are due...",
            async token =>
            {
                var results = await _renewalService.RenewAsync(
                        new RenewalRequest(All: true),
                        CreateProgress(),
                        token)
                    .ConfigureAwait(true);
                AddResults(results);
                await LoadCertificatesAsync(token).ConfigureAwait(true);
            },
            cancellationToken);

    private async Task RunOperationAsync(
        string activity,
        Func<CancellationToken, Task> action,
        CancellationToken cancellationToken)
    {
        IsBusy = true;
        ErrorMessage = null;
        Activity = activity;
        try
        {
            await action(cancellationToken).ConfigureAwait(true);
            Activity = "Ready.";
        }
        catch (OperationCanceledException)
        {
            Activity = "Operation cancelled.";
            AddProgress("cancel", "Operation cancelled.");
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Certificates operation failed");
            ErrorMessage = exception.Message;
            Activity = "Operation failed.";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task LoadCertificatesAsync(CancellationToken cancellationToken)
    {
        var statuses = await _renewalService.GetStatusAsync(cancellationToken).ConfigureAwait(true);
        // The details' name wins: stopping the first site of a shared certificate renames it.
        var kept = SelectedCertificate is null ? null : Details.SelectedSite ?? SelectedCertificate.SiteName;
        _reloading = true;
        try
        {
            Certificates.Clear();
            NeedsAttention.Clear();
            foreach (var status in statuses)
            {
                var row = new CertificateRowViewModel(status);
                Certificates.Add(row);
                if (row.NeedsAttention) NeedsAttention.Add(row);
            }

            // Keep the same certificate selected, now with its new state.
            SelectedCertificate = kept is null
                ? null
                : Certificates.FirstOrDefault(value => string.Equals(value.SiteName, kept, StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            _reloading = false;
        }

        if (SelectedCertificate is { } selected) Details.Summary = selected;
        else if (kept is not null) Details.Clear();

        OnPropertyChanged(nameof(TotalCount));
        OnPropertyChanged(nameof(AttentionCount));
        OnPropertyChanged(nameof(AutomaticCount));
        OnPropertyChanged(nameof(ByHandCount));
        OnPropertyChanged(nameof(HasCertificates));
        OnPropertyChanged(nameof(HasNoCertificates));
        OnPropertyChanged(nameof(HasAttention));
        OnPropertyChanged(nameof(AllFine));
        _renewAllCommand.NotifyCanExecuteChanged();
        await UpdateHealthAlertAsync(cancellationToken).ConfigureAwait(true);
    }

    private async Task UpdateHealthAlertAsync(CancellationToken cancellationToken)
    {
        try
        {
            var problems = (await _healthCheckService.RunQuickAsync(cancellationToken).ConfigureAwait(true))
                .Where(result => result.Status != HealthStatus.Pass)
                .OrderByDescending(result => result.Status)
                .ToArray();
            HealthAlertDetails = problems.Length == 0
                ? null
                : string.Join(" ", problems.Take(2).Select(result => $"{result.Name}: {result.Message}")) +
                  (problems.Length > 2 ? $" (+{problems.Length - 2} more)" : string.Empty);
            HealthAlertTitle = problems.Length == 0
                ? null
                : problems[0].Status == HealthStatus.Fail
                    ? $"{problems.Length} health problem(s) need attention"
                    : $"{problems.Length} health warning(s)";
            HealthState = problems.Length == 0 ? "Ok" : problems[0].Status == HealthStatus.Fail ? "Fail" : "Warning";
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // The header status is advisory; the certificate list has already loaded.
            _logger.LogWarning(exception, "Quick health check failed");
            HealthState = "Unknown";
        }
    }

    private IProgress<ProgressEvent> CreateProgress() =>
        new Progress<ProgressEvent>(value => AddProgress(value.Step, value.Message));

    private void AddResults(IEnumerable<RenewalResult> results)
    {
        foreach (var result in results)
        {
            AddProgress(result.Succeeded ? "result" : "error", $"{result.SiteName}: {result.Message}");
        }
    }

    private void AddProgress(string step, string message)
    {
        ProgressLines.Add($"[{DateTime.Now:HH:mm:ss}] [{step}] {message}");
        while (ProgressLines.Count > 200)
        {
            ProgressLines.RemoveAt(0);
        }
    }

    private bool CanRun() => !IsBusy;

    private bool CanRenewAll() => !IsBusy && Certificates.Count > 0;

    private bool CanCancel() => IsBusy;

    private void Cancel()
    {
        _refreshCommand.Cancel();
        _renewAllCommand.Cancel();
    }
}
