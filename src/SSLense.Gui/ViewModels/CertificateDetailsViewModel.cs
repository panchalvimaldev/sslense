using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Deployment;
using SSLense.Core.Iis;
using SSLense.Core.Reminders;
using SSLense.Core.Renewal;

namespace SSLense.Gui.ViewModels;

public partial class CertificateDetailsViewModel : ObservableObject
{
    private readonly ICertificateManagementService _managementService;
    private readonly IRenewalService _renewalService;
    private readonly ILogger<CertificateDetailsViewModel> _logger;
    private readonly INavigationService _navigation;
    private readonly IReminderService _reminderService;
    private readonly ICertificateSharingService _sharingService;
    private readonly IIisService _iisService;
    private readonly IDeploymentService _deploymentService;
    private readonly AsyncRelayCommand _addDeploymentStepCommand;
    private readonly AsyncRelayCommand<DeploymentStepRow> _removeDeploymentStepCommand;
    private readonly AsyncRelayCommand _runDeploymentCommand;
    private readonly AsyncRelayCommand _addSiteCommand;
    private readonly AsyncRelayCommand<SharedSiteRow> _stopManagingCommand;
    private readonly AsyncRelayCommand _catchUpCommand;
    private readonly AsyncRelayCommand _applyReminderCommand;
    private readonly AsyncRelayCommand _refreshCommand;
    private readonly AsyncRelayCommand _renewCommand;
    private readonly AsyncRelayCommand _removeCommand;
    private bool _suppressSelectionRefresh;
    private bool _isNoSite;

    [ObservableProperty] private string? selectedSite;

    /// <summary>The certificate's row in the list: its title, state and what to do, in plain words.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasCertificate))]
    private CertificateRowViewModel? summary;

    [ObservableProperty] private bool isBusy;
    [ObservableProperty] private string? errorMessage;
    [ObservableProperty] private string hosts = string.Empty;
    [ObservableProperty] private string issuer = string.Empty;
    [ObservableProperty] private string thumbprint = string.Empty;
    [ObservableProperty] private string issueDate = string.Empty;
    [ObservableProperty] private string expiryDate = string.Empty;
    [ObservableProperty] private string boundSites = string.Empty;
    [ObservableProperty] private string resultMessage = string.Empty;
    [ObservableProperty] private string environment = string.Empty;
    [ObservableProperty] private bool isImported;
    [ObservableProperty] private bool isManualDns;
    [ObservableProperty] private string validation = string.Empty;
    [ObservableProperty] private string certificateNames = string.Empty;
    [ObservableProperty] private ReminderChoice? selectedReminderChoice;
    [ObservableProperty] private string reminderState = string.Empty;
    [ObservableProperty] private string lastReminded = string.Empty;
    [ObservableProperty] private bool canShare;
    [ObservableProperty] private string sharingNote = string.Empty;
    [ObservableProperty] private string? siteToAdd;
    [ObservableProperty] private string hostsToAdd = string.Empty;
    [ObservableProperty] private bool replaceExistingCertificate;
    [ObservableProperty] private bool hasSitesLeftBehind;
    [ObservableProperty] private string deploymentState = string.Empty;
    [ObservableProperty] private bool deploymentPending;
    [ObservableProperty] private DeploymentKindChoice? selectedDeploymentKind;
    [ObservableProperty] private string deploymentValue = string.Empty;
    [ObservableProperty] private string deploymentPassword = string.Empty;

    public CertificateDetailsViewModel(
        ICertificateManagementService managementService,
        IRenewalService renewalService,
        ILogger<CertificateDetailsViewModel> logger,
        INavigationService navigation,
        IReminderService reminderService,
        ICertificateSharingService sharingService,
        IIisService iisService,
        IDeploymentService deploymentService,
        InstallRenewalViewModel installRenewal)
    {
        _deploymentService = deploymentService;
        InstallRenewal = installRenewal;
        installRenewal.Installed += () =>
        {
            _ = _refreshCommand?.ExecuteAsync(null);
            CertificatesChanged?.Invoke(null);
        };
        _addDeploymentStepCommand = new AsyncRelayCommand(AddDeploymentStepAsync, () => CanOperate() && SelectedDeploymentKind is not null && !string.IsNullOrWhiteSpace(DeploymentValue));
        _removeDeploymentStepCommand = new AsyncRelayCommand<DeploymentStepRow>(RemoveDeploymentStepAsync, row => CanOperate() && row is not null);
        _runDeploymentCommand = new AsyncRelayCommand(RunDeploymentAsync, () => CanOperate() && DeploymentSteps.Count > 0);
        // Not held back while the certificate loads: Check reads the site, not what is loading.
        CheckCommand = new AsyncRelayCommand(CheckAsync, () => SelectedSite is not null);
        RemindersOffCommand = new RelayCommand(() => SelectedReminderChoice = ReminderChoices[3], () => !IsBusy && SelectedSite is not null);
        OpenReminderSettingsCommand = new RelayCommand(() => navigation.Navigate("Settings", "Reminders"));
        _reminderService = reminderService;
        _sharingService = sharingService;
        _iisService = iisService;
        _addSiteCommand = new AsyncRelayCommand(AddSiteAsync, () => CanOperate() && CanShare && SiteToAdd is not null);
        _stopManagingCommand = new AsyncRelayCommand<SharedSiteRow>(StopManagingAsync, row => CanOperate() && row is { CanStopManaging: true });
        _catchUpCommand = new AsyncRelayCommand(CatchUpAsync, () => CanOperate() && HasSitesLeftBehind);
        _applyReminderCommand = new AsyncRelayCommand(ApplyReminderAsync, () => CanOperate() && SelectedReminderChoice is not null);
        _managementService = managementService;
        _renewalService = renewalService;
        _logger = logger;
        _navigation = navigation;
        InstallRenewalCommand = new RelayCommand(() => { if (Summary is { } row) _ = InstallRenewal.OpenAsync(row); }, () => !IsBusy && IsImported);
        _refreshCommand = new AsyncRelayCommand(RefreshAsync, CanOperate);
        _renewCommand = new AsyncRelayCommand(RenewAsync, () => CanOperate() && !IsImported && !IsManualDns);
        _removeCommand = new AsyncRelayCommand(RemoveAsync, CanOperate);
        RenewByHandCommand = new RelayCommand(() => _navigation.Navigate("Issue", SelectedSite), () => !IsBusy && IsManualDns);

        SharedSites.CollectionChanged += (_, _) => OnPropertyChanged(nameof(ShowSites));
        DeploymentSteps.CollectionChanged += (_, _) => OnPropertyChanged(nameof(HasDeploymentSteps));
        RecentLogLines.CollectionChanged += (_, _) => OnPropertyChanged(nameof(HasHistory));

        // Last: setting it notifies the commands, so they must all exist by now.
        SelectedDeploymentKind = DeploymentKinds[0];
    }

    /// <summary>
    /// Raised when the certificate changed in a way the list shows, with a message to show there when the
    /// certificate is no longer selected, such as after it was removed.
    /// </summary>
    public event Action<string?>? CertificatesChanged;

    public bool HasCertificate => Summary is not null;

    /// <summary>The Sites section: only for a certificate that can be shared, or already is.</summary>
    public bool ShowSites => CanShare || SharedSites.Count > 1 || HasSitesLeftBehind;

    public bool HasDeploymentSteps => DeploymentSteps.Count > 0;

    public bool HasHistory => RecentLogLines.Count > 0;

    /// <summary>Shows a certificate from the list.</summary>
    public async Task ShowAsync(CertificateRowViewModel row)
    {
        Summary = row;
        LastCheckPassed = null;
        LastCheckText = string.Empty;
        ErrorMessage = null;
        ResultMessage = string.Empty;
        _suppressSelectionRefresh = true;
        SelectedSite = row.SiteName;
        _suppressSelectionRefresh = false;
        await RefreshAsync(CancellationToken.None).ConfigureAwait(true);
    }

    /// <summary>Shows no certificate.</summary>
    public void Clear()
    {
        LastCheckPassed = null;
        LastCheckText = string.Empty;
        _suppressSelectionRefresh = true;
        SelectedSite = null;
        _suppressSelectionRefresh = false;
        Summary = null;
        ErrorMessage = null;
        ResultMessage = string.Empty;
        SharedSites.Clear();
        DeploymentSteps.Clear();
        RecentLogLines.Clear();
    }

    /// <summary>Each manual DNS renewal needs new records, so it goes through the wizard, which shows them.</summary>
    public IRelayCommand RenewByHandCommand { get; }

    public ObservableCollection<string> Sites { get; } = [];
    public ObservableCollection<string> RecentLogLines { get; } = [];

    /// <summary>Every site using the selected certificate, starting with the first site.</summary>
    public ObservableCollection<SharedSiteRow> SharedSites { get; } = [];

    /// <summary>IIS sites not using the selected certificate yet.</summary>
    public ObservableCollection<string> SitesToAdd { get; } = [];

    public IAsyncRelayCommand AddSiteCommand => _addSiteCommand;

    /// <summary>The selected certificate's deployment steps, in the order they run.</summary>
    public ObservableCollection<DeploymentStepRow> DeploymentSteps { get; } = [];

    public IReadOnlyList<DeploymentKindChoice> DeploymentKinds { get; } =
    [
        new("Give an account access to the private key", DeploymentStepKind.GrantKeyAccess, "ACCOUNT", "Such as IIS AppPool\\Shop or NT Service\\MSSQLSERVER."),
        new("Restart a Windows service", DeploymentStepKind.RestartService, "SERVICE NAME", "The service name, such as MSSQLSERVER, not its display name."),
        new("Run a PowerShell script", DeploymentStepKind.Script, "SCRIPT", "SSLense runs its own copy, checked by hash. Examples are in the deploy-scripts folder where SSLense is installed."),
        new("Export a PFX file", DeploymentStepKind.ExportPfx, "PFX FILE", "A full path, such as D:\\Certs\\shop.pfx. Needs a certificate issued with an exportable private key."),
        new("Export PEM files", DeploymentStepKind.ExportPem, "FOLDER", "cert.pem, chain.pem, fullchain.pem, and key.pem, which only administrators can read. Needs an exportable private key."),
        new("Export to the IIS Central Certificate Store", DeploymentStepKind.CentralStore, "STORE FOLDER", "One PFX per name, protected by the store's password as set in IIS. Needs an exportable private key.")
    ];

    public IAsyncRelayCommand AddDeploymentStepCommand => _addDeploymentStepCommand;
    public IAsyncRelayCommand<DeploymentStepRow> RemoveDeploymentStepCommand => _removeDeploymentStepCommand;

    /// <summary>Raised after a step is added, so the view can clear its password box, which cannot be bound.</summary>
    public event Action? PasswordCleared;

    /// <summary>Runs every step now, for the certificate in use.</summary>
    public IAsyncRelayCommand RunDeploymentCommand => _runDeploymentCommand;

    public IAsyncRelayCommand<SharedSiteRow> StopManagingCommand => _stopManagingCommand;

    /// <summary>Moves sites left behind to the current certificate, without ordering a new one.</summary>
    public IAsyncRelayCommand CatchUpCommand => _catchUpCommand;
    public IAsyncRelayCommand RefreshCommand => _refreshCommand;
    public IAsyncRelayCommand RenewCommand => _renewCommand;
    public IAsyncRelayCommand RemoveCommand => _removeCommand;

    /// <summary>A certificate bought from a provider is renewed by the provider; this installs the renewed one.</summary>
    public IRelayCommand InstallRenewalCommand { get; }

    /// <summary>The Install renewal dialog, shown over the window.</summary>
    public InstallRenewalViewModel InstallRenewal { get; }

    public IAsyncRelayCommand ApplyReminderCommand => _applyReminderCommand;

    public IReadOnlyList<ReminderChoice> ReminderChoices { get; } =
    [
        new("On: email me before it expires", ReminderMode.On, null),
        new("Snooze for 7 days", ReminderMode.Snoozed, 7),
        new("Snooze for 30 days", ReminderMode.Snoozed, 30),
        new("Off until this certificate is replaced", ReminderMode.OffUntilReplaced, null),
        new("Off permanently (renewal failures are still reported)", ReminderMode.Off, null)
    ];

    /// <summary>Checks now that IIS serves this certificate on each of its host names.</summary>
    public IAsyncRelayCommand CheckCommand { get; private set; } = null!;

    /// <summary>Turns reminders off until the certificate is replaced, from the ⋯ menu.</summary>
    public IRelayCommand RemindersOffCommand { get; private set; } = null!;

    /// <summary>Settings, at its Reminders tab.</summary>
    public IRelayCommand OpenReminderSettingsCommand { get; private set; } = null!;

    public async Task InitializeAsync(string? requestedSite = null)
    {
        try
        {
            var statuses = await _renewalService.GetStatusAsync();
            Sites.Clear();
            foreach (var status in statuses) Sites.Add(status.SiteName);
            _suppressSelectionRefresh = true;
            SelectedSite = requestedSite is not null && Sites.Contains(requestedSite) ? requestedSite : Sites.FirstOrDefault();
            _suppressSelectionRefresh = false;
            if (SelectedSite is not null) await RefreshAsync(CancellationToken.None);
        }
        catch (Exception exception)
        {
            _suppressSelectionRefresh = false;
            _logger.LogError(exception, "Could not initialize certificate details");
            ErrorMessage = exception.Message;
        }
    }

    partial void OnSelectedSiteChanged(string? value)
    {
        NotifyCommands();
        if (value is not null && !IsBusy && !_suppressSelectionRefresh) _ = _refreshCommand.ExecuteAsync(null);
    }

    partial void OnIsBusyChanged(bool value) => NotifyCommands();

    private async Task RefreshAsync(CancellationToken cancellationToken)
    {
        if (SelectedSite is null) return;
        await RunAsync(async token =>
        {
            var detail = await _managementService.GetDetailsAsync(SelectedSite, token).ConfigureAwait(true);
            Hosts = string.Join(", ", detail.Hosts);
            Issuer = detail.Issuer;
            Thumbprint = detail.Thumbprint;
            IssueDate = detail.NotBefore.ToString("yyyy-MM-dd HH:mm:ss 'UTC'");
            ExpiryDate = detail.NotAfter.ToString("yyyy-MM-dd HH:mm:ss 'UTC'");
            BoundSites = detail.BoundSites.Count == 0 ? "None" : string.Join(", ", detail.BoundSites);
            Environment = detail.AuthorityName;
            IsImported = detail.Source == CertificateSource.Imported;
            LoadSharedSites(detail);
            await LoadReminderAsync(token).ConfigureAwait(true);
            await LoadSitesToAddAsync(token).ConfigureAwait(true);
            await LoadDeploymentAsync(token).ConfigureAwait(true);
            RecentLogLines.Clear();
            foreach (var line in detail.RecentLogLines) RecentLogLines.Add(line);
        }, cancellationToken);
    }

    private void LoadSharedSites(CertificateDetails detail)
    {
        CertificateTarget[] targets = [new(detail.SiteName, detail.Hosts, detail.SitePendingSince), .. detail.AdditionalTargets ?? []];
        SharedSites.Clear();
        foreach (var target in targets)
        {
            SharedSites.Add(new SharedSiteRow(
                target.SiteName,
                string.Join(", ", target.Hosts),
                target.PendingSince is { } since
                    ? $"Left behind on its previous certificate since {since.ToLocalTime():dd MMM yyyy HH:mm}. SSLense keeps trying to move it."
                    : "Using this certificate",
                target.PendingSince is not null,
                targets.Length > 1));
        }

        HasSitesLeftBehind = targets.Any(target => target.PendingSince is not null);
    }

    private async Task LoadSitesToAddAsync(CancellationToken cancellationToken)
    {
        var sites = await _iisService.GetSitesAsync(cancellationToken).ConfigureAwait(true);
        SitesToAdd.Clear();
        foreach (var site in sites.Where(site => SharedSites.All(row => !string.Equals(row.SiteName, site.Name, StringComparison.OrdinalIgnoreCase))))
        {
            SitesToAdd.Add(site.Name);
        }

        SiteToAdd = null;
        HostsToAdd = string.Empty;
        ReplaceExistingCertificate = false;
    }

    private async Task AddSiteAsync(CancellationToken cancellationToken)
    {
        if (SelectedSite is null || SiteToAdd is not { } site) return;
        await RunAsync(async token =>
        {
            var hosts = HostsToAdd.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var bound = await _sharingService.AddSiteAsync(SelectedSite, site, hosts, ReplaceExistingCertificate, null, token).ConfigureAwait(true);
            ResultMessage = $"'{site}' now shares this certificate ({string.Join(", ", bound)}). They renew together.";
            await InitializeAsync(SelectedSite).ConfigureAwait(true);
            CertificatesChanged?.Invoke(null);
        }, cancellationToken);
    }

    private async Task StopManagingAsync(SharedSiteRow? row, CancellationToken cancellationToken)
    {
        if (row is null || SelectedSite is null) return;

        // The next site becomes the first when the first one goes, and the list is by first site.
        var remaining = string.Equals(row.SiteName, SelectedSite, StringComparison.OrdinalIgnoreCase)
            ? SharedSites.First(value => value != row).SiteName
            : SelectedSite;
        await RunAsync(async token =>
        {
            ResultMessage = await _sharingService.RemoveSiteAsync(row.SiteName, token).ConfigureAwait(true);
            await InitializeAsync(remaining).ConfigureAwait(true);
            CertificatesChanged?.Invoke(null);
        }, cancellationToken);
    }

    private async Task CatchUpAsync(CancellationToken cancellationToken)
    {
        if (SelectedSite is null) return;
        await RunAsync(async token =>
        {
            var moved = await _sharingService.CatchUpAsync(SelectedSite, null, token).ConfigureAwait(true);
            ResultMessage = moved.Count == 0
                ? "No site could move yet. Fix the site in IIS, then try again."
                : $"Moved to the current certificate: {string.Join(", ", moved)}.";
            await RefreshAsync(token).ConfigureAwait(true);
            CertificatesChanged?.Invoke(null);
        }, cancellationToken);
    }

    private async Task LoadDeploymentAsync(CancellationToken cancellationToken)
    {
        if (SelectedSite is null) return;
        var overview = await _deploymentService.ListAsync(SelectedSite, cancellationToken).ConfigureAwait(true);
        DeploymentSteps.Clear();
        for (var index = 0; index < overview.Steps.Count; index++)
        {
            var step = overview.Steps[index];
            DeploymentSteps.Add(new DeploymentStepRow(
                index + 1,
                $"{index + 1}. {step.Describe()}" + (step.TimeoutSeconds is { } seconds ? $", up to {seconds} seconds" : string.Empty)));
        }

        DeploymentPending = overview.Pending;
        var state = overview.State;
        DeploymentState = overview.Steps.Count == 0
            ? "None. Steps run after every install and renewal, such as giving an application pool access to the key or restarting a service."
            : overview.Pending
                ? "Pending: not yet succeeded for this certificate. SSLense retries every hour." +
                  (state?.LastError is { } error ? $" Last error: {error}" : string.Empty) +
                  (state?.RetainedThumbprint is { } kept ? $" The previous certificate {kept} is kept until they succeed." : string.Empty)
                : "Done for this certificate." +
                  (state?.LastAttempt is { } at ? $" Last run {at.ToLocalTime():dd MMM yyyy HH:mm}." : " They run after the next renewal, or now with Run now.");
        _runDeploymentCommand.NotifyCanExecuteChanged();
    }

    private async Task AddDeploymentStepAsync(CancellationToken cancellationToken)
    {
        if (SelectedSite is null || SelectedDeploymentKind is not { } kind) return;
        await RunAsync(async token =>
        {
            var step = await _deploymentService
                .AddAsync(new DeploymentStepRequest(SelectedSite, kind.Kind, DeploymentValue.Trim(), Password: kind.NeedsPassword ? DeploymentPassword : null), token)
                .ConfigureAwait(true);
            DeploymentValue = string.Empty;
            DeploymentPassword = string.Empty;
            PasswordCleared?.Invoke();
            ResultMessage = $"Added: {step.Describe()}. The steps run after every renewal; Run now runs them for this certificate.";
            await LoadDeploymentAsync(token).ConfigureAwait(true);
        }, cancellationToken);
    }

    private async Task RemoveDeploymentStepAsync(DeploymentStepRow? row, CancellationToken cancellationToken)
    {
        if (SelectedSite is null || row is null) return;
        await RunAsync(async token =>
        {
            var removed = await _deploymentService.RemoveAsync(SelectedSite, row.Number, token).ConfigureAwait(true);
            ResultMessage = $"Removed: {removed.Describe()}. What it already did is not undone.";
            await LoadDeploymentAsync(token).ConfigureAwait(true);
        }, cancellationToken);
    }

    private async Task RunDeploymentAsync(CancellationToken cancellationToken)
    {
        if (SelectedSite is null) return;
        await RunAsync(async token =>
        {
            var result = await _deploymentService.RunAsync(SelectedSite, null, token).ConfigureAwait(true);
            await LoadDeploymentAsync(token).ConfigureAwait(true);
            if (!result.Succeeded) throw new InvalidOperationException(result.Message);
            ResultMessage = result.Message;
        }, cancellationToken);
    }

    private async Task LoadReminderAsync(CancellationToken cancellationToken)

    {
        var overview = await _reminderService.GetOverviewAsync(cancellationToken).ConfigureAwait(true);
        var record = overview.Certificates.FirstOrDefault(value =>
            string.Equals(value.SiteName, SelectedSite, StringComparison.OrdinalIgnoreCase));
        if (record is null) return;
        IsManualDns = record.Source == CertificateSource.Acme && record.ValidationMethod == ValidationMethod.Dns01Manual;
        Validation = record.Source == CertificateSource.Imported
            ? "Validated by the provider"
            : record.ValidationMethod switch
            {
                ValidationMethod.Dns01Provider => "DNS provider; renews automatically",
                ValidationMethod.Dns01Manual => "Manual DNS; renew it by hand",
                _ => "HTTP (port 80); renews automatically"
            };
        var options = new List<string>();
        if (record.KeyType != CertificateKeyType.EcdsaP256) options.Add($"key {CertificateKeyTypes.Name(record.KeyType)}");
        if (record.Profile is { } profile) options.Add($"profile {profile}");
        if (record.PreferredChain is { } chain) options.Add($"chain to {chain}");
        if (record.ExportableKey) options.Add("exportable key");
        if (record.ReuseKey) options.Add("key kept at renewal");
        if (options.Count > 0) Validation += $". Options: {string.Join(", ", options)}";
        CertificateNames = string.Join(", ", record.CertificateNames ?? record.Hosts);
        CanShare = record.CanBeShared();
        _isNoSite = record.NoSite;
        SharingNote = CanShare
            ? string.Empty
            : record.NoSite
                ? "This certificate has no IIS site, so nothing is bound. Its deployment steps hand it to its services."
            : record.Source == CertificateSource.Imported
                ? "Certificates from other providers cannot be shared for now."
                : "To share this certificate with other sites, issue it again with DNS validation.";
        ReminderState = record.Reminders switch
        {
            ReminderMode.Snoozed when record.SnoozedUntil is { } until && until > DateTimeOffset.UtcNow =>
                $"Snoozed until {until.ToLocalTime():dd MMM yyyy HH:mm}",
            ReminderMode.OffUntilReplaced => "Off until this certificate is replaced",
            ReminderMode.Off => "Off permanently (renewal failures are still reported)",
            _ => $"On: from {overview.Settings.StartDays} days before expiry, in the daily digest at {overview.Settings.SendAtHour:00}:00"
        };
        LastReminded = record.LastRemindedAt is { } at ? at.ToLocalTime().ToString("dd MMM yyyy HH:mm") : "Not yet";
        var settings = overview.Settings;
        ReminderSchedule = $"From {settings.StartDays} days before it expires, in the daily digest at {settings.SendAtHour:00}:00" +
                           (settings.RepeatDays <= 1 ? ", every day until it is renewed." : $", every {settings.RepeatDays} days until it is renewed.");

        // Shown as chosen; choosing another one applies it at once.
        _loadingReminder = true;
        try
        {
            SelectedReminderChoice = record.Reminders switch
            {
                // The snooze that ends closest to it; the line above gives its exact end.
                ReminderMode.Snoozed when record.SnoozedUntil is { } snoozed && snoozed > DateTimeOffset.UtcNow =>
                    (snoozed - DateTimeOffset.UtcNow).TotalDays <= 7.5 ? ReminderChoices[1] : ReminderChoices[2],
                ReminderMode.OffUntilReplaced => ReminderChoices[3],
                ReminderMode.Off => ReminderChoices[4],
                _ => ReminderChoices[0]
            };
        }
        finally
        {
            _loadingReminder = false;
        }
    }

    private bool _loadingReminder;

    /// <summary>When reminders are sent, from Settings › Reminders.</summary>
    [ObservableProperty] private string reminderSchedule = string.Empty;

    /// <summary>The result of the last Check: whether the expected certificate was served, and what was found.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasCheck), nameof(CheckFailed))]
    private bool? lastCheckPassed;

    [ObservableProperty] private string lastCheckText = string.Empty;

    public bool HasCheck => LastCheckPassed is not null;

    public bool CheckFailed => LastCheckPassed == false;

    /// <summary>True while Check connects to the site, which can take up to ten seconds for a site that does not answer.</summary>
    [ObservableProperty] private bool isChecking;

    /// <summary>The section shown: 0 is Status, where Check shows its result.</summary>
    [ObservableProperty] private int selectedSection;

    private async Task CheckAsync(CancellationToken cancellationToken)
    {
        if (SelectedSite is null) return;
        var name = SelectedSite;
        ResultMessage = string.Empty;
        SelectedSection = 0;
        IsChecking = true;
        LastCheckPassed = null;
        LastCheckText = string.Empty;
        _logger.LogInformation("Checking the certificate served for {Certificate}", name);
        try
        {
            await RunAsync(async token =>
            {
                var check = await Task.Run(() => _managementService.CheckServedAsync(name, token), token).ConfigureAwait(true);
                _logger.LogInformation("Check for {Certificate}: {Result}", name, check.Message);
                LastCheckPassed = check.Passed;
                LastCheckText = $"Checked at {DateTime.Now:HH:mm}. {check.Message}";
                if (check.Passed) ResultMessage = check.Message;
                else ErrorMessage = check.Message;
            }, cancellationToken);

            // The check itself could not run, such as when IIS could not be read: say so where its result goes.
            if (LastCheckPassed is null && ErrorMessage is { } error)
            {
                LastCheckPassed = false;
                LastCheckText = $"Could not check at {DateTime.Now:HH:mm}. {error}";
            }
        }
        finally
        {
            IsChecking = false;
        }
    }

    private async Task ApplyReminderAsync(CancellationToken cancellationToken)
    {
        if (SelectedSite is null || SelectedReminderChoice is not { } choice) return;
        await RunAsync(async token =>
        {
            await _reminderService.SetCertificateRemindersAsync(SelectedSite, choice.Mode, choice.SnoozeDays, token).ConfigureAwait(true);
            await LoadReminderAsync(token).ConfigureAwait(true);
            ResultMessage = $"Reminders: {ReminderState}.";
            CertificatesChanged?.Invoke(null);
        }, cancellationToken);
    }

    private async Task RenewAsync(CancellationToken cancellationToken)
    {
        if (SelectedSite is null) return;
        await RunAsync(async token =>
        {
            var result = AssertSingle(await _renewalService.RenewAsync(
                new RenewalRequest(SiteName: SelectedSite, Force: true), null, token).ConfigureAwait(true));
            ResultMessage = result.Message;
            CertificatesChanged?.Invoke(null);
            if (!result.Succeeded) throw new InvalidOperationException(result.Message);
            await RefreshAsync(token).ConfigureAwait(true);
        }, cancellationToken);
    }

    private async Task RemoveAsync(CancellationToken cancellationToken)
    {
        if (SelectedSite is null) return;
        var removedSite = SelectedSite;
        await RunAsync(async token =>
        {
            await _managementService.RemoveAsync(removedSite, token).ConfigureAwait(true);
            var message = _isNoSite
                ? $"Stopped managing '{removedSite}'. The certificate stays in LocalMachine\\My for the services that may use it; delete it in certlm when they no longer do."
                : SharedSites.Count > 1
                ? $"Removed the managed certificate and its IIS HTTPS bindings on {string.Join(", ", SharedSites.Select(row => $"'{row.SiteName}'"))}."
                : $"Removed the managed certificate and its matching IIS HTTPS bindings for '{removedSite}'.";
            Clear();
            CertificatesChanged?.Invoke(message);
        }, cancellationToken);
    }

    /// <summary>Operations running now. Loading a certificate and a choice made meanwhile, such as a reminder, can overlap.</summary>
    private int _running;

    private async Task RunAsync(Func<CancellationToken, Task> action, CancellationToken cancellationToken)
    {
        _running++;
        IsBusy = true; ErrorMessage = null;
        try { await action(cancellationToken).ConfigureAwait(true); }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Certificate details operation failed");
            ErrorMessage = exception.Message;
        }
        finally { IsBusy = --_running > 0; }
    }

    private bool CanOperate() => !IsBusy && SelectedSite is not null;
    partial void OnIsImportedChanged(bool value) => NotifyCommands();
    partial void OnIsManualDnsChanged(bool value) => NotifyCommands();
    partial void OnCanShareChanged(bool value) { NotifyCommands(); OnPropertyChanged(nameof(ShowSites)); }
    partial void OnSiteToAddChanged(string? value) => NotifyCommands();
    partial void OnHasSitesLeftBehindChanged(bool value) { NotifyCommands(); OnPropertyChanged(nameof(ShowSites)); }
    partial void OnSelectedDeploymentKindChanged(DeploymentKindChoice? value) => NotifyCommands();
    partial void OnDeploymentValueChanged(string value) => NotifyCommands();
    private void NotifyCommands()
    {
        (RenewByHandCommand as RelayCommand)?.NotifyCanExecuteChanged();
        _refreshCommand?.NotifyCanExecuteChanged(); _renewCommand?.NotifyCanExecuteChanged(); _removeCommand?.NotifyCanExecuteChanged();
        (InstallRenewalCommand as RelayCommand)?.NotifyCanExecuteChanged();
        (CheckCommand as AsyncRelayCommand)?.NotifyCanExecuteChanged();
        (RemindersOffCommand as RelayCommand)?.NotifyCanExecuteChanged();
        _applyReminderCommand?.NotifyCanExecuteChanged();
        _addSiteCommand?.NotifyCanExecuteChanged();
        _stopManagingCommand?.NotifyCanExecuteChanged();
        _catchUpCommand?.NotifyCanExecuteChanged();
        _addDeploymentStepCommand?.NotifyCanExecuteChanged();
        _removeDeploymentStepCommand?.NotifyCanExecuteChanged();
        _runDeploymentCommand?.NotifyCanExecuteChanged();
    }
    partial void OnSelectedReminderChoiceChanged(ReminderChoice? value)
    {
        _applyReminderCommand?.NotifyCanExecuteChanged();
        // Applied even while the certificate is still loading, so a click is never dropped.
        if (!_loadingReminder && value is not null && SelectedSite is not null) _ = _applyReminderCommand?.ExecuteAsync(null);
    }
    private static RenewalResult AssertSingle(IReadOnlyList<RenewalResult> results) => results.Single();
}

/// <summary>One line of "Sites using this certificate".</summary>
public sealed record SharedSiteRow(string SiteName, string Hosts, string State, bool IsLeftBehind, bool CanStopManaging);

public sealed record ReminderChoice(string Label, ReminderMode Mode, int? SnoozeDays)
{
    public override string ToString() => Label;
}

/// <summary>One deployment step, numbered as 'deploy list' numbers it.</summary>
public sealed record DeploymentStepRow(int Number, string Description);

public sealed record DeploymentKindChoice(string Label, DeploymentStepKind Kind, string ValueLabel, string Hint)
{
    public bool IsScript => Kind == DeploymentStepKind.Script;

    public bool NeedsPassword => Kind is DeploymentStepKind.ExportPfx or DeploymentStepKind.CentralStore;

    public override string ToString() => Label;
}
