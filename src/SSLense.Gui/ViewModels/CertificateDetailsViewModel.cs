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
    private readonly AsyncRelayCommand _unmanageCommand;
    private readonly AsyncRelayCommand _revokeCommand;
    private readonly IRevocationService? _revocationService;
    private readonly ICertificateHistoryService? _historyService;
    private readonly AsyncRelayCommand _rollbackCommand;
    private readonly SSLense.Core.Iis.IHttpsRedirectService? _redirectService;
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
    [ObservableProperty] private string rollbackMessage = string.Empty;
    [ObservableProperty] private bool canRollBack;

    public CertificateDetailsViewModel(
        ICertificateManagementService managementService,
        IRenewalService renewalService,
        ILogger<CertificateDetailsViewModel> logger,
        INavigationService navigation,
        IReminderService reminderService,
        ICertificateSharingService sharingService,
        IIisService iisService,
        IDeploymentService deploymentService,
        InstallRenewalViewModel installRenewal,
        IRevocationService? revocationService = null,
        SSLense.Core.Iis.IHttpsRedirectService? redirectService = null,
        ICertificateHistoryService? historyService = null)
    {
        _historyService = historyService;
        _rollbackCommand = new AsyncRelayCommand(RollBackAsync, () => CanOperate() && CanRollBack && _historyService is not null);
        _revocationService = revocationService;
        _redirectService = redirectService;
        RedirectOnCommand = new AsyncRelayCommand(token => ChangeRedirectAsync(true, token), () => CanOperate() && _redirectService is not null);
        RedirectOffCommand = new AsyncRelayCommand(token => ChangeRedirectAsync(false, token), () => CanOperate() && _redirectService is not null);
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
        _unmanageCommand = new AsyncRelayCommand(UnmanageAsync, CanOperate);
        _revokeCommand = new AsyncRelayCommand(RevokeAndReplaceAsync, () => CanOperate() && _revocationService is not null);
        RenewByHandCommand = new RelayCommand(() => _navigation.Navigate("Issue", SelectedSite), () => !IsBusy && IsManualDns);

        SharedSites.CollectionChanged += (_, _) => OnPropertyChanged(nameof(ShowSites));
        DeploymentSteps.CollectionChanged += (_, _) => OnPropertyChanged(nameof(HasDeploymentSteps));
        RecentLogLines.CollectionChanged += (_, _) => OnPropertyChanged(nameof(HasHistory));
        Timeline.CollectionChanged += (_, _) => OnPropertyChanged(nameof(HasTimeline));

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
        StartSelection();
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

    /// <summary>
    /// Reads the shown certificate again after the list was reloaded, keeping the last result and check on screen.
    /// A different certificate (the shown one was renamed) is shown afresh.
    /// </summary>
    public async Task ReloadAsync(CertificateRowViewModel row)
    {
        if (!string.Equals(row.SiteName, SelectedSite, StringComparison.OrdinalIgnoreCase))
        {
            await ShowAsync(row).ConfigureAwait(true);
            return;
        }

        Summary = row;
        await RefreshAsync(CancellationToken.None).ConfigureAwait(true);
    }

    /// <summary>Shows no certificate.</summary>
    public void Clear()
    {
        StartSelection();
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
        Timeline.Clear();
        RollbackMessage = string.Empty;
        CanRollBack = false;
    }

    /// <summary>Each manual DNS renewal needs new records, so it goes through the wizard, which shows them.</summary>
    public IRelayCommand RenewByHandCommand { get; }

    public ObservableCollection<string> Sites { get; } = [];
    public ObservableCollection<string> RecentLogLines { get; } = [];

    /// <summary>What happened to the certificate, newest first (docs/design/history-and-rollback.md).</summary>
    public ObservableCollection<string> Timeline { get; } = [];

    public bool HasTimeline => Timeline.Count > 0;

    /// <summary>Binds the certificate the last renewal replaced again.</summary>
    public IAsyncRelayCommand RollBackCommand => _rollbackCommand;

    /// <summary>Every site using the selected certificate, starting with the first site.</summary>
    public ObservableCollection<SharedSiteRow> SharedSites { get; } = [];

    /// <summary>IIS sites not using the selected certificate yet.</summary>
    public ObservableCollection<string> SitesToAdd { get; } = [];

    public IAsyncRelayCommand AddSiteCommand => _addSiteCommand;

    /// <summary>The selected certificate's deployment steps, in the order they run.</summary>
    public ObservableCollection<DeploymentStepRow> DeploymentSteps { get; } = [];

    public IReadOnlyList<DeploymentKindChoice> DeploymentKinds { get; } =
    [
        new("Give an account access to the private key", DeploymentStepKind.GrantKeyAccess, "Account", "Such as IIS AppPool\\Shop or NT Service\\MSSQLSERVER."),
        new("Restart a Windows service", DeploymentStepKind.RestartService, "Service name", "The service name, such as MSSQLSERVER, not its display name."),
        new("Run a PowerShell script", DeploymentStepKind.Script, "Script", "SSLense runs its own copy, checked by hash. Examples are in the deploy-scripts folder where SSLense is installed."),
        new("Export a PFX file", DeploymentStepKind.ExportPfx, "PFX file", "A full path, such as D:\\Certs\\shop.pfx. Needs a certificate issued with an exportable private key."),
        new("Export PEM files", DeploymentStepKind.ExportPem, "Folder", "cert.pem, chain.pem, fullchain.pem, and key.pem, which only administrators can read. Needs an exportable private key."),
        new("Export to the IIS Central Certificate Store", DeploymentStepKind.CentralStore, "Store folder", "One PFX per name, protected by the store's password as set in IIS. Needs an exportable private key."),
        new("Use it for an IIS FTP site", DeploymentStepKind.FtpSite, "FTP site", "The IIS site with the FTP binding, as IIS Manager names it. Set again after every renewal; new FTP connections use the new certificate."),
        new("Import into Azure Key Vault", DeploymentStepKind.KeyVault, "Vault/certificate", "Such as contoso-kv/shop. In the password box, the app registration as tenant:client ID:client secret. Needs an exportable private key."),
        new("Use it for Azure App Service", DeploymentStepKind.AppService, "Subscription/group/app", "Such as <subscription ID>/web-rg/contoso-shop. In the password box, the app registration as tenant:client ID:client secret. The app's custom domains the certificate covers are bound. Needs an exportable private key."),
        new("Bind it in HTTP.sys outside IIS", DeploymentStepKind.HttpSysBinding, "Endpoint", "An IP address and port, such as 0.0.0.0:5986 for WinRM over HTTPS, or a host name and port for SNI, such as api.example.com:8443. Not one an IIS site binds."),
        new("Use it for Remote Desktop", DeploymentStepKind.RemoteDesktop, "Listener", "Type RDP-Tcp. NETWORK SERVICE is given the key, and new connections use the certificate at once."),
        new("Use it for SQL Server", DeploymentStepKind.SqlServer, "Instance", "MSSQLSERVER for the default instance, or its name, such as SQLEXPRESS. Its account is given the key, and it is restarted at every renewal."),
        new("Use it for Apache, nginx or Tomcat", DeploymentStepKind.WebServer, "Server|folder|service", "Such as apache|D:\\Certs\\shop|Apache2.4. PEM files for Apache and nginx; for tomcat, certificate.pfx with the password below. The service is restarted. Needs an exportable private key.")
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

    /// <summary>SSLense stops managing the certificate and leaves IIS and the certificate store as they are.</summary>
    public IAsyncRelayCommand UnmanageCommand => _unmanageCommand;

    /// <summary>Revoke and replace, for a key that may have leaked (docs/design/compromise-recovery.md).</summary>
    public IAsyncRelayCommand RevokeAndReplaceCommand => _revokeCommand;

    /// <summary>The HTTP-to-HTTPS redirect on the certificate's site (docs/design/https-redirect.md).</summary>
    public IAsyncRelayCommand RedirectOnCommand { get; }

    public IAsyncRelayCommand RedirectOffCommand { get; }

    private async Task ChangeRedirectAsync(bool enabled, CancellationToken cancellationToken)
    {
        if (SelectedSite is null || _redirectService is null) return;
        var name = SelectedSite;
        await RunAsync(async token =>
        {
            var message = enabled
                ? await _redirectService.EnableAsync(name, token).ConfigureAwait(true)
                : await _redirectService.DisableAsync(name, token).ConfigureAwait(true);
            _logger.LogInformation("{Message}", message);
            Report(message);
        }, cancellationToken);
    }

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
            ErrorMessage = SSLense.Core.Errors.ErrorCode.Describe(exception);
        }
    }

    partial void OnSelectedSiteChanged(string? value)
    {
        NotifyCommands();
        if (value is not null && !IsBusy && !_suppressSelectionRefresh) _ = _refreshCommand.ExecuteAsync(null);
    }

    partial void OnIsBusyChanged(bool value) => NotifyCommands();

    /// <summary>
    /// Cancelled when another certificate is shown, so a slower load of the previous one cannot write over it. Every
    /// loader checks it after each call, before changing what is shown.
    /// </summary>
    private CancellationTokenSource _selection = new();

    private void StartSelection()
    {
        _selection.Cancel();
        _selection.Dispose();
        _selection = new CancellationTokenSource();
        // A check of the previous certificate still running reports nowhere now.
        IsChecking = false;
    }

    private async Task RefreshAsync(CancellationToken cancellationToken)
    {
        if (SelectedSite is not { } site) return;
        using var load = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _selection.Token);
        await RunAsync(async token =>
        {
            var detail = await _managementService.GetDetailsAsync(site, token).ConfigureAwait(true);
            token.ThrowIfCancellationRequested();
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
            await LoadHistoryAsync(site, token).ConfigureAwait(true);
        }, load.Token);
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
        cancellationToken.ThrowIfCancellationRequested();
        SitesToAdd.Clear();
        // By IIS site: a second certificate on a site is named "site/host", and its own site is not one to add.
        foreach (var site in sites.Where(site => SharedSites.All(row =>
                     !string.Equals(ManagedCertificateNames.IisSiteOf(row.SiteName), site.Name, StringComparison.OrdinalIgnoreCase))))
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
            Report($"'{site}' now shares this certificate ({string.Join(", ", bound)}). They renew together.");
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
            Report(await _sharingService.RemoveSiteAsync(row.SiteName, token).ConfigureAwait(true));
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
            Report(moved.Count == 0
                ? "No site could move yet. Fix the site in IIS, then try again."
                : $"Moved to the current certificate: {string.Join(", ", moved)}.");
            await RefreshAsync(token).ConfigureAwait(true);
            CertificatesChanged?.Invoke(null);
        }, cancellationToken);
    }

    private async Task LoadDeploymentAsync(CancellationToken cancellationToken)
    {
        if (SelectedSite is null) return;
        var overview = await _deploymentService.ListAsync(SelectedSite, cancellationToken).ConfigureAwait(true);
        cancellationToken.ThrowIfCancellationRequested();
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
            Report($"Added: {step.Describe()}. The steps run after every renewal; Run now runs them for this certificate.");
            await LoadDeploymentAsync(token).ConfigureAwait(true);
        }, cancellationToken);
    }

    private async Task RemoveDeploymentStepAsync(DeploymentStepRow? row, CancellationToken cancellationToken)
    {
        if (SelectedSite is null || row is null) return;
        await RunAsync(async token =>
        {
            var removed = await _deploymentService.RemoveAsync(SelectedSite, row.Number, token).ConfigureAwait(true);
            Report($"Removed: {removed.Describe()}. What it already did is not undone.");
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
            Report(result.Message);
        }, cancellationToken);
    }

    private async Task LoadReminderAsync(CancellationToken cancellationToken)

    {
        var overview = await _reminderService.GetOverviewAsync(cancellationToken).ConfigureAwait(true);
        cancellationToken.ThrowIfCancellationRequested();
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
        // The result belongs to this certificate: after another is chosen it is only logged.
        var shown = _selection.Token;
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
                if (shown.IsCancellationRequested) return;
                LastCheckPassed = check.Passed;
                LastCheckText = $"Checked at {DateTime.Now:HH:mm}. {check.Message}";
                if (check.Passed) ResultMessage = check.Message;
                else ErrorMessage = check.Message;
            }, cancellationToken);

            // The check itself could not run, such as when IIS could not be read: say so where its result goes.
            if (!shown.IsCancellationRequested && LastCheckPassed is null && ErrorMessage is { } error)
            {
                LastCheckPassed = false;
                LastCheckText = $"Could not check at {DateTime.Now:HH:mm}. {error}";
            }
        }
        finally
        {
            if (!shown.IsCancellationRequested) IsChecking = false;
        }
    }

    private async Task ApplyReminderAsync(CancellationToken cancellationToken)
    {
        if (SelectedSite is null || SelectedReminderChoice is not { } choice) return;
        await RunAsync(async token =>
        {
            await _reminderService.SetCertificateRemindersAsync(SelectedSite, choice.Mode, choice.SnoozeDays, token).ConfigureAwait(true);
            await LoadReminderAsync(token).ConfigureAwait(true);
            Report($"Reminders: {ReminderState}.");
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
            Report(result.Message);
            CertificatesChanged?.Invoke(null);
            if (!result.Succeeded) throw new InvalidOperationException(result.Message);
            await RefreshAsync(token).ConfigureAwait(true);
        }, cancellationToken);
    }

    private async Task RevokeAndReplaceAsync(CancellationToken cancellationToken)
    {
        if (SelectedSite is null || _revocationService is null) return;
        var name = SelectedSite;
        await RunAsync(async token =>
        {
            var result = await _revocationService.RevokeAsync(name, CertificateRevocationReason.KeyCompromise, replace: true, cancellationToken: token).ConfigureAwait(true);
            _logger.LogWarning("Revoked certificate {Thumbprint} of {Certificate} and replaced it with {NewThumbprint}", result.RevokedThumbprint, name, result.NewThumbprint);
            CertificatesChanged?.Invoke(result.Message);
            await RefreshAsync(token).ConfigureAwait(true);
        }, cancellationToken);
    }

    private async Task LoadHistoryAsync(string site, CancellationToken cancellationToken)
    {
        Timeline.Clear();
        CanRollBack = false;
        if (_historyService is null)
        {
            RollbackMessage = string.Empty;
            return;
        }

        try
        {
            var view = await _historyService.GetAsync(site, cancellationToken).ConfigureAwait(true);
            foreach (var entry in view.Entries)
            {
                Timeline.Add($"{entry.At.ToLocalTime():yyyy-MM-dd HH:mm}  {Describe(entry.Kind)}  {entry.Message}");
            }

            RollbackMessage = view.Rollback.Message;
            CanRollBack = view.Rollback.Available;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // The rest of the certificate's details are still worth showing.
            RollbackMessage = $"The history could not be read: {exception.Message}";
        }
    }

    private static string Describe(CertificateHistoryKind kind) => kind switch
    {
        CertificateHistoryKind.Issued => "Issued",
        CertificateHistoryKind.Renewed => "Renewed",
        CertificateHistoryKind.RenewalFailed => "Renewal failed",
        CertificateHistoryKind.RolledBack => "Rolled back",
        CertificateHistoryKind.Revoked => "Revoked",
        _ => kind.ToString()
    };

    private async Task RollBackAsync(CancellationToken cancellationToken)
    {
        if (SelectedSite is null || _historyService is null) return;
        var name = SelectedSite;
        await RunAsync(async token =>
        {
            var message = await _historyService.RollBackAsync(name, cancellationToken: token).ConfigureAwait(true);
            _logger.LogWarning("Rolled back {Certificate} to its previous certificate", name);
            Report(message);
            CertificatesChanged?.Invoke(null);
            await RefreshAsync(token).ConfigureAwait(true);
        }, cancellationToken);
    }

    private async Task UnmanageAsync(CancellationToken cancellationToken)
    {
        if (SelectedSite is null) return;
        var name = SelectedSite;
        await RunAsync(async token =>
        {
            var message = await _managementService.StopManagingAsync(name, token).ConfigureAwait(true);
            _logger.LogInformation("Stopped managing the certificate for {Certificate}; IIS was not changed", name);
            Clear();
            CertificatesChanged?.Invoke(message);
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
                ? $"Stopped managing '{removedSite}'. The certificate stays in the Windows certificate store for the services that may use it. Delete it there when they no longer do."
                : SharedSites.Count > 1
                ? $"Removed the managed certificate and its IIS HTTPS bindings on {string.Join(", ", SharedSites.Select(row => $"'{row.SiteName}'"))}."
                : $"Removed the managed certificate and its matching IIS HTTPS bindings for '{removedSite}'.";
            Clear();
            CertificatesChanged?.Invoke(message);
        }, cancellationToken);
    }

    /// <summary>Operations running now. Loading a certificate and a choice made meanwhile, such as a reminder, can overlap.</summary>
    private int _running;

    /// <summary>
    /// The certificate shown when the running operation started, as its selection token: an operation that finishes after
    /// another certificate was chosen does not report on the new one. It flows into the operation's continuations.
    /// </summary>
    private static readonly AsyncLocal<CancellationToken> ShownWhenStarted = new();

    /// <summary>True when another certificate was chosen since the running operation started.</summary>
    private static bool Superseded => ShownWhenStarted.Value.IsCancellationRequested;

    /// <summary>Shows the result of an operation, unless another certificate is shown now.</summary>
    private void Report(string message)
    {
        if (!Superseded) ResultMessage = message;
    }

    private async Task RunAsync(Func<CancellationToken, Task> action, CancellationToken cancellationToken)
    {
        _running++;
        ShownWhenStarted.Value = _selection.Token;
        IsBusy = true; ErrorMessage = null;
        try { await action(cancellationToken).ConfigureAwait(true); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Another certificate was chosen, or the operation was cancelled: nothing to report.
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Certificate details operation failed");
            if (!Superseded) ErrorMessage = SSLense.Core.Errors.ErrorCode.Describe(exception);
        }
        finally { IsBusy = --_running > 0; }
    }

    private bool CanOperate() => !IsBusy && SelectedSite is not null;
    partial void OnIsImportedChanged(bool value) => NotifyCommands();
    partial void OnIsManualDnsChanged(bool value) => NotifyCommands();
    partial void OnCanRollBackChanged(bool value) => NotifyCommands();
    partial void OnCanShareChanged(bool value) { NotifyCommands(); OnPropertyChanged(nameof(ShowSites)); }
    partial void OnSiteToAddChanged(string? value) => NotifyCommands();
    partial void OnHasSitesLeftBehindChanged(bool value) { NotifyCommands(); OnPropertyChanged(nameof(ShowSites)); }
    partial void OnSelectedDeploymentKindChanged(DeploymentKindChoice? value) => NotifyCommands();
    partial void OnDeploymentValueChanged(string value) => NotifyCommands();
    private void NotifyCommands()
    {
        (RenewByHandCommand as RelayCommand)?.NotifyCanExecuteChanged();
        _refreshCommand?.NotifyCanExecuteChanged(); _renewCommand?.NotifyCanExecuteChanged(); _removeCommand?.NotifyCanExecuteChanged(); _unmanageCommand?.NotifyCanExecuteChanged(); _revokeCommand?.NotifyCanExecuteChanged(); _rollbackCommand?.NotifyCanExecuteChanged(); (RedirectOnCommand as AsyncRelayCommand)?.NotifyCanExecuteChanged(); (RedirectOffCommand as AsyncRelayCommand)?.NotifyCanExecuteChanged();
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

    public bool NeedsPassword => Kind is DeploymentStepKind.ExportPfx or DeploymentStepKind.CentralStore or DeploymentStepKind.KeyVault or DeploymentStepKind.WebServer or DeploymentStepKind.AppService;

    public override string ToString() => Label;
}
