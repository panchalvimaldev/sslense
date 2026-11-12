using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using SSLense.Core;
using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.DnsValidation;
using SSLense.Core.Iis;
using SSLense.Core.Validation;

namespace SSLense.Gui.ViewModels;

public partial class IssueCertificateViewModel : ObservableObject
{
    private readonly IIisService _iisService;
    private readonly IPreflightService _preflightService;
    private readonly IAcmeService _acmeService;
    private readonly ISettingsService _settingsService;
    private readonly IImportedCertificateService _certificates;
    private readonly IManagedCertificateStore _managedStore;
    private readonly ICertificateAuthorityService _authorities;
    private readonly ILogger<IssueCertificateViewModel> _logger;
    private readonly AsyncRelayCommand _preflightCommand;
    private readonly AsyncRelayCommand _issueCommand;
    private TaskCompletionSource<bool>? _manualAnswer;
    private ManagedCertificate? _renewing;

    [ObservableProperty] private IisSiteOption? selectedSite;
    [ObservableProperty] private int currentStep = 1;
    [ObservableProperty] private string email = string.Empty;
    [ObservableProperty] private bool isBusy;
    [ObservableProperty] private bool preflightPassed;
    [ObservableProperty] private string? errorMessage;
    [ObservableProperty] private string resultMessage = string.Empty;
    [ObservableProperty] private CertificateAuthorityOverview? selectedAuthority;
    [ObservableProperty] private bool productionRiskAccepted;
    [ObservableProperty] private ValidationMethod selectedValidation = ValidationMethod.Http01;
    [ObservableProperty] private string certificateNames = string.Empty;
    [ObservableProperty] private bool replaceExisting;
    [ObservableProperty] private bool isWaitingForManualDns;
    [ObservableProperty] private string renewalNotice = string.Empty;
    [ObservableProperty] private bool noSite;
    [ObservableProperty] private bool exportableKey;
    [ObservableProperty] private string noSiteName = string.Empty;

    public IssueCertificateViewModel(
        IIisService iisService,
        IPreflightService preflightService,
        IAcmeService acmeService,
        ISettingsService settingsService,
        IImportedCertificateService certificates,
        IManagedCertificateStore managedStore,
        ICertificateAuthorityService authorities,
        ILogger<IssueCertificateViewModel> logger)
    {
        _managedStore = managedStore;
        _authorities = authorities;
        _iisService = iisService;
        _preflightService = preflightService;
        _acmeService = acmeService;
        _settingsService = settingsService;
        _certificates = certificates;
        _logger = logger;
        NextCommand = new RelayCommand(Next, CanNext);
        BackCommand = new RelayCommand(Back, () => !IsBusy && CurrentStep > 1);
        _preflightCommand = new AsyncRelayCommand(RunPreflightAsync, CanRunPreflight);
        _issueCommand = new AsyncRelayCommand(IssueAsync, CanIssue);
        CancelCommand = new RelayCommand(Cancel, () => IsBusy);
        StartOverCommand = new RelayCommand(StartOver, () => !IsBusy);
        ConfirmManualRecordsCommand = new RelayCommand(() => _manualAnswer?.TrySetResult(true), () => IsWaitingForManualDns);
    }

    public ObservableCollection<DnsTxtRecord> ManualRecords { get; } = [];
    public IRelayCommand ConfirmManualRecordsCommand { get; }

    // A radio button clears itself by setting false, which says nothing about which method was chosen.
    public bool UseHttpValidation
    {
        get => SelectedValidation == ValidationMethod.Http01;
        set { if (value) SelectedValidation = ValidationMethod.Http01; }
    }

    public bool UseDnsProvider
    {
        get => SelectedValidation == ValidationMethod.Dns01Provider;
        set { if (value) SelectedValidation = ValidationMethod.Dns01Provider; }
    }

    public bool UseDnsManual
    {
        get => SelectedValidation == ValidationMethod.Dns01Manual;
        set { if (value) SelectedValidation = ValidationMethod.Dns01Manual; }
    }

    public bool UsesDns => SelectedValidation != ValidationMethod.Http01;

    /// <summary>The site picker and host names apply only to a certificate for an IIS site.</summary>
    public bool ShowSitePicker => !NoSite;

    /// <summary>The name of the certificate: the IIS site's, or the one chosen for a certificate with no site.</summary>
    private string CertificateName() => NoSite ? NoSiteName.Trim() : SelectedSite!.Name;

    partial void OnNoSiteChanged(bool value)
    {
        OnPropertyChanged(nameof(ShowSitePicker));

        // HTTP validation needs a site to serve the file.
        if (value && SelectedValidation == ValidationMethod.Http01)
        {
            SelectedValidation = ValidationMethod.Dns01Provider;
        }

        NotifyCommands();
    }

    partial void OnNoSiteNameChanged(string value) => NotifyCommands();
    public bool IsRenewingByHand => _renewing is not null;

    /// <summary>A certificate renewed by hand stays with the CA that issued it; moving CA is a new issue with Replace.</summary>
    public bool CanChooseAuthority => !IsRenewingByHand;

    public string ValidationHint => SelectedValidation switch
    {
        ValidationMethod.Dns01Provider =>
            "SSLense adds a temporary DNS record through a provider set up in Settings, and renews automatically. Port 80 is not needed.",
        ValidationMethod.Dns01Manual =>
            "You create the DNS records yourself, with any DNS service. Port 80 is not needed.",
        _ => "The certificate authority checks the site over port 80, and SSLense renews automatically. This cannot issue wildcard certificates."
    };

    public string PreflightSubtitle => UsesDns
        ? "SSLense checks the bindings, certificate names, and DNS before contacting the certificate authority. Nothing in DNS changes yet."
        : "SSLense checks access, bindings, and challenge-folder permissions before contacting the certificate authority.";

    public ObservableCollection<IisSiteOption> Sites { get; } = [];
    public ObservableCollection<HostOptionViewModel> Hosts { get; } = [];
    public ObservableCollection<PreflightCheckViewModel> PreflightChecks { get; } = [];
    public ObservableCollection<string> ProgressLines { get; } = [];
    public IRelayCommand NextCommand { get; }
    public IRelayCommand BackCommand { get; }
    public IAsyncRelayCommand PreflightCommand => _preflightCommand;
    public IAsyncRelayCommand IssueCommand => _issueCommand;
    public IRelayCommand CancelCommand { get; }
    public IRelayCommand StartOverCommand { get; }
    public bool IsStepOne => CurrentStep == 1;
    public bool IsStepTwo => CurrentStep == 2;
    public bool IsStepThree => CurrentStep == 3;
    /// <summary>Let's Encrypt and every CA added in Settings; Let's Encrypt staging is chosen first.</summary>
    public ObservableCollection<CertificateAuthorityOverview> Authorities { get; } = [];

    /// <summary>The chosen CA issues trusted certificates, so issuing needs the confirmation below.</summary>
    public bool UseProduction => SelectedAuthority is { IsTest: false };
    public string StepTitle => $"Step {CurrentStep} of 3";

    /// <param name="renewSite">A site whose manual DNS certificate is being renewed by hand; the wizard is filled in from its record.</param>
    public async Task InitializeAsync(string? renewSite = null)
    {
        try
        {
            // Read each time the wizard opens, so a CA added in Settings since appears.
            if (!IsBusy)
            {
                var chosen = SelectedAuthority?.Id ?? CertificateAuthorities.LetsEncryptStagingId;
                Authorities.Clear();
                foreach (var authority in await _authorities.ListAsync())
                {
                    Authorities.Add(authority);
                }

                SelectedAuthority = Authorities.FirstOrDefault(value => value.Id == chosen) ?? Authorities.FirstOrDefault();
            }

            if (Sites.Count > 0 && renewSite is null)
            {
                return;
            }

            if (Sites.Count == 0)
            {
                var config = await _settingsService.GetAsync();
                Email = config.DefaultEmail ?? string.Empty;
                var sites = await _iisService.GetSitesAsync();
                var https = await DescribeHttpsAsync();
                foreach (var site in sites)
                {
                    Sites.Add(new IisSiteOption(site.Name, site, https.GetValueOrDefault(site.Name)));
                }
                SelectedSite = Sites.FirstOrDefault();
            }

            if (renewSite is not null && !IsBusy)
            {
                await PrepareRenewalAsync(renewSite);
            }
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Could not initialize the issue wizard");
            ErrorMessage = exception.Message;
        }
    }

    private async Task PrepareRenewalAsync(string siteName)
    {
        var records = await _managedStore.GetAllAsync();
        var record = records.FirstOrDefault(value => string.Equals(value.SiteName, siteName, StringComparison.OrdinalIgnoreCase));
        var site = Sites.FirstOrDefault(value => string.Equals(value.Name, siteName, StringComparison.OrdinalIgnoreCase));
        if (record is { NoSite: true })
        {
            StartOver();
            NoSite = true;
            NoSiteName = record.SiteName;
            SelectedValidation = record.ValidationMethod;
            CertificateNames = string.Join(", ", record.CertificateNames ?? record.Hosts);
            Email = record.Email;
            SelectedAuthority = Authorities.FirstOrDefault(value => string.Equals(value.Id, record.AuthorityId, StringComparison.OrdinalIgnoreCase)) ?? SelectedAuthority;
            SetRenewing(record);
            Next();
            return;
        }

        if (record is null || site is null)
        {
            ErrorMessage = $"The certificate or IIS site for '{siteName}' was not found.";
            return;
        }

        StartOver();
        SelectedSite = site;
        SelectedValidation = record.ValidationMethod;
        foreach (var host in Hosts)
        {
            host.IsSelected = record.Hosts.Contains(host.Host, StringComparer.OrdinalIgnoreCase);
        }

        CertificateNames = record.CertificateNames is { } names ? string.Join(", ", names) : string.Empty;
        Email = record.Email;
        SelectedAuthority = Authorities.FirstOrDefault(value => string.Equals(value.Id, record.AuthorityId, StringComparison.OrdinalIgnoreCase));
        if (SelectedAuthority is null)
        {
            ErrorMessage = $"The certificate for '{siteName}' came from '{record.AuthorityId}', which is no longer set up. Add it again under Settings → Certificate authorities.";
            return;
        }
        SetRenewing(record);
        Next();
    }

    private void SetRenewing(ManagedCertificate? record)
    {
        _renewing = record;
        RenewalNotice = record is null
            ? string.Empty
            : $"Renewing the certificate for '{record.SiteName}' by hand. The current certificate stays in place until the new one is ready.";
        OnPropertyChanged(nameof(IsRenewingByHand));
        OnPropertyChanged(nameof(CanChooseAuthority));
    }

    /// <summary>
    /// Per site, the certificates it already serves over HTTPS. Such a site is not hidden: replacing a certificate bought
    /// elsewhere with Let's Encrypt is a normal reason to issue, but the administrator should see what is replaced.
    /// </summary>
    private async Task<Dictionary<string, string>> DescribeHttpsAsync()
    {
        try
        {
            var bindings = await _certificates.DiscoverAsync().ConfigureAwait(true);
            return bindings.Where(binding => binding.Thumbprint is not null)
                .GroupBy(binding => binding.SiteName, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    group => group.Key,
                    group => string.Join("; ", group.Select(binding =>
                        $"{(binding.Host.Length == 0 ? "(no host name)" : binding.Host)}:{binding.Port} uses a certificate from " +
                        $"{binding.IssuerName ?? "an unknown issuer"}" +
                        (binding.NotAfter is { } expires ? $", expiring {expires.LocalDateTime:dd MMM yyyy}" : string.Empty) +
                        (binding.IsManaged ? " (managed by SSLense)" : string.Empty))),
                    StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // Only a hint; the wizard works without it.
            _logger.LogWarning(exception, "Could not describe existing HTTPS bindings");
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    partial void OnSelectedSiteChanged(IisSiteOption? value)
    {
        SetRenewing(null);
        ReplaceExisting = false;
        foreach (var host in Hosts)
        {
            host.PropertyChanged -= OnHostPropertyChanged;
        }
        Hosts.Clear();
        if (value is not null)
        {
            var names = value.Site.Bindings.Where(binding => !string.IsNullOrWhiteSpace(binding.HostName))
                .Select(binding => binding.HostName).Distinct(StringComparer.OrdinalIgnoreCase);
            foreach (var name in names)
            {
                var ready = value.Site.Bindings.Any(binding =>
                    string.Equals(binding.Protocol, "http", StringComparison.OrdinalIgnoreCase) &&
                    binding.Port == 80 && string.Equals(binding.HostName, name, StringComparison.OrdinalIgnoreCase));
                var dnsReady = !name.Contains('*') && value.Site.Bindings.Any(binding =>
                    binding.Protocol is "http" or "https" &&
                    string.Equals(binding.HostName, name, StringComparison.OrdinalIgnoreCase));
                var option = new HostOptionViewModel(name, ready, dnsReady) { UsesDns = UsesDns };
                option.IsSelected = option.IsReady;
                option.PropertyChanged += OnHostPropertyChanged;
                Hosts.Add(option);
            }
        }
        NotifyCommands();
    }

    partial void OnSelectedValidationChanged(ValidationMethod value)
    {
        OnPropertyChanged(nameof(UseHttpValidation));
        OnPropertyChanged(nameof(UseDnsProvider));
        OnPropertyChanged(nameof(UseDnsManual));
        OnPropertyChanged(nameof(UsesDns));
        OnPropertyChanged(nameof(ValidationHint));
        OnPropertyChanged(nameof(PreflightSubtitle));
        foreach (var host in Hosts)
        {
            host.UsesDns = UsesDns;
            host.IsSelected = host.IsReady;
        }

        PreflightPassed = false;
        NotifyCommands();
    }

    partial void OnCertificateNamesChanged(string value)
    {
        PreflightPassed = false;
        NotifyCommands();
    }

    partial void OnIsWaitingForManualDnsChanged(bool value) => NotifyCommands();

    partial void OnCurrentStepChanged(int value)
    {
        OnPropertyChanged(nameof(IsStepOne));
        OnPropertyChanged(nameof(IsStepTwo));
        OnPropertyChanged(nameof(IsStepThree));
        OnPropertyChanged(nameof(StepTitle));
        NotifyCommands();
    }

    partial void OnEmailChanged(string value) => NotifyCommands();
    partial void OnPreflightPassedChanged(bool value) => NotifyCommands();
    partial void OnIsBusyChanged(bool value) => NotifyCommands();
    partial void OnSelectedAuthorityChanged(CertificateAuthorityOverview? value)
    {
        OnPropertyChanged(nameof(UseProduction));

        // A confirmation for one CA never carries over to another.
        ProductionRiskAccepted = false;
        PreflightPassed = false;
        NotifyCommands();
    }
    partial void OnProductionRiskAcceptedChanged(bool value) => NotifyCommands();

    private void OnHostPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(HostOptionViewModel.IsSelected))
        {
            PreflightPassed = false;
            NotifyCommands();
        }
    }

    private void Next()
    {
        CurrentStep = 2;
        PreflightPassed = false;
        PreflightChecks.Clear();
    }

    private void Back() => CurrentStep = Math.Max(1, CurrentStep - 1);

    private async Task RunPreflightAsync(CancellationToken cancellationToken)
    {
        await RunBusyAsync(async token =>
        {
            PreflightChecks.Clear();
            var checks = UsesDns
                ? await _preflightService.CheckDnsAsync(
                    new DnsPreflightRequest(CertificateName(), NoSite ? [] : SelectedHosts(), SelectedNames(), SelectedValidation, SelectedAuthorityId(), NoSite),
                    token).ConfigureAwait(true)
                : await _preflightService.CheckAsync(SelectedSite!.Name, SelectedHosts(), token).ConfigureAwait(true);
            foreach (var check in checks)
            {
                PreflightChecks.Add(new PreflightCheckViewModel(check));
            }
            PreflightPassed = checks.Count > 0 && checks.All(check => check.Succeeded);
            ResultMessage = PreflightPassed ? "All pre-flight checks passed." : "Fix the failed checks before issuing.";
        }, cancellationToken);
    }

    private async Task IssueAsync(CancellationToken cancellationToken)
    {
        CurrentStep = 3;
        ProgressLines.Clear();
        ResultMessage = string.Empty;
        ManualRecords.Clear();
        await RunBusyAsync(async token =>
        {
            var result = await _acmeService.IssueAsync(
                new AcmeIssueRequest(
                    CertificateName(),
                    NoSite ? [] : SelectedHosts(),
                    Email,
                    OutputDirectory: _renewing?.OutputDirectory,
                    Force: ReplaceExisting || _renewing is not null,
                    AuthorityId: SelectedAuthorityId(),
                    ExpectedCurrentThumbprint: _renewing?.Thumbprint,
                    ValidationMethod: SelectedValidation,
                    ConfirmManualDns: SelectedValidation == ValidationMethod.Dns01Manual ? ConfirmManualDnsAsync : null,
                    CertificateNames: UsesDns ? SelectedNames() : null,
                    AcceptProductionRisk: UseProduction && ProductionRiskAccepted,
                    NoSite: NoSite,
                    ExportableKey: _renewing?.ExportableKey ?? ExportableKey),
                new Progress<ProgressEvent>(value =>
                    ProgressLines.Add($"[{DateTime.Now:HH:mm:ss}] [{value.Step}] {value.Message}")),
                token).ConfigureAwait(true);
            ResultMessage = $"Certificate from {SelectedAuthority?.Name ?? "the certificate authority"} installed successfully. Thumbprint: {result.CertificateThumbprint}" +
                            (SelectedValidation == ValidationMethod.Dns01Manual ? " You can now delete the TXT records you created." : string.Empty);
        }, cancellationToken);
    }

    private Task<bool> ConfirmManualDnsAsync(IReadOnlyList<DnsTxtRecord> records, CancellationToken token) =>
        // Core continues on a pool thread, and the records and commands belong to the UI thread.
        Application.Current.Dispatcher.InvokeAsync(() => ShowManualRecordsAsync(records, token)).Task.Unwrap();

    private async Task<bool> ShowManualRecordsAsync(IReadOnlyList<DnsTxtRecord> records, CancellationToken token)
    {
        var answer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _manualAnswer = answer;
        ManualRecords.Clear();
        foreach (var record in records)
        {
            ManualRecords.Add(record);
        }

        IsWaitingForManualDns = true;
        await using var cancellation = token.Register(() => answer.TrySetCanceled(token));
        try
        {
            return await answer.Task.ConfigureAwait(true);
        }
        finally
        {
            _manualAnswer = null;
            IsWaitingForManualDns = false;
        }
    }

    private async Task RunBusyAsync(Func<CancellationToken, Task> action, CancellationToken cancellationToken)
    {
        IsBusy = true;
        ErrorMessage = null;
        try { await action(cancellationToken).ConfigureAwait(true); }
        catch (OperationCanceledException) { ResultMessage = "Operation cancelled."; }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Issue wizard operation failed");
            ErrorMessage = exception.Message;
        }
        finally { IsBusy = false; }
    }

    private IReadOnlyList<string> SelectedHosts() => Hosts.Where(value => value.IsSelected).Select(value => value.Host).ToArray();
    private string SelectedAuthorityId() => SelectedAuthority?.Id ?? CertificateAuthorities.LetsEncryptStagingId;
    private IReadOnlyList<string>? SelectedNames() =>
        CertificateNames.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) is { Length: > 0 } names ? names : null;
    private bool CanNext() => !IsBusy && CurrentStep == 1 && (NoSite
        ? !string.IsNullOrWhiteSpace(NoSiteName) && SelectedNames() is not null && UsesDns
        : SelectedSite is not null && Hosts.Any(value => value.IsSelected));
    private bool CanRunPreflight() => !IsBusy && CurrentStep == 2 && (NoSite || SelectedSite is not null) && !string.IsNullOrWhiteSpace(Email);
    private bool CanIssue() =>
        !IsBusy && CurrentStep == 2 && PreflightPassed && (!UseProduction || ProductionRiskAccepted);
    private void Cancel() { _preflightCommand.Cancel(); _issueCommand.Cancel(); }
    private void StartOver() { CurrentStep = 1; NoSite = false; ExportableKey = false; NoSiteName = string.Empty; PreflightPassed = false; ProductionRiskAccepted = false; ReplaceExisting = false; CertificateNames = string.Empty; SetRenewing(null); PreflightChecks.Clear(); ProgressLines.Clear(); ManualRecords.Clear(); ErrorMessage = null; ResultMessage = string.Empty; }
    private void NotifyCommands()
    {
        (NextCommand as RelayCommand)?.NotifyCanExecuteChanged();
        (BackCommand as RelayCommand)?.NotifyCanExecuteChanged();
        _preflightCommand.NotifyCanExecuteChanged();
        _issueCommand.NotifyCanExecuteChanged();
        (CancelCommand as RelayCommand)?.NotifyCanExecuteChanged();
        (StartOverCommand as RelayCommand)?.NotifyCanExecuteChanged();
        (ConfirmManualRecordsCommand as RelayCommand)?.NotifyCanExecuteChanged();
    }
}
