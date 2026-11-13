using System.Collections.ObjectModel;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using SSLense.Core;
using SSLense.Core.Certificates;

namespace SSLense.Gui.ViewModels;

/// <summary>
/// The Install renewal dialog for a certificate bought from a provider: choose the file, confirm, done
/// (docs/design/gui-redesign.md, step 2). Installing is <see cref="IImportedCertificateService"/>'s, with its
/// checks, HTTPS verification and rollback; this class only gathers the files and shows the outcome.
/// </summary>
public partial class InstallRenewalViewModel : ObservableObject
{
    public const int ChooseStep = 1;
    public const int ConfirmStep = 2;
    public const int DoneStep = 3;

    private readonly IImportedCertificateService _service;
    private readonly IPendingRequestStore _pendingStore;
    private readonly INavigationService _navigation;
    private readonly ILogger<InstallRenewalViewModel> _logger;
    private readonly RelayCommand _nextCommand;
    private readonly AsyncRelayCommand _installCommand;

    [ObservableProperty] private bool isOpen;
    [ObservableProperty] private bool isBusy;
    [ObservableProperty] private string? errorMessage;
    [ObservableProperty] private string resultText = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsChooseStep), nameof(IsConfirmStep), nameof(IsDoneStep), nameof(StepText))]
    private int step = ChooseStep;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Title), nameof(ConfirmText))]
    private CertificateRowViewModel? certificate;

    /// <summary>The request SSLense created for this certificate, waiting for the provider's certificate file.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasPendingRequest), nameof(PendingRequestText))]
    private PendingCertificateRequest? pendingRequest;

    /// <summary>True: a PFX file with its private key; false: the certificate the provider issued for the pending request.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(UseRequest), nameof(ConfirmText))]
    private bool usePfx = true;

    [ObservableProperty] private string pfxPath = string.Empty;
    [ObservableProperty] private string pfxPassword = string.Empty;
    [ObservableProperty] private string certificatePath = string.Empty;
    [ObservableProperty] private string chainPath = string.Empty;

    public InstallRenewalViewModel(
        IImportedCertificateService service,
        IPendingRequestStore pendingStore,
        INavigationService navigation,
        ILogger<InstallRenewalViewModel> logger)
    {
        _service = service;
        _pendingStore = pendingStore;
        _navigation = navigation;
        _logger = logger;
        _nextCommand = new RelayCommand(() => Step = ConfirmStep, CanContinue);
        _installCommand = new AsyncRelayCommand(InstallAsync, () => !IsBusy && CanContinue());
        BackCommand = new RelayCommand(() => { ErrorMessage = null; Step = ChooseStep; });
        CloseCommand = new RelayCommand(Close, () => !IsBusy);
        CreateRequestCommand = new RelayCommand(CreateRequest);
    }

    /// <summary>Raised after a renewal was installed, so the certificate's screen and the list show it.</summary>
    public event Action? Installed;

    public ObservableCollection<string> ProgressLines { get; } = [];

    public IRelayCommand NextCommand => _nextCommand;
    public IAsyncRelayCommand InstallCommand => _installCommand;
    public IRelayCommand BackCommand { get; }
    public IRelayCommand CloseCommand { get; }

    /// <summary>For a provider that needs a request (CSR): Add certificate, filled in for this certificate.</summary>
    public IRelayCommand CreateRequestCommand { get; }

    public bool IsChooseStep => Step == ChooseStep;
    public bool IsConfirmStep => Step == ConfirmStep;
    public bool IsDoneStep => Step == DoneStep;
    public string StepText => $"Step {Step} of 3";
    public bool UseRequest => !UsePfx;
    public bool HasPendingRequest => PendingRequest is not null;

    public string Title => $"Install renewal for {Certificate?.Title}";

    public string PendingRequestText => PendingRequest is { } request
        ? $"SSLense created a request (CSR) for {string.Join(", ", request.Hosts)} on {request.CreatedAt.LocalDateTime:dd MMM yyyy}. Choose the certificate the provider issued for it."
        : string.Empty;

    public string ConfirmText => Certificate is not { } row
        ? string.Empty
        : $"SSLense replaces the certificate for {string.Join(", ", row.HostList)} on IIS site {row.IisSite} with the one in " +
          $"{Path.GetFileName(UsePfx ? PfxPath : CertificatePath)}. Only this certificate's bindings change; the other certificates on the site stay as they are. " +
          "The new certificate is checked first: its domains, dates, chain and private key. If the site then doesn't serve it correctly, the previous certificate is put back.";

    /// <summary>Opens the dialog for a certificate from the list.</summary>
    public async Task OpenAsync(CertificateRowViewModel row)
    {
        Certificate = row;
        Step = ChooseStep;
        PfxPath = string.Empty;
        PfxPassword = string.Empty;
        CertificatePath = string.Empty;
        ChainPath = string.Empty;
        ErrorMessage = null;
        ResultText = string.Empty;
        ProgressLines.Clear();
        PendingRequest = null;
        UsePfx = true;
        IsOpen = true;
        try
        {
            PendingRequest = await _pendingStore.GetAsync(row.SiteName).ConfigureAwait(true);
            UsePfx = PendingRequest is null;
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Could not read the pending request for {Certificate}", row.SiteName);
        }
    }

    partial void OnIsBusyChanged(bool value) => NotifyCommands();
    partial void OnUsePfxChanged(bool value) => NotifyCommands();
    partial void OnPfxPathChanged(string value) { NotifyCommands(); OnPropertyChanged(nameof(ConfirmText)); }
    partial void OnCertificatePathChanged(string value) { NotifyCommands(); OnPropertyChanged(nameof(ConfirmText)); }

    private bool CanContinue() => UsePfx ? PfxPath.Length > 0 : CertificatePath.Length > 0 && PendingRequest is not null;

    private async Task InstallAsync(CancellationToken cancellationToken)
    {
        if (Certificate is not { } row) return;
        IsBusy = true;
        ErrorMessage = null;
        try
        {
            var progress = new Progress<ProgressEvent>(value => ProgressLines.Add(value.Message));
            ImportResult result;
            if (UsePfx)
            {
                var pfx = await File.ReadAllBytesAsync(PfxPath, cancellationToken).ConfigureAwait(true);
                try
                {
                    // The IIS site and this certificate's host names: on a site with several certificates, they pick this one.
                    var (site, hosts, password) = (row.IisSite, row.HostList, PfxPassword);
                    result = await Task.Run(() => _service.ImportPfxAsync(site, hosts, pfx, password, false, progress, cancellationToken), cancellationToken)
                        .ConfigureAwait(true);
                }
                finally
                {
                    Array.Clear(pfx);
                }
            }
            else
            {
                var file = await File.ReadAllBytesAsync(CertificatePath, cancellationToken).ConfigureAwait(true);
                var chain = ChainPath.Length > 0 ? await File.ReadAllBytesAsync(ChainPath, cancellationToken).ConfigureAwait(true) : null;
                var name = row.SiteName;
                result = await Task.Run(() => _service.CompleteRequestAsync(name, file, chain, false, progress, cancellationToken), cancellationToken)
                    .ConfigureAwait(true);
            }

            PfxPassword = string.Empty;
            ResultText = string.Join(" ", new[]
            {
                $"Installed. https://{row.Title} now serves the new certificate, valid until {result.Certificate.NotAfter.LocalDateTime:dd MMM yyyy}."
            }.Concat(result.Notes));
            Step = DoneStep;
            Installed?.Invoke();
        }
        catch (OperationCanceledException)
        {
            ErrorMessage = "Cancelled. Nothing was changed.";
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Installing the renewal for {Certificate} failed", row.SiteName);
            ErrorMessage = exception.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void Close()
    {
        PfxPassword = string.Empty;
        IsOpen = false;
    }

    private void CreateRequest()
    {
        var name = Certificate?.SiteName;
        Close();
        _navigation.Navigate("Certificate request", name);
    }

    private void NotifyCommands()
    {
        _nextCommand.NotifyCanExecuteChanged();
        _installCommand.NotifyCanExecuteChanged();
        (CloseCommand as RelayCommand)?.NotifyCanExecuteChanged();
    }
}
