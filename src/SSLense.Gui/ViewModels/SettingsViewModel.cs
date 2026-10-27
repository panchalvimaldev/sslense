using CommunityToolkit.Mvvm.ComponentModel;
using System.IO;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using SSLense.Core.Config;
using SSLense.Core.Notifications;
using SSLense.Core.WindowsServices;

namespace SSLense.Gui.ViewModels;

public partial class SettingsViewModel : ObservableObject
{
    private readonly ISettingsService _settingsService;
    private readonly INotificationSettingsService _notificationSettingsService;
    private readonly INotifier _notifier;
    private readonly IWindowsServiceManager _serviceManager;
    private readonly ILogger<SettingsViewModel> _logger;

    [ObservableProperty] private string defaultEmail = string.Empty;
    [ObservableProperty] private int renewalThresholdDays = 30;
    [ObservableProperty] private string smtpHost = string.Empty;
    [ObservableProperty] private int smtpPort = 587;
    [ObservableProperty] private bool smtpTls = true;
    [ObservableProperty] private string smtpUsername = string.Empty;
    [ObservableProperty] private string smtpPassword = string.Empty;
    [ObservableProperty] private string smtpFrom = string.Empty;
    [ObservableProperty] private string smtpTo = string.Empty;
    [ObservableProperty] private string webhookUrl = string.Empty;
    [ObservableProperty] private bool notifyOnSuccess;
    [ObservableProperty] private string notificationStatus = "Not configured";
    [ObservableProperty] private string servicePath = Path.Combine(AppContext.BaseDirectory, "SSLense.Service.exe");
    [ObservableProperty] private string serviceStatus = "Checking...";
    [ObservableProperty] private bool isBusy;
    [ObservableProperty] private string? errorMessage;
    [ObservableProperty] private string resultMessage = string.Empty;

    public SettingsViewModel(
        ISettingsService settingsService,
        INotificationSettingsService notificationSettingsService,
        INotifier notifier,
        IWindowsServiceManager serviceManager,
        ILogger<SettingsViewModel> logger)
    {
        _settingsService = settingsService;
        _notificationSettingsService = notificationSettingsService;
        _notifier = notifier;
        _serviceManager = serviceManager;
        _logger = logger;
        SaveGeneralCommand = Command(SaveGeneralAsync);
        SaveNotificationsCommand = Command(SaveNotificationsAsync);
        TestNotificationCommand = Command(TestNotificationAsync);
        ClearNotificationsCommand = Command(ClearNotificationsAsync);
        RefreshServiceCommand = Command(RefreshServiceAsync);
        InstallServiceCommand = Command(InstallServiceAsync);
        StartServiceCommand = Command(StartServiceAsync);
        StopServiceCommand = Command(StopServiceAsync);
        UninstallServiceCommand = Command(UninstallServiceAsync);
    }

    public IAsyncRelayCommand SaveGeneralCommand { get; }
    public IAsyncRelayCommand SaveNotificationsCommand { get; }
    public IAsyncRelayCommand TestNotificationCommand { get; }
    public IAsyncRelayCommand ClearNotificationsCommand { get; }
    public IAsyncRelayCommand RefreshServiceCommand { get; }
    public IAsyncRelayCommand InstallServiceCommand { get; }
    public IAsyncRelayCommand StartServiceCommand { get; }
    public IAsyncRelayCommand StopServiceCommand { get; }
    public IAsyncRelayCommand UninstallServiceCommand { get; }

    public async Task InitializeAsync()
    {
        await RunAsync(async token =>
        {
            var config = await _settingsService.GetAsync(token).ConfigureAwait(true);
            DefaultEmail = config.DefaultEmail ?? string.Empty;
            RenewalThresholdDays = config.RenewalThresholdDays;
            NotifyOnSuccess = config.Notifications.NotifyOnSuccess;
            if (config.Notifications.Smtp is { } smtp)
            {
                SmtpHost = smtp.Host; SmtpPort = smtp.Port; SmtpTls = smtp.EnableSsl;
                SmtpUsername = smtp.Username ?? string.Empty; SmtpFrom = smtp.From; SmtpTo = smtp.To;
            }
            NotificationStatus = $"SMTP: {(config.Notifications.Smtp is null ? "off" : "configured")}; " +
                                 $"Webhook: {(config.Notifications.Webhook is null ? "off" : "configured")}";
            await RefreshServiceCoreAsync(token).ConfigureAwait(true);
        }, CancellationToken.None);
    }

    partial void OnIsBusyChanged(bool value)
    {
        foreach (var command in AllCommands()) command.NotifyCanExecuteChanged();
    }

    private AsyncRelayCommand Command(Func<CancellationToken, Task> action) => new(action, () => !IsBusy);

    private Task SaveGeneralAsync(CancellationToken token) => RunAsync(async ct =>
    {
        await _settingsService.SaveGeneralAsync(DefaultEmail, RenewalThresholdDays, ct).ConfigureAwait(true);
        ResultMessage = "General settings saved. Staging remains enforced.";
    }, token);

    private Task SaveNotificationsAsync(CancellationToken token) => RunAsync(async ct =>
    {
        SmtpSettingsRequest? smtp = string.IsNullOrWhiteSpace(SmtpHost) ? null : new(
            SmtpHost, SmtpPort, SmtpTls,
            string.IsNullOrWhiteSpace(SmtpUsername) ? null : SmtpUsername,
            string.IsNullOrWhiteSpace(SmtpUsername) || string.IsNullOrEmpty(SmtpPassword) ? null : SmtpPassword,
            SmtpFrom, SmtpTo);
        await _notificationSettingsService.ConfigureAsync(
            new NotificationSettingsRequest(
                smtp,
                string.IsNullOrWhiteSpace(WebhookUrl) ? null : WebhookUrl,
                NotifyOnSuccess,
                PreserveExistingSmtpPassword: true,
                PreserveExistingWebhook: true), ct)
            .ConfigureAwait(true);
        SmtpPassword = string.Empty; WebhookUrl = string.Empty;
        ResultMessage = "Notification settings saved with DPAPI protection.";
        await InitializeAsync().ConfigureAwait(true);
    }, token);

    private Task TestNotificationAsync(CancellationToken token) => RunAsync(async ct =>
    {
        await _notifier.NotifyAsync(new NotificationMessage(
            NotificationKind.Test, "SSLense test notification", "SSLense notification delivery is configured correctly."), ct)
            .ConfigureAwait(true);
        ResultMessage = "Test notification sent.";
    }, token);

    private Task ClearNotificationsAsync(CancellationToken token) => RunAsync(async ct =>
    {
        await _notificationSettingsService.ClearAsync(ct).ConfigureAwait(true);
        ResultMessage = "Notification settings cleared.";
        NotificationStatus = "Not configured";
    }, token);

    private Task RefreshServiceAsync(CancellationToken token) => RunAsync(RefreshServiceCoreAsync, token);
    private Task InstallServiceAsync(CancellationToken token) => ServiceActionAsync(ct => _serviceManager.InstallAsync(ServicePath, ct), "Service installed and started.", token);
    private Task StartServiceAsync(CancellationToken token) => ServiceActionAsync(_serviceManager.StartAsync, "Service started.", token);
    private Task StopServiceAsync(CancellationToken token) => ServiceActionAsync(_serviceManager.StopAsync, "Service stopped.", token);
    private Task UninstallServiceAsync(CancellationToken token) => ServiceActionAsync(_serviceManager.UninstallAsync, "Service uninstalled.", token);

    private Task ServiceActionAsync(Func<CancellationToken, Task> action, string message, CancellationToken token) => RunAsync(async ct =>
    {
        await action(ct).ConfigureAwait(true); ResultMessage = message; await RefreshServiceCoreAsync(ct).ConfigureAwait(true);
    }, token);

    private async Task RefreshServiceCoreAsync(CancellationToken token) =>
        ServiceStatus = (await _serviceManager.GetStatusAsync(token).ConfigureAwait(true)).ToString();

    private async Task RunAsync(Func<CancellationToken, Task> action, CancellationToken token)
    {
        IsBusy = true; ErrorMessage = null;
        try { await action(token).ConfigureAwait(true); }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Settings operation failed"); ErrorMessage = exception.Message;
        }
        finally { IsBusy = false; }
    }

    private IEnumerable<AsyncRelayCommand> AllCommands() =>
    [
        (AsyncRelayCommand)SaveGeneralCommand, (AsyncRelayCommand)SaveNotificationsCommand,
        (AsyncRelayCommand)TestNotificationCommand, (AsyncRelayCommand)ClearNotificationsCommand,
        (AsyncRelayCommand)RefreshServiceCommand, (AsyncRelayCommand)InstallServiceCommand,
        (AsyncRelayCommand)StartServiceCommand, (AsyncRelayCommand)StopServiceCommand,
        (AsyncRelayCommand)UninstallServiceCommand
    ];
}
