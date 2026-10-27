using CommunityToolkit.Mvvm.ComponentModel;

namespace SSLense.Gui.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly DashboardViewModel _dashboard;
    private readonly LogsViewModel _logs;
    private readonly IssueCertificateViewModel _issue;
    private readonly CertificateDetailsViewModel _details;
    private readonly SettingsViewModel _settings;
    private readonly INavigationService _navigation;
    private string? _pendingNavigationContext;

    [ObservableProperty]
    private NavigationItem selectedPage;

    public MainViewModel(
        DashboardViewModel dashboard,
        IssueCertificateViewModel issue,
        CertificateDetailsViewModel details,
        SettingsViewModel settings,
        LogsViewModel logs,
        INavigationService navigation)
    {
        _dashboard = dashboard;
        _logs = logs;
        _issue = issue;
        _details = details;
        _settings = settings;
        _navigation = navigation;
        Pages =
        [
            new NavigationItem("Dashboard", dashboard),
            new NavigationItem("Issue Certificate", issue),
            new NavigationItem("Certificate Details", details),
            new NavigationItem("Settings", settings),
            new NavigationItem("Logs", logs)
        ];
        selectedPage = Pages[0];
        _navigation.NavigationRequested += OnNavigationRequested;
    }

    public IReadOnlyList<NavigationItem> Pages { get; }

    public async Task InitializeAsync()
    {
        await _dashboard.InitializeAsync();
        await _issue.InitializeAsync();
        _logs.StartLiveUpdates();
    }

    partial void OnSelectedPageChanged(NavigationItem value)
    {
        var context = _pendingNavigationContext;
        _pendingNavigationContext = null;
        _ = InitializePageAsync(value, context);
    }

    private void OnNavigationRequested(object? sender, NavigationRequest request)
    {
        var page = Pages.FirstOrDefault(value => value.Title.StartsWith(request.Page, StringComparison.OrdinalIgnoreCase));
        if (page is null) return;
        if (ReferenceEquals(SelectedPage, page))
        {
            _ = InitializePageAsync(page, request.Context);
        }
        else
        {
            _pendingNavigationContext = request.Context;
            SelectedPage = page;
        }
    }

    private async Task InitializePageAsync(NavigationItem page, string? context)
    {
        if (ReferenceEquals(page.ViewModel, _dashboard)) await _dashboard.InitializeAsync();
        else if (ReferenceEquals(page.ViewModel, _issue)) await _issue.InitializeAsync();
        else if (ReferenceEquals(page.ViewModel, _details)) await _details.InitializeAsync(context);
        else if (ReferenceEquals(page.ViewModel, _settings)) await _settings.InitializeAsync();
    }
}
