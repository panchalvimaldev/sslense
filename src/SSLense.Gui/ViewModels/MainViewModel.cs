using CommunityToolkit.Mvvm.ComponentModel;

namespace SSLense.Gui.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly DashboardViewModel _dashboard;
    private readonly LogsViewModel _logs;

    [ObservableProperty]
    private NavigationItem selectedPage;

    public MainViewModel(DashboardViewModel dashboard, LogsViewModel logs)
    {
        _dashboard = dashboard;
        _logs = logs;
        Pages =
        [
            new NavigationItem("Dashboard", dashboard),
            new NavigationItem("Logs", logs)
        ];
        selectedPage = Pages[0];
    }

    public IReadOnlyList<NavigationItem> Pages { get; }

    public async Task InitializeAsync()
    {
        await _dashboard.InitializeAsync();
        _logs.StartLiveUpdates();
    }
}
