using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace SSLense.Gui.ViewModels;

/// <summary>The window: three tabs (Certificates, Activity, Settings) and the Add certificate page.</summary>
public partial class MainViewModel : ObservableObject
{
    private readonly DashboardViewModel _certificates;
    private readonly IssueCertificateViewModel _issue;
    private readonly AddCertificateViewModel _add;
    private readonly ActivityViewModel _activity;
    private readonly SettingsViewModel _settings;
    private readonly LogsViewModel _logs;

    /// <summary>The selected tab, or null while Add certificate is open.</summary>
    [ObservableProperty]
    private NavigationItem? selectedTab;

    /// <summary>The view model of the page shown below the tabs.</summary>
    [ObservableProperty]
    private object currentPage;

    public MainViewModel(
        DashboardViewModel certificates,
        IssueCertificateViewModel issue,
        AddCertificateViewModel add,
        ActivityViewModel activity,
        SettingsViewModel settings,
        LogsViewModel logs,
        INavigationService navigation)
    {
        _certificates = certificates;
        _issue = issue;
        _add = add;
        _activity = activity;
        _settings = settings;
        _logs = logs;
        Tabs =
        [
            new NavigationItem("Certificates", "", certificates),
            new NavigationItem("Activity", "", activity),
            new NavigationItem("Settings", "", settings)
        ];
        selectedTab = Tabs[0];
        currentPage = certificates;
        AddCertificateCommand = new RelayCommand(() => _ = ShowAddCertificateAsync(AddCertificateViewModel.AutomaticTab, null));
        OpenActivityCommand = new RelayCommand(() => SelectedTab = Tabs[1]);
        navigation.NavigationRequested += OnNavigationRequested;
    }

    public IReadOnlyList<NavigationItem> Tabs { get; }

    /// <summary>The Certificates tab, which also keeps the header's health status and the running operation.</summary>
    public DashboardViewModel Certificates => _certificates;

    public IRelayCommand AddCertificateCommand { get; }

    public IRelayCommand OpenActivityCommand { get; }

    public IAsyncRelayCommand RenewAllCommand => _certificates.RenewAllCommand;

    public IRelayCommand OpenHealthCommand => _certificates.OpenHealthCommand;

    public bool IsAddingCertificate => ReferenceEquals(CurrentPage, _add);

    public async Task InitializeAsync()
    {
        await _certificates.InitializeAsync();
        await _issue.InitializeAsync();
        _logs.StartLiveUpdates();
    }

    partial void OnCurrentPageChanged(object value) => OnPropertyChanged(nameof(IsAddingCertificate));

    partial void OnSelectedTabChanged(NavigationItem? value)
    {
        if (value is null) return;
        CurrentPage = value.ViewModel;
        if (ReferenceEquals(value.ViewModel, _certificates)) _ = _certificates.InitializeAsync();
        else if (ReferenceEquals(value.ViewModel, _settings)) _ = _settings.InitializeAsync();
    }

    private Task ShowAddCertificateAsync(int tab, string? context)
    {
        SelectedTab = null;
        CurrentPage = _add;
        return _add.ShowAsync(tab, context);
    }

    /// <summary>Other screens ask for a page by the name it had in the side menu; this maps each one to its new place.</summary>
    private void OnNavigationRequested(object? sender, NavigationRequest request)
    {
        var page = request.Page;
        if (Is(page, "Issue") || Is(page, "Add certificate"))
        {
            _ = ShowAddCertificateAsync(AddCertificateViewModel.AutomaticTab, request.Context);
        }
        else if (Is(page, "Other Providers"))
        {
            _ = ShowAddCertificateAsync(AddCertificateViewModel.OtherProvidersTab, request.Context);
        }
        else if (Is(page, "Health") || Is(page, "Logs"))
        {
            _activity.SelectedTab = Is(page, "Logs") ? ActivityViewModel.LogTab : ActivityViewModel.HealthTab;
            SelectedTab = Tabs[1];
        }
        else if (Is(page, "Settings"))
        {
            SelectedTab = Tabs[2];
        }
        else
        {
            // Dashboard, Certificates, Certificate Details: the list, with the named certificate selected.
            SelectedTab = Tabs[0];
            _ = _certificates.SelectAsync(request.Context);
        }
    }

    private static bool Is(string page, string name) => page.StartsWith(name, StringComparison.OrdinalIgnoreCase);
}
