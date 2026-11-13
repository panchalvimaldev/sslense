using CommunityToolkit.Mvvm.ComponentModel;

namespace SSLense.Gui.ViewModels;

/// <summary>Activity: what is running, the health checks and the log, as tabs (docs/design/gui-redesign.md, step 1).</summary>
public partial class ActivityViewModel(DashboardViewModel certificates, HealthViewModel health, LogsViewModel logs) : ObservableObject
{
    public const int HealthTab = 0;
    public const int LogTab = 1;

    /// <summary>0: health checks; 1: the log.</summary>
    [ObservableProperty]
    private int selectedTab;

    /// <summary>The progress of renewals started from the Certificates tab.</summary>
    public DashboardViewModel Certificates { get; } = certificates;

    public HealthViewModel Health { get; } = health;

    public LogsViewModel Logs { get; } = logs;
}
