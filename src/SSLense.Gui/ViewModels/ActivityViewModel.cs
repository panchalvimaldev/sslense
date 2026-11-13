namespace SSLense.Gui.ViewModels;

/// <summary>Activity: what is running, the health checks and the log, on one page (docs/design/gui-redesign.md).</summary>
public sealed class ActivityViewModel(DashboardViewModel certificates, HealthViewModel health, LogsViewModel logs)
{
    /// <summary>The progress of renewals started in the app.</summary>
    public DashboardViewModel Certificates { get; } = certificates;

    public HealthViewModel Health { get; } = health;

    public LogsViewModel Logs { get; } = logs;
}
