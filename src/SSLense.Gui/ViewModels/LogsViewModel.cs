using System.Collections.ObjectModel;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using SSLense.Core.Logs;

namespace SSLense.Gui.ViewModels;

public partial class LogsViewModel : ObservableObject, IDisposable
{
    private readonly ILogService _logService;
    private readonly ILogger<LogsViewModel> _logger;
    private readonly DispatcherTimer _timer;
    private readonly AsyncRelayCommand _refreshCommand;

    [ObservableProperty]
    private string selectedLevel = "All";

    [ObservableProperty]
    private string filePath = "No log file found.";

    [ObservableProperty]
    private string? errorMessage;

    [ObservableProperty]
    private bool isRefreshing;

    public LogsViewModel(ILogService logService, ILogger<LogsViewModel> logger)
    {
        _logService = logService;
        _logger = logger;
        _refreshCommand = new AsyncRelayCommand(RefreshAsync, () => !IsRefreshing);
        OpenFolderCommand = new RelayCommand(OpenFolder);
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _timer.Tick += OnTimerTick;
    }

    public IReadOnlyList<string> Levels { get; } = ["All", "Debug", "Information", "Warning", "Error"];

    public ObservableCollection<string> Lines { get; } = [];

    public IAsyncRelayCommand RefreshCommand => _refreshCommand;

    public IRelayCommand OpenFolderCommand { get; }

    public void StartLiveUpdates()
    {
        if (!_timer.IsEnabled)
        {
            _timer.Start();
            _ = _refreshCommand.ExecuteAsync(null);
        }
    }

    partial void OnSelectedLevelChanged(string value) => _ = _refreshCommand.ExecuteAsync(null);

    partial void OnIsRefreshingChanged(bool value) => _refreshCommand.NotifyCanExecuteChanged();

    private async void OnTimerTick(object? sender, EventArgs e)
    {
        if (!IsRefreshing)
        {
            await _refreshCommand.ExecuteAsync(null);
        }
    }

    private async Task RefreshAsync()
    {
        IsRefreshing = true;
        ErrorMessage = null;
        try
        {
            var snapshot = await _logService.ReadCurrentAsync(SelectedLevel).ConfigureAwait(true);
            FilePath = snapshot.FilePath ?? "No log file found.";
            Lines.Clear();
            foreach (var line in snapshot.Lines)
            {
                Lines.Add(line);
            }
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Could not refresh the GUI log viewer");
            ErrorMessage = exception.Message;
        }
        finally
        {
            IsRefreshing = false;
        }
    }

    private void OpenFolder()
    {
        try
        {
            _logService.OpenLogDirectory();
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Could not open the log directory");
            ErrorMessage = exception.Message;
        }
    }

    public void Dispose()
    {
        _timer.Stop();
        _timer.Tick -= OnTimerTick;
    }
}
