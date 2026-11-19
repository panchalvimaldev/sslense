using System.Windows.Controls;

namespace SSLense.Gui.Views;

public partial class HealthView : UserControl
{
    public HealthView()
    {
        InitializeComponent();
    }

    private async void OnRemoveUnusedClick(object sender, System.Windows.RoutedEventArgs e)
    {
        if (DataContext is not SSLense.Gui.ViewModels.HealthViewModel viewModel) return;
        var count = viewModel.UnusedCertificates.Count(row => row.IsChecked);
        if (count == 0) return;
        var answer = System.Windows.MessageBox.Show(
            $"Remove {count} certificate(s) from LocalMachine\\My?\n\n" +
            "SSLense checks each again first. A removed certificate cannot be restored unless you have a copy, so check that no other service, such as SQL Server or Exchange, uses it.",
            "Remove unused certificates",
            System.Windows.MessageBoxButton.YesNo,
            System.Windows.MessageBoxImage.Warning);
        if (answer == System.Windows.MessageBoxResult.Yes && viewModel.RemoveUnusedCommand.CanExecute(null)) await viewModel.RemoveUnusedCommand.ExecuteAsync(null);
    }
}
