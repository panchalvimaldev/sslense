using System.Windows;
using System.Windows.Controls;
using SSLense.Gui.ViewModels;

namespace SSLense.Gui.Views;

public partial class CertificateDetailsView : UserControl
{
    public CertificateDetailsView() => InitializeComponent();

    private async void OnRemoveClick(object sender, RoutedEventArgs e)
    {
        if (DataContext is not CertificateDetailsViewModel viewModel || viewModel.SelectedSite is null) return;
        var answer = MessageBox.Show(
            $"Remove the managed certificate and matching HTTPS bindings for '{viewModel.SelectedSite}'?",
            "Confirm certificate removal",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (answer == MessageBoxResult.Yes) await viewModel.RemoveCommand.ExecuteAsync(null);
    }
}
