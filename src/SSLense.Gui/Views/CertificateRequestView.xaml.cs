using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using SSLense.Gui.ViewModels;

namespace SSLense.Gui.Views;

/// <summary>File dialogs, the clipboard, and the confirmation to cancel a request live here.</summary>
public partial class CertificateRequestView : UserControl
{
    private const string CertificateFilter = "Certificates (*.crt;*.cer;*.pem;*.ca-bundle)|*.crt;*.cer;*.pem;*.ca-bundle|All files (*.*)|*.*";

    public CertificateRequestView() => InitializeComponent();

    private OtherProvidersViewModel? ViewModel => DataContext as OtherProvidersViewModel;

    private void OnCopyCsrClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel?.SelectedCsr is { } csr) Clipboard.SetText(csr);
    }

    private async void OnSaveCsrClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm) return;
        var dialog = new SaveFileDialog
        {
            FileName = vm.SuggestedCsrFileName,
            Filter = "Certificate request (*.csr)|*.csr|All files (*.*)|*.*",
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)
        };
        if (dialog.ShowDialog() == true) await vm.SaveCsrAsync(dialog.FileName);
    }

    private void OnBrowseCertificateClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm && Browse(CertificateFilter) is { } path) vm.CertificatePath = path;
    }

    private void OnBrowseChainClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm && Browse(CertificateFilter) is { } path) vm.ChainPath = path;
    }

    private async void OnCancelRequestClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { SelectedPending: { } pending } vm) return;
        var answer = MessageBox.Show(
            $"Cancel the request for {pending.Hosts}? Its private key is deleted, so a certificate the provider " +
            "issues for this request can no longer be installed.",
            "Cancel the request",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (answer == MessageBoxResult.Yes) await vm.CancelRequestCommand.ExecuteAsync(null);
    }

    private static string? Browse(string filter)
    {
        var dialog = new OpenFileDialog { Filter = filter };
        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }
}
