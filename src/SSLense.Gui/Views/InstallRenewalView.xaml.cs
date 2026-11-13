using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using SSLense.Gui.ViewModels;

namespace SSLense.Gui.Views;

/// <summary>
/// File pickers for the Install renewal dialog. The password goes to the view model because PasswordBox cannot be
/// data-bound, and the box is cleared when the view model clears its copy.
/// </summary>
public partial class InstallRenewalView : UserControl
{
    private const string CertificateFilter = "Certificates (*.crt;*.cer;*.pem;*.ca-bundle)|*.crt;*.cer;*.pem;*.ca-bundle|All files (*.*)|*.*";

    public InstallRenewalView()
    {
        InitializeComponent();
        DataContextChanged += (_, e) =>
        {
            if (e.OldValue is InstallRenewalViewModel old) old.PropertyChanged -= OnViewModelPropertyChanged;
            if (e.NewValue is InstallRenewalViewModel current) current.PropertyChanged += OnViewModelPropertyChanged;
        };
    }

    private InstallRenewalViewModel? ViewModel => DataContext as InstallRenewalViewModel;

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(InstallRenewalViewModel.PfxPassword) && ViewModel?.PfxPassword.Length == 0) PfxPasswordBox.Clear();
    }

    private void OnPfxPasswordChanged(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm) vm.PfxPassword = PfxPasswordBox.Password;
    }

    private void OnUseRequestChecked(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm) vm.UsePfx = false;
    }

    private void OnBrowsePfxClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm && Browse("PFX files (*.pfx;*.p12)|*.pfx;*.p12|All files (*.*)|*.*") is { } path) vm.PfxPath = path;
    }

    private void OnBrowseCertificateClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm && Browse(CertificateFilter) is { } path) vm.CertificatePath = path;
    }

    private void OnBrowseChainClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm && Browse(CertificateFilter) is { } path) vm.ChainPath = path;
    }

    private static string? Browse(string filter)
    {
        var dialog = new OpenFileDialog { Filter = filter };
        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }
}
