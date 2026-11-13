using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using SSLense.Gui.ViewModels;

namespace SSLense.Gui.Views;

/// <summary>
/// PasswordBox cannot be data-bound, so secrets are passed to the view model here, and the boxes are cleared
/// once the view model clears its copy after saving.
/// </summary>
public partial class SettingsView : UserControl
{
    public SettingsView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private SettingsViewModel? ViewModel => DataContext as SettingsViewModel;

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (e.OldValue is SettingsViewModel oldViewModel) oldViewModel.PropertyChanged -= OnViewModelPropertyChanged;
        if (e.NewValue is SettingsViewModel newViewModel) newViewModel.PropertyChanged += OnViewModelPropertyChanged;
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (ViewModel is not { } vm) return;
        if (e.PropertyName == nameof(SettingsViewModel.EmailPassword) && vm.EmailPassword.Length == 0) EmailPasswordBox.Clear();
        if (e.PropertyName == nameof(SettingsViewModel.NewChatUrl) && vm.NewChatUrl.Length == 0) ChatUrlBox.Clear();
        if (e.PropertyName == nameof(SettingsViewModel.HeartbeatUrl) && vm.HeartbeatUrl.Length == 0) HeartbeatUrlBox.Clear();
        if (e.PropertyName == nameof(SettingsViewModel.NewDnsToken) && vm.NewDnsToken.Length == 0) DnsTokenBox.Clear();
        if (e.PropertyName == nameof(SettingsViewModel.NewCaEabHmacKey) && vm.NewCaEabHmacKey.Length == 0) CaHmacBox.Clear();
        if (e.PropertyName == nameof(SettingsViewModel.NewAcmeDnsPassword) && vm.NewAcmeDnsPassword.Length == 0) AcmeDnsPasswordBox.Clear();
    }

    private void OnDnsTokenChanged(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm) vm.NewDnsToken = DnsTokenBox.Password;
    }

    private void OnCaHmacChanged(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm) vm.NewCaEabHmacKey = CaHmacBox.Password;
    }

    private void OnAcmeDnsPasswordChanged(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm) vm.NewAcmeDnsPassword = AcmeDnsPasswordBox.Password;
    }

    private void OnBrowseDnsScriptClick(object sender, RoutedEventArgs e)
    {
        var examples = Path.Combine(AppContext.BaseDirectory, "..", "dns-scripts");
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "PowerShell scripts (*.ps1)|*.ps1",
            InitialDirectory = Directory.Exists(examples) ? Path.GetFullPath(examples) : null
        };
        if (dialog.ShowDialog() == true && ViewModel is { } vm) vm.NewDnsScriptPath = dialog.FileName;
    }

    private void OnEmailPasswordChanged(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm) vm.EmailPassword = EmailPasswordBox.Password;
    }

    private void OnChatUrlChanged(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm) vm.NewChatUrl = ChatUrlBox.Password;
    }

    private void OnHeartbeatUrlChanged(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm) vm.HeartbeatUrl = HeartbeatUrlBox.Password;
    }

    /// <summary>A certificate authority row's Test or Remove: the row becomes the selected one, then its action runs.</summary>
    private async void OnCaRowClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm || sender is not FrameworkElement { DataContext: SSLense.Core.Acme.CertificateAuthorityOverview authority, Tag: string action }) return;
        vm.SelectedCertificateAuthority = authority;
        if (action == "remove" && !Confirm($"Remove the certificate authority '{authority.Name}'? Its ACME account key on this server is deleted.")) return;
        var command = action == "remove" ? vm.RemoveCaCommand : vm.TestCaCommand;
        if (command.CanExecute(null)) await command.ExecuteAsync(null);
    }

    /// <summary>A DNS provider row's Test, Replace token, Update script or Remove, run for that row.</summary>
    private async void OnDnsRowClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm || sender is not FrameworkElement { DataContext: SSLense.Core.DnsValidation.DnsProviderOverview provider, Tag: string action }) return;
        vm.SelectedDnsProvider = provider;
        if (action == "remove" && !Confirm($"Remove the DNS provider '{provider.Name}'? Revoke its token in the DNS service too.")) return;
        var command = action switch
        {
            "remove" => vm.RemoveDnsProviderCommand,
            "token" => vm.ReplaceDnsTokenCommand,
            "script" => vm.UpdateDnsScriptCommand,
            _ => vm.TestDnsProviderCommand
        };
        if (command.CanExecute(null)) await command.ExecuteAsync(null);
        else if (action is "token" or "script")
        {
            MessageBox.Show(action == "token"
                    ? "Enter the new token or secret under Add a DNS provider, then choose Replace token again."
                    : "Choose the changed script under Add a DNS provider, then choose Update script again.",
                "SSLense", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private static bool Confirm(string question) =>
        MessageBox.Show(question, "SSLense", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes;
}
