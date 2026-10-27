using System.Windows;
using System.Windows.Controls;
using SSLense.Gui.ViewModels;

namespace SSLense.Gui.Views;

public partial class SettingsView : UserControl
{
    public SettingsView() => InitializeComponent();
    private void OnSmtpPasswordChanged(object sender, RoutedEventArgs e)
    {
        if (DataContext is SettingsViewModel vm && sender is PasswordBox box) vm.SmtpPassword = box.Password;
    }
    private void OnWebhookChanged(object sender, RoutedEventArgs e)
    {
        if (DataContext is SettingsViewModel vm && sender is PasswordBox box) vm.WebhookUrl = box.Password;
    }
}
