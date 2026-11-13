using System.Windows;
using System.Windows.Controls;
using SSLense.Gui.ViewModels;

namespace SSLense.Gui.Views;

public partial class CertificateDetailsView : UserControl
{
    public CertificateDetailsView()
    {
        InitializeComponent();
        DataContextChanged += (_, e) =>
        {
            if (e.OldValue is CertificateDetailsViewModel old) old.PasswordCleared -= ClearPassword;
            if (e.NewValue is CertificateDetailsViewModel current) current.PasswordCleared += ClearPassword;
        };
    }

    private void ClearPassword() => DeploymentPasswordBox.Clear();

    private void OnDeploymentPasswordChanged(object sender, RoutedEventArgs e)
    {
        if (DataContext is CertificateDetailsViewModel viewModel) viewModel.DeploymentPassword = DeploymentPasswordBox.Password;
    }

    /// <summary>Opens the ⋯ menu under its button.</summary>
    private void OnMoreClick(object sender, RoutedEventArgs e)
    {
        if (MoreButton.ContextMenu is not { } menu) return;
        menu.DataContext = DataContext;
        menu.PlacementTarget = MoreButton;
        menu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
        menu.IsOpen = true;
    }

    /// <summary>Opens https://host for the certificate's first host name; a wildcard opens the domain it covers.</summary>
    private void OnOpenSiteClick(object sender, RoutedEventArgs e)
    {
        if (DataContext is not CertificateDetailsViewModel { Summary: { HostList.Count: > 0 } row }) return;
        var host = row.HostList[0].StartsWith("*.", StringComparison.Ordinal) ? row.HostList[0][2..] : row.HostList[0];
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo($"https://{host}/") { UseShellExecute = true });
        }
        catch (Exception exception)
        {
            MessageBox.Show(exception.Message, "Could not open the browser", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void OnRemoveClick(object sender, RoutedEventArgs e)
    {
        if (DataContext is not CertificateDetailsViewModel viewModel || viewModel.SelectedSite is null) return;
        var sites = string.Join(", ", viewModel.SharedSites.Select(row => $"'{row.SiteName}'"));
        var name = viewModel.Summary?.Title ?? viewModel.SelectedSite;
        var answer = MessageBox.Show(
            viewModel.Summary?.IsNoSite == true
                ? $"Stop managing {name}? It has no IIS site, so no binding changes, and the certificate stays in the Windows certificate store for the services that use it."
            : viewModel.SharedSites.Count > 1
                ? $"Remove the certificate for {name} and its HTTPS bindings on every site using it: {sites}?\n\nVisitors get a certificate error on those addresses until another certificate is bound."
                : $"Remove the certificate for {name} and its HTTPS bindings in IIS?\n\nVisitors get a certificate error on these addresses until another certificate is bound.",
            "Remove certificate and HTTPS bindings",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (answer == MessageBoxResult.Yes) await viewModel.RemoveCommand.ExecuteAsync(null);
    }

    private void OnBrowseScriptClick(object sender, RoutedEventArgs e)
    {
        if (DataContext is not CertificateDetailsViewModel viewModel) return;
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Choose a deployment script",
            Filter = "PowerShell scripts (*.ps1)|*.ps1",
            CheckFileExists = true
        };
        var examples = System.IO.Path.Combine(AppContext.BaseDirectory, "..", "deploy-scripts");
        if (System.IO.Directory.Exists(examples)) dialog.InitialDirectory = System.IO.Path.GetFullPath(examples);
        if (dialog.ShowDialog(Window.GetWindow(this)) == true) viewModel.DeploymentValue = dialog.FileName;
    }

    private async void OnStopManagingClick(
object sender, RoutedEventArgs e)
    {
        if (DataContext is not CertificateDetailsViewModel viewModel || sender is not FrameworkElement { DataContext: SharedSiteRow row }) return;
        var answer = MessageBox.Show(
            $"Stop managing '{row.SiteName}'? Its binding stays as it is, so the site keeps working until this certificate expires, but SSLense will no longer renew it.",
            "Confirm stop managing",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (answer == MessageBoxResult.Yes) await viewModel.StopManagingCommand.ExecuteAsync(row);
    }
}
