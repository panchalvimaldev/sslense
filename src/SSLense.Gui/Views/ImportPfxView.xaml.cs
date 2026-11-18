using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using SSLense.Gui.ViewModels;

namespace SSLense.Gui.Views;

/// <summary>
/// The file picker, and the PFX password, which goes to the view model because PasswordBox cannot be data-bound;
/// the box is cleared once the view model clears its copy after an import.
/// </summary>
public partial class ImportPfxView : UserControl
{
    public ImportPfxView()
    {
        InitializeComponent();
        DataContextChanged += (_, e) =>
        {
            if (e.OldValue is OtherProvidersViewModel old) old.PropertyChanged -= OnViewModelPropertyChanged;
            if (e.NewValue is OtherProvidersViewModel current) current.PropertyChanged += OnViewModelPropertyChanged;
        };
    }

    private OtherProvidersViewModel? ViewModel => DataContext as OtherProvidersViewModel;

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(OtherProvidersViewModel.PfxPassword) && ViewModel?.PfxPassword.Length == 0) PfxPasswordBox.Clear();
    }

    private void OnPfxPasswordChanged(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm) vm.PfxPassword = PfxPasswordBox.Password;
    }

    private void OnBrowsePfxClick(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = "PFX files (*.pfx;*.p12)|*.pfx;*.p12|All files (*.*)|*.*" };
        if (ViewModel is { } vm && dialog.ShowDialog() == true) vm.PfxPath = dialog.FileName;
    }
}
