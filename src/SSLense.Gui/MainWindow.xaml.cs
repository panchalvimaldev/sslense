using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using SSLense.Gui.Themes;
using SSLense.Gui.ViewModels;

namespace SSLense.Gui;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel;
    private double _scale = 1d;

    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        _viewModel = viewModel;
        DataContext = viewModel;
        Loaded += OnLoaded;

        // Windows' text size, and Ctrl+Plus, Ctrl+Minus and Ctrl+0 to change it here (docs/design/accessibility.md).
        Zoom = AccessibilityTheme.ReadTextScale();
        foreach (var (key, change) in new (Key Key, double Change)[]
                 {
                     (Key.OemPlus, 0.1), (Key.Add, 0.1), (Key.OemMinus, -0.1), (Key.Subtract, -0.1), (Key.D0, 0), (Key.NumPad0, 0)
                 })
        {
            InputBindings.Add(new KeyBinding(
                new ZoomCommand(() => Zoom = change == 0 ? AccessibilityTheme.ReadTextScale() : Zoom + change),
                key,
                ModifierKeys.Control));
        }
    }

    /// <summary>The whole window scales, so text, spacing and controls grow together and nothing is cut off.</summary>
    public double Zoom
    {
        get => _scale;
        set
        {
            _scale = AccessibilityTheme.Clamp(value);
            if (Content is FrameworkElement content)
            {
                content.LayoutTransform = _scale == 1d ? Transform.Identity : new ScaleTransform(_scale, _scale);
            }

            // Larger text needs room: the minimum size grows with it, up to what the screen allows.
            MinWidth = Math.Min(1020 * _scale, SystemParameters.WorkArea.Width);
            MinHeight = Math.Min(640 * _scale, SystemParameters.WorkArea.Height);
        }
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loaded -= OnLoaded;
        await _viewModel.InitializeAsync();
    }

    private sealed class ZoomCommand(Action execute) : ICommand
    {
        public event EventHandler? CanExecuteChanged { add { } remove { } }

        public bool CanExecute(object? parameter) => true;

        public void Execute(object? parameter) => execute();
    }
}
