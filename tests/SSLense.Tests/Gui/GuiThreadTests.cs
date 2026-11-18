using System.Windows;
using System.Windows.Threading;
using Xunit;

namespace SSLense.Tests.Gui;

/// <summary>The shared UI thread keeps working for every GUI test, whichever runs first.</summary>
public sealed class GuiThreadTests
{
    [Fact]
    public void AfterTheLastWindowCloses_ScreensStillLoad() => GuiThread.Run(() =>
    {
        // Every window other tests left open, then one of this test's own: the last window closes.
        foreach (var open in Application.Current.Windows.OfType<Window>().ToArray()) open.Close();
        var window = new Window { Left = -10000, Top = -10000, Width = 100, Height = 100, ShowActivated = false, ShowInTaskbar = false };
        window.Show();
        window.Close();
        Assert.Empty(Application.Current.Windows);

        // What happens between two tests: WPF runs what the close queued.
        Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.Background);

        // A screen loads its XAML from the app's resources, which WPF refuses once the app has shut down.
        Assert.NotNull(Application.Current);
        Assert.NotNull(new SSLense.Gui.Views.LogsView());
    });
}
