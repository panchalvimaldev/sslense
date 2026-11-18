using System.Runtime.ExceptionServices;
using System.Windows.Threading;
using SSLense.Gui;

namespace SSLense.Tests.Gui;

/// <summary>
/// One UI thread for every GUI test, with the app's resources loaded once: WPF allows one Application per
/// process, and its styles belong to the thread that loaded them.
/// </summary>
internal static class GuiThread
{
    private static readonly Lazy<Dispatcher> Dispatcher = new(Start);

    public static void Run(Action action)
    {
        ExceptionDispatchInfo? failure = null;
        Dispatcher.Value.Invoke(() =>
        {
            try { action(); }
            catch (Exception exception) { failure = ExceptionDispatchInfo.Capture(exception); }
        });
        failure?.Throw();
    }

    private static Dispatcher Start()
    {
        Dispatcher? dispatcher = null;
        using var ready = new ManualResetEventSlim();
        var thread = new Thread(() =>
        {
            dispatcher = System.Windows.Threading.Dispatcher.CurrentDispatcher;
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));
            // The app's own resources (styles, brushes), which the screens use.
            new App().InitializeComponent();
            ready.Set();
            System.Windows.Threading.Dispatcher.Run();
        })
        {
            IsBackground = true,
            Name = "GUI tests"
        };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        ready.Wait();
        return dispatcher!;
    }
}
