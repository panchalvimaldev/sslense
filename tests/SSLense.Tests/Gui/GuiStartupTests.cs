using System.Runtime.ExceptionServices;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SSLense.Gui;
using SSLense.Gui.ViewModels;
using SSLense.Gui.Views;
using Xunit;

namespace SSLense.Tests.Gui;

/// <summary>
/// The app builds every screen's view model before its window opens, so an exception in any of their
/// constructors stops the app from starting (0.22.0: "Object reference not set to an instance of an object").
/// </summary>
public sealed class GuiStartupTests
{
    [Fact]
    public void EveryViewModel_CanBeBuilt_AsAtStartup()
    {
        using var provider = BuildViewModels();

        Assert.NotNull(provider.GetRequiredService<MainViewModel>());
        Assert.NotNull(provider.GetRequiredService<CertificateDetailsViewModel>().SelectedDeploymentKind);
    }

    [Fact]
    public void EveryScreen_LoadsAndLaysOut_WithItsViewModel()
    {
        GuiThread.Run(() =>
        {
            using var provider = BuildViewModels();
            (UserControl View, object ViewModel)[] screens =
            [
                (new DashboardView(), provider.GetRequiredService<DashboardViewModel>()),
                (new IssueCertificateView(), provider.GetRequiredService<IssueCertificateViewModel>()),
                (new OtherProvidersView(), provider.GetRequiredService<OtherProvidersViewModel>()),
                (new CertificateDetailsView(), provider.GetRequiredService<CertificateDetailsViewModel>()),
                (new SettingsView(), provider.GetRequiredService<SettingsViewModel>()),
                (new HealthView(), provider.GetRequiredService<HealthViewModel>()),
                (new LogsView(), provider.GetRequiredService<LogsViewModel>()),
                (new AddCertificateView(), provider.GetRequiredService<AddCertificateViewModel>()),
                (new ActivityView(), provider.GetRequiredService<ActivityViewModel>()),
            ];

            foreach (var (view, viewModel) in screens)
            {
                view.DataContext = viewModel;
                view.Measure(new Size(1280, 900));
                view.Arrange(new Rect(0, 0, 1280, 900));
                view.UpdateLayout();
            }

            // Shown off screen, which runs its first load, then closed.
            var window = new MainWindow(provider.GetRequiredService<MainViewModel>())
            {
                WindowStartupLocation = WindowStartupLocation.Manual, Left = -10000, Top = -10000, ShowActivated = false
            };
            window.Show();
            window.Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.ApplicationIdle);
            window.Close();
        });
    }

    /// <summary>The view models as the app registers them, with every Core service an empty mock.</summary>
    private static ServiceProvider BuildViewModels()
    {
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<INavigationService, NavigationService>();
        services.AddSingleton<DashboardViewModel>();
        services.AddSingleton<IssueCertificateViewModel>();
        services.AddSingleton<OtherProvidersViewModel>();
        services.AddSingleton<CertificateDetailsViewModel>();
        services.AddSingleton<SettingsViewModel>();
        services.AddSingleton<HealthViewModel>();
        services.AddSingleton<LogsViewModel>();
        services.AddSingleton<AddCertificateViewModel>();
        services.AddSingleton<ActivityViewModel>();
        services.AddSingleton<MainViewModel>();

        var coreServices = typeof(MainViewModel).Assembly.GetTypes()
            .Where(type => type.Namespace == typeof(MainViewModel).Namespace && type.IsClass && !type.IsAbstract)
            .SelectMany(type => type.GetConstructors())
            .SelectMany(constructor => constructor.GetParameters())
            .Select(parameter => parameter.ParameterType)
            .Where(type => type.IsInterface && !type.IsGenericType && type != typeof(INavigationService))
            .Distinct();
        foreach (var type in coreServices)
        {
            var mock = (Mock)Activator.CreateInstance(typeof(Mock<>).MakeGenericType(type))!;
            mock.DefaultValue = DefaultValue.Mock;
            services.AddSingleton(type, mock.Object);
        }

        return services.BuildServiceProvider();
    }
}
