using System.Windows;
using System.IO;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using SSLense.Core;
using SSLense.Core.Config;
using SSLense.Gui.ViewModels;

namespace SSLense.Gui;

public partial class App : Application
{
    private IHost? _host;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.File(
                Path.Combine(AppPaths.LogDirectory, "sslense-.log"),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 30,
                shared: true)
            .CreateLogger();

        try
        {
            var builder = Host.CreateApplicationBuilder(e.Args);
            builder.Services.AddSerilog();
            builder.Services.AddSSLenseCore();
            builder.Services.AddSingleton<INavigationService, NavigationService>();
            builder.Services.AddSingleton<DashboardViewModel>();
            builder.Services.AddSingleton<IssueCertificateViewModel>();
            builder.Services.AddSingleton<CertificateDetailsViewModel>();
            builder.Services.AddSingleton<SettingsViewModel>();
            builder.Services.AddSingleton<LogsViewModel>();
            builder.Services.AddSingleton<MainViewModel>();
            builder.Services.AddSingleton<MainWindow>();
            _host = builder.Build();
            await _host.StartAsync().ConfigureAwait(true);

            var window = _host.Services.GetRequiredService<MainWindow>();
            MainWindow = window;
            window.Show();
        }
        catch (Exception exception)
        {
            Log.Fatal(exception, "SSLense GUI failed to start");
            MessageBox.Show(
                exception.Message,
                "SSLense could not start",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Shutdown(1);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (_host is not null)
        {
            _host.StopAsync().GetAwaiter().GetResult();
            _host.Dispose();
        }

        Log.CloseAndFlush();
        base.OnExit(e);
    }
}
