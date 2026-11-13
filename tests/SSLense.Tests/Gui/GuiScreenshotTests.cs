using System.IO;
using System.Runtime.ExceptionServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Deployment;
using SSLense.Core.Diagnostics;
using SSLense.Core.Reminders;
using SSLense.Core.Renewal;
using SSLense.Gui;
using SSLense.Gui.ViewModels;
using Xunit;
using Xunit.Abstractions;

namespace SSLense.Tests.Gui;

/// <summary>
/// Opens the window with sample certificates, goes through its main screens, and saves an image of each to
/// the test output's "screens" folder, so the screens can be reviewed without a server (docs/design/gui-redesign.md).
/// </summary>
public sealed class GuiScreenshotTests(ITestOutputHelper output)
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    [Fact]
    public void TheMainScreens_RenderWithSampleCertificates()
    {
        var folder = Path.Combine(AppContext.BaseDirectory, "screens");
        Directory.CreateDirectory(folder);
        GuiThread.Run(() =>
        {
            using var provider = BuildViewModels();
            var main = provider.GetRequiredService<MainViewModel>();
            var window = new MainWindow(main)
            {
                WindowStartupLocation = WindowStartupLocation.Manual, Left = -10000, Top = -10000, ShowActivated = false,
                Width = 1280, Height = 800
            };
            window.Show();
            Settle();

            var certificates = main.Certificates;
            Assert.Equal(5, certificates.TotalCount);
            Assert.Equal(2, certificates.AttentionCount);
            Save(window, folder, "01-certificates-summary");

            certificates.SelectedCertificate = certificates.Certificates.Single(row => row.Title == "www.domain3.co.uk");
            Settle();
            Assert.Equal("Main/www.domain3.co.uk", certificates.Details.SelectedSite);
            Save(window, folder, "02-certificate-bought-due");

            certificates.SelectedCertificate = certificates.Certificates.Single(row => row.Title == "shop.example.com");
            Settle();
            Save(window, folder, "03-certificate-renewal-failed");

            SelectSection(window, "Certificate");
            Save(window, folder, "04-certificate-section");
            SelectSection(window, "After install");
            Save(window, folder, "05-after-install-section");
            SelectSection(window, "Status");

            main.SelectedTab = main.Tabs[1];
            Settle();
            Save(window, folder, "06-activity");

            main.SelectedTab = main.Tabs[2];
            Settle();
            Save(window, folder, "07-settings");

            main.AddCertificateCommand.Execute(null);
            Settle();
            Assert.True(main.IsAddingCertificate);
            Save(window, folder, "08-add-certificate");

            window.Close();
        });
        output.WriteLine($"Screens saved to {folder}");
    }

    private static void SelectSection(Window window, string header)
    {
        var tabs = Find<TabControl>(window).First(control => control.IsVisible && control.Items.OfType<TabItem>().Any(item => Equals(item.Header, "Status")));
        tabs.SelectedItem = tabs.Items.OfType<TabItem>().Single(item => Equals(item.Header, header));
        Settle();
    }

    private static IEnumerable<T> Find<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(parent); index++)
        {
            var child = VisualTreeHelper.GetChild(parent, index);
            if (child is T match) yield return match;
            foreach (var descendant in Find<T>(child)) yield return descendant;
        }
    }

    /// <summary>Lets bindings, layout and the view models' completed tasks run.</summary>
    private static void Settle()
    {
        for (var round = 0; round < 6; round++)
        {
            Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
        }
    }

    private static void Save(Window window, string folder, string name)
    {
        var content = (FrameworkElement)window.Content;
        content.UpdateLayout();
        var bitmap = new RenderTargetBitmap((int)content.ActualWidth, (int)content.ActualHeight, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(content);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var file = File.Create(Path.Combine(folder, name + ".png"));
        encoder.Save(file);
    }

    /// <summary>The view models as the app registers them, with sample certificates behind them.</summary>
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

        var records = SampleRecords();
        var renewal = new Mock<IRenewalService> { DefaultValue = DefaultValue.Mock };
        renewal.Setup(value => value.GetStatusAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(records.Select(Status).ToArray());
        var management = new Mock<ICertificateManagementService> { DefaultValue = DefaultValue.Mock };
        management.Setup(value => value.GetDetailsAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string name, CancellationToken _) => Details(records.Single(record => record.SiteName == name)));
        var reminders = new Mock<IReminderService> { DefaultValue = DefaultValue.Mock };
        reminders.Setup(value => value.GetOverviewAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ReminderOverview(new ReminderConfig(), records, null));
        var deployment = new Mock<IDeploymentService> { DefaultValue = DefaultValue.Mock };
        deployment.Setup(value => value.ListAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string site, CancellationToken _) => new DeploymentOverview(site, "AB12", [], null, false));
        var settings = new Mock<ISettingsService> { DefaultValue = DefaultValue.Mock };
        settings.Setup(value => value.GetAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new AppConfig());
        services.AddSingleton(settings.Object);
        var health = new Mock<IHealthCheckService> { DefaultValue = DefaultValue.Mock };
        health.Setup(value => value.RunQuickAsync(It.IsAny<CancellationToken>())).ReturnsAsync([]);
        services.AddSingleton(renewal.Object);
        services.AddSingleton(management.Object);
        services.AddSingleton(reminders.Object);
        services.AddSingleton(deployment.Object);
        services.AddSingleton(health.Object);

        var configured = new HashSet<Type> { typeof(IRenewalService), typeof(ICertificateManagementService), typeof(IReminderService), typeof(IDeploymentService), typeof(IHealthCheckService), typeof(ISettingsService) };
        var coreServices = typeof(MainViewModel).Assembly.GetTypes()
            .Where(type => type.Namespace == typeof(MainViewModel).Namespace && type.IsClass && !type.IsAbstract)
            .SelectMany(type => type.GetConstructors())
            .SelectMany(constructor => constructor.GetParameters())
            .Select(parameter => parameter.ParameterType)
            .Where(type => type.IsInterface && !type.IsGenericType && type != typeof(INavigationService) && !configured.Contains(type))
            .Distinct();
        foreach (var type in coreServices)
        {
            var mock = (Mock)Activator.CreateInstance(typeof(Mock<>).MakeGenericType(type))!;
            mock.DefaultValue = DefaultValue.Mock;
            services.AddSingleton(type, mock.Object);
        }

        return services.BuildServiceProvider();
    }

    /// <summary>Three bought certificates on one site, as on the server that asked for it, and two from Let's Encrypt.</summary>
    private static ManagedCertificate[] SampleRecords() =>
    [
        Record("Main", "www.domain1.co.uk", 40, CertificateSource.Imported),
        Record("Main/www.domain2.co.uk", "www.domain2.co.uk", 60, CertificateSource.Imported),
        Record("Main/www.domain3.co.uk", "www.domain3.co.uk", 9, CertificateSource.Imported),
        Record("Blog", "blog.example.com", 52, CertificateSource.Acme) with { CertificateNames = ["blog.example.com", "www.blog.example.com"] },
        Record("Shop", "shop.example.com", 26, CertificateSource.Acme) with
        {
            LastRenewalAttempt = Now.AddHours(-5),
            LastRenewalSucceeded = false,
            LastRenewalMessage = "Let's Encrypt could not reach http://shop.example.com/.well-known/acme-challenge/ on port 80 (connection timed out)",
            ConsecutiveFailures = 2
        }
    ];

    private static ManagedCertificate Record(string name, string host, int days, CertificateSource source) =>
        new(name, [host], "ops@example.com", "3F2A9C0D1E8B7A6C5D4E3F2A1B0C9D8E7F6A5B4C", Now.AddDays(days - 365), Now.AddDays(days),
            Source: source, Issuer: source == CertificateSource.Imported ? "Sectigo RSA Domain Validation Secure Server CA" : "(STAGING) Let's Encrypt",
            LastRemindedAt: days < 14 ? Now.AddHours(-10) : null);

    private static ManagedCertificateStatus Status(ManagedCertificate record) =>
        new(record.SiteName, record.Hosts, record.NotBefore, record.NotAfter, (int)(record.NotAfter - Now).TotalDays + 1, record.Thumbprint,
            record.LastRenewalAttempt, record.LastRenewalSucceeded, record.LastRenewalMessage,
            Source: record.Source, Issuer: record.Issuer, ValidationMethod: record.ValidationMethod, CertificateNames: record.CertificateNames);

    private static CertificateDetails Details(ManagedCertificate record) =>
        new(record.SiteName, record.Hosts, record.Thumbprint, record.Issuer!, record.NotBefore, record.NotAfter,
            [ManagedCertificateNames.IisSiteOf(record.SiteName)],
            [$"{Now.AddDays(-10):yyyy-MM-dd HH:mm} Checked: https://{record.Hosts[0]} serves the expected certificate."],
            AuthorityName: record.Source == CertificateSource.Imported ? "Another provider" : "Let's Encrypt staging",
            Source: record.Source);
}
