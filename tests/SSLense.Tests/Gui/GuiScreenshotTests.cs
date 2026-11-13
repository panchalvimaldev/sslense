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
using SSLense.Core.Iis;
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
            SelectSection(window, "Reminders");
            Save(window, folder, "05b-reminders-section");
            ClickReminder(window, 3);
            WaitFor(() => !certificates.Details.IsBusy);
            Assert.Equal(3, ReminderList(window).SelectedIndex);
            Assert.Contains("Off until", certificates.Details.ReminderState, StringComparison.Ordinal);
            ClickReminder(window, 1);
            WaitFor(() => !certificates.Details.IsBusy);
            Assert.Equal(1, ReminderList(window).SelectedIndex);
            Assert.Contains("Snoozed until", certificates.Details.ReminderState, StringComparison.Ordinal);
            Assert.Null(certificates.Details.ErrorMessage);
            Save(window, folder, "05d-reminders-snoozed");
            SelectSection(window, "Status");

            // Check, and the ⋯ menu, which must open with its actions.
            // Pressed as a person would: through the button, not its command.
            var check = Find<Button>(window).Single(button => button.IsVisible && System.Windows.Automation.AutomationProperties.GetName(button) == "Check");
            Assert.True(check.IsEnabled);
            ((System.Windows.Automation.Provider.IInvokeProvider)new System.Windows.Automation.Peers.ButtonAutomationPeer(check)
                .GetPattern(System.Windows.Automation.Peers.PatternInterface.Invoke)).Invoke();
            WaitFor(() => certificates.Details.LastCheckPassed is not null);
            Assert.True(certificates.Details.LastCheckPassed);
            Save(window, folder, "05c-checked");
            var more = Find<Button>(window).Single(button => button.IsVisible && System.Windows.Automation.AutomationProperties.GetName(button) == "More actions");
            more.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
            Settle();
            Assert.True(more.ContextMenu!.IsOpen);
            Assert.Equal(5, more.ContextMenu.Items.OfType<MenuItem>().Count());
            Assert.Contains(more.ContextMenu.Items.OfType<MenuItem>(), item => (string)item.Header == "Stop managing, keep it in IIS…" && item.IsVisible);
            more.ContextMenu.IsOpen = false;
            Settle();

            main.SelectedTab = main.Tabs[1];
            Settle();
            var healthChecks = provider.GetRequiredService<HealthViewModel>();
            healthChecks.RunCommand.Execute(null);
            WaitFor(() => healthChecks.Results.Count == 3);
            Save(window, folder, "06-activity");

            main.SelectedTab = main.Tabs[2];
            Settle();
            Save(window, folder, "07-settings");
            provider.GetRequiredService<SettingsViewModel>().ShowSection("Notifications");
            Settle();
            Save(window, folder, "07b-settings-notifications");
            provider.GetRequiredService<SettingsViewModel>().ShowSection("Certificate authorities");
            Settle();
            Save(window, folder, "07c-settings-authorities");
            provider.GetRequiredService<SettingsViewModel>().ShowSection("DNS providers");
            Settle();
            Save(window, folder, "07d-settings-dns");

            main.AddCertificateCommand.Execute(null);
            Settle();
            Assert.True(main.IsAddingCertificate);
            Save(window, folder, "08-add-certificate");

            var add = provider.GetRequiredService<AddCertificateViewModel>();
            string[] sources = [AddCertificateViewModel.Automatic, AddCertificateViewModel.File, AddCertificateViewModel.Request, AddCertificateViewModel.Watch];
            for (var index = 0; index < sources.Length; index++)
            {
                add.Sources[index].Choose.Execute(null);
                Settle();
                Assert.Equal(sources[index], add.Source);
                Save(window, folder, $"{9 + index:00}-add-{sources[index]}");
            }

            Assert.Equal(2, add.OtherProviders.Bindings.Count(row => row.CanAdopt));
            add.OtherProviders.Bindings.First(row => row.CanAdopt).IsChecked = true;
            Assert.Equal("Watch 1 certificate", add.OtherProviders.AdoptCheckedLabel);

            // Install renewal, from a bought certificate that is due.
            main.SelectedTab = main.Tabs[0];
            Settle();
            certificates.SelectedCertificate = certificates.Certificates.Single(row => row.Title == "www.domain3.co.uk");
            Settle();
            certificates.Details.InstallRenewalCommand.Execute(null);
            Settle();
            var dialog = certificates.Details.InstallRenewal;
            Assert.True(dialog.IsOpen);
            Assert.True(dialog.UsePfx);
            Save(window, folder, "13-install-renewal");
            dialog.PfxPath = @"C:\Users\admin\Downloads\domain3-renewed.pfx";
            dialog.NextCommand.Execute(null);
            Settle();
            Save(window, folder, "14-install-renewal-confirm");
            dialog.CloseCommand.Execute(null);

            window.Close();
        });
        output.WriteLine($"Screens saved to {folder}");
    }

    private static ListBox ReminderList(Window window) =>
        Find<ListBox>(window).Single(list => list.IsVisible && System.Windows.Automation.AutomationProperties.GetName(list) == "Reminders for this certificate");

    /// <summary>Clicks a reminder choice with the mouse button, as a person would.</summary>
    private static void ClickReminder(Window window, int index)
    {
        var item = (ListBoxItem)ReminderList(window).ItemContainerGenerator.ContainerFromIndex(index);
        item.RaiseEvent(new System.Windows.Input.MouseButtonEventArgs(System.Windows.Input.Mouse.PrimaryDevice, 0, System.Windows.Input.MouseButton.Left)
        {
            RoutedEvent = UIElement.MouseLeftButtonDownEvent
        });
        Settle();
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

    /// <summary>Runs the UI thread until the condition holds, for work that finishes on another thread first.</summary>
    private static void WaitFor(Func<bool> condition)
    {
        var until = DateTime.UtcNow.AddSeconds(10);
        while (!condition() && DateTime.UtcNow < until)
        {
            Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.Background);
            Thread.Sleep(20);
        }

        Settle();
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
        services.AddSingleton<InstallRenewalViewModel>();
        services.AddSingleton<MainViewModel>();

        var records = SampleRecords();
        var renewal = new Mock<IRenewalService> { DefaultValue = DefaultValue.Mock };
        renewal.Setup(value => value.GetStatusAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(records.Select(Status).ToArray());
        var management = new Mock<ICertificateManagementService> { DefaultValue = DefaultValue.Mock };
        management.Setup(value => value.GetDetailsAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string name, CancellationToken _) => Details(records.Single(record => record.SiteName == name)));
        management.Setup(value => value.CheckServedAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(async (string name, CancellationToken _) => { await Task.Delay(40); return new CertificateCheckResult(true, $"https://{records.Single(record => record.SiteName == name).Hosts[0]} serves the expected certificate."); });
        var reminders = new Mock<IReminderService> { DefaultValue = DefaultValue.Mock };
        // Saves like the real store: the next overview shows the new setting.
        reminders.Setup(value => value.GetOverviewAsync(It.IsAny<CancellationToken>()))
            .Returns(async () => { await Task.Delay(40); return new ReminderOverview(new ReminderConfig(), records.ToArray(), null); });
        reminders.Setup(value => value.SetCertificateRemindersAsync(It.IsAny<string>(), It.IsAny<ReminderMode>(), It.IsAny<int?>(), It.IsAny<CancellationToken>()))
            .Callback<string, ReminderMode, int?, CancellationToken>((name, mode, days, _) =>
            {
                var index = Array.FindIndex(records, record => record.SiteName == name);
                records[index] = records[index] with { Reminders = mode, SnoozedUntil = days is { } d ? DateTimeOffset.UtcNow.AddDays(d) : null };
            })
            .Returns(() => Task.Delay(40));
        var deployment = new Mock<IDeploymentService> { DefaultValue = DefaultValue.Mock };
        deployment.Setup(value => value.ListAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string site, CancellationToken _) => new DeploymentOverview(site, "AB12", [], null, false));
        var imported = new Mock<IImportedCertificateService> { DefaultValue = DefaultValue.Mock };
        imported.Setup(value => value.DiscoverAsync(It.IsAny<CancellationToken>())).ReturnsAsync(
        [
            new DiscoveredBinding("Main", "www.domain1.co.uk", 443, "AA01", "Sectigo RSA Domain Validation Secure Server CA", Now.AddDays(40), true, "Main"),
            new DiscoveredBinding("Main", "www.domain2.co.uk", 443, "AA02", "Sectigo RSA Domain Validation Secure Server CA", Now.AddDays(60), true, "Main/www.domain2.co.uk"),
            new DiscoveredBinding("Main", "www.domain3.co.uk", 443, "AA03", "Sectigo RSA Domain Validation Secure Server CA", Now.AddDays(9), true, "Main/www.domain3.co.uk"),
            new DiscoveredBinding("Intranet", "intranet.example.local", 443, "AA04", "Example Internal CA", Now.AddDays(110), false),
            new DiscoveredBinding("Legacy", "legacy.example.com", 443, "AA05", "DigiCert Global G2 TLS RSA SHA256 2020 CA1", Now.AddDays(17), false),
            new DiscoveredBinding("Legacy", "old.example.com", 443, null, null, null, false)
        ]);
        services.AddSingleton(imported.Object);
        var pending = new Mock<IPendingRequestStore> { DefaultValue = DefaultValue.Mock };
        pending.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync(
            [new PendingCertificateRequest("Main/www.domain4.co.uk", ["www.domain4.co.uk"], "key", "RSA2048",
                "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...sample...\n-----END CERTIFICATE REQUEST-----", Now.AddDays(-2))]);
        pending.Setup(value => value.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync((PendingCertificateRequest?)null);
        services.AddSingleton(pending.Object);
        var iis = new Mock<IIisService> { DefaultValue = DefaultValue.Mock };
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(
        [
            new IisSite(1, "Main", "Started", @"C:\inetpub\main", [new IisBinding("https", "*", 443, "www.domain1.co.uk", "AA01", "My", true)]),
            new IisSite(2, "Blog", "Started", @"C:\inetpub\blog", [new IisBinding("http", "*", 80, "blog.example.com", null, null, false)])
        ]);
        services.AddSingleton(iis.Object);
        var authorities = new Mock<SSLense.Core.Acme.ICertificateAuthorityService> { DefaultValue = DefaultValue.Mock };
        authorities.Setup(value => value.ListAsync(It.IsAny<CancellationToken>())).ReturnsAsync(
        [
            new SSLense.Core.Acme.CertificateAuthorityOverview("letsencrypt-staging", "Let's Encrypt staging", new Uri("https://acme-staging-v02.api.letsencrypt.org/directory"), true, true, false, ["letsencrypt.org"], ["Blog", "Shop"]),
            new SSLense.Core.Acme.CertificateAuthorityOverview("letsencrypt", "Let's Encrypt", new Uri("https://acme-v02.api.letsencrypt.org/directory"), false, true, false, ["letsencrypt.org"], []),
            new SSLense.Core.Acme.CertificateAuthorityOverview("zerossl", "ZeroSSL", new Uri("https://acme.zerossl.com/v2/DV90"), false, false, true, ["sectigo.com"], []),
            new SSLense.Core.Acme.CertificateAuthorityOverview("google", "Google Trust Services", new Uri("https://dv.acme-v02.api.pki.goog/directory"), false, false, true, ["pki.goog"], [])
        ]);
        services.AddSingleton(authorities.Object);
        var dns = new Mock<SSLense.Core.DnsValidation.IDnsProviderService> { DefaultValue = DefaultValue.Mock };
        dns.Setup(value => value.ListAsync(It.IsAny<CancellationToken>())).ReturnsAsync(
        [
            new SSLense.Core.DnsValidation.DnsProviderOverview("example-cloudflare", SSLense.Core.DnsValidation.DnsProviderType.Cloudflare, "example.com", "0123456789abcdef"),
            new SSLense.Core.DnsValidation.DnsProviderOverview("domain1-script", SSLense.Core.DnsValidation.DnsProviderType.Script, "domain1.co.uk", null, "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"),
            new SSLense.Core.DnsValidation.DnsProviderOverview("intranet-acme-dns", SSLense.Core.DnsValidation.DnsProviderType.AcmeDns, "example.local", null, null, "_acme-challenge.example.local CNAME 8e5700ea.auth.acme-dns.io")
        ]);
        services.AddSingleton(dns.Object);
        var settings = new Mock<ISettingsService> { DefaultValue = DefaultValue.Mock };
        settings.Setup(value => value.GetAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new AppConfig());
        services.AddSingleton(settings.Object);
        var health = new Mock<IHealthCheckService> { DefaultValue = DefaultValue.Mock };
        health.Setup(value => value.RunAsync(It.IsAny<IProgress<SSLense.Core.ProgressEvent>>(), It.IsAny<CancellationToken>())).ReturnsAsync(
        [
            new HealthCheckResult("Renewal service", HealthStatus.Pass, "Running; last check 12 minutes ago."),
            new HealthCheckResult("Port 80 for shop.example.com", HealthStatus.Fail, "Let's Encrypt could not reach the site on port 80.", "Open port 80 in the Windows firewall, or switch the certificate to DNS validation."),
            new HealthCheckResult("Notifications", HealthStatus.Warning, "No email or chat channel is set up.", "Add one in Settings, Notifications, and send a test.")
        ]);
        health.Setup(value => value.RunQuickAsync(It.IsAny<CancellationToken>())).ReturnsAsync([]);
        services.AddSingleton(renewal.Object);
        services.AddSingleton(management.Object);
        services.AddSingleton(reminders.Object);
        services.AddSingleton(deployment.Object);
        services.AddSingleton(health.Object);

        var configured = new HashSet<Type> { typeof(IRenewalService), typeof(ICertificateManagementService), typeof(IReminderService), typeof(IDeploymentService), typeof(IHealthCheckService), typeof(ISettingsService), typeof(IImportedCertificateService), typeof(IPendingRequestStore), typeof(IIisService), typeof(SSLense.Core.Acme.ICertificateAuthorityService), typeof(SSLense.Core.DnsValidation.IDnsProviderService) };
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
