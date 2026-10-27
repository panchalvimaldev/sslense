using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Core.Validation;
using SSLense.Core.Renewal;
using SSLense.Core.WindowsServices;
using SSLense.Core.Notifications;
using SSLense.Core.Logs;
using Microsoft.Extensions.DependencyInjection;

namespace SSLense.Core;

public static class DependencyInjection
{
    public static IServiceCollection AddSSLenseCore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddSingleton<IFileSystem, PhysicalFileSystem>();
        services.AddSingleton<IConfigStore, JsonConfigStore>();
        services.AddSingleton<IManagedCertificateStore, JsonManagedCertificateStore>();
        services.AddSingleton<ISecretProtector, DpapiSecretProtector>();
        services.AddSingleton<IAcmeAccountStore, AcmeAccountStore>();
        services.AddSingleton<IChallengeProbe, HttpChallengeProbe>();
        services.AddTransient<IChallengeHandler, Http01Handler>();
        services.AddTransient<ICertificateArtifactStore, CertificateArtifactStore>();
        services.AddTransient<ICertificateStore, WindowsCertificateStore>();
        services.AddTransient<IAcmeProtocolClient, CertesAcmeProtocolClient>();
        services.AddTransient<IAcmeService, AcmeService>();
        services.AddTransient<IIisService, IisService>();
        services.AddTransient<IRenewalService, RenewalService>();
        services.AddSingleton<IRenewalDelay, RenewalDelay>();
        services.AddTransient<IWindowsServiceManager, WindowsServiceManager>();
        services.AddSingleton<IEmailSender, SmtpEmailSender>();
        services.AddSingleton<IWebhookSender, WebhookSender>();
        services.AddTransient<INotifier, Notifier>();
        services.AddTransient<INotificationSettingsService, NotificationSettingsService>();
        services.AddSingleton<ILogService, LogService>();
        return services;
    }
}
