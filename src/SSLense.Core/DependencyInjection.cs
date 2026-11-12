using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.DnsValidation;
using SSLense.Core.Iis;
using SSLense.Core.Validation;
using SSLense.Core.Renewal;
using SSLense.Core.WindowsServices;
using SSLense.Core.Notifications;
using SSLense.Core.Logs;
using SSLense.Core.Diagnostics;
using SSLense.Core.Reminders;
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
        services.AddSingleton<ICertificateAuthorityRegistry, CertificateAuthorityRegistry>();
        services.AddSingleton<IAcmeDirectoryReader, AcmeDirectoryReader>();
        services.AddSingleton<ICertificateAuthorityLock>(_ => new FileCertificateAuthorityLock());
        services.AddTransient<ICertificateAuthorityService, CertificateAuthorityService>();
        services.AddSingleton<IChallengeProbe, HttpChallengeProbe>();
        services.AddSingleton<IChallengeJournal, JsonChallengeJournal>();
        services.AddSingleton<IIisSectionLocks, IisSectionLocks>();
        services.AddTransient<IChallengeHandler, Http01Handler>();
        services.AddSingleton<IDnsLookup, DnsClientLookup>();
        services.AddSingleton<IDnsProvider, CloudflareDnsProvider>();
        services.AddSingleton<IDnsScriptStore>(_ => new DnsScriptStore());
        services.AddSingleton<IScriptRunner, PowerShellScriptRunner>();
        services.AddSingleton<IDnsProvider, ScriptDnsProvider>();
        services.AddSingleton<IAcmeDnsClient, AcmeDnsClient>();
        services.AddSingleton<IDnsProvider, AcmeDnsProvider>();
        services.AddSingleton<IDnsChallengeJournal, JsonDnsChallengeJournal>();
        services.AddTransient<DnsPropagationChecker>();
        services.AddTransient<IDnsChallengeService, DnsChallengeService>();
        services.AddTransient<IDnsProviderService, DnsProviderService>();
        services.AddTransient<ICertificateArtifactStore, CertificateArtifactStore>();
        services.AddTransient<ICertificateStore, WindowsCertificateStore>();
        services.AddSingleton<ICertificateOperationLock, CertificateOperationLock>();
        services.AddSingleton<ICertificateTransactionJournal, JsonCertificateTransactionJournal>();
        services.AddTransient<ICertificateRecoveryService, CertificateRecoveryService>();
        services.AddTransient<IAcmeProtocolClient, CertesAcmeProtocolClient>();
        services.AddTransient<IAcmeService, AcmeService>();
        services.AddSingleton<ITlsBindingProbe, TlsBindingProbe>();
        services.AddTransient<IIisService, IisService>();
        services.AddTransient<ICertificateSharingService, CertificateSharingService>();
        services.AddTransient<IRenewalService, RenewalService>();
        services.AddTransient<IReminderService, ReminderService>();
        services.AddTransient<IOutsideRenewalDetector, OutsideRenewalDetector>();
        services.AddTransient<IRenewalReadinessCheck, RenewalReadinessCheck>();
        services.AddTransient<IServedCertificateCheck, ServedCertificateCheck>();
        services.AddSingleton<IReminderStateStore, JsonReminderStateStore>();
        services.AddSingleton<HttpClient>();
        services.AddSingleton<IRenewalInfoProvider, AcmeRenewalInfoProvider>();
        services.AddTransient<IWindowsServiceManager, WindowsServiceManager>();
        services.AddSingleton<IEmailSender, MailKitEmailSender>();
        services.AddSingleton<IEventLogWriter, WindowsEventLogWriter>();
        services.AddSingleton<IChatSender, ChatSender>();
        services.AddTransient<INotifier, Notifier>();
        services.AddTransient<INotificationSettingsService, NotificationSettingsService>();
        services.AddSingleton<ILogService, LogService>();
        services.AddTransient<IPreflightService, PreflightService>();
        services.AddTransient<ISettingsService, SettingsService>();
        services.AddTransient<ICertificateManagementService, CertificateManagementService>();
        services.AddSingleton<IPendingRequestStore, JsonPendingRequestStore>();
        services.AddSingleton<IPrivateKeyStore>(_ => new CngPrivateKeyStore(machineScope: true));
        services.AddTransient<IImportedCertificateService, ImportedCertificateService>();
        services.AddSingleton<IServiceHeartbeatStore, JsonServiceHeartbeatStore>();
        services.AddSingleton<IHostResolver, DnsHostResolver>();
        services.AddTransient<IHealthCheckService, HealthCheckService>();
        services.AddTransient<IDiagnosticBundleService, DiagnosticBundleService>();
        return services;
    }
}
