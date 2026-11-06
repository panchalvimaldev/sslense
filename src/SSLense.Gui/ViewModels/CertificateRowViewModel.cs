using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.Renewal;

namespace SSLense.Gui.ViewModels;

public sealed class CertificateRowViewModel
{
    public CertificateRowViewModel(ManagedCertificateStatus status)
    {
        SiteName = status.SiteName;
        var others = status.AdditionalTargets ?? [];
        SiteLabel = others.Count switch
        {
            0 => status.SiteName,
            1 => $"{status.SiteName} +1 site",
            _ => $"{status.SiteName} +{others.Count} sites"
        };
        Hosts = string.Join(", ", status.Hosts.Concat(others.SelectMany(target => target.Hosts)));
        Expiry = status.NotAfter;
        DaysRemaining = status.DaysRemaining;
        Thumbprint = status.Thumbprint;
        IsImported = status.Source == CertificateSource.Imported;
        IsManualDns = !IsImported && status.ValidationMethod == ValidationMethod.Dns01Manual;
        Reminders = status.Reminders switch
        {
            ReminderMode.Snoozed when status.SnoozedUntil is { } until && until > DateTimeOffset.UtcNow => $"Snoozed to {until.ToLocalTime():dd MMM}",
            ReminderMode.Snoozed => "On",
            ReminderMode.OffUntilReplaced => "Off until replaced",
            ReminderMode.Off => "Off",
            _ => "On"
        };
        Environment = IsImported
            ? "Imported"
            : CertificateAuthorities.IsBuiltIn(status.AuthorityId)
                ? status.IsTestAuthority ? "Staging" : "Production"
                : status.AuthorityName;

        if (status.LastRenewalSucceeded == false)
        {
            Status = "Renewal failed";
            StatusKey = "Red";
        }
        else if (status.DaysRemaining < 0)
        {
            Status = "Expired";
            StatusKey = "Red";
        }
        else if (status.SitePendingSince is not null || others.Any(target => target.PendingSince is not null))
        {
            Status = "Site left behind";
            StatusKey = "Amber";
        }
        else if (status.DaysRemaining <= 30)
        {
            // SSLense cannot renew an imported certificate; the administrator orders the next one.
            Status = IsImported ? "Order renewal" : IsManualDns ? "Renew by hand" : "Renew soon";
            StatusKey = "Amber";
        }
        else
        {
            Status = "Healthy";
            StatusKey = "Green";
        }
    }

    public string SiteName { get; }

    /// <summary>The site, and how many others share its certificate, such as "Shop +2 sites".</summary>
    public string SiteLabel { get; }

    public string Hosts { get; }

    public DateTimeOffset Expiry { get; }

    public int DaysRemaining { get; }

    public string Thumbprint { get; }

    public string Environment { get; }

    public bool IsImported { get; }

    public bool IsManualDns { get; }

    public string Reminders { get; }

    public string Status { get; }

    public string StatusKey { get; }
}
