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
        HostList = status.Hosts;
        Title = status.Hosts.Count > 0 ? status.Hosts[0] : status.SiteName;
        IsNoSite = status.NoSite;
        IisSite = status.NoSite ? status.SiteName : ManagedCertificateNames.IisSiteOf(status.SiteName);
        GroupName = status.NoSite ? "Not on an IIS site" : $"IIS site · {IisSite}";
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
        SourceTag = IsImported ? "Bought" : IsManualDns ? "By hand" : "Automatic";
        var where = status.NoSite ? "Not on an IIS site" : $"IIS site {IisSite}";
        Subtitle = IsImported
            ? $"{where} · from another provider · you install renewals"
            : IsManualDns
                ? $"{where} · {status.AuthorityName} · manual DNS, renewed by hand"
                : $"{where} · {status.AuthorityName} · renews automatically";
        RenewalText = IsImported
            ? "You install it. SSLense reminds you before it expires."
            : IsManualDns
                ? "By hand, with new DNS records each time."
                : "Automatic, before it expires.";

        var days = Days(status.DaysRemaining);
        if (status.LastRenewalSucceeded == false)
        {
            Status = "Renewal failed";
            StatusKey = "Red";
            StatusHead = status.DaysRemaining < 0 ? "Renewal failed, and the certificate has expired" : $"Renewal failed. Expires in {days}";
            StatusText = (status.LastRenewalMessage is { Length: > 0 } message ? message.TrimEnd('.') + ". " : string.Empty) +
                         "Fix the cause, then choose Renew now. Activity has the full log.";
        }
        else if (status.DaysRemaining < 0)
        {
            Status = "Expired";
            StatusKey = "Red";
            StatusHead = "Expired";
            StatusText = IsImported
                ? "Visitors see a warning. Install the renewed certificate from your provider now."
                : "Visitors see a warning. Renew it now.";
        }
        else if (status.SitePendingSince is not null || others.Any(target => target.PendingSince is not null))
        {
            Status = "Site left behind";
            StatusKey = "Amber";
            StatusHead = "A site is still on the previous certificate";
            StatusText = "SSLense keeps trying to move it. Sites has the details and a button to try now.";
        }
        else if (status.DaysRemaining <= 30)
        {
            // SSLense cannot renew an imported certificate; the administrator orders the next one.
            Status = IsImported ? "Order renewal" : IsManualDns ? "Renew by hand" : "Renew soon";
            StatusKey = "Amber";
            StatusHead = $"Expires in {days}";
            StatusText = IsImported
                ? "Get the renewed certificate from your provider, then choose Install renewal. Only this certificate's bindings change."
                : IsManualDns
                    ? "It uses manual DNS validation, so it is renewed by hand. Choose Renew by hand, then create the DNS records it shows."
                    : "SSLense renews it automatically. Nothing to do.";
        }
        else
        {
            Status = "Healthy";
            StatusKey = "Green";
            StatusHead = "All good";
            StatusText = IsImported
                ? "SSLense reminds you before it expires. Then get the renewal from your provider and choose Install renewal."
                : IsManualDns
                    ? "SSLense reminds you before it expires. Then choose Renew by hand."
                    : "SSLense renews it automatically before it expires. Nothing to do.";
        }

        DaysText = status.LastRenewalSucceeded == false
            ? status.DaysRemaining < 0 ? "Renewal failed · expired" : $"Renewal failed · {days} left"
            : status.DaysRemaining < 0
                ? $"Expired {Days(-status.DaysRemaining)} ago"
                : $"Expires in {days}";
    }

    /// <summary>The managed certificate's name: its IIS site, or "site/host" for a further certificate on the site.</summary>
    public string SiteName { get; }

    /// <summary>The site, and how many others share its certificate, such as "Shop +2 sites".</summary>
    public string SiteLabel { get; }

    /// <summary>The certificate's first host name, which names it in the list.</summary>
    public string Title { get; }

    /// <summary>The IIS site the certificate is on, which the list groups by.</summary>
    public string IisSite { get; }

    public string GroupName { get; }

    public bool IsNoSite { get; }

    /// <summary>The certificate's own host names on its site, not those of other sites sharing it.</summary>
    public IReadOnlyList<string> HostList { get; }

    public string Hosts { get; }

    public DateTimeOffset Expiry { get; }

    public int DaysRemaining { get; }

    /// <summary>"Expires in 40 days", "Renewal failed · 3 days left" or "Expired 2 days ago".</summary>
    public string DaysText { get; }

    public string Thumbprint { get; }

    public string Environment { get; }

    /// <summary>Automatic, By hand, or Bought.</summary>
    public string SourceTag { get; }

    public string Subtitle { get; }

    public string RenewalText { get; }

    public bool IsImported { get; }

    public bool IsManualDns { get; }

    /// <summary>Renewed by SSLense on its own: issued here, without manual DNS.</summary>
    public bool IsAutomatic => !IsImported && !IsManualDns;

    public string Reminders { get; }

    public string Status { get; }

    /// <summary>Green, Amber or Red.</summary>
    public string StatusKey { get; }

    public bool NeedsAttention => StatusKey != "Green";

    /// <summary>What the certificate's state is, in a few words, such as "Expires in 9 days".</summary>
    public string StatusHead { get; }

    /// <summary>What to do about it, if anything.</summary>
    public string StatusText { get; }

    private static string Days(int days) => days == 1 ? "1 day" : $"{days} days";
}
