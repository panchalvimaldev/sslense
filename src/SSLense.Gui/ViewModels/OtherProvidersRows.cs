using CommunityToolkit.Mvvm.ComponentModel;
using SSLense.Core.Certificates;

namespace SSLense.Gui.ViewModels;

public sealed record KeyTypeOption(string Id, string Label);

public sealed class PendingRequestRowViewModel(PendingCertificateRequest request)
{
    public PendingCertificateRequest Request { get; } = request;
    public string SiteName => Request.SiteName;

    /// <summary>The IIS site, without the host name a second certificate on the site is named after.</summary>
    public string IisSite => SSLense.Core.Config.ManagedCertificateNames.IisSiteOf(Request.SiteName);
    public string Hosts => string.Join(", ", Request.Hosts);
    public string KeyType => Request.KeyType;
    public DateTime Created => Request.CreatedAt.LocalDateTime;
    public int AgeDays => Math.Max(0, (int)(DateTimeOffset.UtcNow - Request.CreatedAt).TotalDays);
}

public sealed partial class DiscoveredBindingRowViewModel(DiscoveredBinding binding) : ObservableObject
{
    /// <summary>Ticked to be watched by SSLense.</summary>
    [ObservableProperty]
    private bool isChecked;

    public DiscoveredBinding Binding { get; } = binding;
    public string SiteName => Binding.SiteName;
    public string Host => Binding.Host.Length == 0 ? "(no host name)" : Binding.Host;
    public string Address => $"{Host}:{Binding.Port}";
    public string Issuer => Binding.Thumbprint is null ? "No certificate" : Binding.IssuerName ?? "Unknown";
    public DateTime? Expires => Binding.NotAfter?.LocalDateTime;
    /// <summary>"Managed", or the certificate's name when it is one of several on the site.</summary>
    public string Managed => !Binding.IsManaged ? string.Empty
        : Binding.ManagedAs is { } name && !string.Equals(name, Binding.SiteName, StringComparison.OrdinalIgnoreCase) ? $"Managed as {name}"
        : "Managed";
    public bool CanAdopt => Binding.Thumbprint is not null && !Binding.IsManaged;

    /// <summary>Why the row cannot be ticked, or empty.</summary>
    public string Note => Binding.IsManaged ? "Already watched" : Binding.Thumbprint is null ? "No certificate bound" : string.Empty;
}
