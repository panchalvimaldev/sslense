using CommunityToolkit.Mvvm.ComponentModel;

namespace SSLense.Gui.ViewModels;

public partial class HostOptionViewModel : ObservableObject
{
    [ObservableProperty]
    private bool isSelected;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsReady))]
    [NotifyPropertyChangedFor(nameof(BindingStatus))]
    private bool usesDns;

    /// <summary>SSLense answers HTTP-01 itself, so any binding for the host will do (docs/design/self-hosted-http-validation.md).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsReady))]
    [NotifyPropertyChangedFor(nameof(BindingStatus))]
    private bool selfHostedHttp;

    /// <param name="hasDnsBinding">It has an HTTP or HTTPS binding SSLense can manage; DNS validation needs nothing more.</param>
    public HostOptionViewModel(string host, bool hasHttpBinding, bool hasDnsBinding)
    {
        Host = host;
        HasHttpBinding = hasHttpBinding;
        HasDnsBinding = hasDnsBinding;
        isSelected = hasHttpBinding;
    }

    /// <summary>The certificate on the site that has this host name, such as "Managed as Main/www.domain3.co.uk, bought"; empty when none.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasOwner))]
    private string owner = string.Empty;

    public bool HasOwner => Owner.Length > 0;

    public string Host { get; }

    public bool HasHttpBinding { get; }

    public bool HasDnsBinding { get; }

    public bool IsReady => UsesDns || SelfHostedHttp ? HasDnsBinding : HasHttpBinding;

    public string BindingStatus => SelfHostedHttp && !UsesDns
        ? HasDnsBinding ? "Ready: SSLense answers on port 80" : "⚠ Needs a real host name binding"
        : UsesDns
        ? HasDnsBinding ? "Ready for DNS validation" : "⚠ Needs a real host name binding"
        : HasHttpBinding ? "HTTP :80 ready" : "⚠ Missing HTTP :80 binding";
}
