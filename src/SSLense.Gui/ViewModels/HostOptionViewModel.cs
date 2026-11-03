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

    /// <param name="hasDnsBinding">It has an HTTP or HTTPS binding SSLense can manage; DNS validation needs nothing more.</param>
    public HostOptionViewModel(string host, bool hasHttpBinding, bool hasDnsBinding)
    {
        Host = host;
        HasHttpBinding = hasHttpBinding;
        HasDnsBinding = hasDnsBinding;
        isSelected = hasHttpBinding;
    }

    public string Host { get; }

    public bool HasHttpBinding { get; }

    public bool HasDnsBinding { get; }

    public bool IsReady => UsesDns ? HasDnsBinding : HasHttpBinding;

    public string BindingStatus => UsesDns
        ? HasDnsBinding ? "Ready for DNS validation" : "⚠ Needs a real host name binding"
        : HasHttpBinding ? "HTTP :80 ready" : "⚠ Missing HTTP :80 binding";
}
