using CommunityToolkit.Mvvm.ComponentModel;

namespace SSLense.Gui.ViewModels;

public partial class HostOptionViewModel : ObservableObject
{
    [ObservableProperty]
    private bool isSelected;

    public HostOptionViewModel(string host, bool hasHttpBinding)
    {
        Host = host;
        HasHttpBinding = hasHttpBinding;
        isSelected = hasHttpBinding;
    }

    public string Host { get; }

    public bool HasHttpBinding { get; }

    public string BindingStatus => HasHttpBinding ? "HTTP :80 ready" : "⚠ Missing HTTP :80 binding";
}
