using CommunityToolkit.Mvvm.ComponentModel;

namespace SSLense.Gui.ViewModels;

/// <summary>
/// Add certificate: for now the Issue screen (Let's Encrypt and other ACME authorities) and the screen for
/// certificates bought elsewhere or already in IIS, as two tabs (docs/design/gui-redesign.md, step 1).
/// </summary>
public partial class AddCertificateViewModel(IssueCertificateViewModel issue, OtherProvidersViewModel otherProviders) : ObservableObject
{
    public const int AutomaticTab = 0;
    public const int OtherProvidersTab = 1;

    private string? _pendingContext;

    /// <summary>0: free and automatic; 1: bought, or already in IIS.</summary>
    [ObservableProperty]
    private int selectedTab;

    public IssueCertificateViewModel Issue { get; } = issue;

    public OtherProvidersViewModel OtherProviders { get; } = otherProviders;

    /// <summary>Opens a tab, filled in for a certificate when one is named.</summary>
    public Task ShowAsync(int tab, string? context)
    {
        if (SelectedTab == tab) return InitializeTabAsync(tab, context);
        _pendingContext = context;
        SelectedTab = tab;
        return Task.CompletedTask;
    }

    partial void OnSelectedTabChanged(int value)
    {
        var context = _pendingContext;
        _pendingContext = null;
        _ = InitializeTabAsync(value, context);
    }

    private Task InitializeTabAsync(int tab, string? context) =>
        tab == OtherProvidersTab ? OtherProviders.InitializeAsync(context) : Issue.InitializeAsync(context);
}
