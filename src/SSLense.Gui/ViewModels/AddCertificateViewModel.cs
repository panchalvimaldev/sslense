using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace SSLense.Gui.ViewModels;

/// <summary>One answer to "Where does the certificate come from?".</summary>
public sealed record AddSourceOption(string Key, string Title, string Text, bool Recommended, IRelayCommand Choose);

/// <summary>
/// Add certificate: first where the certificate comes from, then the screen for that source
/// (docs/design/gui-redesign.md, step 2).
/// </summary>
public partial class AddCertificateViewModel : ObservableObject
{
    public const string Automatic = "automatic";
    public const string File = "file";
    public const string Request = "request";
    public const string Watch = "watch";

    private readonly INavigationService _navigation;

    /// <summary>The chosen source, or null while asking.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsChoosing), nameof(IsAutomatic), nameof(IsFile), nameof(IsRequest), nameof(IsWatch), nameof(IsFromProvider), nameof(Subtitle))]
    private string? source;

    public AddCertificateViewModel(IssueCertificateViewModel issue, OtherProvidersViewModel otherProviders, INavigationService navigation)
    {
        Issue = issue;
        OtherProviders = otherProviders;
        _navigation = navigation;
        BackCommand = new RelayCommand(() => Source = null);
        CancelCommand = new RelayCommand(() => _navigation.Navigate("Certificates"));
        Sources =
        [
            Option(Automatic, "Free and automatic", "Let's Encrypt issues it and SSLense renews it for you. The site must be reachable from the internet over port 80, or you need access to its DNS.", true),
            Option(File, "I bought it and have the file", "Install a PFX file from a provider such as Fasthosts, 123-reg or Sectigo. SSLense checks it, binds it, and reminds you before it expires."),
            Option(Request, "I bought it and the provider needs a request", "SSLense creates a request (CSR) to give your provider, and installs the certificate they send back. The private key never leaves this server."),
            Option(Watch, "It's already installed in IIS", "Just watch it: reminders and checks, without changing anything in IIS.")
        ];
    }

    public IssueCertificateViewModel Issue { get; }

    public OtherProvidersViewModel OtherProviders { get; }

    public IReadOnlyList<AddSourceOption> Sources { get; }

    public IRelayCommand BackCommand { get; }

    public IRelayCommand CancelCommand { get; }

    public bool IsChoosing => Source is null;
    public bool IsAutomatic => Source == Automatic;
    public bool IsFile => Source == File;
    public bool IsRequest => Source == Request;
    public bool IsWatch => Source == Watch;

    /// <summary>One of the three sources for a certificate bought elsewhere, which share their messages.</summary>
    public bool IsFromProvider => Source is File or Request or Watch;

    public string Subtitle => Source switch
    {
        Automatic => "Free and automatic, from Let's Encrypt or another ACME certificate authority.",
        File => "Install a certificate you bought, from its PFX file.",
        Request => "Create a request (CSR) for your provider, then install the certificate they send.",
        Watch => "Watch certificates that are already installed in IIS.",
        _ => "Where does the certificate come from?"
    };

    /// <summary>Opens Add certificate at a source, or at the question when it is null, filled in for a certificate when one is named.</summary>
    public Task ShowAsync(string? source, string? context = null)
    {
        Source = source;
        return source switch
        {
            null => Task.CompletedTask,
            Automatic => Issue.InitializeAsync(context),
            _ => OtherProviders.InitializeAsync(context)
        };
    }

    private AddSourceOption Option(string key, string title, string text, bool recommended = false) =>
        new(key, title, text, recommended, new RelayCommand(() => _ = ShowAsync(key)));
}
