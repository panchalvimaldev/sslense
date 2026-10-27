namespace SSLense.Gui.ViewModels;

public interface INavigationService
{
    event EventHandler<NavigationRequest>? NavigationRequested;

    void Navigate(string page, string? context = null);
}

public sealed record NavigationRequest(string Page, string? Context);

public sealed class NavigationService : INavigationService
{
    public event EventHandler<NavigationRequest>? NavigationRequested;

    public void Navigate(string page, string? context = null) =>
        NavigationRequested?.Invoke(this, new NavigationRequest(page, context));
}
