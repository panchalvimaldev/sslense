using System.Net.Http.Headers;
using System.Reflection;
using System.Text.Json;
using SSLense.Core.Config;

namespace SSLense.Core.Diagnostics;

/// <summary>A newer SSLense release than the one running.</summary>
public sealed record UpdateInfo(string CurrentVersion, string LatestVersion, Uri ReleaseUrl, bool IsPrerelease);

/// <summary>
/// Tells the administrator when a newer SSLense is published (docs/design/version-notice.md). It reads the project's
/// releases on GitHub, never downloads or installs anything, and can be turned off in Settings.
/// </summary>
public interface IUpdateCheckService
{
    /// <summary>The newer release, or null when this one is current, the check is off, or GitHub cannot be reached.</summary>
    Task<UpdateInfo?> CheckAsync(CancellationToken cancellationToken = default);

    /// <summary>Whether the check is on (Settings › General), so "nothing newer" can be told apart from "not checked".</summary>
    Task<bool> IsOnAsync(CancellationToken cancellationToken = default);

    /// <summary>The version running, such as 0.24.0.</summary>
    string CurrentVersion { get; }
}

internal sealed class UpdateCheckService : IUpdateCheckService, IDisposable
{
    internal const string ReleasesUrl = "https://api.github.com/repos/panchalvimaldev/sslense/releases?per_page=20";

    private readonly IConfigStore _configStore;
    private readonly HttpClient _httpClient;
    private readonly string? _currentOverride;

    public UpdateCheckService(IConfigStore configStore)
        : this(configStore, new HttpClientHandler(), null)
    {
    }

    internal UpdateCheckService(IConfigStore configStore, HttpMessageHandler handler, string? currentVersion)
    {
        _configStore = configStore;
        _httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        _currentOverride = currentVersion;
    }

    public string CurrentVersion => _currentOverride ??
        (typeof(UpdateCheckService).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0")
            .Split('+')[0];

    public async Task<bool> IsOnAsync(CancellationToken cancellationToken = default) =>
        (await _configStore.LoadAsync(cancellationToken).ConfigureAwait(false)).CheckForUpdates;

    public async Task<UpdateInfo?> CheckAsync(CancellationToken cancellationToken = default)
    {
        if (!await IsOnAsync(cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, ReleasesUrl);
            request.Headers.UserAgent.Add(new ProductInfoHeaderValue("SSLense", CurrentVersion));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
            using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
            var current = Parse(CurrentVersion);
            var latest = document.RootElement.EnumerateArray()
                .Where(release => !(release.TryGetProperty("draft", out var draft) && draft.GetBoolean()))
                .Select(release => (
                    Version: Parse(release.GetProperty("tag_name").GetString() ?? string.Empty),
                    Tag: release.GetProperty("tag_name").GetString() ?? string.Empty,
                    Url: release.GetProperty("html_url").GetString(),
                    Prerelease: release.TryGetProperty("prerelease", out var pre) && pre.GetBoolean()))
                .Where(release => release.Version is not null && release.Url is not null)
                .OrderByDescending(release => release.Version)
                .FirstOrDefault();
            return latest.Version is not null && current is not null && latest.Version > current
                ? new UpdateInfo(CurrentVersion, latest.Tag.TrimStart('v'), new Uri(latest.Url!), latest.Prerelease)
                : null;
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException or JsonException or InvalidOperationException or KeyNotFoundException)
        {
            // Only a notice: no network, a proxy, or a changed answer must never get in the way.
            return null;
        }
    }

    public void Dispose() => _httpClient.Dispose();

    /// <summary>"v0.24.1" or "0.24.1-beta" as a version; null when it is not one.</summary>
    internal static Version? Parse(string value) =>
        Version.TryParse(value.Trim().TrimStart('v', 'V').Split('-', '+')[0], out var version) ? version : null;
}
