namespace SSLense.Core.Config;

public interface IConfigStore
{
    Task<AppConfig> LoadAsync(CancellationToken cancellationToken = default);

    Task SaveAsync(AppConfig config, CancellationToken cancellationToken = default);

    /// <summary>
    /// Applies a change to the configuration as it is now. The JSON store holds its cross-process lock from the read to the
    /// write, so a change another process made in between is never lost.
    /// </summary>
    async Task UpdateAsync(Func<AppConfig, AppConfig> change, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(change);
        await SaveAsync(change(await LoadAsync(cancellationToken).ConfigureAwait(false)), cancellationToken).ConfigureAwait(false);
    }
}
