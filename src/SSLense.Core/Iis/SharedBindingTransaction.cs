using SSLense.Core.Config;

namespace SSLense.Core.Iis;

/// <summary>A site that keeps its previous certificate after the others moved to a new one.</summary>
public sealed record LeftOutSite(string SiteName, string Reason);

/// <summary>
/// Moves several sites to one certificate. IIS cannot change them atomically, and a failed commit can leave a site without
/// HTTPS, so the certificate is tried first and sites change one at a time (docs/design/shared-certificates.md, section 5).
/// </summary>
internal static class SharedBindingTransaction
{
    /// <param name="leaveOutFailures">
    /// Whether a site that fails stays behind while the others continue, for the last days before expiry. Otherwise the first
    /// failure puts back every site changed so far.
    /// </param>
    /// <returns>The sites left behind; always empty unless <paramref name="leaveOutFailures"/> is set.</returns>
    /// <exception cref="IisBindingException">No site moved. <see cref="IisBindingException.PreviousBindingsRestored"/> says whether every site is back as it was.</exception>
    public static async Task<IReadOnlyList<LeftOutSite>> ApplyAsync(
        IIisService iisService,
        IReadOnlyList<CertificateTarget> targets,
        string thumbprint,
        bool leaveOutFailures,
        IProgress<ProgressEvent>? progress,
        CancellationToken cancellationToken)
    {
        await iisService.TryCertificateAsync(thumbprint, "My", cancellationToken).ConfigureAwait(false);

        var changed = new List<HttpsBindingUndo>();
        var leftOut = new List<LeftOutSite>();
        foreach (var target in targets)
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                progress?.Report(new ProgressEvent("binding", $"Moving IIS site '{target.SiteName}' to the new certificate."));
                changed.Add(await iisService
                    .SwitchHttpsBindingsAsync(target.SiteName, target.Hosts, thumbprint, "My", cancellationToken)
                    .ConfigureAwait(false));
            }
            catch (IisBindingException exception) when (leaveOutFailures)
            {
                progress?.Report(new ProgressEvent("binding", $"IIS site '{target.SiteName}' was left on its previous certificate: {exception.Message}"));
                leftOut.Add(new LeftOutSite(target.SiteName, exception.Message));
            }
            catch (Exception exception)
            {
                throw await PutBackAsync(iisService, changed, target.SiteName, exception, progress).ConfigureAwait(false);
            }
        }

        if (changed.Count == 0)
        {
            throw new IisBindingException(
                $"No IIS site could use the new certificate: {string.Join(" ", leftOut.Select(site => site.Reason))}",
                previousBindingsRestored: true,
                new InvalidOperationException("Every site failed."));
        }

        return leftOut;
    }

    private static async Task<IisBindingException> PutBackAsync(
        IIisService iisService,
        List<HttpsBindingUndo> changed,
        string failedSite,
        Exception failure,
        IProgress<ProgressEvent>? progress)
    {
        var notRestored = new List<string>();
        if (failure is IisBindingException { PreviousBindingsRestored: false })
        {
            notRestored.Add(failedSite);
        }

        for (var index = changed.Count - 1; index >= 0; index--)
        {
            progress?.Report(new ProgressEvent("binding", $"Putting IIS site '{changed[index].SiteName}' back on its previous certificate."));
            try
            {
                await iisService.UndoHttpsBindingsAsync(changed[index], CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception)
            {
                notRestored.Add(changed[index].SiteName);
            }
        }

        return notRestored.Count == 0
            ? new IisBindingException(
                $"IIS site '{failedSite}' could not use the new certificate, so every site was put back on its previous certificate. {failure.Message}",
                previousBindingsRestored: true,
                failure)
            : new IisBindingException(
                $"IIS site '{failedSite}' could not use the new certificate. {failure.Message} " +
                $"However, these sites could not be confirmed as restored: {string.Join(", ", notRestored.Select(site => $"'{site}'"))}. Check them in IIS now.",
                previousBindingsRestored: false,
                failure);
    }
}
