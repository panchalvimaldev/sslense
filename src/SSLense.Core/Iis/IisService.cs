using Microsoft.Web.Administration;
using SSLense.Core.Config;
using SSLense.Core.Errors;
using System.Diagnostics;

namespace SSLense.Core.Iis;

internal sealed class IisService(ITlsBindingProbe tlsProbe, IFileSystem fileSystem) : IIisService
{
    /// <summary>A reserved name, so no site can ever use this entry.</summary>
    private const string TrialHostNamePort = "sslense-certificate-trial.invalid:443";

    /// <summary>The application ID IIS uses for its own HTTP.sys certificate entries.</summary>
    private const string TrialAppId = "{4dc3e181-e14b-4a21-b022-59fc669b0914}";

    private static readonly TimeSpan TrialTimeout = TimeSpan.FromSeconds(30);
    private static readonly string[] TrialDeleteArguments = ["http", "delete", "sslcert", $"hostnameport={TrialHostNamePort}"];
    private static string TrialLockPath => Path.Combine(AppPaths.OperationLockDirectory, "certificate-trial.lock");

    private static readonly TimeSpan LiveVerificationTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan LiveVerificationInterval = TimeSpan.FromMilliseconds(500);

    public Task<IReadOnlyList<IisSite>> GetSitesAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("IIS site discovery is only supported on Windows.");
        }

        try
        {
            using var serverManager = new ServerManager();
            var sites = serverManager.Sites
                .Select(MapSite)
                .OrderBy(site => site.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            return Task.FromResult<IReadOnlyList<IisSite>>(sites);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new SslenseException(ErrorCodes.IisConfigurationUnreadable, 
                "IIS configuration could not be read. Run SSLense from an Administrator terminal.",
                exception);
        }
        catch (FileNotFoundException exception)
        {
            throw new SslenseException(ErrorCodes.IisManagementMissing, 
                "IIS management components were not found. Install IIS Management Scripts and Tools.",
                exception);
        }
    }

    public async Task ConfigureHttpsBindingsAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        string certificateThumbprint,
        string certificateStoreName = "My",
        CancellationToken cancellationToken = default)
    {
        await TryCertificateAsync(certificateThumbprint, certificateStoreName, cancellationToken).ConfigureAwait(false);
        await SwitchHttpsBindingsAsync(siteName, hosts, certificateThumbprint, certificateStoreName, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task TryCertificateAsync(
        string certificateThumbprint,
        string certificateStoreName = "My",
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(certificateThumbprint);
        ArgumentException.ThrowIfNullOrWhiteSpace(certificateStoreName);
        await using var trialLock = await fileSystem
            .AcquireExclusiveFileLockAsync(TrialLockPath, cancellationToken)
            .ConfigureAwait(false);
        (int ExitCode, string Output) result;
        try
        {
            await RunNetshAsync(TrialDeleteArguments, cancellationToken).ConfigureAwait(false);
            result = await RunNetshAsync(
                    [
                        "http", "add", "sslcert",
                        $"hostnameport={TrialHostNamePort}",
                        $"certhash={NormalizeThumbprint(certificateThumbprint)}",
                        $"certstorename={certificateStoreName}",
                        $"appid={TrialAppId}"
                    ],
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            throw new IisBindingException(
                $"Windows could not try the new certificate, so no site was changed: {exception.Message}",
                previousBindingsRestored: true,
                exception);
        }
        finally
        {
            await DeleteTrialQuietlyAsync().ConfigureAwait(false);
        }

        if (result.ExitCode != 0)
        {
            // Only the exit code decides, because netsh translates its text.
            throw new IisBindingException(
                $"Windows refused certificate {NormalizeThumbprint(certificateThumbprint)} for HTTPS, so no site was changed. " +
                $"Check that the certificate is in LocalMachine\\{certificateStoreName} and that its private key is usable. {result.Output}".TrimEnd(),
                previousBindingsRestored: true,
                new InvalidOperationException($"netsh exited with code {result.ExitCode}."));
        }
    }

    public async Task RemoveCertificateTrialAsync(CancellationToken cancellationToken = default)
    {
        await using var trialLock = await fileSystem
            .AcquireExclusiveFileLockAsync(TrialLockPath, cancellationToken)
            .ConfigureAwait(false);
        await RunNetshAsync(TrialDeleteArguments, cancellationToken).ConfigureAwait(false);
    }

    private static async Task DeleteTrialQuietlyAsync()
    {
        try
        {
            await RunNetshAsync(TrialDeleteArguments, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Harmless: nothing uses this host name, and it is deleted before the next trial and at the next start.
        }
    }

    private static async Task<(int ExitCode, string Output)> RunNetshAsync(
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "netsh.exe"))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo)
            ?? throw new SslenseException(ErrorCodes.NetshUnavailable, "netsh could not be started.");
        var output = process.StandardOutput.ReadToEndAsync(CancellationToken.None);
        var errors = process.StandardError.ReadToEndAsync(CancellationToken.None);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TrialTimeout);
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            throw new TimeoutException(ErrorCodes.NetshTimeout.Format($"netsh did not finish within {TrialTimeout.TotalSeconds:0} seconds."));
        }

        var text = string.Join(' ', (await output.ConfigureAwait(false) + " " + await errors.ConfigureAwait(false))
            .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return (process.ExitCode, text);
    }

    public async Task<HttpsBindingUndo> SwitchHttpsBindingsAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        string certificateThumbprint,
        string certificateStoreName = "My",
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(siteName);
        ArgumentNullException.ThrowIfNull(hosts);
        ArgumentException.ThrowIfNullOrWhiteSpace(certificateThumbprint);
        ArgumentException.ThrowIfNullOrWhiteSpace(certificateStoreName);
        cancellationToken.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("IIS binding configuration is only supported on Windows.");
        }

        var certificateHash = Convert.FromHexString(NormalizeThumbprint(certificateThumbprint));
        var changes = new List<HttpsBindingChange>();
        var probeTargets = new List<(string IpAddress, string Host)>();
        var siteStarted = false;
        try
        {
            using (var serverManager = new ServerManager())
            {
                var site = FindSite(serverManager, siteName);
                siteStarted = IsStarted(site);
                foreach (var host in hosts)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var binding = FindHttpsBinding(site, host);
                    if (binding is null)
                    {
                        // An IP address is bound by address, without SNI (docs/design/ip-certificates.md).
                        binding = site.Bindings.Add(
                            IsIpAddress(host) ? $"{BindingAddress(host)}:443:" : $"*:443:{host}",
                            certificateHash,
                            certificateStoreName,
                            IsIpAddress(host) ? SslFlags.None : SslFlags.Sni);
                        changes.Add(new HttpsBindingChange(host, WasAdded: true, binding.BindingInformation, null, null, (int)SslFlags.None));
                    }
                    else if (!AlreadyUses(binding, host, certificateHash, certificateStoreName))
                    {
                        changes.Add(new HttpsBindingChange(
                            host,
                            WasAdded: false,
                            binding.BindingInformation,
                            binding.CertificateHash?.ToArray(),
                            binding.CertificateStoreName,
                            (int)binding.SslFlags));
                        binding.CertificateHash = certificateHash;
                        binding.CertificateStoreName = certificateStoreName;

                        // Keep unrelated flags such as DisableHTTP2; SSLense binds from the store, not the CCS.
                        binding.SslFlags = IsIpAddress(host)
                            ? binding.SslFlags & ~SslFlags.Sni & ~SslFlags.CentralCertStore
                            : (binding.SslFlags | SslFlags.Sni) & ~SslFlags.CentralCertStore;
                    }

                    probeTargets.Add((ParseBindingInformation(binding.BindingInformation).IpAddress, host));
                }

                // Rewriting a binding that is already right would drop its new connections for nothing.
                if (changes.Count > 0)
                {
                    serverManager.CommitChanges();
                }
            }

            using var verificationManager = new ServerManager();
            var verificationSite = FindSite(verificationManager, siteName);
            foreach (var host in hosts)
            {
                var binding = FindHttpsBinding(verificationSite, host)
                    ?? throw new SslenseException(ErrorCodes.HttpsBindingNotFound, 
                        $"HTTPS binding verification failed for '{host}': the binding was not found.");
                if (binding.CertificateHash is null ||
                    !binding.CertificateHash.SequenceEqual(certificateHash) ||
                    !string.Equals(binding.CertificateStoreName, certificateStoreName, StringComparison.OrdinalIgnoreCase) ||
                    ((binding.SslFlags & SslFlags.Sni) == SslFlags.Sni) == IsIpAddress(host))
                {
                    throw new SslenseException(ErrorCodes.HttpsBindingNotRetained, 
                        $"HTTPS binding verification failed for '{host}': IIS did not retain the certificate and SNI settings.");
                }
            }

            // A stopped site may have no listener, so there may be nothing live to verify yet.
            if (siteStarted)
            {
                foreach (var (ipAddress, host) in probeTargets)
                {
                    await VerifyServedCertificateAsync(ipAddress, host, certificateThumbprint, cancellationToken)
                        .ConfigureAwait(false);
                }
            }

            return new HttpsBindingUndo(siteName, siteStarted, changes);
        }
        catch (Exception exception)
        {
            try
            {
                if (changes.Count > 0)
                {
                    await RestoreAsync(new HttpsBindingUndo(siteName, siteStarted, changes)).ConfigureAwait(false);
                }
            }
            catch (Exception rollbackException)
            {
                throw new IisBindingException(
                    $"IIS binding configuration failed for site '{siteName}' and the previous bindings could not be fully restored: {rollbackException.Message}",
                    previousBindingsRestored: false,
                    new AggregateException(exception, rollbackException));
            }

            if (exception is UnauthorizedAccessException)
            {
                throw new IisBindingException(
                    "IIS bindings could not be changed. Run SSLense from an Administrator terminal.",
                    previousBindingsRestored: true,
                    exception);
            }

            throw new IisBindingException(
                $"Could not configure HTTPS bindings for IIS site '{siteName}': {exception.Message} The site's previous bindings were restored and checked.",
                previousBindingsRestored: true,
                exception);
        }
    }

    public async Task UndoHttpsBindingsAsync(HttpsBindingUndo undo, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(undo);
        if (undo.Changes.Count == 0)
        {
            return;
        }

        try
        {
            await RestoreAsync(undo).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            throw new IisBindingException(
                $"The previous bindings of IIS site '{undo.SiteName}' could not be fully restored: {exception.Message}",
                previousBindingsRestored: false,
                exception);
        }
    }

    public async Task<string?> GetHttpsProblemAsync(
        IisSite site,
        IReadOnlyList<string> hosts,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(site);
        foreach (var host in hosts)
        {
            foreach (var binding in site.Bindings.Where(binding =>
                         string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase) &&
                         binding.Port == 443 &&
                         string.Equals(binding.HostName, host, StringComparison.OrdinalIgnoreCase)))
            {
                var address = binding.IpAddress is "*" or "" ? "127.0.0.1" : binding.IpAddress.Trim('[', ']');
                try
                {
                    await tlsProbe.GetServedThumbprintAsync(address, host, 443, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
                {
                    return $"{host} did not answer on port 443 ({exception.Message}).";
                }
            }
        }

        return null;
    }

    /// <summary>
    /// On real IIS, a restore can report success and leave a binding without its certificate, depending on how it is done
    /// (docs/design/shared-certificates.md, section 5.1). So nothing counts as restored until it is checked, and a failed
    /// check gets one attempt by removing and re-adding the binding.
    /// </summary>
    private async Task RestoreAsync(HttpsBindingUndo undo)
    {
        string? problem;
        try
        {
            RollBackBindings(undo.SiteName, undo.Changes);
            problem = await FindRestoreProblemAsync(undo).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not UnauthorizedAccessException)
        {
            problem = exception.Message;
        }

        if (problem is null)
        {
            return;
        }

        ReAddBindings(undo.SiteName, undo.Changes);
        problem = await FindRestoreProblemAsync(undo).ConfigureAwait(false);
        if (problem is not null)
        {
            throw new SslenseException(ErrorCodes.HttpsBindingChangeFailed, problem);
        }
    }

    private async Task<string?> FindRestoreProblemAsync(HttpsBindingUndo undo)
    {
        var probes = new List<(string IpAddress, string Host, string Thumbprint)>();
        using (var serverManager = new ServerManager())
        {
            var site = FindSite(serverManager, undo.SiteName);
            foreach (var change in undo.Changes)
            {
                var binding = FindHttpsBinding(site, change.Host);
                if (change.WasAdded)
                {
                    if (binding is not null)
                    {
                        return $"the new HTTPS binding for '{change.Host}' was not removed.";
                    }

                    continue;
                }

                if (binding is null)
                {
                    return $"the HTTPS binding for '{change.Host}' no longer exists.";
                }

                if (change.CertificateHash is null)
                {
                    continue;
                }

                if (binding.CertificateHash is null || !binding.CertificateHash.SequenceEqual(change.CertificateHash))
                {
                    return $"the HTTPS binding for '{change.Host}' does not have its previous certificate.";
                }

                probes.Add((ParseBindingInformation(binding.BindingInformation).IpAddress, change.Host, Convert.ToHexString(change.CertificateHash)));
            }
        }

        if (undo.SiteStarted)
        {
            foreach (var (ipAddress, host, thumbprint) in probes)
            {
                try
                {
                    await VerifyServedCertificateAsync(ipAddress, host, thumbprint, CancellationToken.None).ConfigureAwait(false);
                }
                catch (InvalidOperationException exception)
                {
                    return exception.Message;
                }
            }
        }

        return null;
    }

    private static bool AlreadyUses(Binding binding, string host, byte[] certificateHash, string certificateStoreName) =>
        binding.CertificateHash is { } hash &&
        hash.SequenceEqual(certificateHash) &&
        string.Equals(binding.CertificateStoreName, certificateStoreName, StringComparison.OrdinalIgnoreCase) &&
        ((binding.SslFlags & SslFlags.Sni) == SslFlags.Sni) != IsIpAddress(host) &&
        (binding.SslFlags & SslFlags.CentralCertStore) == 0;

    /// <summary>The name of SSLense's rule, so it is found again and never confused with the administrator's own.</summary>
    internal const string RedirectRuleName = "SSLense: HTTP to HTTPS";

    public async Task<IReadOnlyList<string>> GetHttpSysCertificateThumbprintsAsync(CancellationToken cancellationToken = default)
    {
        // netsh translates its labels, so only the 40-hex-digit hashes are read.
        var (exitCode, output) = await RunNetshAsync(["http", "show", "sslcert"], cancellationToken).ConfigureAwait(false);
        return exitCode != 0
            ? []
            : [.. System.Text.RegularExpressions.Regex.Matches(output, @"\b[0-9A-Fa-f]{40}\b").Select(match => match.Value.ToUpperInvariant()).Distinct()];
    }

    public Task<IReadOnlyList<FtpSite>> GetFtpSitesAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var serverManager = new ServerManager();
        IReadOnlyList<FtpSite> sites =
        [
            .. serverManager.Sites
                .Where(site => site.Bindings.Any(binding => string.Equals(binding.Protocol, "ftp", StringComparison.OrdinalIgnoreCase)))
                .Select(site => new FtpSite(
                    site.Name,
                    [.. site.Bindings
                        .Where(binding => string.Equals(binding.Protocol, "ftp", StringComparison.OrdinalIgnoreCase))
                        .Select(binding => binding.BindingInformation.Split(':') is { Length: 3 } parts ? parts[2] : string.Empty)
                        .Where(host => host.Length > 0)
                        .Distinct(StringComparer.OrdinalIgnoreCase)],
                    FtpSsl(site)["serverCertHash"] is string { Length: > 0 } hash ? hash.ToUpperInvariant() : null))
        ];
        return Task.FromResult(sites);
    }

    /// <summary>
    /// Sets ftpServer/security/ssl on the site: the certificate's hash and store. The FTP service reads it for each new
    /// connection, so nothing restarts (docs/design/ftp-sites.md).
    /// </summary>
    public Task SetFtpCertificateAsync(string siteName, string thumbprint, string storeName = "My", CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using (var serverManager = new ServerManager())
        {
            var site = FindSite(serverManager, siteName);
            if (!site.Bindings.Any(binding => string.Equals(binding.Protocol, "ftp", StringComparison.OrdinalIgnoreCase)))
            {
                throw new SslenseException(ErrorCodes.FtpSiteNotFound, $"IIS site '{site.Name}' has no FTP binding.");
            }

            var ssl = FtpSsl(site);
            ssl["serverCertHash"] = thumbprint.ToUpperInvariant();
            ssl["serverCertStoreName"] = storeName;
            serverManager.CommitChanges();
        }

        // Read back, as for HTTPS bindings: a commit that did not reach applicationHost.config would otherwise pass unnoticed.
        using var verification = new ServerManager();
        if (!string.Equals(FtpSsl(FindSite(verification, siteName))["serverCertHash"] as string, thumbprint, StringComparison.OrdinalIgnoreCase))
        {
            throw new SslenseException(ErrorCodes.FtpSiteNotFound, $"IIS did not keep the certificate for FTP site '{siteName}'.");
        }

        return Task.CompletedTask;
    }

    private static ConfigurationElement FtpSsl(Site site) =>
        site.GetChildElement("ftpServer").GetChildElement("security").GetChildElement("ssl");

    public Task<HttpsRedirectState> GetHttpsRedirectAsync(string siteName, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var serverManager = new ServerManager();
        if (!IsUrlRewriteInstalled(serverManager))
        {
            return Task.FromResult(HttpsRedirectState.UrlRewriteMissing);
        }

        var site = FindSite(serverManager, siteName);
        var rules = serverManager.GetWebConfiguration(site.Name).GetSection("system.webServer/rewrite/rules").GetCollection();
        return Task.FromResult(rules.Any(rule => string.Equals(rule["name"] as string, RedirectRuleName, StringComparison.Ordinal))
            ? HttpsRedirectState.On
            : HttpsRedirectState.Off);
    }

    /// <summary>
    /// The rule redirects every plain HTTP request to HTTPS, except /.well-known/acme-challenge/, so HTTP validation keeps
    /// working (docs/design/https-redirect.md). It is the site's first rule, and the only one SSLense touches.
    /// </summary>
    public Task SetHttpsRedirectAsync(string siteName, bool enabled, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var serverManager = new ServerManager();
        if (!IsUrlRewriteInstalled(serverManager))
        {
            throw new SslenseException(ErrorCodes.UrlRewriteMissing, "The IIS URL Rewrite module is not installed, so SSLense cannot add the redirect.");
        }

        var site = FindSite(serverManager, siteName);
        var rules = serverManager.GetWebConfiguration(site.Name).GetSection("system.webServer/rewrite/rules").GetCollection();
        var existing = rules.FirstOrDefault(rule => string.Equals(rule["name"] as string, RedirectRuleName, StringComparison.Ordinal));
        if (enabled == existing is not null)
        {
            return Task.CompletedTask;
        }

        if (existing is not null)
        {
            rules.Remove(existing);
        }
        else
        {
            var rule = rules.CreateElement("rule");
            rule["name"] = RedirectRuleName;
            rule["stopProcessing"] = true;
            rule.GetChildElement("match")["url"] = "(.*)";
            var conditions = rule.GetChildElement("conditions").GetCollection();
            var https = conditions.CreateElement("add");
            https["input"] = "{HTTPS}";
            https["pattern"] = "^OFF$";
            conditions.Add(https);
            var challenge = conditions.CreateElement("add");
            challenge["input"] = "{REQUEST_URI}";
            challenge["pattern"] = "^/\\.well-known/acme-challenge/";
            challenge["negate"] = true;
            conditions.Add(challenge);
            var action = rule.GetChildElement("action");
            action["type"] = "Redirect";
            action["url"] = "https://{HTTP_HOST}{REQUEST_URI}";
            action["appendQueryString"] = false;
            action["redirectType"] = "Permanent";
            rules.AddAt(0, rule);
        }

        serverManager.CommitChanges();
        return Task.CompletedTask;
    }

    private static bool IsUrlRewriteInstalled(ServerManager serverManager) =>
        serverManager.GetApplicationHostConfiguration().GetSection("system.webServer/globalModules").GetCollection()
            .Any(module => string.Equals(module["name"] as string, "RewriteModule", StringComparison.OrdinalIgnoreCase));

    public Task RemoveHttpsBindingsAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        string expectedCertificateThumbprint,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var expectedHash = Convert.FromHexString(NormalizeThumbprint(expectedCertificateThumbprint));
        try
        {
            using var serverManager = new ServerManager();
            var site = FindSite(serverManager, siteName);
            foreach (var host in hosts)
            {
                var binding = FindHttpsBinding(site, host);
                if (binding is null)
                {
                    continue;
                }

                if (binding.CertificateHash is null || !binding.CertificateHash.SequenceEqual(expectedHash))
                {
                    throw new SslenseException(ErrorCodes.HttpsBindingUsesOtherCertificate, 
                        $"The HTTPS binding for '{host}' uses a different certificate and was not removed.");
                }

                site.Bindings.Remove(binding);
            }

            serverManager.CommitChanges();

            using var verificationManager = new ServerManager();
            var verificationSite = FindSite(verificationManager, siteName);
            foreach (var host in hosts)
            {
                var binding = FindHttpsBinding(verificationSite, host);
                if (binding?.CertificateHash is { } hash && hash.SequenceEqual(expectedHash))
                {
                    throw new SslenseException(ErrorCodes.HttpsBindingRemovalUnverified, 
                        $"HTTPS binding removal verification failed for '{host}'. The certificate was not removed from the store.");
                }
            }

            return Task.CompletedTask;
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new SslenseException(ErrorCodes.HttpsBindingRemovalFailed, 
                "IIS bindings could not be removed. Run SSLense as Administrator.",
                exception);
        }
    }

    private async Task VerifyServedCertificateAsync(
        string bindingIpAddress,
        string host,
        string expectedThumbprint,
        CancellationToken cancellationToken)
    {
        // A wildcard binding also listens on loopback, so the check never leaves this machine.
        var ipAddress = bindingIpAddress is "*" or "" ? "127.0.0.1" : bindingIpAddress.Trim('[', ']');
        var expected = NormalizeThumbprint(expectedThumbprint);
        var deadline = DateTimeOffset.UtcNow + LiveVerificationTimeout;
        string observed;
        while (true)
        {
            try
            {
                observed = NormalizeThumbprint(await tlsProbe
                    .GetServedThumbprintAsync(ipAddress, host, 443, cancellationToken)
                    .ConfigureAwait(false));
                if (string.Equals(observed, expected, StringComparison.Ordinal))
                {
                    return;
                }

                observed = $"certificate {observed}";
            }
            catch (Exception exception) when (exception is not OperationCanceledException ||
                                              !cancellationToken.IsCancellationRequested)
            {
                observed = $"error: {exception.Message}";
            }

            // HTTP.sys applies configuration changes asynchronously after CommitChanges.
            if (DateTimeOffset.UtcNow >= deadline)
            {
                throw new SslenseException(ErrorCodes.HttpsCertificateNotServed, 
                    $"HTTPS verification failed for '{host}': {ipAddress}:443 did not serve certificate " +
                    $"{expected} within {LiveVerificationTimeout.TotalSeconds:0} seconds (last result: {observed}).");
            }

            await Task.Delay(LiveVerificationInterval, cancellationToken).ConfigureAwait(false);
        }
    }

    private static bool IsStarted(Site site)
    {
        try
        {
            return site.State == ObjectState.Started;
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            // State is unavailable when the Windows Process Activation Service is stopped.
            return false;
        }
    }

    private static IisSite MapSite(Site site)
    {
        var rootApplication = site.Applications.FirstOrDefault(application => application.Path == "/");
        var rootDirectory = rootApplication?.VirtualDirectories.FirstOrDefault(directory => directory.Path == "/");
        var physicalPath = rootDirectory?.PhysicalPath is { } path
            ? Environment.ExpandEnvironmentVariables(path)
            : null;

        var bindings = site.Bindings.Select(MapBinding).ToArray();
        return new IisSite(site.Id, site.Name, ReadState(site), physicalPath, bindings);
    }

    /// <summary>
    /// Some sites have no run state: FTP-only sites, sites whose bindings use only non-HTTP protocols, or any site while
    /// the Windows Process Activation Service is stopped. Reading it then throws (0x800710D8, "The object identifier does
    /// not represent a valid object"), which must not stop every other site from being listed.
    /// </summary>
    private static string ReadState(Site site)
    {
        try
        {
            return site.State.ToString();
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            return "Unknown";
        }
    }

    private static IisBinding MapBinding(Binding binding)
    {
        var (ipAddress, port, hostName) = ParseBindingInformation(binding.BindingInformation);
        var thumbprint = binding.CertificateHash is { Length: > 0 } hash
            ? Convert.ToHexString(hash)
            : null;

        return new IisBinding(
            binding.Protocol,
            ipAddress,
            port,
            hostName,
            thumbprint,
            binding.CertificateStoreName,
            (binding.SslFlags & SslFlags.Sni) == SslFlags.Sni);
    }

    /// <summary>
    /// The IIS site of a certificate name: every method here takes the name of the certificate whose bindings change,
    /// which for a second certificate on a site is "site/host" (docs/design/multiple-certificates-per-site.md).
    /// </summary>
    private static Site FindSite(ServerManager serverManager, string siteName)
    {
        var name = ManagedCertificateNames.IisSiteOf(siteName);
        return serverManager.Sites.FirstOrDefault(site => string.Equals(site.Name, name, StringComparison.OrdinalIgnoreCase))
            ?? throw new SslenseException(ErrorCodes.IisSiteNotFound, $"IIS site '{name}' was not found.");
    }

    private static bool IsIpAddress(string host) => Uri.CheckHostName(host) is UriHostNameType.IPv4 or UriHostNameType.IPv6;

    /// <summary>An address as IIS writes it in a binding: IPv6 in brackets.</summary>
    private static string BindingAddress(string ip) => Uri.CheckHostName(ip) == UriHostNameType.IPv6 ? $"[{ip}]" : ip;

    private static Binding? FindHttpsBinding(Site site, string host) =>
        site.Bindings.FirstOrDefault(binding =>
        {
            if (!string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var (address, port, bindingHost) = ParseBindingInformation(binding.BindingInformation);
            return port == 443 && (IsIpAddress(host)
                ? bindingHost.Length == 0 && System.Net.IPAddress.TryParse(address.Trim('[', ']'), out var bound) && bound.ToString() == host
                : string.Equals(bindingHost, host, StringComparison.OrdinalIgnoreCase));
        });

    private static void RollBackBindings(string siteName, IReadOnlyList<HttpsBindingChange> changes)
    {
        using var serverManager = new ServerManager();
        var site = FindSite(serverManager, siteName);
        foreach (var change in changes)
        {
            var binding = FindHttpsBinding(site, change.Host);
            if (change.WasAdded)
            {
                if (binding is not null)
                {
                    site.Bindings.Remove(binding);
                }

                continue;
            }

            if (binding is null)
            {
                throw new SslenseException(ErrorCodes.PreviousBindingGone, 
                    $"Cannot restore the previous HTTPS binding for '{change.Host}' because it no longer exists.");
            }

            binding.CertificateHash = change.CertificateHash;
            binding.CertificateStoreName = change.CertificateStoreName;
            binding.SslFlags = (SslFlags)change.SslFlags;
        }

        serverManager.CommitChanges();
    }

    private static void ReAddBindings(string siteName, IReadOnlyList<HttpsBindingChange> changes)
    {
        using var serverManager = new ServerManager();
        var site = FindSite(serverManager, siteName);
        foreach (var change in changes)
        {
            if (FindHttpsBinding(site, change.Host) is { } binding)
            {
                site.Bindings.Remove(binding);
            }

            if (change.WasAdded)
            {
                continue;
            }

            var restored = change.CertificateHash is { } hash
                ? site.Bindings.Add(change.BindingInformation, hash, change.CertificateStoreName ?? "My", (SslFlags)change.SslFlags)
                : site.Bindings.Add(change.BindingInformation, "https");
            restored.SslFlags = (SslFlags)change.SslFlags;
        }

        serverManager.CommitChanges();
    }

    private static string NormalizeThumbprint(string thumbprint) =>
        string.Concat(thumbprint.Where(Uri.IsHexDigit)).ToUpperInvariant();

    private static (string IpAddress, int Port, string HostName) ParseBindingInformation(string value)
    {
        var hostSeparator = value.LastIndexOf(':');
        var portSeparator = hostSeparator > 0 ? value.LastIndexOf(':', hostSeparator - 1) : -1;
        if (portSeparator < 0 || hostSeparator < 0 ||
            !int.TryParse(value.AsSpan(portSeparator + 1, hostSeparator - portSeparator - 1), out var port))
        {
            throw new InvalidDataException(ErrorCodes.IisBindingUnreadable.Format($"IIS returned an invalid binding: '{value}'."));
        }

        return (value[..portSeparator], port, value[(hostSeparator + 1)..]);
    }
}
