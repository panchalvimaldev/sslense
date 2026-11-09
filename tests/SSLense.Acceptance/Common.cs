using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Microsoft.Web.Administration;
using SSLense.Core.Iis;

namespace SSLense.Acceptance;

/// <summary>Prints and saves results, so a failed check never stops the checks after it.</summary>
internal static class Report
{
    private static StreamWriter? _file;
    public static int Passed { get; private set; }
    public static List<string> Failed { get; } = [];
    public static string? Scrub { get; set; }

    public static void Open(string path)
    {
        // Appended, so a second attempt cannot hide why the first one failed.
        _file = new StreamWriter(path, append: true) { AutoFlush = true };
        Info($"Started {DateTimeOffset.Now:o}");
    }

    public static void Info(string text)
    {
        if (!string.IsNullOrEmpty(Scrub))
        {
            text = text.Replace(Scrub, "<email>", StringComparison.OrdinalIgnoreCase);
        }

        Console.WriteLine(text);
        _file?.WriteLine(text);
    }

    public static void Heading(string text) => Info($"{Environment.NewLine}=== {text}");

    public static bool Check(string name, bool ok, string evidence = "")
    {
        Info($"{(ok ? "PASS" : "FAIL")}  {name}{(evidence.Length > 0 ? $"  [{evidence}]" : "")}");
        if (ok)
        {
            Passed++;
        }
        else
        {
            Failed.Add(name);
        }

        return ok;
    }

    public static async Task<bool> Scenario(string name, Func<Task> body)
    {
        Heading(name);
        var failuresBefore = Failed.Count;
        try
        {
            await body();
        }
        catch (Exception exception)
        {
            Check($"{name}: finished without an unexpected error", false, $"{exception.GetType().Name}: {exception.Message}");
        }

        return Failed.Count == failuresBefore;
    }

    public static int Finish()
    {
        Heading($"RESULT: {Passed} passed, {Failed.Count} failed");
        foreach (var name in Failed)
        {
            Info($"  FAILED: {name}");
        }

        Info($"Finished {DateTimeOffset.Now:o}");
        _file?.Dispose();
        _file = null;
        return Failed.Count == 0 ? 0 : 1;
    }
}

/// <summary>Looks at IIS and HTTP.sys independently of what SSLense reports.</summary>
internal static class Iis
{
    public const string Root = @"C:\SSLenseAccept";
    private static readonly TlsBindingProbe Probe = new();

    public static void EnsureSite(string name, string host)
    {
        var path = Path.Combine(Root, name);
        Directory.CreateDirectory(path);
        using (var manager = new ServerManager())
        {
            var site = manager.Sites[name];
            if (site is null)
            {
                // The second binding keeps a site valid when a test removes the host's own bindings.
                site = manager.Sites.Add(name, "http", $"*:80:{name.ToLowerInvariant()}.keep.sslense.test", path);
            }

            if (!site.Bindings.Any(binding => binding.BindingInformation.Equals($"*:80:{host}", StringComparison.OrdinalIgnoreCase)))
            {
                site.Bindings.Add($"*:80:{host}", "http");
            }

            manager.CommitChanges();
        }

        StartSite(name);
    }

    public static void DeleteSite(string name)
    {
        using var manager = new ServerManager();
        if (manager.Sites[name] is { } site)
        {
            manager.Sites.Remove(site);
            manager.CommitChanges();
        }
    }

    public static void StartSite(string name) => SetState(name, start: true);

    public static void StopSite(string name) => SetState(name, start: false);

    private static void SetState(string name, bool start)
    {
        var wanted = start ? ObjectState.Started : ObjectState.Stopped;
        Exception? last = null;
        for (var attempt = 0; attempt < 40; attempt++)
        {
            try
            {
                using var manager = new ServerManager();
                var site = manager.Sites[name] ?? throw new InvalidOperationException($"No site {name}.");
                if (site.State == wanted)
                {
                    return;
                }

                if (start)
                {
                    site.Start();
                }
                else
                {
                    site.Stop();
                }
            }
            catch (System.Runtime.InteropServices.COMException exception)
            {
                last = exception;
            }

            Thread.Sleep(250);
        }

        throw new InvalidOperationException($"Site {name} did not reach {wanted}: {last?.Message}");
    }

    public static bool SiteExists(string name)
    {
        using var manager = new ServerManager();
        return manager.Sites[name] is not null;
    }

    public static void BindHttps(string siteName, string host, string thumbprint)
    {
        // Two commits, because removing and adding the same binding in one commit may not rewrite a lost HTTP.sys entry.
        RemoveHostHttps(siteName, host);
        using var manager = new ServerManager();
        manager.Sites[siteName].Bindings.Add($"*:443:{host}", Convert.FromHexString(thumbprint), "My", SslFlags.Sni);
        manager.CommitChanges();
    }

    public static void RemoveHostHttps(string siteName, string host)
    {
        using var manager = new ServerManager();
        var site = manager.Sites[siteName];
        if (FindHttps(site, host) is { } existing)
        {
            site.Bindings.Remove(existing);
            manager.CommitChanges();
        }
    }

    /// <summary>Removes the host's bindings, leaving the site itself.</summary>
    public static void RemoveHostBindings(string siteName, string host)
    {
        using var manager = new ServerManager();
        var site = manager.Sites[siteName];
        foreach (var binding in site.Bindings.Where(value => value.BindingInformation.EndsWith($":{host}", StringComparison.OrdinalIgnoreCase)).ToArray())
        {
            site.Bindings.Remove(binding);
        }

        manager.CommitChanges();
    }

    public static string? BoundThumbprint(string siteName, string host)
    {
        using var manager = new ServerManager();
        return manager.Sites[siteName] is { } site && FindHttps(site, host)?.CertificateHash is { Length: > 0 } hash
            ? Convert.ToHexString(hash)
            : null;
    }

    public static bool HasHttpsBinding(string siteName, string host)
    {
        using var manager = new ServerManager();
        return manager.Sites[siteName] is { } site && FindHttps(site, host) is not null;
    }

    private static Binding? FindHttps(Site site, string host) =>
        site.Bindings.FirstOrDefault(binding =>
            binding.Protocol == "https" && binding.BindingInformation.EndsWith($":443:{host}", StringComparison.OrdinalIgnoreCase));

    /// <summary>What the site really serves, or text starting with ERR. Connects to this machine only.</summary>
    public static async Task<string> Served(string host)
    {
        try
        {
            return await Probe.GetServedThumbprintAsync("127.0.0.1", host, 443, CancellationToken.None);
        }
        catch (Exception exception)
        {
            return $"ERR {exception.GetType().Name}";
        }
    }

    /// <summary>HTTP.sys applies changes shortly after a commit, so this waits for the expected answer.</summary>
    public static async Task<string> WaitServed(string host, string expected, int seconds = 15)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(seconds);
        while (true)
        {
            var served = await Served(host);
            if (string.Equals(served, expected, StringComparison.OrdinalIgnoreCase) || DateTimeOffset.UtcNow >= deadline)
            {
                return served;
            }

            await Task.Delay(300);
        }
    }

    public static async Task<bool> IsServing(string host, string expected) =>
        string.Equals(await WaitServed(host, expected), expected, StringComparison.OrdinalIgnoreCase);

    public static string Short(string? value) => value is null ? "none" : value.Length == 40 ? value[..8] : value;

    public static (int ExitCode, string Output) Netsh(params string[] arguments)
    {
        var info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "netsh.exe"))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in arguments)
        {
            info.ArgumentList.Add(argument);
        }

        using var process = Process.Start(info)!;
        var errors = process.StandardError.ReadToEndAsync();
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, output + errors.GetAwaiter().GetResult());
    }

    /// <summary>The certificate HTTP.sys holds for a host. Reads only the hash, because netsh translates its text.</summary>
    public static string? SysHash(string hostPort)
    {
        var (exitCode, output) = Netsh("http", "show", "sslcert", $"hostnameport={hostPort}");
        var match = Regex.Match(output, @"\b[0-9a-fA-F]{40}\b");
        return exitCode == 0 && match.Success ? match.Value.ToUpperInvariant() : null;
    }

    public static void DropSysEntry(string host) => Netsh("http", "delete", "sslcert", $"hostnameport={host}:443");

    public static void RemoveCertificates(Func<X509Certificate2, bool> match)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        foreach (var certificate in store.Certificates.Where(match).ToArray())
        {
            try
            {
                using var key = certificate.GetRSAPrivateKey();
                if (key is RSACng cng)
                {
                    cng.Key.Delete();
                }
                else if (key is RSACryptoServiceProvider provider)
                {
                    provider.PersistKeyInCsp = false;
                }
            }
            catch (CryptographicException)
            {
                // No usable key, so there is nothing to delete.
            }

            store.Remove(certificate);
        }
    }

    public static bool InStore(string thumbprint)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false).Count > 0;
    }

    public static void RemoveTestFolder()
    {
        if (Directory.Exists(Root))
        {
            Directory.Delete(Root, recursive: true);
        }
    }
}
