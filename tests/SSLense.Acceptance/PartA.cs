using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;

namespace SSLense.Acceptance;

/// <summary>Answers from the real probe, but reports a failure when a test says so. Everything else is real IIS.</summary>
internal sealed class FaultyProbe(Func<string, string, bool> fail) : ITlsBindingProbe
{
    private readonly TlsBindingProbe _real = new();
    public int Faults;

    public async Task<string> GetServedThumbprintAsync(string ipAddress, string host, int port, CancellationToken cancellationToken)
    {
        var served = await _real.GetServedThumbprintAsync(ipAddress, host, port, cancellationToken);
        if (fail(host, served))
        {
            Interlocked.Increment(ref Faults);
            throw new IOException("Simulated: this site does not answer.");
        }

        return served;
    }
}

/// <summary>Real IIS and HTTP.sys with self-signed certificates. No certificate authority, DNS, or SSLense state file.</summary>
internal static class PartA
{
    private const string Subject = "CN=SSLense acceptance";
    private const string TrialHost = "sslense-certificate-trial.invalid:443";
    private static readonly string[] Sites = ["SSLenseAccept1", "SSLenseAccept2", "SSLenseAccept3"];
    private static readonly string[] Hosts = ["accept1.sslense.test", "accept2.sslense.test", "accept3.sslense.test"];
    private static string _a = "", _b = "", _noKey = "", _missing = "";

    private static IisService Real() => new(new TlsBindingProbe(), new PhysicalFileSystem());
    private static IisService With(FaultyProbe probe) => new(probe, new PhysicalFileSystem());

    public static async Task RunAsync()
    {
        Cleanup();
        try
        {
            _a = CreateCertificate("A", install: true, keepKey: true);
            _b = CreateCertificate("B", install: true, keepKey: true);
            _noKey = CreateCertificate("no key", install: true, keepKey: false);
            _missing = CreateCertificate("missing", install: false, keepKey: false);
            Report.Info($"A={Iis.Short(_a)} B={Iis.Short(_b)} noKey={Iis.Short(_noKey)} missing={Iis.Short(_missing)}");
            await ScenariosAsync();
        }
        finally
        {
            Cleanup();
            Report.Heading("Cleanup");
            Report.Check("Test sites removed", Sites.All(site => !Iis.SiteExists(site)));
            Report.Check("No HTTP.sys entries left", Hosts.All(host => Iis.SysHash($"{host}:443") is null) && Iis.SysHash(TrialHost) is null);
        }
    }

    private static async Task ScenariosAsync()
    {
        await Report.Scenario("A1 Trial with a good certificate", async () =>
        {
            await Reset();
            await Real().TryCertificateAsync(_b);
            Report.Check("Accepted", true);
            Report.Check("Trial entry deleted afterwards", Iis.SysHash(TrialHost) is null);
            await RequireAllServe(_a, "Real sites unchanged");
        });

        foreach (var (label, thumbprint) in new[] { ("no private key", _noKey), ("missing from the store", _missing) })
        {
            await Report.Scenario($"A2 Trial refuses a certificate with {label}", async () =>
            {
                await Reset();
                var error = await Capture(() => Real().TryCertificateAsync(thumbprint));
                Report.Check("Refused", error is not null, error?.Message ?? "accepted");
                Report.Check("Says no site changed", error?.PreviousBindingsRestored == true);
                Report.Check("Trial entry deleted afterwards", Iis.SysHash(TrialHost) is null);
                await RequireAllServe(_a, "Real sites unchanged");
            });
        }

        await Report.Scenario("A3 Single-site install refuses a bad certificate before touching the site", async () =>
        {
            await Reset();
            var error = await Capture(() => Real().ConfigureHttpsBindingsAsync(Sites[0], [Hosts[0]], _noKey));
            Report.Check("Refused", error is not null, error?.Message ?? "accepted");
            await RequireAllServe(_a, "Sites unchanged");
        });

        await Report.Scenario("A4 A trial entry left by a crash is removed", async () =>
        {
            await Reset();
            var added = Iis.Netsh("http", "add", "sslcert", $"hostnameport={TrialHost}", $"certhash={_a}", "certstorename=My", "appid={4dc3e181-e14b-4a21-b022-59fc669b0914}");
            Report.Check("Left a trial entry behind on purpose", Iis.SysHash(TrialHost) is not null, $"netsh exit {added.ExitCode}");
            await Real().RemoveCertificateTrialAsync();
            Report.Check("Removed", Iis.SysHash(TrialHost) is null);
            await Real().RemoveCertificateTrialAsync();
            Report.Check("Removing when there is none is harmless", true);
        });

        await Report.Scenario("A5 Switch and undo", async () =>
        {
            await Reset();
            var undo = await Real().SwitchHttpsBindingsAsync(Sites[0], [Hosts[0]], _b);
            Report.Check("Site serves B", await Iis.IsServing(Hosts[0], _b));
            Report.Check("HTTP.sys holds B", Iis.SysHash($"{Hosts[0]}:443") == _b);
            Report.Check("Other sites still serve A", await Iis.IsServing(Hosts[1], _a) && await Iis.IsServing(Hosts[2], _a));
            await Real().UndoHttpsBindingsAsync(undo);
            Report.Check("Undo: site serves A", await Iis.IsServing(Hosts[0], _a));
        });

        await Report.Scenario("A6 A binding already right is left alone", async () =>
        {
            await Reset();
            var undo = await Real().SwitchHttpsBindingsAsync(Sites[0], [Hosts[0]], _a);
            Report.Check("Nothing recorded as changed", undo.Changes.Count == 0, $"{undo.Changes.Count} changes");
        });

        foreach (var (label, thumbprint) in new[] { ("no private key", _noKey), ("missing from the store", _missing) })
        {
            await Report.Scenario($"A7 IIS itself refuses a certificate with {label}, skipping the trial: the failed site is restored", async () =>
            {
                await Reset();
                var error = await Capture(() => Real().SwitchHttpsBindingsAsync(Sites[0], [Hosts[0]], thumbprint));
                Report.Check("Failed", error is not null, error?.Message ?? "no failure");
                Report.Check("Reports restored", error?.PreviousBindingsRestored == true);
                await RequireAllServe(_a, "Every site really serves A");
            });
        }

        await Report.Scenario("A8 Second of three sites fails its live check, with more than 7 days left: all go back", async () =>
        {
            await Reset();
            var probe = new FaultyProbe((host, served) => host == Hosts[1] && Same(served, _b));
            var error = await Capture(() => SharedBindingTransaction.ApplyAsync(With(probe), Targets(), _b, leaveOutFailures: false, null, CancellationToken.None));
            Report.Check("Failed", error is not null, error?.Message ?? "no failure");
            Report.Check("Reports restored", error?.PreviousBindingsRestored == true);
            await RequireAllServe(_a, "Every site really serves A");
        });

        await Report.Scenario("A9 Second of three sites fails its live check, in the last 7 days: only it goes back", async () =>
        {
            await Reset();
            var probe = new FaultyProbe((host, served) => host == Hosts[1] && Same(served, _b));
            var leftOut = await SharedBindingTransaction.ApplyAsync(With(probe), Targets(), _b, leaveOutFailures: true, null, CancellationToken.None);
            Report.Check("That one site is reported", leftOut.Count == 1 && leftOut[0].SiteName == Sites[1], string.Join(", ", leftOut.Select(site => site.SiteName)));
            Report.Check("Sites 1 and 3 serve B", await Iis.IsServing(Hosts[0], _b) && await Iis.IsServing(Hosts[2], _b));
            Report.Check("Site 2 still serves A", await Iis.IsServing(Hosts[1], _a));
        });

        await Report.Scenario("A10 A restore that fails its check gets a second attempt", async () =>
        {
            await Reset();
            DateTimeOffset? firstBlocked = null;
            var probe = new FaultyProbe((host, served) =>
            {
                if (host != Hosts[0])
                {
                    return false;
                }

                if (Same(served, _b))
                {
                    return true;
                }

                // A looks down for long enough to fail the first restore check, then recovers during the second.
                firstBlocked ??= DateTimeOffset.UtcNow;
                return DateTimeOffset.UtcNow - firstBlocked < TimeSpan.FromSeconds(20);
            });
            var started = DateTimeOffset.UtcNow;
            var error = await Capture(() => With(probe).SwitchHttpsBindingsAsync(Sites[0], [Hosts[0]], _b));
            Report.Check("Failed and reports restored", error?.PreviousBindingsRestored == true, error?.Message ?? "no failure");
            Report.Check("The first check really failed", DateTimeOffset.UtcNow - firstBlocked > TimeSpan.FromSeconds(15), $"{(DateTimeOffset.UtcNow - started).TotalSeconds:0} s in all");
            await RequireAllServe(_a, "After removing and re-adding, every site really serves A");
            Report.Check("HTTP.sys holds A", Iis.SysHash($"{Hosts[0]}:443") == _a);
        });

        await Report.Scenario("A11 A restore that cannot be confirmed is reported, and the site is named", async () =>
        {
            await Reset();
            var probe = new FaultyProbe((host, _) => host == Hosts[0]);
            var error = await Capture(() => With(probe).SwitchHttpsBindingsAsync(Sites[0], [Hosts[0]], _b));
            Report.Check("Reports NOT restored", error?.PreviousBindingsRestored == false, error?.Message ?? "no failure");

            var transaction = new FaultyProbe((host, served) => host == Hosts[0] ? Same(served, _a) && _blockRestore : host == Hosts[1] && Same(served, _b));
            _blockRestore = true;
            await Reset();
            var shared = await Capture(() => SharedBindingTransaction.ApplyAsync(With(transaction), Targets(), _b, leaveOutFailures: false, null, CancellationToken.None));
            _blockRestore = false;
            Report.Check("Across sites: reports NOT restored", shared?.PreviousBindingsRestored == false, shared?.Message ?? "no failure");
            Report.Check("Across sites: names the site that could not be confirmed", shared?.Message.Contains(Sites[0], StringComparison.Ordinal) == true);
        });

        await Report.Scenario("A12 A stopped site is changed without a live check", async () =>
        {
            await Reset();
            Iis.StopSite(Sites[2]);
            var undo = await Real().SwitchHttpsBindingsAsync(Sites[2], [Hosts[2]], _b);
            Report.Check("Recorded as stopped", !undo.SiteStarted);
            Report.Check("Binding uses B", Iis.BoundThumbprint(Sites[2], Hosts[2]) == _b);
            Iis.StartSite(Sites[2]);
            Report.Check("Serves B once started", await Iis.IsServing(Hosts[2], _b));
            await Real().UndoHttpsBindingsAsync(undo);
            Report.Check("Undo: serves A", await Iis.IsServing(Hosts[2], _a));
        });

        await Report.Scenario("A13 A new binding is removed again by undo", async () =>
        {
            await Reset();
            var host = "accept1-new.sslense.test";
            Iis.EnsureSite(Sites[0], host);
            var undo = await Real().SwitchHttpsBindingsAsync(Sites[0], [host], _b);
            Report.Check("Recorded as added", undo.Changes.Single().WasAdded);
            Report.Check("Serves B", await Iis.IsServing(host, _b));
            await Real().UndoHttpsBindingsAsync(undo);
            Report.Check("HTTPS binding gone", !Iis.HasHttpsBinding(Sites[0], host));
            Report.Check("Other host on that site still serves A", await Iis.IsServing(Hosts[0], _a));
            Iis.RemoveHostBindings(Sites[0], host);
        });

        await Report.Scenario("A14 A site that has lost its HTTP.sys entry is found before ordering", async () =>
        {
            await Reset();
            var sites = await Real().GetSitesAsync();
            var site = sites.Single(value => value.Name == Sites[1]);
            Report.Check("Healthy site has no problem", await Real().GetHttpsProblemAsync(site, [Hosts[1]]) is null);
            Iis.DropSysEntry(Hosts[1]);
            var served = await Iis.Served(Hosts[1]);
            Report.Check("Site really stopped answering", served.StartsWith("ERR", StringComparison.Ordinal), Iis.Short(served));
            var problem = await Real().GetHttpsProblemAsync(site, [Hosts[1]]);
            Report.Check("Problem found", problem is not null, problem ?? "none");
        });

        await Report.Scenario("A15 Sites with different certificates work side by side", async () =>
        {
            await Reset();
            await Real().SwitchHttpsBindingsAsync(Sites[0], [Hosts[0]], _b);
            Report.Check("Site 1 serves B", await Iis.IsServing(Hosts[0], _b));
            Report.Check("Site 2 serves A", await Iis.IsServing(Hosts[1], _a));
        });
    }

    private static bool _blockRestore;

    private static IReadOnlyList<CertificateTarget> Targets() =>
        Sites.Select((site, index) => new CertificateTarget(site, [Hosts[index]])).ToArray();

    private static bool Same(string left, string right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private static async Task<IisBindingException?> Capture(Func<Task> action)
    {
        try
        {
            await action();
            return null;
        }
        catch (IisBindingException exception)
        {
            return exception;
        }
    }

    /// <summary>Puts all three sites on certificate A, without using the code being tested.</summary>
    private static async Task Reset()
    {
        for (var index = 0; index < Sites.Length; index++)
        {
            Iis.EnsureSite(Sites[index], Hosts[index]);
            Iis.BindHttps(Sites[index], Hosts[index], _a);
        }

        foreach (var host in Hosts)
        {
            if (!await Iis.IsServing(host, _a))
            {
                throw new InvalidOperationException($"Test setup failed: {host} does not serve certificate A.");
            }
        }
    }

    private static async Task RequireAllServe(string thumbprint, string name)
    {
        var served = new List<string>();
        foreach (var host in Hosts)
        {
            served.Add(await Iis.WaitServed(host, thumbprint));
        }

        Report.Check(name, served.All(value => Same(value, thumbprint)), string.Join(" ", served.Select(Iis.Short)));
    }

    private static string CreateCertificate(string label, bool install, bool keepKey)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest($"{Subject} {label}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        using var created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var thumbprint = created.Thumbprint;
        if (install)
        {
            using var loaded = keepKey
                ? X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pkcs12, "x"), "x", X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet)
                : X509CertificateLoader.LoadCertificate(created.RawData);
            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            store.Add(loaded);
        }

        return thumbprint;
    }

    private static void Cleanup()
    {
        foreach (var site in Sites)
        {
            Iis.DeleteSite(site);
        }

        foreach (var host in Hosts.Append("accept1-new.sslense.test"))
        {
            Iis.DropSysEntry(host);
        }

        Iis.Netsh("http", "delete", "sslcert", $"hostnameport={TrialHost}");
        Iis.RemoveCertificates(certificate => certificate.Subject.StartsWith(Subject, StringComparison.Ordinal));
        Iis.RemoveTestFolder();
    }
}
