using System.Diagnostics;
using System.Net;
using System.ServiceProcess;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using DnsClient;
using SSLense.Core.Config;

namespace SSLense.Acceptance;

internal sealed record Record(string Id, string Site, string Thumbprint, DateTimeOffset NotAfter, string? SitePending, IReadOnlyList<(string Site, string? Pending)> More)
{
    public bool Lists(string site) => Site == site || More.Any(target => target.Site == site);
    public bool IsPending(string site) => site == Site ? SitePending is not null : More.Any(target => target.Site == site && target.Pending is not null);
    public bool AnyPending => SitePending is not null || More.Any(target => target.Pending is not null);
}

/// <summary>
/// The real commands against Let's Encrypt STAGING. These use C:\ProgramData\SSLense, which the installed release shares, so the
/// service is stopped and the folder is backed up first and restored afterwards.
/// </summary>
internal static partial class PartB
{
    private const string Service = "SSLense";
    private const string DefaultInstalledCli = @"C:\Program Files\SSLense\cli\SSLense.Cli.exe";
    private const string A = "SSLenseAccept1", B = "SSLenseAccept2", C = "SSLenseAccept3";
    private static string Zone = "";
    private static string Cli = "";

    /// <summary>A release to compare with, when it differs from the build under test.</summary>
    private static string? InstalledCli;
    private static string Domain => $"accept.{Zone}";
    private static string HostA => $"site1.{Domain}";
    private static string HostB => $"site2.{Domain}";
    private static string HostC => $"site3.{Domain}";
    private static string ZoneFile => Path.Combine(Backup, "zone.txt");
    private static readonly string Backup = AppPaths.DataDirectory + ".acceptance-backup";
    private static readonly string CompleteFlag = Path.Combine(Backup, "backup-complete.flag");
    private static readonly TimeSpan OrderSpacing = TimeSpan.FromSeconds(30);
    private static string _email = "";

    public static void Configure(string? zone, string? cli, string? installed)
    {
        Zone = zone ?? "";
        Cli = cli ?? FindBuiltCli() ?? throw new InvalidOperationException("No built SSLense.Cli.exe was found. Build the solution, or pass --cli.");
        if (!File.Exists(Cli))
        {
            throw new InvalidOperationException($"Not found: {Cli}");
        }

        var candidate = installed ?? DefaultInstalledCli;
        InstalledCli = File.Exists(candidate) && !string.Equals(Path.GetFullPath(candidate), Path.GetFullPath(Cli), StringComparison.OrdinalIgnoreCase)
            ? candidate
            : null;
    }

    private static string? FindBuiltCli()
    {
        for (var folder = new DirectoryInfo(AppContext.BaseDirectory); folder is not null; folder = folder.Parent)
        {
            if (File.Exists(Path.Combine(folder.FullName, "SSLense.sln")))
            {
                return new[] { "Debug", "Release" }
                    .Select(configuration => new FileInfo(Path.Combine(folder.FullName, "src", "SSLense.Cli", "bin", configuration, "net10.0-windows", "SSLense.Cli.exe")))
                    .Where(file => file.Exists)
                    .OrderByDescending(file => file.LastWriteTimeUtc)
                    .FirstOrDefault()?.FullName;
            }
        }

        return null;
    }

    private static void RequireReady()
    {
        if (string.IsNullOrWhiteSpace(Zone))
        {
            throw new InvalidOperationException("Pass --zone with a DNS zone on Cloudflare, such as --zone example.com.");
        }

        if (Directory.Exists(Backup))
        {
            throw new InvalidOperationException($"{Backup} already exists, so an earlier run did not finish. Run this program with 'restore' first.");
        }

        RequireAppClosed();
        Console.WriteLine($"This uses {AppPaths.DataDirectory}, stops the SSLense service while it runs, and adds temporary TXT records under {Domain}.");
        Console.WriteLine("It only uses Let's Encrypt staging. Do not run it while this server has a renewal that must not wait.");
        Console.Write("Type yes to continue: ");
        if (!string.Equals(Console.ReadLine()?.Trim(), "yes", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Stopped. Nothing was changed.");
        }
    }

    private static void RequireAppClosed()
    {
        if (Process.GetProcessesByName("SSLense.Gui").Length > 0)
        {
            throw new InvalidOperationException("Close the SSLense app first.");
        }
    }

    /// <summary>Leaves three sites and one certificate on staging, so the app can be tried by hand. Finish with 'restore'.</summary>
    public static async Task SetUpForAppAsync()
    {
        RequireReady();
        Console.Write("Email for the Let's Encrypt staging account: ");
        _email = Console.ReadLine()?.Trim() ?? "";
        Report.Scrub = _email;
        TakeBackup(StopService());
        try
        {
            CleanupTestObjects();
            await AddDnsProviderAsync();
            foreach (var (site, host) in new[] { (A, HostA), (B, HostB), (C, HostC) })
            {
                Iis.EnsureSite(site, host);
            }

            var result = await Run(Cli, "issue", "--site", A, "--email", _email, "--validation", "dns", "--staging", "--names", $"*.{Domain}", "--hosts", HostA);
            if (!Report.Check("Certificate issued", result.ExitCode == 0, $"exit {result.ExitCode}"))
            {
                throw new InvalidOperationException("The certificate was not issued, so there is nothing to try in the app.");
            }
        }
        catch (Exception exception)
        {
            // Nothing can be tried, so this machine should not stay with its service stopped.
            Report.Check("Setup finished", false, exception.Message);
            await RestoreAsync();
            return;
        }

        Report.Info($"Ready: {A} has the certificate; {B} ({HostB}) and {C} ({HostC}) can be added to it.");
        Report.Info("Run the app from the same build. When finished, close it and run this program with 'restore'.");
    }

    /// <summary>The installed service, not a command, moves a site left behind. Its first cycle runs when it starts.</summary>
    public static async Task ServiceCheckAsync()
    {
        RequireReady();
        if (!ServiceExists())
        {
            throw new InvalidOperationException("The SSLense service is not installed, so there is nothing to check.");
        }

        Console.Write("Email for the Let's Encrypt staging account: ");
        _email = Console.ReadLine()?.Trim() ?? "";
        Report.Scrub = _email;
        Report.Info($"Build: {(await Run(Cli, "--version")).Output.Trim()}");
        TakeBackup(StopService());
        try
        {
            CleanupTestObjects();
            await AddDnsProviderAsync();
            await Report.Scenario("S1 The service moves a site left behind, without a new certificate", async () =>
            {
                foreach (var (site, host) in new[] { (A, HostA), (B, HostB), (C, HostC) })
                {
                    Iis.EnsureSite(site, host);
                }

                var issued = await Run(Cli, "issue", "--site", A, "--email", _email, "--validation", "dns", "--staging", "--names", $"*.{Domain}", "--hosts", HostA);
                Report.Check("Issued", issued.ExitCode == 0, $"exit {issued.ExitCode}");
                await Run(Cli, "share", "add", "--from", A, "--to", B, "--hosts", HostB);
                await Run(Cli, "share", "add", "--from", A, "--to", C, "--hosts", HostC);
                Iis.RemoveHostBindings(C, HostC);
                await Renew(A, force: true, expectNew: true);
                var record = Get(A);
                Report.Check("Left behind", record.IsPending(C));

                Iis.EnsureSite(C, HostC);
                using (var service = new ServiceController(Service))
                {
                    service.Start();
                    service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromMinutes(2));
                }

                var deadline = DateTimeOffset.UtcNow.AddMinutes(5);
                var after = Get(A);
                while (after.IsPending(C) && DateTimeOffset.UtcNow < deadline)
                {
                    await Task.Delay(TimeSpan.FromSeconds(5));
                    try
                    {
                        after = Get(A);
                    }
                    catch (IOException)
                    {
                        // The service was saving the file; read it on the next pass.
                    }
                }

                Report.Check("The service caught it up", !after.IsPending(C));
                Report.Check("Without a new certificate", Same(after.Thumbprint, record.Thumbprint));
                await RequireServing(after.Thumbprint, HostA, HostB, HostC);
            });
        }
        finally
        {
            await RestoreAsync();
        }
    }

    /// <summary>
    /// A single site over HTTP validation, through the trial and the checked install. Needs the first host's name in public DNS,
    /// pointing at this machine, with port 80 open to the internet.
    /// </summary>
    public static async Task HttpCheckAsync()
    {
        RequireReady();
        IPAddress[] addresses;
        try
        {
            addresses = await Dns.GetHostAddressesAsync(HostA);
        }
        catch (System.Net.Sockets.SocketException exception)
        {
            Report.Check($"{HostA} is in public DNS", false,
                $"{exception.Message} Add an A record for it pointing at this machine, set to DNS only. A failed lookup can be cached for up to 30 minutes. Nothing was changed.");
            return;
        }

        Report.Info($"{HostA} resolves to {string.Join(", ", addresses.Select(address => address.ToString()))}");
        Console.Write("Email for the Let's Encrypt staging account: ");
        _email = Console.ReadLine()?.Trim() ?? "";
        Report.Scrub = _email;
        Report.Info($"Build: {(await Run(Cli, "--version")).Output.Trim()}");
        TakeBackup(StopService());
        try
        {
            CleanupTestObjects();
            await Report.Scenario("H1 HTTP validation on one site", async () =>
            {
                Iis.EnsureSite(A, HostA);
                var issued = await Run(Cli, "issue", "--site", A, "--email", _email, "--validation", "http", "--staging", "--hosts", HostA);
                Report.Check("Issued", issued.ExitCode == 0, $"exit {issued.ExitCode}");
                if (issued.ExitCode != 0)
                {
                    return;
                }

                var first = Get(A).Thumbprint;
                await RequireServing(first, HostA);

                await Renew(A, force: true, expectNew: true);
                var renewed = Get(A).Thumbprint;
                Report.Check("Renewed", !Same(first, renewed), $"{Iis.Short(first)} -> {Iis.Short(renewed)}");
                await RequireServing(renewed, HostA);
                Report.Check("Old certificate removed from the store", !Iis.InStore(first));

                Iis.EnsureSite(B, HostB);
                await ExpectRefused("sharing a certificate that uses HTTP validation", "share", "add", "--from", A, "--to", B, "--hosts", HostB);
                var removed = await Run(Cli, "remove", "--site", A, "--yes");
                Report.Check("Removed", removed.ExitCode == 0 && !Iis.InStore(renewed), $"exit {removed.ExitCode}");
            });
        }
        finally
        {
            await RestoreAsync();
        }
    }

    public static async Task RunAsync()
    {
        RequireReady();
        Console.Write("Email for the Let's Encrypt staging account: ");
        _email = Console.ReadLine()?.Trim() ?? "";
        Report.Scrub = _email;
        Report.Info($"Build under test: {(await Run(Cli, "--version")).Output.Trim()}");

        // Read before anything changes, for the comparison after the upgrade.
        if (InstalledCli is not null)
        {
            Report.Info($"Installed release: {(await Run(InstalledCli, "--version")).Output.Trim()}");
            Report.Info("Status from the installed release, before the test:");
            Report.Info((await Run(InstalledCli, "status")).Output);
        }

        var recordsBefore = ReadRecords().Select(record => record.Thumbprint).Order().ToArray();
        var schemaBefore = ReadSchema();

        var serviceWasRunning = StopService();
        TakeBackup(serviceWasRunning);
        try
        {
            CleanupTestObjects();
            await Report.Scenario("B1 Reading the existing 0.13 data", () => CheckReadAsync(recordsBefore, schemaBefore));
            await AddDnsProviderAsync();
            await ScenariosAsync(recordsBefore, schemaBefore);
        }
        finally
        {
            await Report.Scenario("Final checks and cleanup", CleanupAfterRunAsync);
            await RestoreAsync();
        }
    }

    /// <summary>Reading never rewrites the file: the schema changes at the first save, so that is checked after the first issue.</summary>
    private static async Task CheckReadAsync(string[] recordsBefore, int? schemaBefore)
    {
        var status = await Run(Cli, "status");
        Report.Check("New build reads the existing data", status.ExitCode == 0, $"exit {status.ExitCode}");
        Report.Check("Reading does not rewrite the file", ReadSchema() == schemaBefore, $"{schemaBefore} -> {ReadSchema()}");
        Report.Check("Every existing certificate is still there", recordsBefore.SequenceEqual(ReadRecords().Select(record => record.Thumbprint).Order()), $"{recordsBefore.Length} records");
    }

    private static async Task CheckUpgradeAsync(string[] recordsBefore, int? schemaBefore)
    {
        if (schemaBefore is null)
        {
            Report.Info("There was no managed certificate file to upgrade.");
            return;
        }

        Report.Check("Schema is now 5", ReadSchema() == 5, $"{schemaBefore} -> {ReadSchema()}");
        Report.Check("Backup of the old schema exists", File.Exists($"{AppPaths.ManagedCertificatesFile}.v{schemaBefore}.bak"));
        var thumbprints = ReadRecords().Select(record => record.Thumbprint).ToArray();
        Report.Check("Every existing certificate is still there", recordsBefore.All(value => thumbprints.Contains(value)), $"{recordsBefore.Length} existing, {thumbprints.Length} now");
        if (InstalledCli is null)
        {
            Report.Info("No other release is installed, so refusing the newer data was not tested.");
            return;
        }

        var refused = await Run(InstalledCli, "status");
        Report.Check("The installed release refuses the newer data instead of misreading it", refused.ExitCode != 0, refused.Output.Trim());
    }

    private static async Task AddDnsProviderAsync()
    {
        Report.Heading("Cloudflare");
        var existing = (await Run(Cli, "dns", "list")).Output.Split('\n')
            .Select(line => Regex.Match(line.Trim(), @"^(.+): \w+, zone " + Regex.Escape(Zone) + "$"))
            .FirstOrDefault(match => match.Success);
        string name;
        int exitCode;
        string errors;
        if (existing is not null)
        {
            name = existing.Groups[1].Value;
            Console.WriteLine($"Paste the new Cloudflare token for provider '{name}'. It is not shown, and it goes straight to SSLense.");
            (exitCode, errors) = await Interactive("dns", "update-token", "--name", name);
        }
        else
        {
            name = "acceptance";
            string zoneId;
            do
            {
                // Asked again here, because SSLense only checks the format after the token has been pasted.
                Console.Write($"Cloudflare zone ID for {Zone}: 32 hexadecimal characters, from the domain's Overview page: ");
                zoneId = Console.ReadLine()?.Trim() ?? "";
            }
            while (!Regex.IsMatch(zoneId, "^[0-9a-fA-F]{32}$"));

            Console.WriteLine("Paste the new Cloudflare token. It is not shown, and it goes straight to SSLense.");
            (exitCode, errors) = await Interactive("dns", "add", "--provider", "cloudflare", "--name", name, "--zone", Zone, "--zone-id", zoneId);
        }

        if (!Report.Check("DNS provider saved", exitCode == 0, $"exit {exitCode}: {errors.Trim()}"))
        {
            throw new InvalidOperationException("The DNS provider was not saved, so the staging tests were not run.");
        }

        var test = await Run(Cli, "dns", "test", "--name", name);
        if (!Report.Check("Token can change the zone", test.ExitCode == 0, test.Output.Trim()))
        {
            throw new InvalidOperationException("The Cloudflare token did not work, so the staging tests were not run.");
        }
    }

    private static async Task ScenariosAsync(string[] recordsBefore, int? schemaBefore)
    {
        foreach (var (site, host) in new[] { (A, HostA), (B, HostB), (C, HostC) })
        {
            Iis.EnsureSite(site, host);
        }

        var issued = await Report.Scenario("B2 Issue a wildcard for the first site", async () =>
        {
            var result = await Run(Cli, "issue", "--site", A, "--email", _email, "--validation", "dns", "--staging", "--names", $"*.{Domain}", "--hosts", HostA);
            Report.Check("Issued", result.ExitCode == 0, $"exit {result.ExitCode}");
            var record = Get(A);
            Report.Check("Site serves it", await Iis.IsServing(HostA, record.Thumbprint), Iis.Short(record.Thumbprint));
        });
        if (!issued)
        {
            Report.Info("No certificate to share, so the remaining staging tests were skipped.");
            return;
        }

        await Report.Scenario("B2a The first save upgrades the existing 0.13 data", () => CheckUpgradeAsync(recordsBefore, schemaBefore));

        await Report.Scenario("B3 share add, with hosts worked out from the site", async () =>
        {
            var before = Get(A);
            var result = await Run(Cli, "share", "add", "--from", A, "--to", B);
            Report.Check("Added", result.ExitCode == 0, $"exit {result.ExitCode}");
            var after = Get(A);
            Report.Check("Recorded", after.Lists(B));
            Report.Check("No new certificate", Same(after.Thumbprint, before.Thumbprint));
            Report.Check("Second site serves it", await Iis.IsServing(HostB, after.Thumbprint));
        });

        await Report.Scenario("B4 share add on a certificate already bound by hand", async () =>
        {
            var before = Get(A);
            Iis.BindHttps(C, HostC, before.Thumbprint);
            var result = await Run(Cli, "share", "add", "--from", A, "--to", C, "--hosts", HostC);
            Report.Check("Added", result.ExitCode == 0, $"exit {result.ExitCode}");
            var after = Get(A);
            Report.Check("Recorded", after.Lists(C));
            Report.Check("No new certificate", Same(after.Thumbprint, before.Thumbprint));
            Report.Check("Third site still serves it", await Iis.IsServing(HostC, after.Thumbprint));
        });

        await Report.Scenario("B5 Other commands refuse a site that shares a certificate, and status shows every site", async () =>
        {
            var before = Get(A);
            await ExpectRefused("issue", "issue", "--site", B, "--email", _email, "--validation", "dns", "--staging", "--names", $"*.{Domain}", "--hosts", HostB, "--force");
            await ExpectRefused("adopt", "adopt", "--site", B);
            await ExpectRefused("csr", "csr", "--site", B, "--hosts", HostB, "--out", Path.Combine(Iis.Root, "refused.csr"));
            await ExpectRefused("remove", "remove", "--site", B, "--yes");
            await ExpectRefused("issue with names that stop covering a shared host", "issue", "--site", A, "--email", _email, "--validation", "dns", "--staging", "--names", HostA, "--hosts", HostA, "--force");
            Report.Check("Nothing changed", Same(Get(A).Thumbprint, before.Thumbprint) && await Iis.IsServing(HostB, before.Thumbprint));
            var status = await Run(Cli, "status");
            Report.Check("status names all three sites", new[] { A, B, C }.All(site => status.Output.Contains(site, StringComparison.Ordinal)));
            var details = await Run(Cli, "details", "--site", C);
            Report.Check("details works from an additional site, and names all three", details.ExitCode == 0 && new[] { A, B }.All(site => details.Output.Contains(site, StringComparison.Ordinal)));
            var listing = await Run(Cli, "remove", "--site", A);
            Report.Check("remove without --yes lists the shared sites and changes nothing", new[] { B, C }.All(site => listing.Output.Contains(site, StringComparison.Ordinal)) && Get(A).Lists(B));
        });

        await Report.Scenario("B6 Forced renewal, named by an additional site, moves all three", async () =>
        {
            var old = Get(A).Thumbprint;
            await Renew(B, force: true, expectNew: true);
            var now = Get(A).Thumbprint;
            Report.Check("New certificate", !Same(old, now), $"{Iis.Short(old)} -> {Iis.Short(now)}");
            await RequireServing(now, HostA, HostB, HostC);
            Report.Check("Old certificate removed from the store", !Iis.InStore(old));
        });

        await Report.Scenario("B7 A stopped site is included, with no live check", async () =>
        {
            Iis.StopSite(C);
            await Renew(A, force: true, expectNew: true);
            var record = Get(A);
            Report.Check("Not left out", !record.AnyPending);
            Report.Check("Stopped site's binding moved", Same(Iis.BoundThumbprint(C, HostC) ?? "", record.Thumbprint));
            Iis.StartSite(C);
            await RequireServing(record.Thumbprint, HostA, HostB, HostC);
        });

        await Report.Scenario("B8 More than 7 days left, a site is broken: nothing is ordered or changed", async () =>
        {
            var old = Get(A).Thumbprint;
            Iis.DropSysEntry(HostB);
            Report.Check("Site really stopped answering", (await Iis.Served(HostB)).StartsWith("ERR", StringComparison.Ordinal));
            var result = await Run(Cli, "renew", "--site", A, "--force");
            Report.Check("Reports the problem", result.Output.Contains("Nothing was ordered", StringComparison.Ordinal), $"exit {result.ExitCode}");
            Report.Check("Same certificate", Same(Get(A).Thumbprint, old));
            await RequireServing(old, HostA, HostC);
            Repair(B, HostB, old);
            await RequireServing(old, HostB);
        });

        await Report.Scenario("B9 A host's bindings removed: left out, others renew, catches up without an order", async () =>
        {
            var old = Get(A).Thumbprint;
            Iis.RemoveHostBindings(C, HostC);
            await Renew(A, force: true, expectNew: true);
            var record = Get(A);
            Report.Check("Others renewed", !Same(record.Thumbprint, old));
            Report.Check("Left out", record.IsPending(C));
            await RequireServing(record.Thumbprint, HostA, HostB);

            Iis.EnsureSite(C, HostC);
            var caughtUp = await Run(Cli, "renew", "--site", A);
            Report.Check("Second run finished", caughtUp.ExitCode == 0, $"exit {caughtUp.ExitCode}");
            var after = Get(A);
            Report.Check("Caught up", !after.IsPending(C));
            Report.Check("Without a new certificate", Same(after.Thumbprint, record.Thumbprint));
            await RequireServing(after.Thumbprint, HostC);
        });

        await Report.Scenario("B10 A deleted site: left out and kept in the record, catches up when it comes back", async () =>
        {
            Iis.DeleteSite(C);
            await Renew(A, force: true, expectNew: true);
            var record = Get(A);
            Report.Check("Still in the record, marked as left out", record.Lists(C) && record.IsPending(C));
            await RequireServing(record.Thumbprint, HostA, HostB);
            var status = await Run(Cli, "status");
            Report.Check("status still works", status.ExitCode == 0 && status.Output.Contains(C, StringComparison.Ordinal));

            Iis.EnsureSite(C, HostC);
            await Run(Cli, "renew", "--site", C);
            var after = Get(A);
            Report.Check("Caught up", !after.IsPending(C));
            Report.Check("Without a new certificate", Same(after.Thumbprint, record.Thumbprint));
            await RequireServing(after.Thumbprint, HostC);
        });

        await Report.Scenario("B11 Last 7 days, a site is broken: left out, keeps its certificate, catches up", async () =>
        {
            var old = Get(A).Thumbprint;
            SetNotAfter(A, DateTimeOffset.UtcNow.AddDays(5));
            Iis.DropSysEntry(HostB);
            await Renew(A, force: true, expectNew: true);
            var record = Get(A);
            Report.Check("Others renewed", !Same(record.Thumbprint, old));
            Report.Check("Left out", record.IsPending(B));
            Report.Check("Previous certificate kept, because its binding uses it", Iis.InStore(old));
            await RequireServing(record.Thumbprint, HostA, HostC);

            Repair(B, HostB, old);
            await RequireServing(old, HostB);
            await Run(Cli, "renew", "--site", A);
            var after = Get(A);
            Report.Check("Caught up", !after.IsPending(B));
            Report.Check("Without a new certificate", Same(after.Thumbprint, record.Thumbprint));
            await RequireServing(after.Thumbprint, HostB);
        });

        await Report.Scenario("B11a Last 7 days, a site lost its HTTP.sys entry and nobody fixes it: catching up brings it back", async () =>
        {
            SetNotAfter(A, DateTimeOffset.UtcNow.AddDays(5));
            Iis.DropSysEntry(HostB);
            await Renew(A, force: true, expectNew: true);
            var record = Get(A);
            Report.Check("Left out", record.IsPending(B));
            await Run(Cli, "renew", "--site", A);
            var after = Get(A);
            Report.Check("Caught up", !after.IsPending(B));
            Report.Check("Without a new certificate", Same(after.Thumbprint, record.Thumbprint));
            await RequireServing(after.Thumbprint, HostB);
        });

        foreach (var (site, label) in new[] { (A, "first"), (B, "second") })
        {
            await Report.Scenario($"B12 The process is killed while moving the {label} site", async () =>
            {
                var old = Get(A).Thumbprint;
                var killed = await KillDuringMove(site);
                Report.Check("Killed during the move", killed.Killed, $"exit {killed.ExitCode}");
                var servedA = await Iis.Served(HostA);
                Report.Info($"Right after the kill: {HostA}={Iis.Short(servedA)} {HostB}={Iis.Short(await Iis.Served(HostB))} {HostC}={Iis.Short(await Iis.Served(HostC))}");
                if (site == B)
                {
                    Report.Check("The first site had already moved, so the sites really were split", !Same(servedA, old), Iis.Short(servedA));
                }

                // Every command recovers first.
                var recovery = await Run(Cli, "status");
                Report.Check("Next start finishes without an error", recovery.ExitCode == 0, $"exit {recovery.ExitCode}");
                var record = Get(A);
                Report.Info($"Record went from {Iis.Short(old)} to {Iis.Short(record.Thumbprint)}");
                Report.Check("Record's certificate is in the store", Iis.InStore(record.Thumbprint));
                await RequireServing(record.Thumbprint, HostA, HostB, HostC);
                Report.Check("Transaction journal is empty", !Directory.Exists(AppPaths.TransactionDirectory) || Directory.GetFiles(AppPaths.TransactionDirectory).Length == 0);
                Report.Check("No trial entry left", Iis.SysHash("sslense-certificate-trial.invalid:443") is null);
            });
        }

        await Report.Scenario("B13 share remove on an additional site keeps its binding, then it can come back", async () =>
        {
            var old = Get(A).Thumbprint;
            var result = await Run(Cli, "share", "remove", "--site", C);
            Report.Check("Removed", result.ExitCode == 0, $"exit {result.ExitCode}");
            Report.Check("Gone from the record", !Get(A).Lists(C));
            Report.Check("Still serves the certificate", await Iis.IsServing(HostC, old));

            await Renew(A, force: true, expectNew: true);
            var now = Get(A).Thumbprint;
            await RequireServing(now, HostA, HostB);
            Report.Check("The removed site was not touched", await Iis.IsServing(HostC, old));
            Report.Check("Its certificate stays in the store while bound", Iis.InStore(old));

            var back = await Run(Cli, "share", "add", "--from", A, "--to", C, "--hosts", HostC);
            Report.Check("Added back", back.ExitCode == 0, $"exit {back.ExitCode}");
            await RequireServing(now, HostC);
        });

        await Report.Scenario("B14 share remove on the first site promotes the next, and keeps the record", async () =>
        {
            var before = Get(A);
            var result = await Run(Cli, "share", "remove", "--site", A);
            Report.Check("Removed", result.ExitCode == 0, $"exit {result.ExitCode}");
            var after = Get(B);
            Report.Check("Next site is now first", after.Site == B && !after.Lists(A), after.Site);
            Report.Check("Same record ID", after.Id == before.Id);
            Report.Check("Binding kept", await Iis.IsServing(HostA, before.Thumbprint));
            var back = await Run(Cli, "share", "add", "--from", B, "--to", A, "--hosts", HostA);
            Report.Check("Added back", back.ExitCode == 0, $"exit {back.ExitCode}");
        });

        await Report.Scenario("B15 --replace-existing takes over a site with its own certificate", async () =>
        {
            var shared = Get(B).Thumbprint;
            await Run(Cli, "share", "remove", "--site", C);
            var own = await IssueWithRetry("--site", C, "--email", _email, "--validation", "dns", "--staging", "--names", HostC, "--hosts", HostC, "--force");
            Report.Check("Single-site certificate issued, through the trial", own.ExitCode == 0, $"exit {own.ExitCode}");
            var ownThumbprint = Get(C).Thumbprint;
            Report.Check("It serves its own certificate", !Same(ownThumbprint, shared) && await Iis.IsServing(HostC, ownThumbprint));

            await ExpectRefused("share add without --replace-existing", "share", "add", "--from", B, "--to", C, "--hosts", HostC);
            var taken = await Run(Cli, "share", "add", "--from", B, "--to", C, "--hosts", HostC, "--replace-existing");
            Report.Check("Taken over", taken.ExitCode == 0, $"exit {taken.ExitCode}");
            Report.Check("Old record gone", ReadRecords().Count(record => record.Lists(C)) == 1 && Get(C).Id == Get(B).Id);
            Report.Check("Serves the shared certificate", await Iis.IsServing(HostC, shared));
            Report.Check("Its old certificate left the store", !Iis.InStore(ownThumbprint));
        });

        await Report.Scenario("B16 The last site cannot be share-removed, and remove --yes clears every site", async () =>
        {
            var thumbprint = Get(B).Thumbprint;
            await Run(Cli, "share", "remove", "--site", C);
            await Run(Cli, "share", "remove", "--site", A);
            await ExpectRefused("share remove on the only site", "share", "remove", "--site", B);
            await Run(Cli, "share", "add", "--from", B, "--to", A, "--hosts", HostA);
            await Run(Cli, "share", "add", "--from", B, "--to", C, "--hosts", HostC);

            var removed = await Run(Cli, "remove", "--site", B, "--yes");
            Report.Check("Removed", removed.ExitCode == 0, $"exit {removed.ExitCode}");
            Report.Check("Record gone", !ReadRecords().Any(record => record.Lists(A) || record.Lists(B) || record.Lists(C)));
            Report.Check("HTTPS bindings gone on all three", !Iis.HasHttpsBinding(A, HostA) && !Iis.HasHttpsBinding(B, HostB) && !Iis.HasHttpsBinding(C, HostC));
            Report.Check("Certificate left the store", !Iis.InStore(thumbprint));
        });
    }

    private static async Task CleanupAfterRunAsync()
    {
        await Run(Cli, "status");
        Report.Check("No validation record left in the live zone", await NoChallengeRecordLeftAsync());
        var challenges = Directory.Exists(AppPaths.DnsChallengeJournalDirectory) ? Directory.GetFiles(AppPaths.DnsChallengeJournalDirectory).Length : 0;
        Report.Check("No DNS challenge waiting to be cleaned", challenges == 0, $"{challenges} waiting");
    }

    private static async Task<(int ExitCode, string Output, bool Killed)> KillDuringMove(string site)
    {
        for (var attempt = 0; ; attempt++)
        {
            await Task.Delay(OrderSpacing);
            var result = await Run(Cli, ["renew", "--site", A, "--force"], line => line.Contains($"Moving IIS site '{site}' to", StringComparison.Ordinal));
            if (result.Killed || attempt == 2 || !IsWorthRetrying(result.Output))
            {
                return result;
            }

            Report.Info("Staging was busy or a record was still cached. Trying again in 2 minutes.");
            await Task.Delay(TimeSpan.FromMinutes(2));
        }
    }

    private static async Task<bool> NoChallengeRecordLeftAsync()
    {
        var nameServers = await new LookupClient().QueryAsync(Zone, QueryType.NS);
        var servers = await Dns.GetHostAddressesAsync(nameServers.Answers.NsRecords().First().NSDName.Value);
        var client = new LookupClient(new LookupClientOptions(servers.Select(address => new IPEndPoint(address, 53)).ToArray()) { UseCache = false, Recursion = false });
        var answer = await client.QueryAsync($"_acme-challenge.{Domain}", QueryType.TXT);
        return !answer.Answers.TxtRecords().Any();
    }

    private static async Task<(int ExitCode, string Output)> IssueWithRetry(params string[] arguments)
    {
        var result = await Run(Cli, ["issue", .. arguments]);
        if (result.ExitCode != 0 && IsWorthRetrying(result.Output))
        {
            Report.Info("Staging was busy or a record was still cached. Trying again in 2 minutes.");
            await Task.Delay(TimeSpan.FromMinutes(2));
            result = await Run(Cli, ["issue", .. arguments]);
        }

        return (result.ExitCode, result.Output);
    }

    /// <summary>Renewals run back to back here, so a cached record or a busy staging server is a test artefact, not a failure of the feature.</summary>
    private static async Task Renew(string site, bool force, bool expectNew)
    {
        var before = Get(site).Thumbprint;
        string[] arguments = force ? ["renew", "--site", site, "--force"] : ["renew", "--site", site];
        await Task.Delay(OrderSpacing);
        var result = await Run(Cli, arguments);
        for (var attempt = 0; attempt < 2 && result.ExitCode != 0 && IsWorthRetrying(result.Output); attempt++)
        {
            Report.Info("Staging was busy or a record was still cached. Trying again in 2 minutes.");
            await Task.Delay(TimeSpan.FromMinutes(2));
            result = await Run(Cli, arguments);
        }

        Report.Check("Renewal finished", result.ExitCode == 0, $"exit {result.ExitCode}");
        if (expectNew && Same(Get(site).Thumbprint, before))
        {
            Report.Check("A new certificate was installed", false);
        }
    }

    private static bool IsWorthRetrying(string output) =>
        Regex.IsMatch(output, "incorrect TXT|unauthorized|did not appear|rate limit|service busy", RegexOptions.IgnoreCase);

    private static async Task ExpectRefused(string name, params string[] arguments)
    {
        var result = await Run(Cli, arguments);
        Report.Check($"Refused: {name}", result.ExitCode != 0, result.Output.Trim().Split('\n').LastOrDefault()?.Trim() ?? "");
    }

    private static async Task RequireServing(string thumbprint, params string[] hosts)
    {
        foreach (var host in hosts)
        {
            var served = await Iis.WaitServed(host, thumbprint);
            Report.Check($"{host} serves {Iis.Short(thumbprint)}", Same(served, thumbprint), Iis.Short(served));
        }
    }

    private static void Repair(string site, string host, string thumbprint)
    {
        Iis.BindHttps(site, host, thumbprint);
    }

    private static bool Same(string left, string right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private static int? ReadSchema()
    {
        if (!File.Exists(AppPaths.ManagedCertificatesFile))
        {
            return null;
        }

        return JsonNode.Parse(File.ReadAllText(AppPaths.ManagedCertificatesFile))?["schemaVersion"]?.GetValue<int>();
    }

    private static List<Record> ReadRecords()
    {
        if (!File.Exists(AppPaths.ManagedCertificatesFile))
        {
            return [];
        }

        var list = new List<Record>();
        foreach (var node in JsonNode.Parse(File.ReadAllText(AppPaths.ManagedCertificatesFile))?["certificates"]?.AsArray() ?? [])
        {
            var more = (node?["additionalTargets"]?.AsArray() ?? [])
                .Select(target => (target!["siteName"]!.GetValue<string>(), target["pendingSince"]?.ToString()))
                .ToArray();
            list.Add(new Record(
                node!["id"]?.ToString() ?? "",
                node["siteName"]!.GetValue<string>(),
                node["thumbprint"]!.GetValue<string>(),
                DateTimeOffset.Parse(node["notAfter"]!.ToString(), System.Globalization.CultureInfo.InvariantCulture),
                node["sitePendingSince"]?.ToString(),
                more));
        }

        return list;
    }

    private static Record Get(string site) =>
        ReadRecords().SingleOrDefault(record => record.Lists(site))
        ?? throw new InvalidOperationException($"No managed certificate lists '{site}'.");

    /// <summary>Makes the record look close to expiry. Staging certificates last 90 days, and the rule reads this field.</summary>
    private static void SetNotAfter(string site, DateTimeOffset value)
    {
        var document = JsonNode.Parse(File.ReadAllText(AppPaths.ManagedCertificatesFile))!;
        var record = document["certificates"]!.AsArray().Single(node => node!["siteName"]!.GetValue<string>() == site)!;
        record["notAfter"] = value.ToString("o");
        File.WriteAllText(AppPaths.ManagedCertificatesFile, document.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
    }

    private static Task<(int ExitCode, string Output)> Run(string exe, params string[] arguments) => RunTuple(exe, arguments);

    private static async Task<(int ExitCode, string Output)> RunTuple(string exe, string[] arguments)
    {
        var result = await Run(exe, arguments, null);
        return (result.ExitCode, result.Output);
    }

    /// <param name="input">A line for the command to read, such as a made-up secret; only ever a value this program chose.</param>
    private static async Task<(int ExitCode, string Output, bool Killed)> Run(string exe, string[] arguments, Func<string, bool>? killWhen, string? input = null)
    {
        Report.Info($"> {Path.GetFileName(Path.GetDirectoryName(exe))}\\{Path.GetFileName(exe)} {string.Join(' ', arguments)}");
        var info = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        foreach (var argument in arguments)
        {
            info.ArgumentList.Add(argument);
        }

        using var process = Process.Start(info)!;
        if (input is not null)
        {
            process.StandardInput.WriteLine(input);
        }

        process.StandardInput.Close();
        var output = new StringBuilder();
        var killed = false;
        void Line(string? line)
        {
            if (line is null)
            {
                return;
            }

            lock (output)
            {
                output.AppendLine(line);
            }

            Report.Info($"    {line}");
            if (killWhen?.Invoke(line) == true && !killed)
            {
                killed = true;
                process.Kill();
            }
        }

        process.OutputDataReceived += (_, line) => Line(line.Data);
        process.ErrorDataReceived += (_, line) => Line(line.Data);
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(10));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill();
            throw new System.TimeoutException($"Command did not finish in 10 minutes: {string.Join(' ', arguments)}");
        }

        return (process.ExitCode, output.ToString(), killed);
    }

    /// <summary>Uses this console for input, so SSLense reads the token itself and this program never sees it. Only error text is captured.</summary>
    private static async Task<(int ExitCode, string Errors)> Interactive(params string[] arguments)
    {
        var info = new ProcessStartInfo(Cli) { UseShellExecute = false, RedirectStandardError = true };
        foreach (var argument in arguments)
        {
            info.ArgumentList.Add(argument);
        }

        using var process = Process.Start(info)!;
        var errors = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return (process.ExitCode, errors);
    }

    private static bool ServiceExists() => ServiceController.GetServices().Any(service => service.ServiceName == Service);

    private static bool StopService()
    {
        if (!ServiceExists())
        {
            return false;
        }

        using var service = new ServiceController(Service);
        var wasRunning = service.Status != ServiceControllerStatus.Stopped;
        if (wasRunning)
        {
            Report.Info("Stopping the SSLense service for the test.");
            service.Stop();
            service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromMinutes(2));
        }

        return wasRunning;
    }

    private static void TakeBackup(bool serviceWasRunning)
    {
        Directory.CreateDirectory(Backup);
        // It holds the protected secrets, so it gets the same lock as the folder it copies.
        Exec("icacls", Backup, "/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F");
        var copied = Exec("robocopy", AppPaths.DataDirectory, Path.Combine(Backup, "data"), "/E", "/COPY:DATSO", "/DCOPY:DAT", "/XD", "logs", "/R:2", "/W:2", "/NFL", "/NDL", "/NJH", "/NJS");
        if (copied >= 8)
        {
            // A partial copy must never be restored over the real data, so it is deleted here.
            Directory.Delete(Backup, recursive: true);
            if (serviceWasRunning)
            {
                using var service = new ServiceController(Service);
                service.Start();
            }

            throw new InvalidOperationException($"The backup failed (robocopy exit {copied}), so nothing was changed or tested.");
        }

        File.WriteAllText(ZoneFile, Zone);

        // Written last: restore only trusts a backup that finished.
        File.WriteAllText(CompleteFlag, serviceWasRunning ? "running" : "stopped");

        Report.Info($"Backed up {AppPaths.DataDirectory} to {Backup}");
    }

    public static async Task RestoreAsync()
    {
        Report.Heading("Putting this machine back");
        RequireAppClosed();
        if (File.Exists(ZoneFile))
        {
            Zone = File.ReadAllText(ZoneFile).Trim();
        }

        if (!string.IsNullOrWhiteSpace(Zone))
        {
            CleanupTestObjects();
        }

        if (!File.Exists(CompleteFlag))
        {
            Report.Info("No finished backup found, so the data folder was left as it is.");
            return;
        }

        // Stop anything that could be holding files, in case an earlier run was interrupted.
        StopService();
        var restored = Exec("robocopy", Path.Combine(Backup, "data"), AppPaths.DataDirectory, "/MIR", "/COPY:DATSO", "/DCOPY:DAT", "/XD", "logs", "/R:2", "/W:2", "/NFL", "/NDL", "/NJH", "/NJS");
        if (!Report.Check("Data folder restored", restored < 8, $"robocopy exit {restored}"))
        {
            Report.Info($"The backup was kept at {Backup}. Do not delete it.");
            return;
        }

        var status = await Run(InstalledCli ?? Cli, "status");
        var usable = Report.Check("SSLense reads the restored data", status.ExitCode == 0, $"exit {status.ExitCode}");
        var hadService = File.ReadAllText(CompleteFlag) == "running";
        if (hadService)
        {
            using var service = new ServiceController(Service);
            service.Start();
            service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromMinutes(2));
            Report.Check("Service running again", service.Status == ServiceControllerStatus.Running);
        }

        if (usable)
        {
            Directory.Delete(Backup, recursive: true);
            Report.Info("Backup deleted, because SSLense works with the restored data.");
        }
        else
        {
            Report.Info($"The backup was kept at {Backup}.");
        }
    }

    private static void CleanupTestObjects()
    {
        foreach (var site in new[] { A, B, C })
        {
            Iis.DeleteSite(site);
        }

        foreach (var host in new[] { HostA, HostB, HostC })
        {
            Iis.DropSysEntry(host);
        }

        Iis.Netsh("http", "delete", "sslcert", "hostnameport=sslense-certificate-trial.invalid:443");
        Iis.RemoveCertificates(certificate => certificate.Subject.Contains(Domain, StringComparison.OrdinalIgnoreCase));
        Iis.RemoveTestFolder();
    }

    private static int Exec(string file, params string[] arguments)
    {
        var info = new ProcessStartInfo(file) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var argument in arguments)
        {
            info.ArgumentList.Add(argument);
        }

        using var process = Process.Start(info)!;
        var errors = process.StandardError.ReadToEndAsync();
        process.StandardOutput.ReadToEnd();
        errors.GetAwaiter().GetResult();
        process.WaitForExit();
        return process.ExitCode;
    }
}
