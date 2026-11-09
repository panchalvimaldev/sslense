using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Principal;
using DnsClient;
using SSLense.Core.Config;

namespace SSLense.Acceptance;

/// <summary>
/// DNS validation through a script (docs/design/dns-script.md, section 7), with the Cloudflare example script and Let's
/// Encrypt STAGING, then scripts that are broken on purpose.
/// </summary>
internal static partial class PartB
{
    private const string ScriptProvider = "accept-script";
    private const string SystemTask = "SSLenseAcceptRenewAsSystem";

    /// <summary>Given to the broken test scripts only. It is made up, so it can appear in this program and its results.</summary>
    private const string FakeSecret = "acceptance-fake-secret-7Hq2Lw9Zp4";

    private static string Scripts => Path.Combine(Iis.Root, "scripts");

    public static async Task ScriptCheckAsync()
    {
        RequireReady();
        var example = Path.Combine(AppContext.BaseDirectory, "dns-scripts", "Cloudflare.ps1");
        if (!File.Exists(example))
        {
            throw new InvalidOperationException($"The example script was not found at {example}.");
        }

        Console.Write("Email for the Let's Encrypt staging account: ");
        _email = Console.ReadLine()?.Trim() ?? "";
        Report.Scrub = _email;
        Report.Info($"Build: {(await Run(Cli, "--version")).Output.Trim()}");
        TakeBackup(StopService());
        try
        {
            CleanupTestObjects();
            Directory.CreateDirectory(Scripts);
            var original = Path.Combine(Scripts, "Cloudflare.ps1");
            File.Copy(example, original, overwrite: true);

            await Report.Scenario("X1 Add the Cloudflare example as a script provider", () => AddScriptProviderAsync(original));
            var ready = CopiesOf(ScriptProvider).Any();
            if (ready)
            {
                await Report.Scenario("X2 Issue a wildcard through the script", IssueThroughScriptAsync);
                await Report.Scenario("X3 Renew as SYSTEM, as the service does", RenewAsSystemAsync);
                await Report.Scenario("X4 A copy changed in place is refused until update-script", () => ChangedCopyAsync(original));
            }

            // These need no real secret, so they run either way.
            await Report.Scenario("X5 Scripts that fail, hang, lie, or print their secret", BrokenScriptsAsync);
            if (!ready)
            {
                Report.Check("X2, X3, X4, X6, and X7 were not run, because the script provider was not added", false);
                return;
            }

            await Report.Scenario("X6 The process is killed after the script added a record", KillAfterAddAsync);
            await Report.Scenario("X7 Clean up", async () =>
            {
                var removed = await Run(Cli, "remove", "--site", A, "--yes");
                Report.Check("Certificate removed", removed.ExitCode == 0, $"exit {removed.ExitCode}");
                var provider = await Run(Cli, "dns", "remove", "--name", ScriptProvider);
                Report.Check("Script provider removed", provider.ExitCode == 0, provider.Output.Trim());
                Report.Check("Its copy was deleted", !CopiesOf(ScriptProvider).Any());
            });
        }
        finally
        {
            Exec("schtasks", "/delete", "/tn", SystemTask, "/f");
            await Report.Scenario("Final checks and cleanup", CleanupAfterRunAsync);
            await RestoreAsync();
        }
    }

    private static async Task AddScriptProviderAsync(string original)
    {
        // Run by hand in a window of its own: a hidden prompt in a command this program starts received nothing, three times,
        // although the same command typed directly worked. The secret then never passes through this program either.
        var command = $"& '{Cli}' dns add --provider script --name {ScriptProvider} --zone {Domain} --script {original} --secret";
        for (var attempt = 1; attempt <= 3 && !CopiesOf(ScriptProvider).Any(); attempt++)
        {
            Console.WriteLine();
            Console.WriteLine("Open a SECOND Administrator PowerShell window and run this command:");
            Console.WriteLine();
            Console.WriteLine($"  {command}");
            Console.WriteLine();
            Console.WriteLine($"At 'Secret for the script:', paste the Cloudflare zone ID for {Zone}, a colon, then the API token, as one value.");
            Console.Write($"When it says the provider was added, come back here and press Enter (attempt {attempt} of 3): ");
            Console.ReadLine();
        }

        var exitCode = CopiesOf(ScriptProvider).Any() ? 0 : 1;
        var errors = exitCode == 0 ? "" : "The provider was not added in the second window.";
        if (!Report.Check("Script provider added", exitCode == 0, errors))
        {
            throw new InvalidOperationException("The script provider was not added, so the other checks were not run.");
        }

        var copy = CopiesOf(ScriptProvider).Single();
        var sha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(original)));
        var list = await Run(Cli, "dns", "list");
        Report.Check("dns list shows the original's hash", list.Output.Contains(sha256, StringComparison.OrdinalIgnoreCase));
        Report.Check("The copy is in SSLense's folder", Path.GetDirectoryName(copy) == AppPaths.DnsScriptDirectory, copy);
        var problems = DataDirectorySecurity.VerifyFile(copy);
        Report.Check("Only Administrators and SYSTEM can change the copy", problems.Count == 0, string.Join(" ", problems));
        var owner = new FileInfo(copy).GetAccessControl().GetOwner(typeof(SecurityIdentifier));
        Report.Check("The copy is owned by Administrators", owner?.Value == "S-1-5-32-544", owner?.Value ?? "");

        var test = await Run(Cli, "dns", "test", "--name", ScriptProvider);
        if (!Report.Check("dns test waits for the name servers, then removes the record", test.ExitCode == 0 && test.Output.Contains("every authoritative name server", StringComparison.Ordinal), test.Output.Trim()))
        {
            throw new InvalidOperationException("The script could not change the zone, so the other checks were not run.");
        }
    }

    private static async Task IssueThroughScriptAsync()
    {
        Iis.EnsureSite(A, HostA);
        var issued = await IssueWithRetry("--site", A, "--email", _email, "--validation", "dns", "--staging", "--names", $"*.{Domain}", "--hosts", HostA);
        Report.Check("Issued", issued.ExitCode == 0, $"exit {issued.ExitCode}");
        // Staging reuses a validation from an earlier run for 30 days, and then nothing is published. X6 always publishes.
        Report.Check(
            "Published through the script, or reused an earlier validation",
            issued.Output.Contains($"with {ScriptProvider}", StringComparison.Ordinal) || !issued.Output.Contains("[dns-publish]", StringComparison.Ordinal));
        await RequireServing(Get(A).Thumbprint, HostA);
    }

    /// <summary>
    /// A scheduled task runs the renewal as SYSTEM, as the service would, because the service only renews when a certificate is
    /// due. The batch file and its output are kept in the backup folder, which only Administrators and SYSTEM can change.
    /// </summary>
    private static async Task RenewAsSystemAsync()
    {
        var before = Get(A).Thumbprint;
        var batch = Path.Combine(Backup, "renew-as-system.cmd");
        var output = Path.Combine(Backup, "renew-as-system.txt");
        File.WriteAllText(batch, $"@\"{Cli}\" renew --site {A} --force > \"{output}\" 2>&1\r\n@echo exit %ERRORLEVEL% >> \"{output}\"\r\n");
        File.Delete(output);
        await Task.Delay(OrderSpacing);
        // The backup folder's path has no spaces, so the task's command needs no quotes of its own.
        Exec("schtasks", "/create", "/tn", SystemTask, "/ru", "SYSTEM", "/sc", "once", "/st", "23:59", "/tr", batch, "/f");
        var started = Exec("schtasks", "/run", "/tn", SystemTask);
        Report.Check("Started as SYSTEM", started == 0, $"schtasks exit {started}");

        // The task still has the file open while it runs, so it is read with sharing, until the batch file's last line appears.
        var deadline = DateTimeOffset.UtcNow.AddMinutes(10);
        while (DateTimeOffset.UtcNow < deadline && !(File.Exists(output) && ReadFrom(output, 0).Contains("exit ", StringComparison.Ordinal)))
        {
            await Task.Delay(TimeSpan.FromSeconds(5));
        }

        await Task.Delay(TimeSpan.FromSeconds(2));
        var text = File.Exists(output) ? ReadFrom(output, 0) : "";
        foreach (var line in text.Split('\n'))
        {
            Report.Info($"    {line.TrimEnd()}");
        }

        Report.Check("Renewed as SYSTEM through the script", text.Contains("exit 0", StringComparison.Ordinal) && text.Contains("SUCCESS", StringComparison.Ordinal));
        var after = Get(A).Thumbprint;
        Report.Check("New certificate", !Same(before, after), $"{Iis.Short(before)} -> {Iis.Short(after)}");
        await RequireServing(after, HostA);
    }

    private static async Task ChangedCopyAsync(string original)
    {
        var copy = CopiesOf(ScriptProvider).Single();
        File.AppendAllText(copy, "\r\n# changed after SSLense saved it\r\n");

        var test = await Run(Cli, "dns", "test", "--name", ScriptProvider);
        Report.Check("dns test refuses it", test.ExitCode != 0 && test.Output.Contains("was changed", StringComparison.Ordinal), test.Output.Trim());
        var renew = await Run(Cli, "renew", "--site", A, "--force");
        Report.Check("A renewal refuses it before ordering", renew.ExitCode != 0 && renew.Output.Contains("will not run the script", StringComparison.Ordinal) && !renew.Output.Contains("[certificate]", StringComparison.Ordinal));

        var update = await Run(Cli, "dns", "update-script", "--name", ScriptProvider, "--script", original);
        Report.Check("update-script takes a new copy", update.ExitCode == 0, update.Output.Trim());
        var again = await Run(Cli, "dns", "test", "--name", ScriptProvider);
        Report.Check("dns test works again", again.ExitCode == 0, again.Output.Trim());
    }

    private static async Task BrokenScriptsAsync()
    {
        var log = TodaysLog();
        var logLengthBefore = File.Exists(log) ? new FileInfo(log).Length : 0;

        var fail = await AddTestScriptAsync("fail", "if ($Action -eq 'Add') { Write-Output 'The API refused the key'; exit 1 }");
        var failed = await Run(Cli, "dns", "test", "--name", fail);
        Report.Check("A failing script is reported with its exit code and output", failed.ExitCode != 0 && failed.Output.Contains("exit code 1", StringComparison.Ordinal) && failed.Output.Contains("The API refused the key", StringComparison.Ordinal));

        var hang = await AddTestScriptAsync("hang", "if ($Action -eq 'Add') { Start-Sleep -Seconds 600 }", "--timeout", "10");
        var stopwatch = Stopwatch.StartNew();
        var hung = await Run(Cli, "dns", "test", "--name", hang);
        Report.Check("A hanging script is stopped after its timeout", hung.ExitCode != 0 && hung.Output.Contains("within 10 seconds", StringComparison.Ordinal) && stopwatch.Elapsed < TimeSpan.FromMinutes(1), $"{stopwatch.Elapsed.TotalSeconds:0} s");

        Report.Info("The next check waits up to 5 minutes for a record that never appears.");
        var liar = await AddTestScriptAsync("liar", "");
        var lied = await Run(Cli, "dns", "test", "--name", liar);
        Report.Check("A script that only says it added the record is caught by the name servers", lied.ExitCode != 0 && lied.Output.Contains("did not appear", StringComparison.Ordinal));

        var tell = await AddTestScriptAsync("tell", "Write-Output \"debug: the secret is $env:SSLENSE_DNS_SECRET\"; exit 1", expectAdded: false);
        Report.Check("A script that prints its secret is refused, and the secret is not shown", !tell.Output.Contains(FakeSecret, StringComparison.Ordinal) && tell.Output.Contains("[REDACTED]", StringComparison.Ordinal));
        Report.Check("Nothing was saved for it", !(await Run(Cli, "dns", "list")).Output.Contains("accept-tell", StringComparison.Ordinal));

        foreach (var name in new[] { fail, hang, liar })
        {
            await Run(Cli, "dns", "remove", "--name", name);
        }

        var logged = File.Exists(log) ? ReadFrom(log, logLengthBefore) : "";
        Report.Check("The secret is not in the log", !logged.Contains(FakeSecret, StringComparison.Ordinal));
    }

    private static async Task KillAfterAddAsync()
    {
        Iis.EnsureSite(B, HostB);
        var record = $"_acme-challenge.{HostB}";
        await Task.Delay(OrderSpacing);
        var result = await Run(
            Cli,
            ["issue", "--site", B, "--email", _email, "--validation", "dns", "--staging", "--hosts", HostB],
            line => line.Contains("[dns-propagation]", StringComparison.Ordinal));
        // Without a kill there is nothing to clean up, so the checks after it would pass on nothing.
        if (!Report.Check("Killed after the script added the record", result.Killed, $"exit {result.ExitCode}") ||
            !Report.Check("The record is in the zone", await WaitForTxtAsync(record, present: true)))
        {
            return;
        }

        // Any command start runs recovery, which removes what the killed process left through the script.
        await Run(Cli, "status");
        Report.Check("The next start removed it through the script", await WaitForTxtAsync(record, present: false));
        var waiting = Directory.Exists(AppPaths.DnsChallengeJournalDirectory) ? Directory.GetFiles(AppPaths.DnsChallengeJournalDirectory).Length : 0;
        Report.Check("Nothing is left to clean", waiting == 0, $"{waiting} waiting");
    }

    /// <summary>A provider for a zone of its own under the test domain, running a script that is broken on purpose.</summary>
    private static async Task<string> AddTestScriptAsync(string kind, string body, params string[] options) =>
        (await AddTestScriptAsync(kind, body, expectAdded: true, options)).Name;

    private static async Task<(string Name, string Output)> AddTestScriptAsync(string kind, string body, bool expectAdded, params string[] options)
    {
        var path = Path.Combine(Scripts, $"{kind}.ps1");
        File.WriteAllText(path, $"param([string]$Action, [string]$Zone, [string]$RecordName, [string]$Value)\r\n{body}\r\nexit 0\r\n");
        var name = $"accept-{kind}";
        var added = await Run(
            Cli,
            ["dns", "add", "--provider", "script", "--name", name, "--zone", $"{kind}.{Domain}", "--script", path, "--secret", .. options],
            null,
            FakeSecret);
        if (expectAdded)
        {
            Report.Check($"Added '{name}'", added.ExitCode == 0, added.Output.Trim());
        }

        return (name, added.Output);
    }

    private static IEnumerable<string> CopiesOf(string provider) =>
        Directory.Exists(AppPaths.DnsScriptDirectory)
            ? Directory.GetFiles(AppPaths.DnsScriptDirectory, $"{provider}-*.ps1")
            : [];

    private static string TodaysLog() => Path.Combine(AppPaths.LogDirectory, $"sslense-{DateTime.Now:yyyyMMdd}.log");

    private static string ReadFrom(string path, long offset)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        stream.Seek(Math.Min(offset, stream.Length), SeekOrigin.Begin);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    /// <summary>The zone's name servers can take a few seconds to show a change.</summary>
    private static async Task<bool> WaitForTxtAsync(string name, bool present)
    {
        var deadline = DateTimeOffset.UtcNow.AddMinutes(2);
        while (true)
        {
            if ((await TxtValuesAsync(name)).Count > 0 == present)
            {
                return true;
            }

            if (DateTimeOffset.UtcNow > deadline)
            {
                return false;
            }

            await Task.Delay(TimeSpan.FromSeconds(5));
        }
    }

    /// <summary>Asks the zone's own name servers, so nothing cached can hide a record.</summary>
    private static async Task<IReadOnlyList<string>> TxtValuesAsync(string name)
    {
        var nameServers = await new LookupClient().QueryAsync(Zone, QueryType.NS);
        var servers = await Dns.GetHostAddressesAsync(nameServers.Answers.NsRecords().First().NSDName.Value);
        var client = new LookupClient(new LookupClientOptions(servers.Select(address => new IPEndPoint(address, 53)).ToArray()) { UseCache = false, Recursion = false });
        var answer = await client.QueryAsync(name, QueryType.TXT);
        return answer.Answers.TxtRecords().SelectMany(record => record.Text).ToArray();
    }
}
