using System.Text;
using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.DnsValidation;
using Xunit;

namespace SSLense.Tests.DnsValidation;

/// <summary>DNS validation through the administrator's script (docs/design/dns-script.md).</summary>
public sealed class DnsScriptTests : IDisposable
{
    private const string Secret = "key:topsecret-value";
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"sslense-scripts-{Guid.NewGuid():N}");
    private readonly DnsScriptStore _store;
    private readonly FakeRunner _runner = new();
    private readonly FakeConfigStore _config = new();
    private readonly FakeDnsLookup _lookup = new();
    private readonly XorProtector _protector = new();

    public DnsScriptTests()
    {
        Directory.CreateDirectory(_root);
        _store = new DnsScriptStore(Copies, secure: false);
    }

    private string Copies => Path.Combine(_root, "copies");

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private string Original(string content = "exit 0", string fileName = "dns.ps1")
    {
        var path = Path.Combine(_root, fileName);
        File.WriteAllText(path, content);
        return path;
    }

    // ---- SSLense's own copy ----

    [Fact]
    public async Task Store_RunsOnlyItsCopy_SoLaterChangesToTheOriginalDoNotReachTheService()
    {
        var original = Original("'version 1'");
        var sha256 = await _store.SaveAsync("Registrar", original, CancellationToken.None);

        File.WriteAllText(original, "'version 2'");
        var path = _store.GetVerifiedPath("Registrar", sha256);

        Assert.StartsWith(Copies, path, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("'version 1'", File.ReadAllText(path));
    }

    [Fact]
    public async Task Store_ACopyChangedInPlace_IsRefused_AndSaysHowToFixIt()
    {
        var sha256 = await _store.SaveAsync("Registrar", Original(), CancellationToken.None);
        File.AppendAllText(_store.GetVerifiedPath("Registrar", sha256), "\nStart-Process calc");

        var message = Assert.Throws<InvalidOperationException>(() => _store.GetVerifiedPath("Registrar", sha256)).Message;

        Assert.Contains("was changed", message, StringComparison.Ordinal);
        Assert.Contains("dns update-script --name \"Registrar\"", message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Store_AMissingCopy_IsRefused()
    {
        var sha256 = await _store.SaveAsync("Registrar", Original(), CancellationToken.None);
        File.Delete(_store.GetVerifiedPath("Registrar", sha256));

        Assert.Contains("missing", Assert.Throws<InvalidOperationException>(() => _store.GetVerifiedPath("Registrar", sha256)).Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Store_OnlyAcceptsAnExistingPowerShellScript()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => _store.SaveAsync("Registrar", Original(fileName: "dns.txt"), CancellationToken.None));
        await Assert.ThrowsAsync<FileNotFoundException>(() => _store.SaveAsync("Registrar", Path.Combine(_root, "none.ps1"), CancellationToken.None));
    }

    [Theory]
    [InlineData("")]
    [InlineData("../evil")]
    [InlineData("a/b")]
    [InlineData("a\\b")]
    [InlineData("CON")]
    [InlineData("com1.x")]
    [InlineData(" padded")]
    [InlineData("-dash")]
    [InlineData("ends.")]
    public void Store_ProviderNamesThatCannotBeAFileName_AreRefused(string name) =>
        Assert.Throws<ArgumentException>(() => DnsScriptStore.ValidateName(name));

    [Theory]
    [InlineData("Registrar")]
    [InlineData("My DNS-1")]
    [InlineData("a")]
    public void Store_OrdinaryProviderNames_AreAccepted(string name) => DnsScriptStore.ValidateName(name);

    // ---- The script runner, with real Windows PowerShell ----

    [Fact]
    public async Task Runner_PassesArgumentsAsAList_AndTheSecretOnlyInTheEnvironment()
    {
        var script = Original("""
            param([string]$Action, [string]$Zone, [string]$RecordName, [string]$Value)
            "Action=[$Action] Value=[$Value] Secret=[$env:SSLENSE_DNS_SECRET] Extra=[$($args.Count)]"
            exit 7
            """);

        var result = await new PowerShellScriptRunner().RunAsync(
            script, ["-Action:Add", "-Zone:example.com", "-RecordName:_acme-challenge.example.com", "-Value:-abc_DEF"], Secret, TimeSpan.FromSeconds(60), CancellationToken.None);

        Assert.Equal(7, result.ExitCode);
        Assert.False(result.TimedOut);
        Assert.Contains($"Action=[Add] Value=[-abc_DEF] Secret=[{Secret}] Extra=[0]", result.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Runner_StopsAScriptThatRunsTooLong()
    {
        var script = Original("Start-Sleep -Seconds 120");

        var result = await new PowerShellScriptRunner().RunAsync(script, [], null, TimeSpan.FromSeconds(3), CancellationToken.None);

        Assert.True(result.TimedOut);
        Assert.True(result.Duration < TimeSpan.FromSeconds(60), $"Took {result.Duration}.");
    }

    /// <summary>A script that starts a program sharing its output, prints the program's ID, then does the rest.</summary>
    private string ScriptLeavingAChild(string rest) => Original($$"""
        $start = New-Object System.Diagnostics.ProcessStartInfo 'ping.exe', '-n 120 127.0.0.1'
        $start.UseShellExecute = $false
        $child = [System.Diagnostics.Process]::Start($start)
        "child=$($child.Id)"
        {{rest}}
        """);

    private static void AssertStopped(string output)
    {
        var id = int.Parse(System.Text.RegularExpressions.Regex.Match(output, @"child=(\d+)").Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
        try
        {
            using var child = System.Diagnostics.Process.GetProcessById(id);
            Assert.True(child.WaitForExit(5000), $"The program the script started ({id}) is still running.");
        }
        catch (ArgumentException)
        {
            // Already gone.
        }
    }

    [Fact]
    public async Task Runner_AScriptThatExitsLeavingAProgramHoldingItsOutput_StillReturnsAtOnce()
    {
        var result = await new PowerShellScriptRunner().RunAsync(ScriptLeavingAChild("exit 0"), [], null, TimeSpan.FromSeconds(60), CancellationToken.None);

        Assert.False(result.TimedOut);
        Assert.Equal(0, result.ExitCode);
        Assert.True(result.Duration < TimeSpan.FromSeconds(30), $"Took {result.Duration}.");
        AssertStopped(result.Output);
    }

    [Fact]
    public async Task Runner_Timeout_StopsTheProgramsTheScriptStarted()
    {
        var result = await new PowerShellScriptRunner().RunAsync(ScriptLeavingAChild("Start-Sleep -Seconds 120"), [], null, TimeSpan.FromSeconds(5), CancellationToken.None);

        Assert.True(result.TimedOut);
        Assert.True(result.Duration < TimeSpan.FromSeconds(40), $"Took {result.Duration}.");
        AssertStopped(result.Output);
    }

    [Fact]
    public async Task Runner_Cancellation_StopsTheScript()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new PowerShellScriptRunner().RunAsync(
            ScriptLeavingAChild("Start-Sleep -Seconds 120"), [], null, TimeSpan.FromSeconds(120), cancellation.Token));

        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(40), $"Took {stopwatch.Elapsed}.");
    }

    [Fact]
    public async Task Runner_KeepsOnlyTheFirstPartOfAHugeOutput()
    {
        var script = Original("'x' * 200000");

        var result = await new PowerShellScriptRunner().RunAsync(script, [], null, TimeSpan.FromSeconds(60), CancellationToken.None);

        Assert.InRange(result.Output.Length, 1, PowerShellScriptRunner.MaxOutputChars + Environment.NewLine.Length);
    }

    // ---- The example scripts that ship with SSLense ----

    private static string Example(string fileName) => Path.Combine(AppContext.BaseDirectory, "dns-scripts", fileName);

    private static string[] Arguments(string action) =>
        [$"-Action:{action}", "-Zone:example.com", "-RecordName:_acme-challenge.example.com", .. action == "Check" ? Array.Empty<string>() : ["-Value:-abc"]];

    [Fact]
    public async Task Template_ChecksSuccessfully_AndSaysAddAndRemoveAreNotWrittenYet()
    {
        var runner = new PowerShellScriptRunner();

        var check = await runner.RunAsync(Example("Template.ps1"), Arguments("Check"), null, TimeSpan.FromSeconds(60), CancellationToken.None);
        var add = await runner.RunAsync(Example("Template.ps1"), Arguments("Add"), null, TimeSpan.FromSeconds(60), CancellationToken.None);

        Assert.Equal(0, check.ExitCode);
        Assert.Equal(1, add.ExitCode);
        Assert.Contains("Add is not written yet", add.Output, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("no-colon-here")]
    [InlineData("short:token")]
    public async Task CloudflareExample_WithoutAProperSecret_FailsClearly_BeforeContactingCloudflare(string? secret)
    {
        var result = await new PowerShellScriptRunner().RunAsync(
            Example("Cloudflare.ps1"), Arguments("Check"), secret, TimeSpan.FromSeconds(60), CancellationToken.None);

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("The secret must be \"<zone ID>:<API token>\"", result.Output, StringComparison.Ordinal);
    }

    // ---- The provider ----

    [Fact]
    public async Task Provider_Add_RunsTheVerifiedCopy_WithColonArguments_AndTheSecret()
    {
        var profile = await ProfileAsync();

        await Provider().AddTxtRecordAsync(profile, "_acme-challenge.Example.com", "-val_ue", CancellationToken.None);

        var call = Assert.Single(_runner.Calls);
        Assert.Equal(_store.GetVerifiedPath("Registrar", profile.ScriptSha256!), call.Path);
        Assert.Equal(["-Action:Add", "-Zone:example.com", "-RecordName:_acme-challenge.example.com", "-Value:-val_ue"], call.Arguments);
        Assert.Equal(Secret, call.Secret);
    }

    [Fact]
    public async Task Provider_Check_PassesNoValue()
    {
        await Provider().VerifyAccessAsync(await ProfileAsync(), CancellationToken.None);

        Assert.Equal(["-Action:Check", "-Zone:example.com", "-RecordName:_acme-challenge.example.com"], Assert.Single(_runner.Calls).Arguments);
    }

    [Fact]
    public async Task Provider_Failure_ShowsTheLastLines_WithoutTheSecret()
    {
        var profile = await ProfileAsync();
        _runner.Next = new ScriptRunResult(2, "starting\nusing key:topsecret-value\ntopsecret-value alone\nAPI said 403\n", false, TimeSpan.Zero);

        var message = (await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Provider().AddTxtRecordAsync(profile, "_acme-challenge.example.com", "value", CancellationToken.None))).Message;

        Assert.Contains("exit code 2", message, StringComparison.Ordinal);
        Assert.Contains("API said 403", message, StringComparison.Ordinal);
        Assert.DoesNotContain("topsecret", message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Provider_Timeout_SaysTheScriptWasStopped()
    {
        var profile = await ProfileAsync() with { ScriptTimeoutSeconds = 30 };
        _runner.Next = new ScriptRunResult(-1, "", true, TimeSpan.FromSeconds(30));

        var exception = await Assert.ThrowsAsync<System.TimeoutException>(() =>
            Provider().RemoveTxtRecordAsync(profile, "_acme-challenge.example.com", "value", CancellationToken.None));

        Assert.Contains("within 30 seconds", exception.Message, StringComparison.Ordinal);
        Assert.Equal(TimeSpan.FromSeconds(30), _runner.Calls.Single().Timeout);
    }

    [Theory]
    [InlineData("a b")]
    [InlineData("x;y")]
    [InlineData("$(evil)")]
    [InlineData("'quoted'")]
    public async Task Provider_UnexpectedValues_NeverReachTheScript(string value)
    {
        var profile = await ProfileAsync();

        await Assert.ThrowsAsync<ArgumentException>(() =>
            Provider().AddTxtRecordAsync(profile, "_acme-challenge.example.com", value, CancellationToken.None));

        Assert.Empty(_runner.Calls);
    }

    [Fact]
    public async Task Provider_AChangedCopy_IsNeverRun()
    {
        var profile = await ProfileAsync();
        File.AppendAllText(_store.GetVerifiedPath("Registrar", profile.ScriptSha256!), "\n'changed'");

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Provider().AddTxtRecordAsync(profile, "_acme-challenge.example.com", "value", CancellationToken.None));

        Assert.Empty(_runner.Calls);
    }

    [Fact]
    public async Task Provider_EndToEnd_RunsARealScriptThatAddsAndRemoves()
    {
        var log = Path.Combine(_root, "calls.txt");
        var sha256 = await _store.SaveAsync("Registrar", Original($$"""
            param([string]$Action, [string]$Zone, [string]$RecordName, [string]$Value)
            Add-Content -LiteralPath '{{log}}' -Value "$Action $Zone $RecordName $Value $env:SSLENSE_DNS_SECRET"
            """), CancellationToken.None);
        var profile = new DnsProviderProfile("Registrar", DnsProviderType.Script, "example.com", null, Protect(Secret), sha256);
        var provider = new ScriptDnsProvider(_store, new PowerShellScriptRunner(), _protector);

        await provider.AddTxtRecordAsync(profile, "_acme-challenge.example.com", "-v1", CancellationToken.None);
        await provider.RemoveTxtRecordAsync(profile, "_acme-challenge.example.com", "-v1", CancellationToken.None);

        Assert.Equal(
            [$"Add example.com _acme-challenge.example.com -v1 {Secret}", $"Remove example.com _acme-challenge.example.com -v1 {Secret}"],
            File.ReadAllLines(log));
    }

    // ---- Adding, testing, updating, and removing a script provider ----

    [Fact]
    public async Task Add_CopiesTheScript_RunsCheck_AndSaves()
    {
        await Service().AddAsync(ScriptRequest(Original(), Secret));

        var saved = Assert.Single(_config.Config.DnsProviders);
        Assert.Equal(DnsProviderType.Script, saved.Provider);
        Assert.Null(saved.ZoneId);
        Assert.NotNull(saved.ScriptSha256);
        Assert.Empty(_store.Inspect("Registrar", saved.ScriptSha256!));
        Assert.DoesNotContain("topsecret", saved.ProtectedToken, StringComparison.Ordinal);
        Assert.Equal("-Action:Check", Assert.Single(_runner.Calls).Arguments[0]);
    }

    [Fact]
    public async Task Add_WithoutASecret_SavesNoSecret_AndPassesNone()
    {
        await Service().AddAsync(ScriptRequest(Original(), ""));

        Assert.Equal(string.Empty, Assert.Single(_config.Config.DnsProviders).ProtectedToken);
        Assert.Null(Assert.Single(_runner.Calls).Secret);
    }

    [Fact]
    public async Task Add_CheckFails_RemovesTheCopy_AndSavesNothing()
    {
        _runner.Next = new ScriptRunResult(1, "no access", false, TimeSpan.Zero);

        await Assert.ThrowsAsync<InvalidOperationException>(() => Service().AddAsync(ScriptRequest(Original(), "")));

        Assert.Empty(_config.Config.DnsProviders);
        Assert.Empty(Directory.GetFiles(Copies));
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("dns.ps1", 5)]
    [InlineData("dns.ps1", 7200)]
    public async Task Add_MissingScriptOrBadTimeout_IsRefusedBeforeRunningAnything(string? script, int? timeout)
    {
        await Assert.ThrowsAsync<ArgumentException>(() => Service().AddAsync(new DnsProviderRequest(
            "Registrar", DnsProviderType.Script, "example.com", null, "", script is null ? null : Original(fileName: script), timeout)));

        Assert.Empty(_runner.Calls);
    }

    [Fact]
    public async Task UpdateScript_ABrokenNewScript_KeepsTheOldCopyInUse()
    {
        await Service().AddAsync(ScriptRequest(Original("'old'"), ""));
        var before = _config.Config.DnsProviders.Single().ScriptSha256!;
        _runner.Next = new ScriptRunResult(1, "broken", false, TimeSpan.Zero);

        await Assert.ThrowsAsync<InvalidOperationException>(() => Service().UpdateScriptAsync("Registrar", Original("'new'", "new.ps1")));

        Assert.Equal(before, _config.Config.DnsProviders.Single().ScriptSha256);
        Assert.Equal("'old'", File.ReadAllText(_store.GetVerifiedPath("Registrar", before)));
        Assert.Single(Directory.GetFiles(Copies));
    }

    [Fact]
    public async Task UpdateScript_AWorkingNewScript_ReplacesTheCopy()
    {
        await Service().AddAsync(ScriptRequest(Original("'old'"), ""));
        var before = _config.Config.DnsProviders.Single().ScriptSha256!;

        var after = await Service().UpdateScriptAsync("Registrar", Original("'new'", "new.ps1"));

        Assert.NotEqual(before, after);
        Assert.Equal(after, _config.Config.DnsProviders.Single().ScriptSha256);
        Assert.Equal("'new'", File.ReadAllText(_store.GetVerifiedPath("Registrar", after)));
        Assert.Single(Directory.GetFiles(Copies));
    }

    private void ChangeSavedProvider(Func<DnsProviderProfile, DnsProviderProfile> change) =>
        _config.SaveAsync(_config.Config with { DnsProviders = [change(_config.Config.DnsProviders.Single())] }).GetAwaiter().GetResult();

    [Fact]
    public async Task UpdateScript_KeepsASecretReplacedWhileTheNewScriptWasChecked()
    {
        await Service().AddAsync(ScriptRequest(Original("'old'"), "old-secret"));
        var newSecret = Protect("new-secret");
        _runner.During = () => ChangeSavedProvider(profile => profile with { ProtectedToken = newSecret });

        var sha256 = await Service().UpdateScriptAsync("Registrar", Original("'new'", "new.ps1"));

        var saved = _config.Config.DnsProviders.Single();
        Assert.Equal(sha256, saved.ScriptSha256);
        Assert.Equal(newSecret, saved.ProtectedToken);
    }

    [Fact]
    public async Task UpdateToken_KeepsAScriptUpdatedWhileTheTokenWasChecked()
    {
        await Service().AddAsync(ScriptRequest(Original("'old'"), "old-secret"));
        var newer = await _store.SaveAsync("Registrar", Original("'newer'", "newer.ps1"), CancellationToken.None);
        _runner.During = () => ChangeSavedProvider(profile => profile with { ScriptSha256 = newer });

        await Service().UpdateTokenAsync("Registrar", "new-secret");

        var saved = _config.Config.DnsProviders.Single();
        Assert.Equal(newer, saved.ScriptSha256);
        Assert.Equal(Protect("new-secret"), saved.ProtectedToken);
    }

    [Fact]
    public async Task UpdateScript_AnotherUpdateFinishedMeanwhile_KeepsThatOne_AndChangesNothing()
    {
        await Service().AddAsync(ScriptRequest(Original("'old'"), ""));
        var other = await _store.SaveAsync("Registrar", Original("'other'", "other.ps1"), CancellationToken.None);
        _runner.During = () => ChangeSavedProvider(profile => profile with { ScriptSha256 = other });

        var message = (await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Service().UpdateScriptAsync("Registrar", Original("'mine'", "mine.ps1")))).Message;

        Assert.Contains("replaced by another update", message, StringComparison.Ordinal);
        Assert.Equal(other, _config.Config.DnsProviders.Single().ScriptSha256);
        Assert.Empty(_store.Inspect("Registrar", other));
    }

    [Fact]
    public async Task Config_UpdateAppliesTheChangeToTheFileAsItIsNow()
    {
        var files = new InMemoryFileSystem();
        var store = new JsonConfigStore(files, @"C:\data\config.json");
        await store.SaveAsync(new AppConfig { DefaultEmail = "first@example.com" });

        await store.UpdateAsync(config => config with { DnsProviders = [new DnsProviderProfile("Registrar", DnsProviderType.Script, "example.com", null, "", "AABB")] });

        var loaded = await store.LoadAsync();
        Assert.Equal("first@example.com", loaded.DefaultEmail);
        Assert.Equal("Registrar", Assert.Single(loaded.DnsProviders).Name);
    }

    [Fact]
    public async Task Test_WaitsUntilTheNameServersHaveTheRecord_ThenRemovesIt()
    {
        await Service().AddAsync(ScriptRequest(Original(), ""));
        _lookup.Answer = (_, name) => _runner.Published.TryGetValue(name, out var value) ? [value] : [];

        var message = await Service().TestAsync("Registrar");

        Assert.Contains("every authoritative name server returned it", message, StringComparison.Ordinal);
        Assert.Equal(["Check", "Check", "Add", "Remove"], _runner.Calls.Select(call => call.Arguments[0]["-Action:".Length..]));
    }

    [Fact]
    public async Task Test_DnsCannotBeQueried_FailsInsteadOfClaimingTheNameServersHadIt_AndRemovesTheRecord()
    {
        await Service().AddAsync(ScriptRequest(Original(), ""));
        _lookup.Unavailable = true;

        var message = (await Assert.ThrowsAsync<InvalidOperationException>(() => Service().TestAsync("Registrar"))).Message;

        Assert.Contains("could not check that the record exists", message, StringComparison.Ordinal);
        Assert.DoesNotContain("every authoritative name server returned it", message, StringComparison.Ordinal);
        Assert.Equal("-Action:Remove", _runner.Calls[^1].Arguments[0]);
    }

    [Fact]
    public async Task Test_ARecordThatNeverAppears_FailsTheTest_ButIsStillRemoved()
    {
        await Service().AddAsync(ScriptRequest(Original(), ""));

        await Assert.ThrowsAnyAsync<Exception>(() => Service().TestAsync("Registrar"));

        Assert.Equal("-Action:Remove", _runner.Calls[^1].Arguments[0]);
    }

    [Fact]
    public async Task Remove_DeletesTheCopy()
    {
        var managed = new Mock<IManagedCertificateStore>();
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync([]);
        await Service(managed.Object).AddAsync(ScriptRequest(Original(), ""));

        await Service(managed.Object).RemoveAsync("Registrar");

        Assert.Empty(_config.Config.DnsProviders);
        Assert.Empty(Directory.GetFiles(Copies));
    }

    [Fact]
    public async Task Config_KeepsAScriptProvider_AndMovesToSchema7()
    {
        var files = new InMemoryFileSystem();
        var store = new JsonConfigStore(files, @"C:\data\config.json");
        var profile = new DnsProviderProfile("Registrar", DnsProviderType.Script, "example.com", null, "", "AABB", 90);

        await store.SaveAsync(new AppConfig { DnsProviders = [profile] });

        Assert.Equal(profile, Assert.Single((await store.LoadAsync()).DnsProviders));
        Assert.Contains("\"schemaVersion\": 7", await files.ReadAllTextAsync(@"C:\data\config.json", CancellationToken.None),StringComparison.Ordinal);
    }

    private async Task<DnsProviderProfile> ProfileAsync() =>
        new("Registrar", DnsProviderType.Script, "example.com", null, Protect(Secret),
            await _store.SaveAsync("Registrar", Original(), CancellationToken.None));

    private ScriptDnsProvider Provider() => new(_store, _runner, _protector);

    private DnsProviderService Service(IManagedCertificateStore? managed = null) => new(
        _config,
        managed ?? Mock.Of<IManagedCertificateStore>(),
        _protector,
        [Provider()],
        _lookup,
        _store,
        new DnsPropagationChecker(_lookup, new DnsPropagationOptions
        {
            Timeout = TimeSpan.FromMilliseconds(200),
            PollInterval = TimeSpan.FromMilliseconds(20),
            SettleDelay = TimeSpan.Zero,
            UncheckedWait = TimeSpan.Zero
        }));

    private static DnsProviderRequest ScriptRequest(string script, string secret) =>
        new("Registrar", DnsProviderType.Script, "Example.com", null, secret, script);

    private string Protect(string value) => Convert.ToBase64String(_protector.Protect(Encoding.UTF8.GetBytes(value)));

    private sealed class FakeRunner : IScriptRunner
    {
        public List<(string Path, string[] Arguments, string? Secret, TimeSpan Timeout)> Calls { get; } = [];

        /// <summary>What the "script" added, by record name, so a fake name server can answer with it.</summary>
        public Dictionary<string, string> Published { get; } = new(StringComparer.OrdinalIgnoreCase);

        public ScriptRunResult? Next { get; set; }

        /// <summary>Runs once, during the next call, as another process changing settings meanwhile would.</summary>
        public Action? During { get; set; }

        public Task<ScriptRunResult> RunAsync(
            string scriptPath, IReadOnlyList<string> arguments, string? secret, TimeSpan timeout, CancellationToken cancellationToken)
        {
            Calls.Add((scriptPath, [.. arguments], secret, timeout));
            var during = During;
            During = null;
            during?.Invoke();
            if (arguments[0] == "-Action:Add")
            {
                Published[arguments[2]["-RecordName:".Length..]] = arguments[3]["-Value:".Length..];
            }

            var result = Next ?? new ScriptRunResult(0, "", false, TimeSpan.Zero);
            Next = null;
            return Task.FromResult(result);
        }
    }

    private sealed class XorProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => [.. plaintext.Select(value => (byte)(value ^ 0x5A))];

        public byte[] Unprotect(byte[] protectedData) => Protect(protectedData);
    }
}
