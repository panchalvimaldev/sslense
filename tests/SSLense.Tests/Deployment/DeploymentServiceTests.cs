using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using Moq;
using SSLense.Core;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Deployment;
using SSLense.Core.DnsValidation;
using SSLense.Core.Iis;
using SSLense.Core.Notifications;
using Xunit;

namespace SSLense.Tests.Deployment;

public sealed class DeploymentServiceTests : IDisposable
{
    private const string StatePath = @"C:\ProgramData\SSLense\managed-certificates.json";
    private const string LockPath = @"C:\ProgramData\SSLense\managed-certificates.lock";
    private const string OldThumbprint = "AAAA000000000000000000000000000000000001";
    private const string NewThumbprint = "BBBB000000000000000000000000000000000002";

    private readonly string _root = Path.Combine(Path.GetTempPath(), $"sslense-deploy-{Guid.NewGuid():N}");
    private readonly JsonManagedCertificateStore _store = new(new InMemoryFileSystem(), StatePath, LockPath);
    private readonly FakeKeyAccess _keys = new();
    private readonly FakeServices _services = new();
    private readonly FakeRunner _runner = new();
    private readonly Mock<IIisService> _iis = new();
    private readonly Mock<ICertificateStore> _certificates = new();
    private readonly Mock<INotifier> _notifier = new();
    private readonly DnsScriptStore _scripts;
    private readonly DeploymentService _service;

    public DeploymentServiceTests()
    {
        Directory.CreateDirectory(_root);
        _scripts = new DnsScriptStore(Path.Combine(_root, "copies"), secure: false, "deployment step", _ => "Add it again.");
        _iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>())).ReturnsAsync([]);
        _service = new DeploymentService(
            _store, _keys, _services, _scripts, _runner, _iis.Object, _certificates.Object, _notifier.Object);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [Fact]
    public async Task AddAsync_KeepsStepsInOrder_AndCountsThemDoneForTheCertificateInUse()
    {
        await SaveRecordAsync();

        await _service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.GrantKeyAccess, "iis apppool\\shop"));
        await _service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.RestartService, "W3SVC"));
        var overview = await _service.ListAsync("Shop");

        Assert.Equal([DeploymentStepKind.GrantKeyAccess, DeploymentStepKind.RestartService], overview.Steps.Select(step => step.Kind));
        Assert.Equal("IIS APPPOOL\\Shop", overview.Steps[0].Value);
        Assert.False(overview.Pending);
        Assert.Equal(OldThumbprint, overview.State?.CompletedThumbprint);
        Assert.Empty(await _service.RunPendingAsync());
    }

    [Fact]
    public async Task AddAsync_RefusesUnknownAccountsAndServices()
    {
        await SaveRecordAsync();

        await Assert.ThrowsAsync<ArgumentException>(() =>
            _service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.GrantKeyAccess, "nobody")));
        var service = await Assert.ThrowsAsync<ArgumentException>(() =>
            _service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.RestartService, "NoSuchService")));
        Assert.Contains("No Windows service", service.Message, StringComparison.Ordinal);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            _service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.RestartService, "W3SVC & calc")));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            _service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.RestartService, "SSLense")));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            _service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.RestartService, "W3SVC", 60)));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.AddAsync(new DeploymentStepRequest("Nowhere", DeploymentStepKind.RestartService, "W3SVC")));
        Assert.Empty((await _service.ListAsync("Shop")).Steps);
    }

    [Fact]
    public async Task ScriptStep_RunsSSLensesCopyWithTheCertificatesDetails_AndRefusesAChangedCopy()
    {
        await SaveRecordAsync();
        var original = WriteScript("deploy.ps1", "Write-Output 'deployed'");
        var step = await _service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.Script, original, 30));
        File.WriteAllText(original, "Write-Output 'changed later'");

        var result = await _service.RunAsync("Shop");

        Assert.True(result.Succeeded, result.Message);
        var call = Assert.Single(_runner.Calls);
        Assert.NotEqual(original, call.Path);
        Assert.Equal("Write-Output 'deployed'", File.ReadAllText(call.Path));
        Assert.Equal(TimeSpan.FromSeconds(30), call.Timeout);
        Assert.Equal(
            [$"-Thumbprint:{OldThumbprint}", "-Hosts:shop.example.com,www.example.com", "-NotAfter:2027-01-31T12:00:00Z", "-Site:Shop"],
            call.Arguments);
        Assert.Equal("deploy.ps1", step.Value);

        File.WriteAllText(call.Path, "Start-Process calc");
        var refused = await _service.RunAsync("Shop");

        Assert.False(refused.Succeeded);
        Assert.Contains("changed after SSLense saved it", refused.Message, StringComparison.Ordinal);
        Assert.Single(_runner.Calls);
    }

    [Fact]
    public async Task ScriptStep_FailureReportsTheExitCodeAndOutput_WithCredentialsRemoved()
    {
        await SaveRecordAsync();
        await _service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.Script, WriteScript("deploy.ps1", "exit 3")));
        _runner.Next = new ScriptRunResult(3, "connecting\npassword=hunter2hunter2\nfailed", false, TimeSpan.Zero);

        var result = await _service.RunAsync("Shop");

        Assert.False(result.Succeeded);
        Assert.Contains("exit code 3", result.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("hunter2hunter2", result.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AfterRenewal_FailedStepKeepsTheDeployedCertificate_RetriesHourly_AndRemovesItOnSuccess()
    {
        await SaveRecordAsync();
        await _service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.GrantKeyAccess, "IIS AppPool\\Shop"));
        await _service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.RestartService, "W3SVC"));
        await RenewAsync();
        _services.Fail = new InvalidOperationException("The service 'W3SVC' did not stop within 120 seconds.");

        var after = await _service.RunAfterInstallAsync("Shop", OldThumbprint, [], null, CancellationToken.None);

        Assert.True(after.KeepReplaced);
        Assert.False(after.Result!.Succeeded);
        Assert.Equal(1, after.Result.StepsCompleted);
        Assert.Contains("Step 2", after.Result.Message, StringComparison.Ordinal);
        var pending = (await _store.GetAllAsync()).Single();
        Assert.True(pending.HasPendingDeployment());
        Assert.Equal(OldThumbprint, pending.Deployment!.RetainedThumbprint);
        Assert.Equal(1, pending.Deployment.ConsecutiveFailures);
        _notifier.Verify(value => value.NotifyAsync(
            It.Is<NotificationMessage>(message => message.Kind == NotificationKind.RenewalFailure), It.IsAny<CancellationToken>()), Times.Once);
        _certificates.Verify(value => value.RemoveAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);

        // The next service cycle retries, and only the first failure of a run of failures is notified.
        Assert.False(Assert.Single(await _service.RunPendingAsync()).Succeeded);
        _notifier.Verify(value => value.NotifyAsync(It.IsAny<NotificationMessage>(), It.IsAny<CancellationToken>()), Times.Once);

        _services.Fail = null;
        var retried = Assert.Single(await _service.RunPendingAsync());

        Assert.True(retried.Succeeded, retried.Message);
        var done = (await _store.GetAllAsync()).Single();
        Assert.False(done.HasPendingDeployment());
        Assert.Null(done.Deployment!.RetainedThumbprint);
        Assert.Equal(OldThumbprint, done.Deployment.PreviousThumbprint);
        _certificates.Verify(value => value.RemoveAsync(OldThumbprint, It.IsAny<CancellationToken>()), Times.Once);
        _notifier.Verify(value => value.NotifyAsync(
            It.Is<NotificationMessage>(message => message.Kind == NotificationKind.RenewalSuccess), It.IsAny<CancellationToken>()), Times.Once);
        Assert.Empty(await _service.RunPendingAsync());
        Assert.Equal([NewThumbprint, NewThumbprint, NewThumbprint], _keys.Granted.Select(grant => grant.Thumbprint));
    }

    [Fact]
    public async Task AfterRenewal_SucceededStepsLetTheReplacedCertificateGo_AndScriptsGetThePreviousThumbprint()
    {
        await SaveRecordAsync();
        await _service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.Script, WriteScript("deploy.ps1", "exit 0")));
        await RenewAsync();

        var after = await _service.RunAfterInstallAsync("Shop", OldThumbprint, [], null, CancellationToken.None);

        Assert.False(after.KeepReplaced);
        Assert.True(after.Result!.Succeeded);
        Assert.Contains($"-PreviousThumbprint:{OldThumbprint}", Assert.Single(_runner.Calls).Arguments);
        Assert.Contains($"-Thumbprint:{NewThumbprint}", _runner.Calls[0].Arguments);
    }

    [Fact]
    public async Task AfterInstall_WithoutSteps_DoesNothing()
    {
        await SaveRecordAsync();

        var after = await _service.RunAfterInstallAsync("Shop", OldThumbprint, [], null, CancellationToken.None);

        Assert.Null(after.Result);
        Assert.False(after.KeepReplaced);
    }

    [Fact]
    public async Task Renewal_KeepsTheStepsAndTheirState()
    {
        await SaveRecordAsync();
        await _service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.RestartService, "W3SVC"));

        await RenewAsync();
        var renewed = (await _store.GetAllAsync()).Single();

        Assert.Single(renewed.DeploymentSteps!);
        Assert.Equal(OldThumbprint, renewed.Deployment!.CompletedThumbprint);
        Assert.True(renewed.HasPendingDeployment());
    }

    [Fact]
    public async Task RemoveAsync_DeletesTheScriptCopy_AndClearsTheStateWithTheLastStep()
    {
        await SaveRecordAsync();
        await _service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.Script, WriteScript("deploy.ps1", "exit 0")));
        await _service.RunAsync("Shop");
        var copy = Assert.Single(_runner.Calls).Path;

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => _service.RemoveAsync("Shop", 2));
        var removed = await _service.RemoveAsync("Shop", 1);

        Assert.Equal(DeploymentStepKind.Script, removed.Kind);
        Assert.False(File.Exists(copy));
        var record = (await _store.GetAllAsync()).Single();
        Assert.Null(record.DeploymentSteps);
        Assert.Null(record.Deployment);
    }

    [Fact]
    public async Task RunPendingAsync_DeletesCopiesOfRemovedCertificates_ButNotOnesJustAdded()
    {
        await SaveRecordAsync();
        await _service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.Script, WriteScript("deploy.ps1", "exit 0")));
        await _service.RunAsync("Shop");
        var copy = Assert.Single(_runner.Calls).Path;
        var fresh = Path.Combine(Path.GetDirectoryName(copy)!, "step-0123456789abcdef0123456789abcdef-0123456789abcdef.ps1");
        File.WriteAllText(fresh, "exit 0");
        File.SetLastWriteTimeUtc(copy, DateTime.UtcNow.AddHours(-2));

        await _service.RunPendingAsync();
        Assert.True(File.Exists(copy));

        await _store.RemoveAsync("Shop");
        await _service.RunPendingAsync();

        Assert.False(File.Exists(copy));
        Assert.True(File.Exists(fresh));
    }

    [Fact]
    public async Task ManagedCertificateState_WithSteps_RoundTripsInSchema6()
    {
        var fileSystem = new InMemoryFileSystem();
        var store = new JsonManagedCertificateStore(fileSystem, StatePath, LockPath);
        var step = new DeploymentStep(Guid.NewGuid(), DeploymentStepKind.Script, "rdp.ps1", "ABCDEF", 60);
        await store.UpsertAsync(Record() with
        {
            DeploymentSteps = [step],
            Deployment = new DeploymentState(OldThumbprint, null, DateTimeOffset.UnixEpoch, "Step 1 failed", 2, "CCCC")
        });

        var reread = (await new JsonManagedCertificateStore(fileSystem, StatePath, LockPath).GetAllAsync()).Single();

        Assert.Contains("\"schemaVersion\": 6", fileSystem.Files[StatePath], StringComparison.Ordinal);
        Assert.Equal(step, Assert.Single(reread.DeploymentSteps!));
        Assert.Equal("CCCC", reread.Deployment!.RetainedThumbprint);
        Assert.Equal(2, reread.Deployment.ConsecutiveFailures);
    }

    [Fact]
    public void ScServiceRestarter_ReadsTheStateFromScQuery()
    {
        const string output = """
            SERVICE_NAME: W3SVC
                    TYPE               : 30  WIN32
                    STATE              : 4  RUNNING
                                            (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
            """;

        Assert.Equal(4, ScServiceRestarter.ParseState(output));
        Assert.Null(ScServiceRestarter.ParseState("[SC] OpenService FAILED 1060"));
    }

    [Fact]
    public void PrivateKeyAccess_ResolvesWellKnownAccounts_AndRefusesUnknownOnes()
    {
        var (sid, _) = PrivateKeyAccess.Resolve("NT AUTHORITY\\NETWORK SERVICE");

        Assert.Equal(new SecurityIdentifier(WellKnownSidType.NetworkServiceSid, null), sid);
        Assert.Throws<ArgumentException>(() => PrivateKeyAccess.Resolve($"NoSuchAccount{Guid.NewGuid():N}"));
    }

    [Fact]
    public void PrivateKeyAccess_AddsOneReadRuleToARealKeyFile()
    {
        var keyName = $"sslense-test-{Guid.NewGuid():N}";
        using var key = CngKey.Create(CngAlgorithm.ECDsaP256, keyName, new CngKeyCreationParameters
        {
            KeyCreationOptions = CngKeyCreationOptions.None,
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider
        });
        try
        {
            using var ecdsa = new ECDsaCng(key);
            using var certificate = new CertificateRequest("CN=sslense-test", ecdsa, HashAlgorithmName.SHA256)
                .CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
            var userKeys = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Microsoft", "Crypto", "Keys");
            var networkService = new SecurityIdentifier(WellKnownSidType.NetworkServiceSid, null);

            PrivateKeyAccess.GrantRead(certificate, networkService, [Path.Combine(_root, "missing"), userKeys], "NETWORK SERVICE");

            var file = new FileInfo(Path.Combine(userKeys, key.UniqueName!));
            var rules = file.GetAccessControl()
                .GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
                .OfType<FileSystemAccessRule>()
                .Where(rule => rule.IdentityReference.Equals(networkService))
                .ToArray();
            var rule = Assert.Single(rules);
            Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
            Assert.Equal(FileSystemRights.Read, rule.FileSystemRights & ~FileSystemRights.Synchronize);
        }
        finally
        {
            key.Delete();
        }
    }

    [Fact]
    public void ScriptArguments_UseTheColonForm_ForEveryHostOfASharedCertificate()
    {
        var record = Record().WithTargets(
        [
            new CertificateTarget("Shop", ["shop.example.com"]),
            new CertificateTarget("Blog", ["blog.example.com", "shop.example.com"])
        ]);

        var arguments = DeploymentService.ScriptArguments(record, "PREV");

        Assert.Contains("-Hosts:shop.example.com,blog.example.com", arguments);
        Assert.Contains("-PreviousThumbprint:PREV", arguments);
        Assert.All(arguments, argument => Assert.Matches("^-[A-Za-z]+:", argument));
    }

    [Theory]
    [InlineData("Template.ps1", "Deployment failed:")]
    [InlineData("RemoteDesktop.ps1", "is not in LocalMachine\\My")]
    [InlineData("SqlServer.ps1", "is not in LocalMachine\\My")]
    public async Task ExampleScripts_AcceptSSLensesArguments_AndFailClearly(string script, string expected)
    {
        var result = await new PowerShellScriptRunner().RunAsync(
            Path.Combine(AppContext.BaseDirectory, "deploy-scripts", script),
            DeploymentService.ScriptArguments(Record(), "PREV"),
            null,
            TimeSpan.FromSeconds(60),
            CancellationToken.None);

        Assert.Equal(1, result.ExitCode);
        Assert.Contains(expected, result.Output, StringComparison.Ordinal);
    }

    private static ManagedCertificate Record(string thumbprint = OldThumbprint) =>
        new(
            "Shop",
            ["shop.example.com", "www.example.com"],
            "ops@example.com",
            thumbprint,
            new DateTimeOffset(2026, 11, 1, 12, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2027, 1, 31, 12, 0, 0, TimeSpan.Zero));

    private Task SaveRecordAsync() => _store.UpsertAsync(Record());

    /// <summary>As an install does: a fresh record, with no steps of its own, for the new certificate.</summary>
    private Task RenewAsync() => _store.UpsertAsync(Record(NewThumbprint));

    private string WriteScript(string name, string content)
    {
        var path = Path.Combine(_root, name);
        File.WriteAllText(path, content);
        return path;
    }

    private sealed class FakeKeyAccess : IPrivateKeyAccess
    {
        public List<(string Thumbprint, string Account)> Granted { get; } = [];

        public string ResolveAccount(string account) =>
            account.Trim().ToUpperInvariant() switch
            {
                "IIS APPPOOL\\SHOP" => "IIS APPPOOL\\Shop",
                _ => throw new ArgumentException($"Windows does not know the account '{account}'.")
            };

        public Task GrantReadAsync(string thumbprint, string account, CancellationToken cancellationToken)
        {
            Granted.Add((thumbprint, account));
            return Task.CompletedTask;
        }
    }

    private sealed class FakeServices : IServiceRestarter
    {
        public Exception? Fail { get; set; }

        public Task<bool> ExistsAsync(string serviceName, CancellationToken cancellationToken) =>
            Task.FromResult(serviceName is "W3SVC" or "SSLense");

        public Task RestartAsync(string serviceName, TimeSpan timeout, CancellationToken cancellationToken) =>
            Fail is null ? Task.CompletedTask : Task.FromException(Fail);
    }

    private sealed class FakeRunner : IScriptRunner
    {
        public List<(string Path, string[] Arguments, TimeSpan Timeout)> Calls { get; } = [];

        public ScriptRunResult? Next { get; set; }

        public Task<ScriptRunResult> RunAsync(
            string scriptPath, IReadOnlyList<string> arguments, string? secret, TimeSpan timeout, CancellationToken cancellationToken)
        {
            Assert.Null(secret);
            Calls.Add((scriptPath, [.. arguments], timeout));
            var result = Next ?? new ScriptRunResult(0, "", false, TimeSpan.Zero);
            Next = null;
            return Task.FromResult(result);
        }
    }
}
