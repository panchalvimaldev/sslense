using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SSLense.Core.Acme;
using Xunit;

namespace SSLense.Tests.Acme;

/// <summary>
/// Runs only when SSLENSE_PEBBLE names pebble.exe, as the CI build does. Pebble is Let's Encrypt's ACME server for tests
/// (docs/design/certificate-sources.md, 9.5).
/// </summary>
public sealed class PebbleFactAttribute : FactAttribute
{
    public const string Variable = "SSLENSE_PEBBLE";

    public PebbleFactAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable(Variable)))
        {
            Skip = $"Set {Variable} to the path of pebble.exe to run the ACME tests against Pebble.";
        }
    }
}

/// <summary>
/// A Pebble that requires External Account Binding and accepts every challenge, so no DNS or IIS is needed. It serves its API
/// with a certificate made here, which only <see cref="Http"/> trusts.
/// </summary>
public sealed class PebbleServer : IAsyncLifetime
{
    public const string KeyId = "kid-1";
    public const string HmacKey = "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W";

    private readonly string _folder = Path.Combine(Path.GetTempPath(), $"sslense-pebble-{Guid.NewGuid():N}");
    private readonly List<string> _output = [];
    private Process? _process;

    private void Log(string? line)
    {
        if (line is not null)
        {
            lock (_output)
            {
                _output.Add(line);
            }
        }
    }

    public Uri Directory { get; private set; } = new("https://127.0.0.1/dir");

    public HttpClient Http { get; private set; } = new();

    public async Task InitializeAsync()
    {
        var executable = Environment.GetEnvironmentVariable(PebbleFactAttribute.Variable);
        if (string.IsNullOrEmpty(executable))
        {
            return;
        }

        System.IO.Directory.CreateDirectory(_folder);
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("localhost");
        names.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(names.Build());
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        var thumbprint = certificate.Thumbprint;
        await File.WriteAllTextAsync(Path.Combine(_folder, "cert.pem"), certificate.ExportCertificatePem());
        await File.WriteAllTextAsync(Path.Combine(_folder, "key.pem"), key.ExportPkcs8PrivateKeyPem());

        var port = FreePort();
        var config = $$"""
            {
              "pebble": {
                "listenAddress": "127.0.0.1:{{port}}",
                "managementListenAddress": "127.0.0.1:{{FreePort()}}",
                "certificate": "{{Path.Combine(_folder, "cert.pem").Replace("\\", "/")}}",
                "privateKey": "{{Path.Combine(_folder, "key.pem").Replace("\\", "/")}}",
                "httpPort": {{FreePort()}},
                "tlsPort": {{FreePort()}},
                "ocspResponderURL": "",
                "retryAfter": { "authz": 1, "order": 1 },
                "externalAccountBindingRequired": true,
                "externalAccountMACKeys": { "{{KeyId}}": "{{HmacKey}}" }
              }
            }
            """;
        var configPath = Path.Combine(_folder, "pebble.json");
        await File.WriteAllTextAsync(configPath, config);

        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = _folder
        };
        start.ArgumentList.Add("-config");
        start.ArgumentList.Add(configPath);
        start.Environment["PEBBLE_VA_ALWAYS_VALID"] = "1";
        start.Environment["PEBBLE_VA_NOSLEEP"] = "1";
        start.Environment["PEBBLE_WFE_NONCEREJECT"] = "0";
        start.Environment["PEBBLE_AUTHZREUSE"] = "0";
        _process = Process.Start(start)!;
        _process.OutputDataReceived += (_, line) => Log(line.Data);
        _process.ErrorDataReceived += (_, line) => Log(line.Data);
        _process.BeginOutputReadLine();
        _process.BeginErrorReadLine();

        Http = new HttpClient(new HttpClientHandler
        {
            // A system proxy must not see, or answer for, a server on this machine.
            UseProxy = false,
            ServerCertificateCustomValidationCallback = (_, served, _, _) =>
                string.Equals(served?.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase)
        });
        Directory = new Uri($"https://127.0.0.1:{port}/dir");

        var deadline = DateTimeOffset.UtcNow.AddSeconds(30);
        while (true)
        {
            try
            {
                using var probe = AcmeHttp.Get(Directory);
                using var response = await Http.SendAsync(probe);
                if (response.IsSuccessStatusCode)
                {
                    return;
                }

                var body = await response.Content.ReadAsStringAsync();
                Log($"Directory answered HTTP {(int)response.StatusCode}: {body.ReplaceLineEndings(" ")}");
            }
            catch (HttpRequestException exception) when (DateTimeOffset.UtcNow < deadline && !_process.HasExited)
            {
                Log($"Request failed: {exception.Message} {exception.InnerException?.Message}");
            }

            if (DateTimeOffset.UtcNow >= deadline || _process.HasExited)
            {
                string output;
                lock (_output)
                {
                    output = string.Join(Environment.NewLine, _output.TakeLast(20));
                }

                throw new InvalidOperationException($"Pebble did not start at {Directory}. Its output:{Environment.NewLine}{output}");
            }

            await Task.Delay(200);
        }
    }

    public Task DisposeAsync()
    {
        Http.Dispose();
        if (_process is { HasExited: false })
        {
            _process.Kill(entireProcessTree: true);
            _process.WaitForExit(10_000);
        }

        _process?.Dispose();
        try
        {
            System.IO.Directory.Delete(_folder, recursive: true);
        }
        catch (IOException)
        {
        }

        return Task.CompletedTask;
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
}

/// <summary>SSLense's real ACME client against a real ACME server, which no other test reaches.</summary>
public sealed class PebbleTests(PebbleServer pebble) : IClassFixture<PebbleServer>
{
    private const string Email = "admin@example.com";
    private readonly XorProtector _protector = new();

    private CertificateAuthority Authority(string? keyId = PebbleServer.KeyId, string? hmacKey = PebbleServer.HmacKey) =>
        new("pebble", "Pebble", pebble.Directory, IsTest: true, keyId, hmacKey is null ? null : Convert.ToBase64String(_protector.Protect(Encoding.UTF8.GetBytes(hmacKey))));

    private CertesAcmeProtocolClient Client(MemoryAccountStore store) => new(store, _protector, pebble.Http);

    [PebbleFact]
    public async Task Eab_CreatesTheAccount_AndAnHttpOrderGivesACertificateForItsName()
    {
        var store = new MemoryAccountStore();

        var order = await Client(store).CreateOrderAsync(Email, ["site.example.com"], Authority(), CancellationToken.None);
        foreach (var challenge in order.Challenges)
        {
            await order.ValidateAsync(challenge, CancellationToken.None);
        }

        var bundle = await order.FinalizeAsync("site.example.com", "password", CancellationToken.None);

        Assert.Equal(1, store.Saves);
        Assert.Equal(["site.example.com"], DnsNames(bundle));
    }

    [PebbleFact]
    public async Task WithoutEab_TheCaRefusesTheAccount()
    {
        var store = new MemoryAccountStore();

        await Assert.ThrowsAnyAsync<Exception>(() => Client(store).CreateOrderAsync(Email, ["site.example.com"], Authority(null, null), CancellationToken.None));

        Assert.Equal(0, store.Saves);
    }

    [PebbleFact]
    public async Task AWrongHmacKey_TheCaRefusesTheAccount()
    {
        var store = new MemoryAccountStore();
        var wrong = "b10lLJs8l1GPIzsLP0s6pMt8O0XVGnfTaCeROxQM0BIt2XrJMDHJZBM5NuQmQJQH";

        await Assert.ThrowsAnyAsync<Exception>(() => Client(store).CreateOrderAsync(Email, ["site.example.com"], Authority(hmacKey: wrong), CancellationToken.None));

        Assert.Equal(0, store.Saves);
    }

    [PebbleFact]
    public async Task ASecondOrder_UsesTheSavedAccount_WithoutSendingEabAgain()
    {
        var store = new MemoryAccountStore();
        await Client(store).CreateOrderAsync(Email, ["one.example.com"], Authority(), CancellationToken.None);

        // Without EAB the CA would refuse a new account, so this only works through the saved one.
        var second = await Client(store).CreateOrderAsync(Email, ["two.example.com"], Authority(null, null), CancellationToken.None);

        Assert.Single(second.Challenges);
        Assert.Equal(1, store.Saves);
    }

    [PebbleFact]
    public async Task ADnsOrder_ForAWildcardAndItsBaseName_GivesOneCertificateForBoth()
    {
        var store = new MemoryAccountStore();

        var order = await Client(store).CreateDnsOrderAsync(Email, ["*.example.org", "example.org"], Authority(), CancellationToken.None);
        foreach (var challenge in order.DnsChallenges)
        {
            Assert.Equal("_acme-challenge.example.org", challenge.RecordName);
            await order.ValidateAsync(challenge, CancellationToken.None);
        }

        var bundle = await order.FinalizeAsync("example.org", "password", CancellationToken.None);

        Assert.Equal(2, order.DnsChallenges.Count);
        Assert.Equal(["*.example.org", "example.org"], DnsNames(bundle).Order());
    }

    private static string[] DnsNames(CertificateBundle bundle)
    {
        using var certificate = X509Certificate2.CreateFromPem(bundle.CertificatePem);
        return certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single().EnumerateDnsNames().ToArray();
    }

    private sealed class MemoryAccountStore : IAcmeAccountStore
    {
        private readonly Dictionary<string, string> _keys = [];

        public int Saves { get; private set; }

        public Task<string?> LoadKeyAsync(string authorityId, CancellationToken cancellationToken) =>
            Task.FromResult(_keys.GetValueOrDefault(authorityId));

        public Task SaveKeyAsync(string authorityId, string accountKeyPem, CancellationToken cancellationToken)
        {
            _keys[authorityId] = accountKeyPem;
            Saves++;
            return Task.CompletedTask;
        }
    }

    private sealed class XorProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => [.. plaintext.Select(value => (byte)(value ^ 0x5A))];

        public byte[] Unprotect(byte[] protectedData) => Protect(protectedData);
    }
}
