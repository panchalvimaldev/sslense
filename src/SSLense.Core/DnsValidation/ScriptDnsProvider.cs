using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using SSLense.Core.Acme;
using SSLense.Core.Diagnostics;

namespace SSLense.Core.DnsValidation;

/// <summary>
/// Publishes records through the administrator's PowerShell script (docs/design/dns-script.md, section 3). Nothing the
/// script reports is trusted: after it adds a record, propagation is still checked at the authoritative name servers.
/// </summary>
internal sealed partial class ScriptDnsProvider(IDnsScriptStore scripts, IScriptRunner runner, ISecretProtector protector)
    : IDnsProvider
{
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromMinutes(2);
    private const int LinesShown = 20;

    public DnsProviderType Type => DnsProviderType.Script;

    public Task VerifyAccessAsync(DnsProviderProfile profile, CancellationToken cancellationToken) =>
        RunAsync(profile, "Check", $"_acme-challenge.{DnsNames.Normalize(profile.ZoneName)}", null, "check its access to the zone", cancellationToken);

    public Task AddTxtRecordAsync(DnsProviderProfile profile, string name, string value, CancellationToken cancellationToken) =>
        RunAsync(profile, "Add", name, value, $"add the TXT record '{name}'", cancellationToken);

    public Task RemoveTxtRecordAsync(DnsProviderProfile profile, string name, string value, CancellationToken cancellationToken) =>
        RunAsync(profile, "Remove", name, value, $"remove the TXT record '{name}'", cancellationToken);

    private async Task RunAsync(
        DnsProviderProfile profile,
        string action,
        string recordName,
        string? value,
        string purpose,
        CancellationToken cancellationToken)
    {
        // Checked even though the arguments are passed as a list, so nothing can ever be read as PowerShell syntax.
        var zone = DnsNames.Normalize(profile.ZoneName);
        var record = DnsNames.Normalize(recordName);
        if (!HostName().IsMatch(zone) || !HostName().IsMatch(record) || (value is not null && !RecordValue().IsMatch(value)))
        {
            throw new ArgumentException($"SSLense refused to pass an unexpected zone, record name, or value to the script for DNS provider '{profile.Name}'.");
        }

        var path = scripts.GetVerifiedPath(
            profile.Name,
            profile.ScriptSha256 ?? throw new InvalidOperationException($"DNS provider '{profile.Name}' has no script. Remove it and add it again."));

        // The colon form binds a value that starts with '-', which Base64url values can.
        string[] arguments = [$"-Action:{action}", $"-Zone:{zone}", $"-RecordName:{record}", .. value is null ? Array.Empty<string>() : [$"-Value:{value}"]];
        var secret = Unprotect(profile);
        var timeout = profile.ScriptTimeoutSeconds is { } seconds ? TimeSpan.FromSeconds(seconds) : DefaultTimeout;
        var result = await runner.RunAsync(path, arguments, secret, timeout, cancellationToken).ConfigureAwait(false);
        if (result.TimedOut)
        {
            throw new System.TimeoutException(
                $"The script for DNS provider '{profile.Name}' did not {purpose} within {timeout.TotalSeconds:0} seconds, so it was stopped." +
                Tail(result.Output, secret));
        }

        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"The script for DNS provider '{profile.Name}' could not {purpose} (exit code {result.ExitCode})." +
                Tail(result.Output, secret));
        }
    }

    /// <summary>The script's last lines, with the secret and anything that looks like a credential removed.</summary>
    internal static string Tail(string output, string? secret)
    {
        if (!string.IsNullOrEmpty(secret))
        {
            // Also each part of a combined secret such as "key:secret", which a script may print on its own.
            foreach (var part in secret.Split(':').Where(part => part.Length >= 6).Prepend(secret).OrderByDescending(part => part.Length))
            {
                output = output.Replace(part, SecretRedactor.Marker, StringComparison.Ordinal);
            }
        }

        var lines = SecretRedactor.Redact(output)
            .Split('\n')
            .Select(line => line.TrimEnd('\r'))
            .Where(line => line.Trim().Length > 0)
            .TakeLast(LinesShown)
            .ToArray();
        return lines.Length == 0 ? " It printed nothing." : $" Its last output:{Environment.NewLine}{string.Join(Environment.NewLine, lines)}";
    }

    private string? Unprotect(DnsProviderProfile profile)
    {
        if (string.IsNullOrEmpty(profile.ProtectedToken))
        {
            return null;
        }

        byte[] plaintext;
        try
        {
            plaintext = protector.Unprotect(Convert.FromBase64String(profile.ProtectedToken));
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException or System.ComponentModel.Win32Exception)
        {
            throw new InvalidOperationException(
                $"The secret for DNS provider '{profile.Name}' cannot be decrypted. Replace it with 'SSLense.Cli dns update-token --name \"{profile.Name}\"'.",
                exception);
        }

        try
        {
            return Encoding.UTF8.GetString(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    [GeneratedRegex("^[a-z0-9_](?:[a-z0-9_.-]{0,251}[a-z0-9])?$")]
    private static partial Regex HostName();

    [GeneratedRegex("^[A-Za-z0-9_-]{1,512}$")]
    private static partial Regex RecordValue();
}
