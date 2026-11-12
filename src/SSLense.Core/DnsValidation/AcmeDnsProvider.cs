using System.Security.Cryptography;
using System.Text;
using SSLense.Core.Acme;

namespace SSLense.Core.DnsValidation;

/// <summary>
/// Publishes through an acme-dns account (docs/design/acme-dns.md). The account can change only its own name, so it never
/// needs a credential for the domain's zone.
/// </summary>
internal sealed class AcmeDnsProvider(IAcmeDnsClient client, ISecretProtector protector) : IDnsProvider
{
    public DnsProviderType Type => DnsProviderType.AcmeDns;

    /// <summary>acme-dns has no way to check a password without changing a value, so this confirms the server answers.</summary>
    public Task VerifyAccessAsync(DnsProviderProfile profile, CancellationToken cancellationToken) =>
        client.CheckHealthAsync(Server(profile), cancellationToken);

    public async Task AddTxtRecordAsync(DnsProviderProfile profile, string name, string value, CancellationToken cancellationToken)
    {
        // Selection already led here through the CNAME, so the record is the account's own name.
        if (!string.Equals(DnsNames.Normalize(name), DnsNames.Normalize(profile.ZoneName), StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The acme-dns account '{profile.Name}' can only set '{profile.ZoneName}', not '{name}'.");
        }

        if (value.Length != AcmeDnsClient.ValueLength)
        {
            throw new ArgumentException($"acme-dns only accepts values of {AcmeDnsClient.ValueLength} characters.");
        }

        var password = Unprotect(profile);
        await client.UpdateAsync(
                Server(profile),
                profile.AcmeDnsUsername ?? throw Missing(profile),
                password,
                profile.AcmeDnsSubdomain ?? throw Missing(profile),
                value,
                cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>acme-dns cannot delete; the next update replaces the value, which proves nothing once validation is over.</summary>
    public Task RemoveTxtRecordAsync(DnsProviderProfile profile, string name, string value, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    private static Uri Server(DnsProviderProfile profile) => profile.AcmeDnsServer ?? throw Missing(profile);

    private static InvalidOperationException Missing(DnsProviderProfile profile) =>
        new($"The acme-dns account '{profile.Name}' is incomplete. Remove it and register or import it again.");

    private string Unprotect(DnsProviderProfile profile)
    {
        byte[] plaintext;
        try
        {
            plaintext = protector.Unprotect(Convert.FromBase64String(profile.ProtectedToken));
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException or System.ComponentModel.Win32Exception)
        {
            throw new InvalidOperationException(
                $"The password for acme-dns account '{profile.Name}' cannot be decrypted on this server. Import the account again.",
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
}
