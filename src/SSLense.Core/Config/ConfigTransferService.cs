using SSLense.Core.Acme;
using SSLense.Core.Errors;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace SSLense.Core.Config;

/// <summary>
/// Moves SSLense's settings between servers (docs/automation.md, "Settings export and import"). Secrets are left out unless
/// a password is given; then they are encrypted with it, because the DPAPI copies in the settings only open on this server.
/// </summary>
public interface IConfigTransferService
{
    /// <param name="password">Encrypts the secrets into the file; null leaves them out.</param>
    /// <param name="certificatesCsvPath">Also writes the certificates as a file for 'bulk issue' on the other server.</param>
    Task<string> ExportAsync(string path, string? password, string? certificatesCsvPath = null, CancellationToken cancellationToken = default);

    /// <param name="password">Decrypts the secrets in a file exported with them.</param>
    Task<string> ImportAsync(string path, string? password, CancellationToken cancellationToken = default);
}

internal sealed class ConfigTransferService(
    IConfigStore configStore,
    IManagedCertificateStore managedStore,
    ISecretProtector protector,
    IFileSystem fileSystem) : IConfigTransferService
{
    internal const string Format = "sslense-settings";
    internal const int FormatVersion = 1;
    private const string EncryptedPrefix = "enc:";
    private const int Iterations = 600_000;

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public async Task<string> ExportAsync(string path, string? password, string? certificatesCsvPath = null, CancellationToken cancellationToken = default)
    {
        var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        var node = JsonSerializer.SerializeToNode(config with { SchemaVersion = StateSchema.Config }, SerializerOptions)!.AsObject();
        var salt = RandomNumberGenerator.GetBytes(16);
        using var key = password is null ? null : new DisposableKey(DeriveKey(password, salt, Iterations));
        var secrets = 0;
        Transform(node, value =>
        {
            secrets++;
            if (key is null)
            {
                return null;
            }

            var plaintext = protector.Unprotect(Convert.FromBase64String(value));
            try
            {
                return EncryptedPrefix + Encrypt(key.Bytes, plaintext);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        });

        var state = secrets == 0 ? "none" : key is null ? "removed" : "encrypted";
        var document = new JsonObject
        {
            ["format"] = Format,
            ["formatVersion"] = FormatVersion,
            ["exportedAt"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture),
            ["configSchemaVersion"] = StateSchema.Config,
            ["secrets"] = state,
            ["config"] = node
        };
        if (state == "encrypted")
        {
            document["kdf"] = new JsonObject { ["salt"] = Convert.ToBase64String(salt), ["iterations"] = Iterations };
        }

        await fileSystem.WriteAllTextAtomicAsync(Path.GetFullPath(path), document.ToJsonString(SerializerOptions), cancellationToken).ConfigureAwait(false);
        var message = state switch
        {
            "none" => $"Settings exported to '{path}'. They hold no secrets.",
            "removed" => $"Settings exported to '{path}' without their {secrets} secret(s), so only the general settings can be imported. " +
                         "To move the certificate authorities, DNS providers and notifications too, export with a password.",
            _ => $"Settings exported to '{path}' with their {secrets} secret(s) encrypted by your password. Keep the file and the password apart."
        };

        if (certificatesCsvPath is not null)
        {
            message += " " + await ExportCertificatesAsync(certificatesCsvPath, cancellationToken).ConfigureAwait(false);
        }

        return message;
    }

    public async Task<string> ImportAsync(string path, string? password, CancellationToken cancellationToken = default)
    {
        JsonObject document;
        try
        {
            document = JsonNode.Parse(await fileSystem.ReadAllTextAsync(Path.GetFullPath(path), cancellationToken).ConfigureAwait(false)) as JsonObject
                ?? throw new SslenseException(ErrorCodes.ConfigFileInvalid, $"'{path}' is empty.");
        }
        catch (JsonException exception)
        {
            throw new SslenseException(ErrorCodes.ConfigFileInvalid, $"'{path}' is not valid JSON: {exception.Message}", exception);
        }

        if (document["format"]?.GetValue<string>() != Format || document["config"] is not JsonObject node)
        {
            throw new SslenseException(ErrorCodes.ConfigFileInvalid, $"'{path}' is not an SSLense settings file.");
        }

        var schema = document["configSchemaVersion"]?.GetValue<int>() ?? 0;
        if ((document["formatVersion"]?.GetValue<int>() ?? 0) > FormatVersion || schema > StateSchema.Config)
        {
            throw new SslenseException(ErrorCodes.ConfigFileInvalid, $"'{path}' was exported by a newer SSLense. Install that version here first.");
        }

        var state = document["secrets"]?.GetValue<string>() ?? "removed";
        if (state == "encrypted")
        {
            if (string.IsNullOrEmpty(password) || document["kdf"] is not JsonObject kdf)
            {
                throw new SslenseException(ErrorCodes.ConfigPasswordMissingOrWrong, $"'{path}' holds encrypted secrets, and no password was given.");
            }

            using var key = new DisposableKey(DeriveKey(password, Convert.FromBase64String(kdf["salt"]!.GetValue<string>()), kdf["iterations"]!.GetValue<int>()));
            Transform(node, value =>
            {
                if (!value.StartsWith(EncryptedPrefix, StringComparison.Ordinal))
                {
                    throw new SslenseException(ErrorCodes.ConfigFileInvalid, $"'{path}' has a secret that is not encrypted.");
                }

                var plaintext = Decrypt(key.Bytes, value[EncryptedPrefix.Length..]);
                try
                {
                    return Convert.ToBase64String(protector.Protect(plaintext));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(plaintext);
                }
            });
        }

        AppConfig imported;
        try
        {
            var read = node.Deserialize<AppConfig>(SerializerOptions)
                       ?? throw new SslenseException(ErrorCodes.ConfigFileInvalid, $"'{path}' has no settings.");
            imported = ConfigMigrations.Migrate(read with { SchemaVersion = schema });
        }
        catch (JsonException exception)
        {
            throw new SslenseException(ErrorCodes.ConfigFileInvalid, $"'{path}' has settings this SSLense cannot read: {exception.Message}", exception);
        }

        var current = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        var general = current with
        {
            DefaultEmail = imported.DefaultEmail,
            UseStaging = imported.UseStaging,
            RenewalThresholdDays = imported.RenewalThresholdDays,
            Reminders = imported.Reminders,
            MaintenanceWindow = imported.MaintenanceWindow,
            CheckForUpdates = imported.CheckForUpdates
        };
        var everything = state is "encrypted" or "none";
        var result = everything
            ? general with
            {
                CertificateAuthorities = imported.CertificateAuthorities,
                DnsProviders = imported.DnsProviders,
                Notifications = imported.Notifications
            }
            : general;

        // A certificate renewed by an authority the import removes could not renew again.
        var authorities = result.CertificateAuthorities.Select(authority => authority.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var orphaned = (await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false))
            .Where(record => record.Source == CertificateSource.Acme && !CertificateAuthorities.IsBuiltIn(record.AuthorityId) && !authorities.Contains(record.AuthorityId))
            .Select(record => $"'{record.SiteName}' ({record.AuthorityId})")
            .ToArray();
        if (orphaned.Length > 0)
        {
            throw new SslenseException(ErrorCodes.ConfigImportRefused,
                $"Nothing was imported: these certificates are renewed by a certificate authority the file does not have: {string.Join(", ", orphaned)}.");
        }

        // The settings before the import, kept beside them with their DPAPI secrets, which only open on this server.
        var backup = Path.Combine(AppPaths.DataDirectory, $"config.before-import-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}.json");
        fileSystem.CreateDirectory(AppPaths.DataDirectory);
        await fileSystem.WriteAllTextAtomicAsync(backup, JsonSerializer.Serialize(current, SerializerOptions), cancellationToken).ConfigureAwait(false);
        await configStore.SaveAsync(result, cancellationToken).ConfigureAwait(false);
        return everything
            ? $"Imported every setting from '{path}': general settings, {result.CertificateAuthorities.Count} certificate authorit(ies), " +
              $"{result.DnsProviders.Count} DNS provider(s) and notifications. The previous settings are in '{backup}'. " +
              "Restart the SSLense service so it reads them."
            : $"Imported the general settings from '{path}'. Its certificate authorities, DNS providers and notifications were left as they are here, " +
              $"because the file was exported without its secrets. The previous settings are in '{backup}'. Restart the SSLense service so it reads them.";
    }

    /// <summary>The certificates SSLense issues for IIS sites, as a file 'bulk issue' reads on another server.</summary>
    private async Task<string> ExportCertificatesAsync(string path, CancellationToken cancellationToken)
    {
        var records = await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        var lines = new List<string> { "site,hosts,validation,names,email,ca,profile,key" };
        var skipped = new List<string>();
        foreach (var record in records.OrderBy(value => value.SiteName, StringComparer.OrdinalIgnoreCase))
        {
            var validation = record.ValidationMethod switch
            {
                ValidationMethod.Http01 => record.SelfHostedHttp ? "http-self" : "http",
                ValidationMethod.Dns01Provider => "dns",
                _ => null
            };
            if (record.Source != CertificateSource.Acme || record.NoSite || record.IsShared() || validation is null || ManagedCertificateNames.IsAdditional(record.SiteName))
            {
                skipped.Add(record.SiteName);
                continue;
            }

            lines.Add(string.Join(',', new[]
            {
                record.SiteName,
                string.Join(';', record.Hosts),
                validation,
                record.CertificateNames is { Count: > 0 } names ? string.Join(';', names) : string.Empty,
                record.Email,
                record.AuthorityId,
                record.Profile ?? string.Empty,
                CertificateKeyTypes.Name(record.KeyType)
            }.Select(Quote)));
        }

        await fileSystem.WriteAllTextAtomicAsync(Path.GetFullPath(path), string.Join("\r\n", lines) + "\r\n", cancellationToken).ConfigureAwait(false);
        return $"{lines.Count - 1} certificate(s) written to '{path}' for 'bulk issue'" +
               (skipped.Count == 0 ? "." : $"; not written, because a file cannot describe them: {string.Join(", ", skipped)}.");
    }

    private static string Quote(string value) =>
        value.IndexOfAny([',', '"']) >= 0 ? $"\"{value.Replace("\"", "\"\"", StringComparison.Ordinal)}\"" : value;

    /// <summary>Replaces every non-empty string whose property name starts with "protected", the settings' secrets.</summary>
    private static void Transform(JsonNode? node, Func<string, string?> change)
    {
        switch (node)
        {
            case JsonObject value:
                foreach (var (name, child) in value.ToArray())
                {
                    if (name.StartsWith("protected", StringComparison.OrdinalIgnoreCase) && child is JsonValue secret &&
                        secret.TryGetValue<string>(out var text) && text.Length > 0)
                    {
                        value[name] = change(text);
                    }
                    else
                    {
                        Transform(child, change);
                    }
                }

                break;
            case JsonArray array:
                foreach (var child in array)
                {
                    Transform(child, change);
                }

                break;
        }
    }

    private static byte[] DeriveKey(string password, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, 32);

    private static string Encrypt(byte[] key, byte[] plaintext)
    {
        var nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];
        var ciphertext = new byte[plaintext.Length];
        using var aes = new AesGcm(key, tag.Length);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);
        return Convert.ToBase64String([.. nonce, .. tag, .. ciphertext]);
    }

    private static byte[] Decrypt(byte[] key, string value)
    {
        var data = Convert.FromBase64String(value);
        var nonceSize = AesGcm.NonceByteSizes.MaxSize;
        var tagSize = AesGcm.TagByteSizes.MaxSize;
        if (data.Length < nonceSize + tagSize)
        {
            throw new SslenseException(ErrorCodes.ConfigFileInvalid, "A secret in the file is damaged.");
        }

        var plaintext = new byte[data.Length - nonceSize - tagSize];
        try
        {
            using var aes = new AesGcm(key, tagSize);
            aes.Decrypt(data.AsSpan(0, nonceSize), data.AsSpan(nonceSize + tagSize), data.AsSpan(nonceSize, tagSize), plaintext);
            return plaintext;
        }
        catch (AuthenticationTagMismatchException exception)
        {
            throw new SslenseException(ErrorCodes.ConfigPasswordMissingOrWrong, "The password does not open the secrets in the file.", exception);
        }
    }

    private sealed class DisposableKey(byte[] bytes) : IDisposable
    {
        public byte[] Bytes { get; } = bytes;

        public void Dispose() => CryptographicOperations.ZeroMemory(Bytes);
    }
}
