using System.Text;
using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.Errors;
using SSLense.Core.Validation;

namespace SSLense.Core.Certificates;

/// <summary>Bulk operations (docs/design/bulk-operations.md): one result per certificate, and one failure stops nothing else.</summary>
public interface IBulkService
{
    /// <summary>Watches every certificate bound in IIS that SSLense does not manage yet.</summary>
    Task<IReadOnlyList<BulkResult>> WatchAllAsync(IProgress<ProgressEvent>? progress = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Issues a certificate for each row of a CSV file; with <paramref name="dryRun"/>, runs only each row's pre-issue
    /// checks. Columns: site, hosts, validation, names, email, ca, profile, key (see the design for each).
    /// </summary>
    Task<IReadOnlyList<BulkResult>> IssueFromCsvAsync(string path, bool dryRun, bool acceptProductionRisk = false, IProgress<ProgressEvent>? progress = null, CancellationToken cancellationToken = default);
}

/// <param name="Item">What the row was about: a site and its host names, or a CSV line.</param>
public sealed record BulkResult(string Item, bool Succeeded, string Message);

internal sealed class BulkService(
    IImportedCertificateService imported,
    IAcmeService acme,
    IPreflightService preflight,
    ISettingsService settings) : IBulkService
{
    private static readonly string[] Columns = ["site", "hosts", "validation", "names", "email", "ca", "profile", "key"];

    public async Task<IReadOnlyList<BulkResult>> WatchAllAsync(IProgress<ProgressEvent>? progress = null, CancellationToken cancellationToken = default)
    {
        var results = new List<BulkResult>();
        var bindings = await imported.DiscoverAsync(cancellationToken).ConfigureAwait(false);

        // One adoption per certificate on a site: it takes every binding of that certificate there.
        foreach (var binding in bindings.Where(value => value.Thumbprint is not null && !value.IsManaged)
                     .DistinctBy(value => (value.SiteName.ToUpperInvariant(), value.Thumbprint!.ToUpperInvariant())))
        {
            var item = $"{binding.SiteName} ({binding.Host}:{binding.Port})";
            progress?.Report(new ProgressEvent("watch", $"Watching {item}."));
            try
            {
                var record = await imported.AdoptAsync(binding.SiteName, binding.Thumbprint, cancellationToken).ConfigureAwait(false);
                results.Add(new BulkResult(item, true, $"Watched as '{record.SiteName}', expires {record.NotAfter:yyyy-MM-dd}."));
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                results.Add(new BulkResult(item, false, ErrorCode.Describe(exception)));
            }
        }

        return results;
    }

    public async Task<IReadOnlyList<BulkResult>> IssueFromCsvAsync(
        string path,
        bool dryRun,
        bool acceptProductionRisk = false,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var lines = await File.ReadAllLinesAsync(path, cancellationToken).ConfigureAwait(false);
        var rows = lines.Select((line, index) => (Line: index + 1, Fields: ParseLine(line)))
            .Where(row => row.Fields.Count > 0 && !(row.Fields.Count == 1 && row.Fields[0].Length == 0) && !row.Fields[0].StartsWith('#'))
            .ToList();
        if (rows.Count == 0)
        {
            throw new ArgumentException(ErrorCodes.BulkFileInvalid.Format($"'{path}' has no rows."));
        }

        // A header row names the columns; without one they are in the documented order.
        var header = rows[0].Fields.Select(field => field.Trim().ToLowerInvariant()).ToArray();
        var hasHeader = header.Contains("site");
        if (hasHeader && header.FirstOrDefault(name => !Columns.Contains(name)) is { } unknown)
        {
            throw new ArgumentException(ErrorCodes.BulkFileInvalid.Format($"'{path}' has an unknown column '{unknown}'. Columns: {string.Join(", ", Columns)}."));
        }

        var order = hasHeader ? header : Columns;
        var defaultEmail = (await settings.GetAsync(cancellationToken).ConfigureAwait(false)).DefaultEmail;
        var results = new List<BulkResult>();
        foreach (var (line, fields) in hasHeader ? rows.Skip(1) : rows)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string Field(string name) => Array.IndexOf(order, name) is var index and >= 0 && index < fields.Count ? fields[index].Trim() : string.Empty;
            var site = Field("site");
            var item = $"Line {line}: {site}";
            try
            {
                var request = BuildRequest(acceptProductionRisk, site, Field("hosts"), Field("validation"), Field("names"), Field("email") is { Length: > 0 } email ? email : defaultEmail,
                    Field("ca"), Field("profile"), Field("key"));
                if (dryRun)
                {
                    var checks = request.ValidationMethod == ValidationMethod.Http01
                        ? request.SelfHostedHttp
                            ? await preflight.CheckAsync(request.SiteName, request.Hosts, selfHosted: true, cancellationToken).ConfigureAwait(false)
                            : await preflight.CheckAsync(request.SiteName, request.Hosts, cancellationToken).ConfigureAwait(false)
                        : await preflight.CheckDnsAsync(new DnsPreflightRequest(request.SiteName, request.Hosts, request.CertificateNames, request.ValidationMethod, request.AuthorityId), cancellationToken).ConfigureAwait(false);
                    var failed = checks.Where(check => !check.Succeeded).ToArray();
                    results.Add(new BulkResult(item, failed.Length == 0, failed.Length == 0
                        ? "Every check passed."
                        : string.Join(" ", failed.Select(check => $"{check.Name}: {check.Message}"))));
                    continue;
                }

                progress?.Report(new ProgressEvent("issue", $"{item}: issuing."));
                var issued = await acme.IssueAsync(request, progress, cancellationToken).ConfigureAwait(false);
                results.Add(new BulkResult(item, true, $"Issued and bound as '{issued.Name ?? site}', expires {issued.NotAfter:yyyy-MM-dd}."));
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                results.Add(new BulkResult(item, false, ErrorCode.Describe(exception)));
            }
        }

        return results;
    }

    private static AcmeIssueRequest BuildRequest(
        bool acceptProductionRisk,
        string site, string hosts, string validation, string names, string? email, string ca, string profile, string key)
    {
        if (site.Length == 0)
        {
            throw new ArgumentException(ErrorCodes.BulkFileInvalid.Format("The site column is empty."));
        }

        if (string.IsNullOrWhiteSpace(email))
        {
            throw new ArgumentException(ErrorCodes.BulkFileInvalid.Format("No email: fill the email column, or set the default ACME email in Settings."));
        }

        static IReadOnlyList<string> List(string value) =>
            value.Split([';', ' ', '|'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var (method, selfHosted) = validation.Trim().ToLowerInvariant() switch
        {
            "" or "http" => (ValidationMethod.Http01, false),
            "http-self" => (ValidationMethod.Http01, true),
            "dns" => (ValidationMethod.Dns01Provider, false),
            var other => throw new ArgumentException(ErrorCodes.BulkFileInvalid.Format(
                $"'{other}' is not a validation for a file: use http, http-self or dns. Manual DNS needs a person for each certificate."))
        };
        return new AcmeIssueRequest(
            site,
            List(hosts),
            email.Trim(),
            AuthorityId: ca.Length == 0 ? CertificateAuthorities.LetsEncryptStagingId : ca.ToLowerInvariant(),
            ValidationMethod: method,
            CertificateNames: names.Length == 0 ? null : List(names),
            KeyType: key.Length == 0 ? CertificateKeyType.EcdsaP256 : CertificateKeyTypes.Parse(key),
            Profile: profile.Length == 0 ? null : profile,
            SelfHostedHttp: selfHosted,
            AcceptProductionRisk: acceptProductionRisk);
    }

    /// <summary>One CSV line: commas separate fields; a field in double quotes may hold commas, and "" is a quote.</summary>
    internal static IReadOnlyList<string> ParseLine(string line)
    {
        var fields = new List<string>();
        var field = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (quoted)
            {
                if (c == '"' && i + 1 < line.Length && line[i + 1] == '"') { field.Append('"'); i++; }
                else if (c == '"') quoted = false;
                else field.Append(c);
            }
            else if (c == '"') quoted = true;
            else if (c == ',') { fields.Add(field.ToString()); field.Clear(); }
            else field.Append(c);
        }

        fields.Add(field.ToString());
        return fields;
    }
}
