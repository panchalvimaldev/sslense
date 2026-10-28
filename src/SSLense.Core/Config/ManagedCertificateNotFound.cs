namespace SSLense.Core.Config;

internal static class ManagedCertificateNotFound
{
    /// <summary>
    /// Builds the error for an unknown site name, pointing at the right IIS site name when the value
    /// given is one of its host names, which is the most common mix-up.
    /// </summary>
    public static InvalidOperationException Create(string siteName, IReadOnlyList<ManagedCertificate> records)
    {
        var message = $"No managed certificate was found for IIS site '{siteName}'.";
        var byHost = records.FirstOrDefault(record => record.Hosts.Any(host =>
            string.Equals(host.TrimEnd('.'), siteName.Trim().TrimEnd('.'), StringComparison.OrdinalIgnoreCase)));
        if (byHost is not null)
        {
            message += $" '{siteName}' is a host name of IIS site '{byHost.SiteName}'. " +
                $"Use --site \"{byHost.SiteName}\"; --site takes the IIS site name.";
        }
        else if (records.Count > 0)
        {
            message += " Managed IIS sites: " +
                string.Join(", ", records.Select(record => $"'{record.SiteName}'").Order(StringComparer.OrdinalIgnoreCase)) +
                ". Run 'status' to list them.";
        }

        return new InvalidOperationException(message);
    }
}
