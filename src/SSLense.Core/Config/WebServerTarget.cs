using SSLense.Core.Errors;

namespace SSLense.Core.Config;

public enum WebServerKind
{
    Apache = 0,
    Nginx = 1,
    Tomcat = 2
}

/// <summary>
/// A web server on Windows that reads its certificate from files (docs/design/web-servers.md): which server, the folder
/// its configuration points at, and the Windows service that runs it. Stored in a step's value as
/// <c>server|folder|service</c>.
/// </summary>
public sealed record WebServerTarget(WebServerKind Server, string Folder, string Service)
{
    /// <summary>Apache and nginx read PEM files; Tomcat reads a PKCS#12 keystore with a password.</summary>
    public bool NeedsPassword => Server == WebServerKind.Tomcat;

    /// <summary>The file Tomcat's certificateKeystoreFile names.</summary>
    public string KeystorePath => Path.Combine(Folder, "certificate.pfx");

    public string Describe() => Server switch
    {
        WebServerKind.Tomcat => $"Write a keystore for Tomcat to '{KeystorePath}' and restart '{Service}'",
        _ => $"Write PEM files for {Server} to '{Folder}' and restart '{Service}'"
    };

    public override string ToString() => $"{Server.ToString().ToLowerInvariant()}|{Folder}|{Service}";

    public static WebServerTarget Parse(string value)
    {
        var parts = value.Split('|', StringSplitOptions.TrimEntries);
        if (parts.Length != 3 || !Enum.TryParse<WebServerKind>(parts[0], ignoreCase: true, out var server) || !Enum.IsDefined(server) ||
            parts[1].Length == 0 || parts[2].Length == 0)
        {
            throw new ArgumentException(ErrorCodes.DeploymentStepInvalid.Format(
                $"'{value}' is not a web server step. Give apache, nginx or tomcat, the certificate folder and the service, as apache|D:\\Certs\\shop|Apache2.4."));
        }

        var folder = parts[1].Trim('"');
        if (!Path.IsPathFullyQualified(folder))
        {
            throw new ArgumentException(ErrorCodes.DeploymentStepInvalid.Format($"'{folder}' must be a full path, such as D:\\Certs\\shop."));
        }

        return new WebServerTarget(server, Path.GetFullPath(folder), parts[2]);
    }
}
