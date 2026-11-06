using System.Runtime.InteropServices;
using Microsoft.Web.Administration;

namespace SSLense.Core.Iis;

/// <summary>
/// Reads which sections a site's folder may override. A plain IIS install without ASP.NET locks system.webServer/handlers,
/// and a section such as security/authorization is unknown until its feature is installed.
/// </summary>
internal sealed class IisSectionLocks : IIisSectionLocks
{
    public IReadOnlySet<string>? GetSettableSections(
        string siteName,
        string relativePath,
        IReadOnlyCollection<string> sectionPaths)
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        Configuration configuration;
        ServerManager manager;
        try
        {
            manager = new ServerManager();
            configuration = manager.GetApplicationHostConfiguration();
        }
        catch (Exception exception) when (exception is COMException or UnauthorizedAccessException or FileNotFoundException)
        {
            return null;
        }

        using (manager)
        {
            var location = $"{siteName}/{relativePath.Trim('/')}";
            var settable = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var sectionPath in sectionPaths)
            {
                try
                {
                    if (configuration.GetSection(sectionPath, location).OverrideModeEffective == OverrideMode.Allow)
                    {
                        settable.Add(sectionPath);
                    }
                }
                catch (COMException)
                {
                    // The section is not declared, because the feature that defines it is not installed.
                }
            }

            return settable;
        }
    }
}
