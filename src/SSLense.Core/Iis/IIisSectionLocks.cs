namespace SSLense.Core.Iis;

public interface IIisSectionLocks
{
    /// <summary>
    /// Returns the configuration sections, from those given, that a web.config at this path inside the site may set.
    /// IIS refuses every request under a web.config that sets a locked or unknown section, so the others must be left out.
    /// Returns null when IIS configuration cannot be read.
    /// </summary>
    IReadOnlySet<string>? GetSettableSections(string siteName, string relativePath, IReadOnlyCollection<string> sectionPaths);
}
