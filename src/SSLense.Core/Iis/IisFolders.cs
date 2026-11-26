namespace SSLense.Core.Iis;

/// <summary>Folders IIS keeps for itself, which no site should use.</summary>
internal static class IisFolders
{
    /// <summary>
    /// Whether a site's physical path is IIS's configuration history folder (by default %SystemDrive%\inetpub\history),
    /// where IIS keeps backups of its configuration. Only Administrators and SYSTEM can read it, so a site there answers
    /// 401 or 500, and SSLense must not write challenge files into it. Found in the combined test: a test site created with
    /// New-Item -Force silently reused it.
    /// </summary>
    public static bool IsConfigHistory(string physicalPath)
    {
        try
        {
            var history = Normalize(@"%SystemDrive%\inetpub\history");
            var path = Normalize(physicalPath);
            return string.Equals(path, history, StringComparison.OrdinalIgnoreCase) ||
                   path.StartsWith(history + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private static string Normalize(string path) =>
        Path.GetFullPath(Environment.ExpandEnvironmentVariables(path)).TrimEnd(Path.DirectorySeparatorChar);
}
