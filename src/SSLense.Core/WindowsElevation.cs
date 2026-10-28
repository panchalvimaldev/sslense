using System.Security.Principal;

namespace SSLense.Core;

public static class WindowsElevation
{
    public const string RequiredMessage =
        "SSLense must run as Administrator to manage IIS, the LocalMachine certificate store, and " +
        "C:\\ProgramData\\SSLense. Open an elevated terminal (Run as administrator) and try again.";

    public static bool IsAdministrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
