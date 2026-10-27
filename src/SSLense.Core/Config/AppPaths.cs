namespace SSLense.Core.Config;

public static class AppPaths
{
    public static string DataDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "SSLense");

    public static string ConfigFile => Path.Combine(DataDirectory, "config.json");

    public static string ConfigLockFile => Path.Combine(DataDirectory, "config.lock");

    public static string LogDirectory => Path.Combine(DataDirectory, "logs");

    public static string AccountKeyFile => Path.Combine(DataDirectory, "account-key.staging.dat");

    public static string CertificateDirectory => Path.Combine(DataDirectory, "certificates");

    public static string ManagedCertificatesFile => Path.Combine(DataDirectory, "managed-certificates.json");

    public static string ManagedCertificatesLockFile => Path.Combine(DataDirectory, "managed-certificates.lock");
}
