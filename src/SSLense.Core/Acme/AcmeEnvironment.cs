namespace SSLense.Core.Acme;

public enum AcmeEnvironment
{
    Staging = 0,
    Production = 1
}

public static class AcmeEnvironmentExtensions
{
    public static string DisplayName(this AcmeEnvironment environment) => environment switch
    {
        AcmeEnvironment.Staging => "staging",
        AcmeEnvironment.Production => "production",
        _ => throw new ArgumentOutOfRangeException(nameof(environment), environment, null)
    };

    public static Uri DirectoryUri(this AcmeEnvironment environment) => environment switch
    {
        AcmeEnvironment.Staging => new("https://acme-staging-v02.api.letsencrypt.org/directory"),
        AcmeEnvironment.Production => new("https://acme-v02.api.letsencrypt.org/directory"),
        _ => throw new ArgumentOutOfRangeException(nameof(environment), environment, null)
    };
}
