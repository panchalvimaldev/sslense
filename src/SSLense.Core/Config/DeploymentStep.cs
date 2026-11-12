namespace SSLense.Core.Config;

public enum DeploymentStepKind
{
    /// <summary>Gives an account read access to the certificate's private key.</summary>
    GrantKeyAccess = 0,

    /// <summary>Restarts a Windows service and waits for it to run again.</summary>
    RestartService = 1,

    /// <summary>Runs SSLense's own copy of a PowerShell script, checked by hash.</summary>
    Script = 2
}

/// <summary>Something that runs after every install and renewal of a certificate. See docs/design/deployment-steps.md.</summary>
/// <param name="Value">The account, as Windows names it; the service name; or, for a script, the original file's name, for display.</param>
/// <param name="ScriptSha256">For a script, the hash of SSLense's copy, which is checked before every run.</param>
/// <param name="TimeoutSeconds">For a script, how long it may run.</param>
public sealed record DeploymentStep(
    Guid Id,
    DeploymentStepKind Kind,
    string Value,
    string? ScriptSha256 = null,
    int? TimeoutSeconds = null)
{
    public string Describe() => Kind switch
    {
        DeploymentStepKind.GrantKeyAccess => $"Grant '{Value}' read access to the private key",
        DeploymentStepKind.RestartService => $"Restart the service '{Value}'",
        DeploymentStepKind.Script => $"Run the script '{Value}'",
        _ => $"Unknown step '{Value}'"
    };
}

/// <summary>How a certificate's deployment steps last ran.</summary>
/// <param name="CompletedThumbprint">The certificate every step last succeeded for. The steps are pending while it differs from the record's.</param>
/// <param name="PreviousThumbprint">The certificate the steps completed for before that one, given to scripts.</param>
/// <param name="LastError">Why the last run stopped, or null when it succeeded.</param>
/// <param name="ConsecutiveFailures">Runs that failed since the last success.</param>
/// <param name="RetainedThumbprint">An earlier certificate kept in the store because services may still use it until the steps succeed.</param>
public sealed record DeploymentState(
    string? CompletedThumbprint = null,
    string? PreviousThumbprint = null,
    DateTimeOffset? LastAttempt = null,
    string? LastError = null,
    int ConsecutiveFailures = 0,
    string? RetainedThumbprint = null);

public static class ManagedCertificateDeployment
{
    public static bool HasDeploymentSteps(this ManagedCertificate record) => record.DeploymentSteps is { Count: > 0 };

    /// <summary>True when the record has steps that have not yet succeeded for its current certificate.</summary>
    public static bool HasPendingDeployment(this ManagedCertificate record) =>
        record.HasDeploymentSteps() &&
        !string.Equals(record.Deployment?.CompletedThumbprint, record.Thumbprint, StringComparison.OrdinalIgnoreCase);
}
