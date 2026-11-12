<#
.SYNOPSIS
    A starting point for an SSLense deployment script. Copy it, write what should happen with each new certificate,
    then add it to a certificate:

        SSLense.Cli deploy add --site "Shop" --script C:\Scripts\MyDeploy.ps1
        SSLense.Cli deploy run --site "Shop"

.DESCRIPTION
    SSLense runs this script with Windows PowerShell 5.1 after every install and renewal of the certificate, once it is
    installed in LocalMachine\My and bound in IIS. The renewal service runs it as SYSTEM, so:

    - SSLense runs its own copy, kept where only administrators can change it. After you change this file, remove the
      step and add it again ('SSLense.Cli deploy remove', then 'deploy add').
    - Install any module it needs for all users (Install-Module -Scope AllUsers).
    - Do not keep passwords in this file.

    Exit with 0 when it worked, and anything else when it did not. SSLense shows the last 20 lines of output with a
    failure, and retries every hour; the certificate itself stays installed either way. A run may take 5 minutes unless
    'deploy add --timeout' says otherwise. Make it safe to run twice: 'deploy run' runs it again for the same certificate.
#>
param(
    # The new certificate, in LocalMachine\My.
    [Parameter(Mandatory)][string]$Thumbprint,

    # The certificate the steps last completed for, if any. Still installed while the steps are pending.
    [string]$PreviousThumbprint,

    # Every host the certificate is bound for, comma-separated.
    [string]$Hosts,

    # When the certificate expires, in ISO 8601 (UTC).
    [string]$NotAfter,

    # The IIS site the certificate belongs to.
    [string]$Site
)

$ErrorActionPreference = 'Stop'

try {
    $certificate = Get-Item "Cert:\LocalMachine\My\$Thumbprint"
    Write-Output "Deploying $($certificate.Subject) ($Thumbprint), valid until $NotAfter, for $Hosts."

    # Hand the certificate to your service here.
    throw 'The deployment is not written yet.'

    exit 0
}
catch {
    Write-Output "Deployment failed: $($_.Exception.Message)"
    exit 1
}
