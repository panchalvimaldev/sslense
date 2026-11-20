# SSLense PowerShell module: a thin layer over SSLense.Cli --json (docs/automation.md).
# Every function runs the CLI and returns its JSON result as objects; nothing here changes certificates on its own.

Set-StrictMode -Version Latest

function Get-SslenseCliPath {
    $installed = Join-Path $PSScriptRoot '..\..\SSLense.Cli.exe'
    if (Test-Path -LiteralPath $installed) { return (Resolve-Path -LiteralPath $installed).Path }
    $command = Get-Command 'SSLense.Cli.exe' -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    throw 'SSLense.Cli.exe was not found next to the module or on PATH. Install SSLense, or import the module from its installation folder.'
}

function Invoke-Sslense {
    <#
    .SYNOPSIS
    Runs any SSLense.Cli command and returns its JSON result.
    .DESCRIPTION
    Returns an object with Command, ExitCode, Succeeded, ErrorCode, Data, Output and Errors. With -ThrowOnError, a failed
    command throws an error that carries the SSL error code instead.
    .EXAMPLE
    Invoke-Sslense status
    .EXAMPLE
    Invoke-Sslense renew --site 'Contoso' -ThrowOnError
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromRemainingArguments)]
        [string[]] $Arguments,
        [switch] $ThrowOnError
    )

    $cli = Get-SslenseCliPath
    $json = & $cli @Arguments --json
    $exitCode = $LASTEXITCODE
    $result = ($json -join "`n") | ConvertFrom-Json
    if ($ThrowOnError -and $exitCode -ne 0) {
        $message = (@($result.Errors) + @($result.Output) | Select-Object -First 1)
        $exception = [System.InvalidOperationException]::new("SSLense.Cli $($Arguments -join ' ') failed (exit code $exitCode): $message")
        $exception.Data['ErrorCode'] = $result.ErrorCode
        $exception.Data['ExitCode'] = $exitCode
        throw $exception
    }

    $result
}

function Get-SslenseCertificate {
    <#
    .SYNOPSIS
    The certificates SSLense manages, with their expiry and renewal state.
    #>
    [CmdletBinding()]
    param()
    (Invoke-Sslense status -ThrowOnError).Data
}

function Get-SslenseSite {
    <#
    .SYNOPSIS
    The IIS sites and their bindings.
    #>
    [CmdletBinding()]
    param()
    (Invoke-Sslense list-sites -ThrowOnError).Data
}

function Get-SslenseHistory {
    <#
    .SYNOPSIS
    What happened to a certificate, newest first, and whether it can roll back.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipelineByPropertyName)] [Alias('SiteName')] [string] $Site)
    process { (Invoke-Sslense history --site $Site -ThrowOnError).Data }
}

function Test-SslenseHealth {
    <#
    .SYNOPSIS
    Runs the health check and returns each check's result.
    #>
    [CmdletBinding()]
    param()
    (Invoke-Sslense health).Data
}

function Invoke-SslenseRenewal {
    <#
    .SYNOPSIS
    Renews one certificate, or every certificate that is due.
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'All')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Site', ValueFromPipelineByPropertyName)] [Alias('SiteName')] [string] $Site,
        [Parameter(ParameterSetName = 'All')] [switch] $All,
        [switch] $Force
    )
    process {
        $arguments = @('renew')
        $arguments += if ($PSCmdlet.ParameterSetName -eq 'Site') { @('--site', $Site) } else { @('--all') }
        if ($Force) { $arguments += '--force' }
        $target = if ($PSCmdlet.ParameterSetName -eq 'Site') { $Site } else { 'every due certificate' }
        if ($PSCmdlet.ShouldProcess($target, 'Renew')) { (Invoke-Sslense @arguments -ThrowOnError).Data }
    }
}

function Undo-SslenseCertificate {
    <#
    .SYNOPSIS
    Binds the certificate the last renewal replaced again (a rollback). Running it again rolls forward.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory, ValueFromPipelineByPropertyName)] [Alias('SiteName')] [string] $Site)
    process {
        if ($PSCmdlet.ShouldProcess($Site, 'Roll back to the previous certificate')) { Invoke-Sslense rollback --site $Site -ThrowOnError }
    }
}

function Export-SslenseConfig {
    <#
    .SYNOPSIS
    Writes this server's settings to a file. With -Password, the secrets are included, encrypted with it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [securestring] $Password,
        [string] $CertificatesPath
    )
    $arguments = @('config', 'export', '--file', $Path)
    if ($CertificatesPath) { $arguments += @('--certificates', $CertificatesPath) }
    if ($Password) { $arguments += '--include-secrets' }
    Invoke-WithPassword $Password { Invoke-Sslense @arguments -ThrowOnError }
}

function Import-SslenseConfig {
    <#
    .SYNOPSIS
    Replaces this server's settings with a file written by Export-SslenseConfig.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [securestring] $Password
    )
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Replace the SSLense settings with '$Path'")) {
        Invoke-WithPassword $Password { Invoke-Sslense config import --file $Path --yes -ThrowOnError }
    }
}

# The CLI reads the password from SSLENSE_CONFIG_PASSWORD, set only while it runs, so it never appears on a command line.
function Invoke-WithPassword([securestring] $Password, [scriptblock] $Script) {
    $previous = $env:SSLENSE_CONFIG_PASSWORD
    try {
        if ($Password) { $env:SSLENSE_CONFIG_PASSWORD = [System.Net.NetworkCredential]::new('', $Password).Password }
        . $Script
    }
    finally {
        $env:SSLENSE_CONFIG_PASSWORD = $previous
    }
}

Export-ModuleMember -Function Invoke-Sslense, Get-SslenseCertificate, Get-SslenseSite, Get-SslenseHistory, Test-SslenseHealth,
    Invoke-SslenseRenewal, Undo-SslenseCertificate, Export-SslenseConfig, Import-SslenseConfig
