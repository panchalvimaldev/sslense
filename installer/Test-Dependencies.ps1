<#
.SYNOPSIS
    Checks SSLense's NuGet packages for known vulnerabilities, and writes a CycloneDX software bill of materials.
.DESCRIPTION
    Uses only the .NET SDK (docs/design/supply-chain.md):
    - 'dotnet list package --vulnerable --include-transitive' against the NuGet advisory database. Any vulnerable package,
      direct or transitive, in any project fails the script, so CI fails.
    - 'dotnet list package --include-transitive' for the shipped apps (CLI, app, service and Core, not the tests), turned
      into CycloneDX 1.5 JSON with a package URL for every component.
.PARAMETER SbomPath
    Where to write the SBOM. Without it, only the vulnerability check runs.
.PARAMETER Version
    The SSLense version the SBOM describes; read from Directory.Build.props when not given.
#>
[CmdletBinding()]
param(
    [string]$SbomPath,
    [string]$Version
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$solution = Join-Path $root 'SSLense.sln'

function Get-Packages([string]$Target, [string[]]$Extra) {
    $json = & dotnet list $Target package --include-transitive --format json @Extra
    if ($LASTEXITCODE -ne 0) { throw "dotnet list package failed for $Target." }
    return ($json -join "`n") | ConvertFrom-Json
}

# 1. Known vulnerabilities, every project, direct and transitive.
$report = Get-Packages $solution @('--vulnerable')
$found = foreach ($project in $report.projects) {
    foreach ($framework in @($project.frameworks)) {
        foreach ($package in @($framework.topLevelPackages) + @($framework.transitivePackages)) {
            if ($null -ne $package -and $package.vulnerabilities) {
                foreach ($vulnerability in $package.vulnerabilities) {
                    '{0}: {1} {2} ({3}) {4}' -f (Split-Path $project.path -Leaf), $package.id, $package.resolvedVersion, $vulnerability.severity, $vulnerability.advisoryurl
                }
            }
        }
    }
}

if ($found) {
    $found | ForEach-Object { Write-Host "Vulnerable: $_" }
    throw "$(@($found).Count) vulnerable package(s). Update them, or record why one cannot be updated yet in docs/design/supply-chain.md."
}

Write-Host 'No known vulnerable packages, direct or transitive.'

if (-not $SbomPath) { return }

# 2. CycloneDX SBOM for what SSLense ships.
if (-not $Version) {
    $Version = ([xml](Get-Content (Join-Path $root 'Directory.Build.props'))).Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1
}

$components = @{}
foreach ($project in 'SSLense.Core', 'SSLense.Cli', 'SSLense.Gui', 'SSLense.Service') {
    $listed = Get-Packages (Join-Path $root "src/$project/$project.csproj") @()
    foreach ($framework in @($listed.projects[0].frameworks)) {
        foreach ($package in @($framework.topLevelPackages) + @($framework.transitivePackages)) {
            if ($null -eq $package) { continue }
            $purl = "pkg:nuget/$($package.id)@$($package.resolvedVersion)"
            $components[$purl] = [ordered]@{
                type      = 'library'
                'bom-ref' = $purl
                name      = $package.id
                version   = $package.resolvedVersion
                purl      = $purl
                scope     = 'required'
            }
        }
    }
}

$bom = [ordered]@{
    bomFormat    = 'CycloneDX'
    specVersion  = '1.5'
    serialNumber = "urn:uuid:$([guid]::NewGuid())"
    version      = 1
    metadata     = [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        tools     = @([ordered]@{ vendor = 'SSLense'; name = 'installer/Test-Dependencies.ps1' })
        component = [ordered]@{
            type      = 'application'
            'bom-ref' = "pkg:github/panchalvimaldev/sslense@$Version"
            name      = 'SSLense'
            version   = $Version
            licenses  = @(@{ license = @{ id = 'Apache-2.0' } })
            purl      = "pkg:github/panchalvimaldev/sslense@$Version"
        }
    }
    components   = @($components.Keys | Sort-Object | ForEach-Object { $components[$_] })
}

$directory = Split-Path $SbomPath -Parent
if ($directory) { New-Item -ItemType Directory -Force $directory | Out-Null }
$bom | ConvertTo-Json -Depth 8 | Out-File $SbomPath -Encoding utf8
Write-Host "SBOM with $($bom.components.Count) component(s) written to $SbomPath."
