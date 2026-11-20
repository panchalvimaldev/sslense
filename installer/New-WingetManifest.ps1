<#
.SYNOPSIS
    Writes the winget manifests for an SSLense release, ready to submit to microsoft/winget-pkgs.
.DESCRIPTION
    Reads the release's MSI SHA-256 from the .sha256 file published next to it, so the manifest matches exactly what
    users download (docs/design/winget.md). Writes the three files winget's multi-file format needs:
    <id>.yaml (version), <id>.installer.yaml and <id>.locale.en-US.yaml, under
    artifacts/winget/manifests/p/panchalvimal/SSLense/<version>/.

    Submit only after the release has passed the combined test; the owner submits it.
.PARAMETER Version
    The release version, such as 0.24.0. The GitHub release v<Version> must exist.
.PARAMETER Sha256
    The MSI's SHA-256, to write manifests before the .sha256 file can be downloaded (for example in tests).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$Sha256
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$identifier = 'panchalvimal.SSLense'
$manifestVersion = '1.6.0'
$msi = "SSLense-$Version-x64.msi"
$url = "https://github.com/panchalvimaldev/sslense/releases/download/v$Version/$msi"

if (-not $Sha256) {
    $line = (Invoke-WebRequest "$url.sha256" -UseBasicParsing).Content.Trim()
    $Sha256 = ($line -split '\s+')[0]
    if ($Sha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw "The published $msi.sha256 does not start with a SHA-256: '$line'." }
}

# The installer's UpgradeCode, fixed for every version (installer/SSLense.Installer/Package.wxs).
$upgradeCode = '{46AACC03-4D31-4B13-B631-65B9718C4476}'
$header = "# yaml-language-server: `$schema=https://aka.ms/winget-manifest"

$files = [ordered]@{
    "$identifier.yaml" = @"
$header.version.$manifestVersion.schema.json
PackageIdentifier: $identifier
PackageVersion: $Version
DefaultLocale: en-US
ManifestType: version
ManifestVersion: $manifestVersion
"@
    "$identifier.installer.yaml" = @"
$header.installer.$manifestVersion.schema.json
PackageIdentifier: $identifier
PackageVersion: $Version
MinimumOSVersion: 10.0.17763.0
InstallerType: wix
Scope: machine
InstallModes:
  - interactive
  - silent
  - silentWithProgress
UpgradeBehavior: install
ElevationRequirement: elevatesSelf
AppsAndFeaturesEntries:
  - UpgradeCode: '$upgradeCode'
Installers:
  - Architecture: x64
    InstallerUrl: $url
    InstallerSha256: $($Sha256.ToUpperInvariant())
ManifestType: installer
ManifestVersion: $manifestVersion
"@
    "$identifier.locale.en-US.yaml" = @"
$header.defaultLocale.$manifestVersion.schema.json
PackageIdentifier: $identifier
PackageVersion: $Version
PackageLocale: en-US
Publisher: panchalvimal
PublisherUrl: https://github.com/panchalvimaldev
PublisherSupportUrl: https://github.com/panchalvimaldev/sslense/issues
PackageName: SSLense
PackageUrl: https://sslense.com
License: Apache-2.0
LicenseUrl: https://github.com/panchalvimaldev/sslense/blob/main/LICENSE
ShortDescription: Free certificates for IIS from Let's Encrypt or any ACME certificate authority, renewed automatically.
Description: |-
  SSLense issues, installs and renews certificates for IIS sites from Let's Encrypt or any ACME certificate authority,
  validated over HTTP or DNS, and installs certificates bought from other providers safely. A desktop app, a CLI and
  a Windows service; Let's Encrypt staging by default.
Moniker: sslense
Tags:
  - acme
  - certificate
  - https
  - iis
  - letsencrypt
  - ssl
  - tls
ReleaseNotesUrl: https://github.com/panchalvimaldev/sslense/releases/tag/v$Version
ManifestType: defaultLocale
ManifestVersion: $manifestVersion
"@
}

$folder = Join-Path $root "artifacts/winget/manifests/p/panchalvimal/SSLense/$Version"
New-Item -ItemType Directory -Force $folder | Out-Null
foreach ($name in $files.Keys) {
    # winget-pkgs expects UTF-8 without a byte order mark.
    [System.IO.File]::WriteAllText((Join-Path $folder $name), ($files[$name] -replace "`r`n", "`n") + "`n", [System.Text.UTF8Encoding]::new($false))
}

Write-Host "Manifests for $identifier $Version written to $folder."
Write-Host "Check them with: winget validate --manifest `"$folder`""
