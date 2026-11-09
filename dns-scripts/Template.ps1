<#
.SYNOPSIS
    A starting point for an SSLense DNS script. Copy it, fill in the three actions for your DNS service, then add it:

        SSLense.Cli dns add --provider script --name "MyDns" --zone example.com --script C:\Scripts\MyDns.ps1 --secret
        SSLense.Cli dns test --name "MyDns"

.DESCRIPTION
    SSLense runs this script with Windows PowerShell 5.1 to publish the TXT records that prove you control a domain.
    The renewal service runs it as SYSTEM, so:

    - SSLense runs its own copy, kept where only administrators can change it. After you change this file, run
      'SSLense.Cli dns update-script' to take a new copy.
    - Install any module it needs for all users (Install-Module -Scope AllUsers). A module installed only for your
      account works in 'dns test' and then fails at renewal.
    - Do not keep credentials in this file. Use --secret: SSLense stores it encrypted and passes it in the
      SSLENSE_DNS_SECRET environment variable. For two values, such as a key and a secret, use "key:secret".

    Exit with 0 when the action worked, and anything else when it did not. SSLense shows the last 20 lines of
    output with a failure, with the secret removed. Each call may run for 2 minutes unless --timeout says otherwise.

    SSLense does not rely on this script's word: after Add, it checks that every authoritative name server for the
    zone returns the record before it asks the certificate authority.
#>
param(
    # Check: confirm the credentials can change the zone, without changing anything.
    # Add: add one TXT record with this value. Keep any other values at the same name.
    # Remove: remove only the TXT record with this exact value.
    [Parameter(Mandatory)][ValidateSet('Check', 'Add', 'Remove')][string]$Action,

    # The zone the provider was added for, such as example.com.
    [Parameter(Mandatory)][string]$Zone,

    # The full record name, such as _acme-challenge.www.example.com.
    [Parameter(Mandatory)][string]$RecordName,

    # The record's value. Not passed for Check.
    [string]$Value
)

$ErrorActionPreference = 'Stop'
$secret = $env:SSLENSE_DNS_SECRET

try {
    switch ($Action) {
        'Check' {
            # Read something from the zone with the credentials, so a wrong or expired secret is found before an
            # order. If your service cannot do that, leave this as it is: exiting 0 is allowed.
        }
        'Add' {
            # Add a TXT record named $RecordName with the value $Value, with the lowest TTL your service allows.
            throw 'Add is not written yet.'
        }
        'Remove' {
            # Find the TXT records named $RecordName, and delete only the one whose value is exactly $Value.
            throw 'Remove is not written yet.'
        }
    }

    exit 0
}
catch {
    # Never print $secret: SSLense removes it from what it shows, but it should not be written in the first place.
    Write-Output "$Action failed for $RecordName`: $($_.Exception.Message)"
    exit 1
}
