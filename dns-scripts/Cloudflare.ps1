<#
.SYNOPSIS
    An SSLense DNS script for Cloudflare. SSLense has Cloudflare built in, so you only need this as a complete example
    of a script, or to try the script method.

        SSLense.Cli dns add --provider script --name "Cloudflare script" --zone example.com --script C:\Scripts\Cloudflare.ps1 --secret
        SSLense.Cli dns test --name "Cloudflare script"

.DESCRIPTION
    The secret is "<zone ID>:<API token>". The zone ID is on the domain's Overview page in Cloudflare. Use a token
    with Zone > DNS > Edit on this one zone. See Template.ps1 for how SSLense runs a script.
#>
param(
    [Parameter(Mandatory)][ValidateSet('Check', 'Add', 'Remove')][string]$Action,
    [Parameter(Mandatory)][string]$Zone,
    [Parameter(Mandatory)][string]$RecordName,
    [string]$Value
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Invoke-Cloudflare([string]$Method, [string]$Path, $Body) {
    $request = @{
        Method  = $Method
        Uri     = "https://api.cloudflare.com/client/v4/zones/$zoneId$Path"
        Headers = @{ Authorization = "Bearer $token" }
        UseBasicParsing = $true
    }
    if ($null -ne $Body) {
        $request.ContentType = 'application/json'
        $request.Body = $Body | ConvertTo-Json -Compress
    }

    try {
        return Invoke-RestMethod @request
    }
    catch {
        # Cloudflare explains a refusal in its JSON response; show that rather than only the HTTP status.
        $details = $_.ErrorDetails.Message
        if ($details) {
            $errors = ($details | ConvertFrom-Json).errors
            if ($errors) {
                $error0 = $errors[0]
                throw [System.Exception]::new("Cloudflare error $($error0.code): $($error0.message)")
            }
        }
        throw
    }
}

function Find-Records {
    $name = [Uri]::EscapeDataString($RecordName)
    return @((Invoke-Cloudflare 'GET' "/dns_records?type=TXT&name=$name").result)
}

try {
    $parts = "$env:SSLENSE_DNS_SECRET".Split(':', 2)
    if ($parts.Count -ne 2 -or $parts[0].Length -ne 32) {
        throw 'The secret must be "<zone ID>:<API token>". Set it with: SSLense.Cli dns update-token --name <provider>'
    }
    $zoneId = $parts[0]
    $token = $parts[1]

    switch ($Action) {
        'Check' {
            $null = Find-Records
        }
        'Add' {
            # An earlier attempt may have added this exact value already.
            if (-not (Find-Records | Where-Object { $_.content.Trim('"') -ceq $Value })) {
                $null = Invoke-Cloudflare 'POST' '/dns_records' @{ type = 'TXT'; name = $RecordName; content = $Value; ttl = 60 }
            }
        }
        'Remove' {
            foreach ($record in Find-Records | Where-Object { $_.content.Trim('"') -ceq $Value }) {
                $null = Invoke-Cloudflare 'DELETE' "/dns_records/$($record.id)"
            }
        }
    }

    exit 0
}
catch {
    Write-Output "$Action failed for $RecordName`: $($_.Exception.Message)"
    exit 1
}
