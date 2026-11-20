# Automation

Feature 21 of [the delivery plan](delivery-plan.md). How scripts, schedulers and monitoring tools drive SSLense: JSON output, exit codes, settings export and import, and a PowerShell module.

## JSON output

Add `--json` to any command, for example `SSLense.Cli status --json`. Instead of text, the command writes one JSON document to standard output:

```json
{
  "command": "renew",
  "exitCode": 1,
  "succeeded": false,
  "errorCode": "SSL3002",
  "data": [ { "siteName": "Shop", "attempted": true, "succeeded": false, "message": "..." } ],
  "output": [ "lines the command printed" ],
  "errors": [ "Error: SSL3002: ...", "More: https://..." ]
}
```

- `exitCode` is the same as the process exit code (see below).
- `errorCode` is the first SSL code in the errors, or `null`. Each code is explained in [errors.md](errors.md).
- `data` holds the command's result for these commands, and is `null` for the others. Those still report their outcome in `output`, `errors` and `exitCode`.

  | Command | `data` |
  |---|---|
  | `status` | The managed certificates, with expiry and renewal state |
  | `list-sites` | IIS sites and their bindings |
  | `renew` | One result per certificate |
  | `health` | One result per check |
  | `history` | The timeline and whether rollback is available |
  | `cleanup list` | The clean-up candidates |
  | `version` | This version, and a newer release if one is published |

- The properties use camelCase and enums are written as names. New properties may be added in later versions; existing ones are not renamed.
- Commands that wait for someone to type, such as `issue --validation dns-manual`, are not for `--json`: the prompt is captured with the output, so nobody sees it.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. For `health`, no check failed (warnings are allowed). |
| 1 | The command ran and failed, or found a problem. The error line starts with an SSL code. |
| 2 | The command line was not valid: an unknown command or option, or a missing or wrong value. |
| 3 | The command must run as an administrator. Open an elevated terminal. |

In 0.23 and earlier, codes 2 and 3 were both reported as 1.

## Settings export and import

`config export` writes this server's settings to a file:

- the default email;
- staging or production;
- the renewal and reminder settings;
- the maintenance window;
- the version check;
- certificate authorities, DNS providers and notifications.

`config import` puts them on another server.

```powershell
# On the old server
SSLense.Cli config export --file D:\move\settings.json --certificates D:\move\certificates.csv
# On the new server
SSLense.Cli config import --file D:\move\settings.json --yes
SSLense.Cli bulk issue --file D:\move\certificates.csv --dry-run
```

- **Secrets:** DNS tokens, notification passwords and webhook URLs, and EAB keys are protected with DPAPI. DPAPI copies only open on the server that made them, so by default the export leaves them out.
  - A file without secrets imports only the general settings. The certificate authorities, DNS providers and notifications on the new server stay as they are.
  - To move those too, put a password in the `SSLENSE_CONFIG_PASSWORD` environment variable and export with `--include-secrets`. The secrets are then encrypted with AES-256-GCM, using a key derived from the password (PBKDF2-SHA256, 600,000 iterations).
  - Import such a file with the same variable set. The secrets are protected with DPAPI on the new server.
  - The password is never accepted on the command line, so it stays out of shell history.
- **Before importing:** the current settings are saved as `config.before-import-<time>.json` in the data folder. The import is refused (SSL6032) if a certificate here is renewed by a certificate authority that the file doesn't have. Restart the SSLense service after an import.
- **Certificates:** `--certificates` writes the certificates SSLense issues for IIS sites as a CSV file for [`bulk issue`](../README.md). Certificates are issued again on the new server, because private keys never leave the machine store. These are listed as not written:
  - certificates from other providers;
  - certificates with manual DNS validation;
  - certificates with no site;
  - shared certificates;
  - additional certificates on a site.

## PowerShell module

The installer adds a script module next to the CLI. It runs `SSLense.Cli --json` and returns objects, so it needs no PowerShell SDK.

```powershell
Import-Module 'C:\Program Files\SSLense\cli\PowerShell\SSLense'
Get-SslenseCertificate | Where-Object { $_.notAfter -lt (Get-Date).AddDays(14) }
Invoke-SslenseRenewal -Site 'Shop' -WhatIf
Get-SslenseHistory -Site 'Shop'
Undo-SslenseCertificate -Site 'Shop'          # rollback; asks first
Export-SslenseConfig -Path D:\move\settings.json -Password (Read-Host -AsSecureString)
Invoke-Sslense dns list                       # any command, as its JSON result
```

| Function | Command |
|---|---|
| `Invoke-Sslense <arguments> [-ThrowOnError]` | Any command; returns the JSON document |
| `Get-SslenseCertificate` | `status` |
| `Get-SslenseSite` | `list-sites` |
| `Get-SslenseHistory -Site` | `history` |
| `Test-SslenseHealth` | `health` |
| `Invoke-SslenseRenewal -Site \| -All [-Force]` | `renew`, with `-WhatIf` |
| `Undo-SslenseCertificate -Site` | `rollback`, with confirmation |
| `Export-SslenseConfig -Path [-Password] [-CertificatesPath]` | `config export` |
| `Import-SslenseConfig -Path [-Password]` | `config import`, with confirmation |

With `-ThrowOnError`, which every function except `Invoke-Sslense` and `Test-SslenseHealth` uses, a failed command throws. The exception's `Data` holds the error code and the exit code: `$_.Exception.Data['ErrorCode']` and `$_.Exception.Data['ExitCode']`. The module runs in Windows PowerShell 5.1 and PowerShell 7, from an elevated session.

Manual tests: [testing/automation.md](testing/automation.md).
