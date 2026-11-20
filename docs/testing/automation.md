# Manual tests: automation

Feature 21 of [the delivery plan](../delivery-plan.md); described in [docs/automation.md](../automation.md).

| # | Steps | Expected |
|---|---|---|
| 1 | Elevated: `SSLense.Cli status --json` | One JSON document; `exitCode` 0; `data` lists the certificates |
| 2 | Not elevated: `SSLense.Cli status --json`; then `echo $LASTEXITCODE` | `exitCode` 3 in the document and as the process exit code |
| 3 | `SSLense.Cli status --bogus`; `echo $LASTEXITCODE` | 2 |
| 4 | `SSLense.Cli rollback --site <site without a previous certificate> --json` | `exitCode` 1, `errorCode` "SSL4055" |
| 5 | `SSLense.Cli config export --file C:\temp\s.json` | The file has `"secrets": "removed"` and no tokens |
| 6 | `$env:SSLENSE_CONFIG_PASSWORD='…'`; `config export --file C:\temp\s2.json --include-secrets --certificates C:\temp\c.csv` | Secrets start with `enc:`; the CSV has one line per issued certificate |
| 7 | On a second server: `config import --file s2.json --yes` with the password set | DNS providers and notifications appear in Settings and their Test buttons work; a `config.before-import-*.json` is in the data folder |
| 8 | Import `s2.json` with a wrong password | SSL6031; settings unchanged |
| 9 | `Import-Module 'C:\Program Files\SSLense\cli\PowerShell\SSLense'`; `Get-SslenseCertificate`; `Invoke-SslenseRenewal -Site <site> -WhatIf` | Objects listed; the renewal only reports what it would do |
| 10 | `Get-SslenseHistory -Site nothing` | Throws; `$Error[0].Exception.Data['ErrorCode']` is an SSL code |
