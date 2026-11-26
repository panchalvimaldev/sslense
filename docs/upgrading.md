# Upgrading, and known issues

## How to upgrade

1. Run the new MSI. It upgrades in place and keeps `C:\ProgramData\SSLense`. The renewal service is stopped and started again.
2. On first use, SSLense rewrites its state files in their new format:
   - It keeps a copy of each file as it was, `<file>.v<old version>.bak`, next to it. The oldest copy of each version is kept.
   - Interrupted operations from before the upgrade are recovered at start, as always.
3. Run `SSLense.Cli health`.

**Downgrades are not supported.** An older SSLense refuses files written by a newer one (SSL6023), and leaves them untouched. To go back:
1. Install the newer version again.
2. Or restore the `.bak` copies with the older version installed. Changes made since the upgrade are lost.

## Versions and state formats

The numbers are the schema versions of `managed-certificates.json` and `config.json`. A higher number means older versions cannot read the file.

| SSLense | Certificates | Settings | What changed in state |
|---|---|---|---|
| 0.9.11 | 1 | 2 | Versioned files with record IDs; email, chat channels, heartbeat and the Event Log |
| 0.10.x | 2 | 3 | Any ACME certificate authority; certificates from other providers |
| 0.11.x–0.12.x | 3 | 4–5 | Reminders per certificate; proactive checks |
| 0.13.0 | 4 | 6 | DNS validation and DNS providers |
| 0.14.0–0.16.0 | 5 | 6–7 | Sites sharing a certificate; DNS scripts and acme-dns |
| 0.22.x | 10 | 8 | Deployment steps, no-site certificates, exports, key and order options, key reuse |
| 0.23.0 | 11 | 8 | Several certificates on one IIS site |
| 0.24.0 (not released yet) | 21 | 11 | See below |

0.24.0 changes:
- **Certificates:**
  - HTTP validation answered by SSLense;
  - certificates on other machines;
  - the previous certificate kept for rollback;
  - FTP, HTTP.sys, Remote Desktop, SQL Server and web server deployment steps.
- **Settings:**
  - the maintenance window and the new DNS providers;
  - signed webhooks.
- **New files:** `history.json`.
- **Skipped numbers:** some versions in the table were used during development by features removed before release (Key Vault, App Service, web farms, Microsoft Graph email, fleet reports). Nothing they stored is read any more.

**A server that skips versions** is upgraded in one step. Every migration runs in order.

## Known issues

- **Not yet tested against real accounts.** These are tested only against test doubles until the combined test ([testing documents](testing/)):
  - the built-in Azure DNS, Google Cloud DNS, DigitalOcean and Hetzner DNS providers. Amazon Route 53 passed the combined test.
- **The renewal service needs elevation for real port 80 registration:** HTTP validation answered by SSLense registers `http://+:80/.well-known/acme-challenge/` with HTTP.sys. It is covered by the manual tests only.
- **High contrast:** turning it on or off while the app runs takes effect at the next start.
- **TLS-ALPN-01 validation is not available:** IIS owns port 443 through HTTP.sys ([plan](delivery-plan.md), item 12).
- **Exchange:** it is updated through the ready-made `Exchange.ps1` script, not a built-in step. Its settings are reachable only through the Exchange Management Shell.
- **Unsigned releases:** Windows SmartScreen may warn about a downloaded MSI. Check its SHA-256, or install with winget or the PowerShell commands in the README, which check it for you ([about the warning](../README.md#about-the-smartscreen-warning)).
- **Web farms:** HTTP challenges are not copied to other servers. In a farm, use DNS validation, and the Central Certificate Store step to keep every server in step.
