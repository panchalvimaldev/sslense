# Release notes

Older releases are described on their [GitHub release pages](https://github.com/panchalvimaldev/sslense/releases).

## 0.24.0 (not released yet)

Prepared for the combined test. Read [upgrading.md](upgrading.md) first: this version rewrites the state files, and 0.23 cannot read them afterwards.

### Safer renewals

- **History and rollback:** each certificate has a timeline (History tab, `history`). If a renewal breaks something, roll back to the previous certificate with **⋯ › Roll back…** or `rollback`, and roll forward the same way.
- **Maintenance windows:** scheduled renewals wait for the hours you choose, but never so long that a certificate could expire.
- **Renewal information (ARI):** each order tells the CA which certificate it replaces.
- **Compromised key or account:** `revoke` replaces the certificate first and then revokes it, and `account change-key` replaces the ACME account key ([runbook](runbooks/compromised-key-or-account.md)).

### More ways to validate

- **HTTP validation answered by SSLense** on port 80, so a site needs no HTTP binding (`--validation http-self`).
- **Built-in DNS providers:** Amazon Route 53, Azure DNS, Google Cloud DNS, DigitalOcean and Hetzner, without SDKs.
- **Certificates for IP addresses.**
- **Web farms:** HTTP challenges copied to the other servers' folders (`--farm-folders`, `farm`).

### More places for a certificate

- **New deployment steps:**
  - IIS FTP sites;
  - HTTP.sys endpoints outside IIS, such as WinRM;
  - Remote Desktop;
  - SQL Server;
  - Apache, nginx and Tomcat on Windows;
  - Azure Key Vault;
  - Azure App Service.
- **Certificates on other machines:** load balancers and appliances are watched and reminded about (`watch`).
- **Older binding layouts:** HTTPS bindings without a host name are renewed in place, and bindings on other ports, such as 8443, follow the certificate. Sites with them can now be adopted.

### Day-to-day work

- **HTTP-to-HTTPS redirect** for a site, which leaves validation alone (`redirect`).
- **Bulk operations:** watch every unmanaged certificate, and issue for many sites from a CSV file (`bulk`).
- **Clean-up** of expired, test and replaced certificates that nothing uses.
- **New-version notice:** shown in the app's header, and can be turned off.
- **Notifications:** signed webhook payloads, and email through Microsoft Graph for Microsoft 365 tenants without SMTP.
- **Fleet reports:** several servers report to one shared folder, and `fleet status` shows them all.

### Automation

- **JSON output:** `--json` on every command.
- **Exit codes:** 0 success, 1 failed, 2 invalid command line, 3 not elevated.
- **Settings export and import:** with secrets encrypted by a password if you choose.
- **PowerShell module:** a script module over the CLI.

### For everyone

- **Accessibility:** keyboard and screen readers on every screen, Windows high contrast, and larger text with Ctrl+Plus and Ctrl+Minus.
- **Error codes:** every error has a code linked to [what to do](errors.md).
- **Supply chain:** each build checks the dependencies for known vulnerabilities, and each release carries a software bill of materials.

### Changes that may affect you

- **Exit codes:** an invalid command line now exits 2 instead of 1, and a command run without elevation exits 3 instead of 1. Check scripts that test for 1.
- **Previous certificate kept:** after a renewal, the replaced certificate stays in `LocalMachine\My` until the next renewal, for rollback. Revoke and replace still removes it.
- **SQL Server step restarts the instance:** the new built-in step restarts the instance at every renewal. To restart it yourself, keep the ready-made script instead.

### Dependencies

- **MailKit 5.0** (from 4.18), which sends email over SMTP. It now uses MimeKit.Core 5.0 instead of MimeKit. Sending works as before, but this is a major version, so test email notifications after upgrading.
- **System.CommandLine 3.0** (from 2.0), which parses the CLI's commands and options. Commands, options, help and the documented exit codes are unchanged.
- **Microsoft.Extensions 11.0 and System.Diagnostics.EventLog 11.0** (from 10.0), for hosting, the Windows service and the Event Log. SSLense still runs on .NET 10.
- **CommunityToolkit.Mvvm 8.4.2** (from 8.4.0).
- **For contributors:** Moq 4.21 and the newer test SDK; the build uses newer GitHub Actions.

### Not tested on real accounts yet

The new DNS providers, Graph email, Key Vault and App Service. See [known issues](upgrading.md#known-issues).
