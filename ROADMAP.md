# SSLense Roadmap

SSLense is free and open source under the [Apache License 2.0](LICENSE). This roadmap describes how it gets to a dependable 1.0 release and what comes after. It replaces the earlier commercial roadmap; commercial plans are on hold and may be revisited later.

## 1. Principles

- Certificate renewal is safe, automatic, observable, and recoverable.
- A failed operation never leaves a site without its previous working binding.
- Private keys and credentials are never logged or transmitted unexpectedly.
- GUI, CLI, and service call the same Core operations.
- Destructive actions require explicit confirmation.
- Let's Encrypt staging is the default; production requires an explicit choice.

## 2. Current status

Complete:

- IIS site and binding discovery; HTTP-01 issuance against separated Let's Encrypt staging and guarded production
- Certificate-store installation with non-exportable keys and no retained PFX files; SNI binding management with live HTTPS verification and automatic rollback
- Automatic renewal service: ARI-aware scheduling with a lifetime-relative fallback (also used when the CA's renewal window times out), a persisted retry schedule, hourly checks, rate-limit handling, and escalating failure notifications
- Notifications by email (any SMTP setup, including IP-based relays), Teams, Slack, Discord, Telegram, ntfy, generic webhooks, a heartbeat ping, and the Windows Event Log
- Certificates from other providers such as 123-reg (0.10): certificate requests (CSRs) whose private key is a non-exportable machine key, completion with the issued certificate and bundle, PFX import, and adoption of certificates already bound in IIS. Every install is validated first (host coverage, validity, server-authentication purpose, key match, and the full chain with its dates) and uses the same journal, HTTPS verification, and rollback as Let's Encrypt.
- Certificate authority profiles in place of the hard-coded Let's Encrypt environment (0.10): the groundwork for other ACME CAs
- Expiry reminders (0.11): one daily digest, sent only when a certificate needs attention, from a configurable number of days before expiry and repeating until it is renewed; a notice before each automatic renewal; per-certificate snooze, off until replaced, or off permanently; an optional weekly summary; and detection of certificates renewed outside SSLense
- Daily report-only checks (0.12): the pre-flight checks in the 30 days before each automatic renewal, and a comparison of the certificate this server serves with the one SSLense expects, with problems reported in the digest after two daily failures in a row; an option to keep reminding about automatic certificates until they renew; a log line for each reminder decision; and an estimate of the next check, email, and reminder for each certificate
- DNS validation and wildcard certificates (0.13): Cloudflare, CNAME delegation from any DNS service, and a manual method; propagation checks at the zone's authoritative name servers; CAA checks before ordering; DPAPI-protected, per-zone tokens; a journal that removes records left by an interrupted validation; one wildcard per IIS site; in the GUI and CLI ([design](docs/design/dns-validation.md))
- One certificate across several IIS sites (0.14): `share add` and `share remove`, a trial of each new certificate before any real site changes, sites moved one at a time and checked over HTTPS, checked restores, and rules for a site with a problem, so that it cannot take the others down ([design](docs/design/shared-certificates.md)). Tested on Windows 11 and Windows Server with IIS 10, on Let's Encrypt staging and production. Testing on Windows Server also found and fixed an older bug: HTTP validation failed on IIS without ASP.NET
- DNS validation through a script (0.15): any DNS service with an API, through the administrator's PowerShell script with `Check`, `Add`, and `Remove` actions; SSLense runs only its own copy, in its restricted data folder, checked by hash before every run; one optional DPAPI-protected secret passed in the environment; output redacted and runs stopped after a timeout; propagation still checked at the authoritative name servers; a template and a working Cloudflare example installed with SSLense ([design](docs/design/dns-script.md))
- Other ACME certificate authorities (0.16): presets for ZeroSSL, Google Trust Services, SSL.com, and Sectigo, or any ACME directory; External Account Binding with a DPAPI-protected HMAC key; the CA's directory read before it is added, including the CAA identities it publishes, so CAA checks work for every CA; a confirmation for every CA that is not a test endpoint, enforced in Core; a CA choice in the Issue wizard and Settings; and the ACME client tested end to end against Pebble in CI ([design](docs/design/certificate-sources.md), section 9)
- DNS validation through acme-dns (0.17): one CNAME, created once at any DNS host, and an acme-dns account whose credential can change only the validation record; registration or import from SSLense, an optional allowed network, the CNAME checked before each order and daily, and the account's two-value limit checked before ordering ([design](docs/design/acme-dns.md))
- Deployment steps (0.18): after every install and renewal, read access to the private key for an account such as an IIS application pool, a Windows service restart, or a PowerShell script run as SSLense's own checked copy; ready-made scripts for Remote Desktop, SQL Server, and Exchange; a failed step retried hourly while the previous certificate is kept ([design](docs/design/deployment-steps.md))
- Certificates with no IIS site (0.19): issued and renewed through DNS under a name instead of a site, for Remote Desktop, SQL Server, and other services that deployment steps hand them to; removal keeps the certificate in the store ([design](docs/design/no-site-certificates.md))
- Certificate export (0.20): an exportable key chosen per certificate at issue; deployment steps that write a password-protected PFX, PEM files with an administrators-only key, or one PFX per name to the IIS Central Certificate Store; passwords encrypted with DPAPI ([design](docs/design/certificate-export.md))
- Cross-process per-site locking, durable operation journals, and non-fatal startup recovery
- Health check (CLI and GUI) and redacted diagnostic bundles for support
- Versioned state schemas with backup before migration and safe refusal of newer schemas
- `C:\ProgramData\SSLense` restricted to Administrators and SYSTEM, with link-safe hardening
- WPF GUI (Dashboard, Issue Certificate, Other Providers, Certificate Details, Settings, Health, Logs) and matching CLI; the window header shows the quick health check result
- Log viewer with level and text filters, selectable and copyable text, older days and backups, and Clear log that keeps a backup; every SSLense process writes the shared log under one machine-wide lock
- .NET 10 (LTS); self-contained WiX v7 MSI with service registration, upgrades, and silent install
- Branding (icon and logo) across the apps, shortcut, and Add/Remove Programs

A real production issuance remains a manual acceptance test and is never run during development.

The first installation on a real server (October 31, 2026) found the problems fixed in 0.10.1 to 0.10.5: an FTP-only site broke site listing, the log folder could not be opened, and several screens hid their results.

## 3. Certificate lifetime requirements

Scheduling must not assume 90-day certificates.

- Let's Encrypt moved its staging default to 64-day certificates on October 14, 2026, and plans the same for production on February 10, 2027.
- Default lifetimes are expected to keep decreasing toward 45 days.
- SSLense uses ACME Renewal Information (ARI, RFC 9773) and falls back to lifetime-relative scheduling.

References:

- [Let's Encrypt: 64-Day Certificate Lifetimes Coming February 2027](https://letsencrypt.org/2026/10/07/64-day-certs)
- [Let's Encrypt: Decreasing Certificate Lifetimes to 45 Days](https://letsencrypt.org/2025/12/02/from-90-to-45)
- [Let's Encrypt: ACME Renewal Information Published as RFC 9773](https://letsencrypt.org/2025/09/16/ari-rfc)

## 4. Next development

In priority order. Feedback from real users can change the order.

1. **Azure Key Vault.** Export certificates to Azure Key Vault as another kind of step. It needs Microsoft's client library, a new dependency, so it waits for demand.
2. **Key and order options.** A choice of RSA or ECDSA (issuance currently uses ECDSA P-256), optional private-key reuse for sites that pin keys, the CA's preferred chain, and ACME profiles where the CA offers them, such as short-lived certificates.
3. **Built-in DNS providers.** The script method (0.15) covers any service with an API; built-in providers save writing one. One at a time, starting with Amazon Route 53, Azure DNS, Google Cloud DNS, DigitalOcean, and Hetzner, then whichever users ask for most. Each stays labelled untested until it has run on a real account. Providers are compiled in, not loaded as plugins, because the service runs as SYSTEM.
4. **HTTP validation without a port 80 binding.** A short-lived listener of SSLense's own answers the challenge, for sites that have only HTTPS bindings or whose port 80 is used by something else.
5. **Certificates on other machines.** Add host names that are not on this server, such as load balancers and appliances, to the daily served-certificate check, so one place reminds about every certificate.
6. **HTTP-to-HTTPS redirect helper** using an IIS URL Rewrite rule, with a check that it does not block validation.
7. **Bulk operations.** Adopt every unmanaged certificate at once, and issue for many sites from a CSV file.
8. **New version notice.** Tell the administrator when a newer release is available, with a setting to turn the check off. Never install anything automatically.

Later, by demand: certificates for IP addresses, TLS-ALPN-01 validation, IIS FTP sites, and managing several servers from one place.

## 5. Before 1.0

These keep users' sites safe and make SSLense supportable without paid support. Each must be done before a 1.0 release.

### 5.1 Remaining safety work

- Send the ARI `replaces` field on renewal orders (Certes does not expose it yet).
- ~~Journal challenge files so an interrupted validation is cleaned up on recovery.~~ Done October 28, 2026.
- Certificate private-key permissions for IIS application-pool identities (part of item 2 in section 4).
- Configurable maintenance windows that can never let a certificate expire.
- Recovery procedures for a compromised ACME account or private key.

### 5.2 Diagnostics and health check

Done (October 28, 2026): `SSLense.Cli health` and the GUI Health page; a redacted diagnostic bundle (`SSLense.Cli diagnostics`, optional host redaction) with tests that scan it for seeded secrets; a service heartbeat recording each cycle; and a GitHub bug-report template that asks for both.

Remaining:

- Stable, searchable error codes.
- ~~Show the health summary on the Dashboard.~~ Done October 28, 2026: a banner appears when the quick local checks find a problem.

### 5.3 Distribution

- ~~Release builds from GitHub Actions with SHA-256 checksums attached to each GitHub Release.~~ Done October 28, 2026 (`.github/workflows/release.yml`); first used by the v0.9.10 tag.
- Authenticode signing of executables and the MSI, for example through the free [SignPath Foundation](https://signpath.org/) program for open-source projects. Unsigned MSIs trigger Windows SmartScreen warnings.
- ~~An installer UI showing the Apache-2.0 license.~~ Done October 28, 2026, with SSLense branding.
- A [winget](https://learn.microsoft.com/windows/package-manager/) package.
- Install, upgrade, repair, and uninstall verified on each supported Windows Server version.

### 5.4 Quality and compatibility

- A published support matrix of Windows Server and IIS versions, backed by repeatable tests on real IIS virtual machines.
- HTTP-01 tested through direct public IPs, NAT, reverse proxies, and Cloudflare Tunnel.
- IPv4, IPv6, internationalized domain names, SAN certificates, and large binding sets.
- HTTPS bindings without a host name, and on ports other than 443. SSLense manages SNI bindings on port 443, and adoption refuses the others with an explanation; common on servers with older sites.
- Outbound proxies, restricted firewalls, TLS inspection, and clock skew.
- Accessibility: keyboard navigation, high contrast, and scalable text.

### 5.5 Project health

- A documented threat model, updated with each major architecture change.
- Dependency and vulnerability scanning in CI, and a software bill of materials for each release.
- ~~Private vulnerability reporting (see [SECURITY.md](SECURITY.md)) with response targets.~~ Done October 28, 2026.
- Release notes, known issues, and an upgrade compatibility table.
- Documentation: a quick start, firewall/DNS/proxy requirements, troubleshooting runbooks, and migration guides from manual IIS certificates and other ACME clients.

## 6. After 1.0

Ordered roughly by expected demand. Community feedback decides the order.

- **Several certificates per site:** move locks, journals, and CLI/GUI selection from site name to the certificate ID every record already has.
- **Existing-certificate discovery:** adopting a certificate already bound in IIS was added in 0.10. Remaining: find expired, duplicate, self-signed, and staging certificates in `LocalMachine\My` that no binding uses, and suggest clean-up.
- **Certificate history and one-click rollback:** a timeline for each certificate (issued, renewed, replaced, failed) and a way to go back to the previous certificate while it is still valid.
- **Web farms and load-balanced sites:** HTTP-01 validation across several servers (shared storage, FTP, SFTP, or WebDAV) and keeping the certificate in step on every server.
- **More validation methods:** TLS-ALPN-01, self-hosted HTTP validation for servers whose sites cannot serve the challenge, and newer DNS methods such as dns-persist-01 as certificate authorities adopt them.
- **ACME profiles and IP address certificates,** including shorter-lived certificates, as certificate authorities offer them.
- **Automation:** JSON output for every CLI command, documented exit codes, a PowerShell module, and configuration import/export.
- **More notification channels:** signed webhook payloads, and email through the Microsoft Graph API for Microsoft 365 tenants that disable SMTP. (Teams, Slack, Discord, Telegram, ntfy, a heartbeat, the Event Log, and email for any SMTP setup were added October 28, 2026.)
- **Other deployment targets:** HTTP.sys, Kestrel, Remote Desktop Services, SQL Server, Exchange, Apache, nginx, Tomcat, and Azure App Service, each with install, verify, rollback, and remove operations.
- **Multi-server management:** a possible later project with role-based access, built so each server's renewal keeps working when any central component is unavailable.

## 7. Sustainability

SSLense is maintained voluntarily. Donations through [GitHub Sponsors](https://github.com/sponsors/panchalvimaldev) help pay for test infrastructure and code signing. Any future paid offering, such as optional services or support, would leave the open-source core intact. Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
