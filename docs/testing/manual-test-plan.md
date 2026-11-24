# Manual test plan: the combined test

Everything to check by hand before the next release (0.24.0), in one pass. Run it after the [automated tests](automated-tests.md) pass on the same build. Each feature's steps live in its own document, linked below, so the steps and the design stay together. This plan sets the order, the environment and the sign-off.

**Record each result:** in the Result column, write ✅, ❌ (with an issue link) or *n/a* (with the reason). A ❌ in a section marked **Blocks release** stops the release.

## 1. Environment

| What | Used by | Notes |
|---|---|---|
| **Test server A**: Windows Server 2022 with IIS, Management Tools, FTP Server and URL Rewrite (`tests/SSLense.Acceptance/setup-server.ps1`) | Everything | Snapshot it before starting |
| **Test server B**: same, joined to the same network | Web farms, fleet | |
| A public test domain with a **Cloudflare** zone, a token limited to it, and `*.accept.<zone>` pointing at A | HTTP and DNS validation, acceptance checks | Delete the token afterwards |
| Port 80 and 443 on A open to the internet | HTTP validation | |
| A share both servers can write (computer accounts) | Web farms, fleet, Central Certificate Store | |
| SQL Server Express on A; Remote Desktop on | Service steps | |
| Apache, nginx (as a service) and Tomcat on A | Web server step | Any one is enough for a pass; all three for full coverage |
| An Azure test subscription: a key vault, a web app on Basic with a custom domain, an app registration | Key Vault, App Service, Azure DNS | |
| A Microsoft 365 test tenant with an app registration (Mail.Send) | Graph email | |
| Test accounts at Route 53, Google Cloud DNS, DigitalOcean and Hetzner | DNS providers | Each optional; untested ones stay listed as untested |
| webhook.site (or any request bin) and the ntfy app | Notifications | |
| A Windows 11 desktop | The app, accessibility | |
| SSLense **0.23.0** MSI, and the **0.24.0** release candidate MSI with its `.sha256`, SBOM and winget zip | Install and upgrade | |

**Let's Encrypt staging only**, except where a step names another test CA. Never production.

## 2. Install and upgrade (blocks release)

| # | Steps | Expected | Result |
|---|---|---|---|
| 1 | On A, install 0.23.0, issue two staging certificates (one HTTP, one DNS), add a deployment step | Working 0.23.0 setup | ✅ (0.23.0) |
| 2 | Check the 0.24.0 MSI's SHA-256 against the published `.sha256`; install it over 0.23.0; then renew one certificate with `--force` | Upgraded; the service runs; both certificates and the step are still there, unchanged; the renewal succeeds and, as the first save in the new format, leaves `.v<n>.bak` copies | ✅ (5ffea16) |
| 3 | `SSLense.Cli health` | No failures | ✅ 28 passed, 1 warning (no notifications set up) |
| 4 | Reinstall 0.23.0 over 0.24.0 | 0.23.0 refuses the newer data (SSL6023) and changes nothing. 0.23.0 itself reports it as invalid JSON (SSL6022) when it meets a value it does not know; fixed from 0.24.0 ([#83](https://github.com/panchalvimaldev/sslense/pull/83)) | ✅ |
| 5 | Install 0.24.0 again; uninstall; install | `C:\ProgramData\SSLense` kept and used again | ✅ |
| 6 | On a clean VM, download the MSI in Edge and run it | SmartScreen may warn ("Windows protected your PC"); the README's steps (check the SHA-256, then More info › Run anyway or Unblock) install it |
| 7 | On a clean VM, run the README's PowerShell download-and-verify commands | The SHA-256 check passes and the installer runs; note whether SmartScreen prompts |

## 3. Acceptance checks on real IIS (blocks release)

Run each command from [tests/SSLense.Acceptance](../../tests/SSLense.Acceptance/README.md) on A, with the release candidate's CLI (`--cli`).

| # | Command | Result |
|---|---|---|
| 1 | `parta` | ✅ 83/83 (79b9460) |
| 2 | `partb --zone <zone>` | ✅ 124/124 (482c14c); the first run on 79b9460 found [#82](https://github.com/panchalvimaldev/sslense/pull/82) |
| 3 | `httpcheck --zone <zone>` | ✅ 14/14 (482c14c) |
| 4 | `scriptcheck --zone <zone>` | ✅ 38/38 (79b9460) |
| 5 | `servicecheck --zone <zone>` | ✅ 13/13 (79b9460) |

## 4. Features

Run each linked document's steps in order. The count is its number of steps.

### Renewing safely (blocks release)

| Feature | Steps | Result |
|---|---|---|
| [Certificate history and rollback](history-and-rollback.md) | 9 | ✅ 9/9 (5ffea16); step 1 checked through the CLI |
| [Maintenance windows](maintenance-windows.md) | 7 | ✅ 7/7 (5ffea16); steps 3 and 5 used revoked certificates, which ARI makes due at once |
| [ARI replaces](ari-replaces.md) | 2 | ✅ 2/2 (5ffea16) |
| [Recovery from a compromised key or account](compromise-recovery.md) | 7 | ✅ 7/7 (5ffea16) |
| [Error codes](error-codes.md) | 7 | |

### Validation

| Feature | Steps | Result |
|---|---|---|
| [HTTP validation without a port 80 binding](self-hosted-http-validation.md) — **blocks release** | 7 | |
| [Built-in DNS providers](dns-providers.md) | 6 per provider | |
| [Certificates for IP addresses](ip-certificates.md) | 5 | |
| [Web farms](web-farms.md) | 7 | |

### Where certificates go

| Feature | Steps | Result |
|---|---|---|
| [IIS FTP sites](ftp-sites.md) | 8 | |
| [HTTP.sys bindings outside IIS](httpsys-bindings.md) | 6 | |
| [Remote Desktop and SQL Server](service-targets.md) | 6 | |
| [Apache, nginx and Tomcat](web-servers.md) | 6 | |
| [Azure Key Vault](key-vault.md) | 8 | |
| [Azure App Service](app-service.md) | 6 | |
| [Sharing from a site with several certificates](sharing-from-multi-certificate-site.md) | 4 | |
| [Bindings without a host name, and on other ports](other-bindings.md) — **blocks release** | 10 | |

### Day-to-day

| Feature | Steps | Result |
|---|---|---|
| [Certificates on other machines](remote-certificates.md) | 8 | |
| [HTTP-to-HTTPS redirect](https-redirect.md) | 7 | |
| [Bulk operations](bulk-operations.md) | 5 | |
| [New version notice](version-notice.md) | 5 | |
| [Clean-up of unused certificates](certificate-cleanup.md) | 4 | |
| [Signed webhooks and Microsoft Graph email](more-notifications.md) | 8 | |
| [Fleet reports](fleet.md) | 8 | |
| [Automation: JSON, exit codes, settings export, PowerShell](automation.md) | 10 | |

### For everyone

| Feature | Steps | Result |
|---|---|---|
| [Accessibility](accessibility.md) — **blocks release** | 7 | |
| [Dependency scanning and the SBOM](supply-chain.md) | 6 | |
| [The winget package](winget.md) | 5 | |

## 5. Compatibility

One check per row: issue a staging certificate, renew it with `--force`, and open the site. For desktop rows, open the app.

| Environment | Result |
|---|---|
| Windows Server 2016, IIS 10 | |
| Windows Server 2019, IIS 10 | |
| Windows Server 2022, IIS 10 | |
| Windows Server 2025, IIS 10 | |
| Windows 11 with IIS (desktop app and CLI) | |
| Server Core (CLI and service only) | |
| Behind an HTTP proxy set with `setx /M HTTPS_PROXY` ([requirements](../network-requirements.md)) | |
| Behind NAT, with port 80 forwarded | |
| An IPv6-only host name (AAAA record only) | |
| An internationalized domain name (for example `bücher.<zone>`, as punycode in IIS) | |
| Text size 175% and a contrast theme on Windows 11 | |
| A non-English Windows display language (netsh output is translated) | |

## 6. Documentation

| # | Check | Result |
|---|---|---|
| 1 | Follow the [quick start](../../README.md#quick-start) on a clean server, word for word | |
| 2 | Follow [moving SSLense to another server](../runbooks/move-or-restore-server.md) from A to B | |
| 3 | Every link in [docs/README.md](../README.md) opens | |
| 4 | [Known issues](../upgrading.md#known-issues) match what this test found | |

## 7. Sign-off

| | |
|---|---|
| Build tested (version, SHA-256) | |
| Automated tests (CI run link) | |
| Tested by, dates | |
| Open ❌ items and their issues | |
| Decision: release / fix first | |

After a release decision:
1. Tag the release.
2. Publish the release notes from [release-notes.md](../release-notes.md).
3. Submit the winget manifests ([winget.md](../design/winget.md)).
4. Submit the release's MSI to Microsoft Security Intelligence (https://www.microsoft.com/wdsi/filesubmission) as a software developer, so SmartScreen has an analysis of it.
5. Never rebuild or replace a published MSI: its SmartScreen reputation belongs to that exact file. A fix is a new version.
