# Threat model

What SSLense protects, from whom, and how. This is for administrators who decide whether to run it, and for contributors who change it. Report weaknesses privately as [SECURITY.md](../SECURITY.md) describes.

## What SSLense holds

| Asset | Where | Protection |
|---|---|---|
| Certificate private keys | `LocalMachine\My`, as Windows CNG or CAPI keys | Non-exportable unless a certificate is issued with `--exportable-key` for an export step. No PFX file is kept |
| ACME account keys, one per certificate authority | `C:\ProgramData\SSLense\account-key.*.dat` | DPAPI (LocalMachine scope), in a folder only Administrators and SYSTEM may open |
| Secrets in the settings | `config.json` and `managed-certificates.json`: DNS provider tokens, EAB keys, notification passwords and webhook URLs, webhook signing secrets, export and Tomcat passwords, Azure app registrations | DPAPI (LocalMachine), in the same restricted folder |
| State | Managed certificates, transactions, history, reminder state, logs | The restricted folder |
| Scripts SSLense runs | Its own copies in `dns-scripts` and `deploy-scripts` under the data folder | Copied when added, checked by SHA-256 before every run |

**DPAPI LocalMachine:** any process on the machine may decrypt a blob it can read. The folder's ACL is the real boundary. SSLense sets that ACL at install and at every start, and refuses links and multi-link files inside the folder. `SSLense.Cli check-permissions` reports problems, and so does the health check.

## Trust boundaries

1. **Certificate authorities.**
   - SSLense trusts the ACME directory it is given, over HTTPS with normal certificate validation.
   - Let's Encrypt staging is the default. A trusted CA needs an explicit `--accept-production-risk` when a certificate is first issued from it.
2. **DNS providers.**
   - Tokens are scoped by you; give each only its zone.
   - Before validation, SSLense checks propagation at the zone's authoritative name servers, so a resolver it does not control cannot fake success.
3. **IIS and HTTP.sys.**
   - Changes are made through Microsoft.Web.Administration and `netsh`, under a per-site lock and a transaction journal.
   - Every HTTPS binding is checked by an HTTPS request after it changes, and put back if the check fails.
4. **Shares** (web farm folders, fleet reports, the Central Certificate Store): they are trusted to hold what SSLense writes, and nothing more.
   - Challenge files are public by design.
   - Fleet reports hold names and dates, never keys or secrets.
   - Exported PFX files are protected by their password.
5. **Cloud APIs** (Azure Key Vault, App Service, Microsoft Graph, DNS providers): HTTPS only, with client credentials kept by DPAPI. Error messages carry the service's error code, never the request.
6. **Administrators:** every command needs elevation. Anyone who is an administrator on the server can read everything above. SSLense does not try to protect secrets from them.

## Threats and what stops them

| Threat | Mitigation |
|---|---|
| A local, non-administrator user reads keys or secrets | Non-exportable keys; data folder restricted to Administrators and SYSTEM; checked at start |
| Secrets leak through logs or messages | Secrets are never logged, shown or put in errors; URLs are shown by host only; webhook signing secrets and Graph or Azure secrets appear once at entry |
| A tampered script runs as SYSTEM | Only SSLense's own copy runs, and only when its SHA-256 still matches |
| A wrong or broken certificate takes a site down | Validation before install, HTTP.sys trial binding, HTTPS check after binding, automatic put-back; previous certificate kept for one-click rollback |
| Interrupted operation leaves IIS half-changed | Transaction journal; recovery at the next start |
| Accidental production use and rate limits | Staging default; explicit confirmation for trusted CAs; backoff and rate-limit-aware retries |
| A compromised key or ACME account | `revoke` replaces then revokes; `account change-key`; runbook [compromised-key-or-account.md](runbooks/compromised-key-or-account.md) |
| Forged webhook notifications | HMAC-SHA256 signatures with a timestamp on generic webhooks |
| Supply chain | Few dependencies, none added without the owner's approval; every build fails on a known-vulnerable package; an SBOM with each release ([design](design/supply-chain.md)) |
| Settings files moved between servers | Secrets are left out unless encrypted with a password (AES-256-GCM, PBKDF2-SHA256 with 600,000 iterations) |

## Not in scope

- **A malicious administrator, or malware running as SYSTEM:** these own the server.
- **The security of IIS, Windows, the CA, the DNS provider or Azure.**
- **Code signing:** releases are not signed. Check the SHA-256 published with each release.
- **The central fleet view:** it is designed, not built ([design](design/fleet.md)). Until it exists, no server accepts commands from another.
