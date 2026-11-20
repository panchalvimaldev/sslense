# Delivery plan: the whole roadmap, then one test

Status: **approved** November 19, 2026. Progress is marked here as each pull request merges.

The owner's decision (November 19, 2026): build every feature in [ROADMAP.md](../ROADMAP.md) first, then write an automated and a manual test document and test everything together before the next release.

## How the work is done

- **One feature at a time.** Each one gets its own branch and pull request into `main`. CI runs the automated tests on every pull request, Codex can review it, and the owner merges it.
- **Larger features start with a short design** in `docs/design/`, approved before any code, as for several certificates per site.
- **No version tags or releases** until the combined test has passed. `main` stays buildable and green throughout.
- **Test lists build up as features land.** Each pull request adds its own unit tests, plus a section of manual test steps in `docs/testing/` (created with the first feature). The combined test documents are put together from these at the end.
- **No new NuGet packages without approval.** Where a feature would need one, the plan says so below, and the owner decides when that feature starts. Cloud APIs are called over plain HTTPS, without vendor SDKs.
- **Let's Encrypt staging only,** as always.

## Order

Grouped into waves; each line is one pull request unless it says otherwise. Sizes are rough: S is a day or less, M a few days, L a week or more.

### Wave 0: work already built

| # | Feature | Size | Notes |
|---|---|---|---|
| 0 | Several ACME certificates on one IIS site (phase 2) | — | **Done**: pull request #38 |

### Wave 1: safety before 1.0 (ROADMAP 5.1, 5.2)

| # | Feature | Size | Notes |
|---|---|---|---|
| 1 | Stable, searchable error codes **(done)** | M | First, so every later feature uses them. Each message gets a code such as `SSL1042`, with a page in the docs |
| 2 | Maintenance windows **(done)** | M | Renewals wait for an allowed time, but never so long that a certificate could expire |
| 3 | Recovery from a compromised private key or ACME account **(done)** | M | Revoke and replace a certificate at once; roll over the ACME account key; written procedures |
| 4 | ARI `replaces` field on renewal orders **(done)** | S–M | Certes does not expose it. Either a newer Certes version (a package change, needs approval) or sending the order request ourselves |

Already done and only to be marked on the roadmap: private-key permissions for IIS application pools (deployment steps, 0.18).

### Wave 2: validation and issuance (ROADMAP 4, Later, After 1.0)

| # | Feature | Size | Notes |
|---|---|---|---|
| 5 | HTTP validation without a port 80 binding **(done)** | M | SSLense answers the challenge itself through HTTP.sys, which shares port 80 with IIS |
| 6–10 | Built-in DNS providers: Amazon Route 53, Azure DNS, Google Cloud DNS, DigitalOcean, Hetzner **(done, in one pull request)** | S–M each | One pull request each, over HTTPS without SDKs. Each stays labelled untested until it has run on a real account |
| 11 | Certificates for IP addresses **(done)** | M | Let's Encrypt issues them with short-lived profiles; validated over HTTP or TLS-ALPN, bound in IIS by IP |
| 12 | TLS-ALPN-01 validation | Design first | IIS owns port 443 through HTTP.sys, which cannot answer this challenge. The design decides whether a safe way exists, for example briefly on a server without HTTPS sites, or records that it does not |
| 13 | Newer DNS methods such as dns-persist-01 | S | Built only once a certificate authority offers it; until then, a design note |
| 14 | Sharing a certificate with a site that has several certificates **(done: from such a site; to one stays refused, see design 9.5)** | M | Deferred in phase 2 (design section 9.5) |

### Wave 3: day-to-day operations (ROADMAP 4, After 1.0)

| # | Feature | Size | Notes |
|---|---|---|---|
| 15 | Certificates on other machines **(done)** | M | Host names not on this server, such as load balancers, in the daily served-certificate check and reminders |
| 16 | HTTP-to-HTTPS redirect helper **(done)** | M | An IIS URL Rewrite rule, checked so it never blocks validation; needs the URL Rewrite module on the server |
| 17 | Bulk operations **(done)** | M | Watch every unmanaged certificate at once; issue for many sites from a CSV file |
| 18 | New version notice **(done)** | S | Reads GitHub releases; can be turned off; never installs anything |
| 19 | Clean-up of unused certificates **(done)** | M | Expired, duplicate, self-signed and staging certificates in `LocalMachine\My` that nothing uses, with a confirmation before each removal |
| 20 | Certificate history and one-click rollback **(done)** | L | A timeline per certificate, and going back to the previous certificate while it is still valid |
| 21 | Automation **(done: the PowerShell module is a script module over the CLI)** | L | JSON output for every CLI command, documented exit codes, configuration export and import. A PowerShell module would need the PowerShell SDK package: needs approval, or it becomes a script module over the CLI |
| 22 | More notifications **(done)** | M | Signed webhook payloads; email through Microsoft Graph for Microsoft 365 tenants without SMTP |

### Wave 4: more places to put certificates (Later, After 1.0)

| # | Feature | Size | Notes |
|---|---|---|---|
| 23 | IIS FTP sites **(done)** | M | The FTP site's SSL certificate, renewed like a web site's |
| 24 | Export to Azure Key Vault **(done)** | M | Over its REST API with an app registration, so no SDK package |
| 25 | Other deployment targets **(done: HTTP.sys, Remote Desktop, SQL Server, Apache, nginx, Tomcat and Azure App Service; Exchange stays a ready-made script)** | L, several PRs | HTTP.sys, Kestrel, Remote Desktop Services, SQL Server and Exchange as first-class targets (scripts exist today); Apache, nginx and Tomcat on Windows (files and a reload); Azure App Service (REST). Each with install, verify, rollback and remove |
| 26 | Web farms | L, design first | HTTP validation across servers through a shared folder or WebDAV, and the certificate kept in step on every server. SFTP would need a package: needs approval |
| 27 | Several servers from one place | XL, design first | Close to a second product: a central view with roles, built so every server keeps renewing when the central part is down. Last, so everything before it is stable |

### Wave 5: distribution and project health (ROADMAP 5.3–5.5)

| # | Feature | Size | Notes |
|---|---|---|---|
| 28 | Accessibility | M | Keyboard navigation, high contrast and scalable text across the app |
| 29 | Dependency scanning and a software bill of materials in CI | S | |
| 30 | Documentation | M | Threat model, quick start, firewall, DNS and proxy requirements, troubleshooting runbooks, migration guides, release notes, known issues and an upgrade table |
| 31 | winget package | S | The manifest is ready in the repository; it is submitted to winget after the first release that follows the combined test |

Not planned: code signing, which the owner has declined. Compatibility work in ROADMAP 5.4 (Windows and IIS versions, proxies, NAT, IPv6, international names, accessibility checks) becomes part of the combined test documents rather than code.

## After the last feature

1. The automated test document: what CI covers, the Pebble end-to-end tests, and any new automated tests for gaps found while writing it.
2. The manual test document: every feature's steps from `docs/testing/`, in an order that sets up a test server once, on Let's Encrypt staging.
3. The combined test, fixes, then a release.
