# Automated tests

The part of the combined test that runs by itself. The [manual test plan](manual-test-plan.md) covers the rest.

## What runs, and where

| Suite | Runs | Takes | Needs |
|---|---|---|---|
| **Unit and integration tests** (`tests/SSLense.Tests`) | Every CI run, and `dotnet test` locally | About a minute | Nothing outside the machine |
| **Pebble end-to-end tests** (part of the same project) | Every CI run; locally only with `SSLENSE_PEBBLE` set | Seconds | Pebble, Let's Encrypt's test ACME server, a pinned release checked by SHA-256 |
| **GUI tests** (part of the same project) | Every CI run | About 10 seconds | A Windows desktop session; WPF runs off-screen |
| **Dependency check and SBOM** (`installer/Test-Dependencies.ps1`) | Every CI run and release | Under a minute | The NuGet advisory database |
| **Acceptance checks on real IIS** (`tests/SSLense.Acceptance`) | By hand, on a test server, as part of the combined test | 3 to 15 minutes each | IIS; some checks a Cloudflare zone, public DNS and port 80 ([README](../../tests/SSLense.Acceptance/README.md)) |

At the time of writing, the unit suite has 914 test cases from about 720 test methods: 905 pass and 9 are the Pebble tests, skipped without Pebble. In CI all of them run.

## How to run them

```powershell
dotnet build SSLense.sln
dotnet test SSLense.sln                          # unit, integration and GUI tests

# With Pebble, as CI does:
$env:SSLENSE_PEBBLE = 'C:\tools\pebble\pebble.exe' # pebble-windows-amd64 v2.10.1
dotnet test SSLense.sln --filter "FullyQualifiedName~PebbleTests"

./installer/Test-Dependencies.ps1 -SbomPath artifacts/sbom.json

# On a test server, from an Administrator terminal:
.\tests\SSLense.Acceptance\bin\Debug\net10.0-windows\SSLense.Acceptance.exe parta
.\tests\SSLense.Acceptance\bin\Debug\net10.0-windows\SSLense.Acceptance.exe partb --zone <zone>
```

**Pass:**
- The build has 0 warnings and 0 errors.
- Every test passes, with none skipped in CI.
- The dependency check reports no vulnerable package.
- Each acceptance command ends with every check passed in its `result-<command>.txt`.

## What the unit suite covers

| Area | Tests | What is checked |
|---|---|---|
| ACME (`Acme`) | 107 | Ordering, HTTP and DNS validation, installing and binding, renewal replacing (ARI), keeping the previous certificate, web farm challenge copies, CA registry and locks, key and order options, and Pebble end to end: issue, renew, revoke, account key change, External Account Binding |
| Certificates (`Certificates`) | 158 | Inspection and validation of bought certificates, PFX import, CSRs, sharing between sites, transactions and recovery, clean-up, history and rollback, bulk operations, remote certificates, revocation |
| Settings and state (`Config`) | 53 | State file formats and every migration, backups before migration, data folder permissions, maintenance windows, settings export and import with encrypted secrets |
| Deployment steps (`Deployment`) | 32 | Key access, service restarts, scripts checked by hash, PFX, PEM and Central Certificate Store exports, FTP, HTTP.sys, Remote Desktop, SQL Server, web servers, Key Vault and App Service, retries and notifications |
| Diagnostics (`Diagnostics`) | 36 | Health check, diagnostic bundle and its redaction, service heartbeat, version notice, fleet reports |
| DNS validation (`DnsValidation`) | 135 | Every built-in DNS provider's requests, scripts, acme-dns, propagation checks at the authoritative servers, CAA, the challenge journal and cleanup |
| Error codes (`Errors`) | 5 | Every code is unique and documented in errors.md, the issued list only grows, and Core throws coded errors only |
| Desktop app (`Gui`) | 33 | The main screens render with sample certificates (19 screenshots), with every control reachable with Tab and named for screen readers; high contrast covers every theme brush; view models for installing renewals, sharing, reminders and stopping management |
| IIS (`Iis`) | 5 | HTTPS redirect rule, the TLS binding probe |
| Logs (`Logs`) | 8 | Reading, filtering and redaction |
| Notifications (`Notifications`) | 30 | Email (SMTP and Microsoft Graph), every chat format, signed webhooks, Event Log, settings, test sends |
| Reminders (`Reminders`) | 76 | Digest contents, snoozing, outside-renewal detection, served-certificate checks, renewal readiness |
| Renewal (`Renewal`) | 25 | Scheduling, backoff, rate limits, maintenance windows, the hold after a rollback, notifications |
| Validation (`Validation`) | 19 | HTTP-01 files and web.config, HTTP answered by SSLense, DNS pre-checks, web farm folders |

## What automated tests cannot show

These are in the manual test plan:
- real IIS and HTTP.sys (the acceptance checks);
- real certificate authorities other than Let's Encrypt staging;
- real DNS provider accounts, Microsoft 365 and Azure;
- the installer and upgrades;
- Windows Server versions;
- what Narrator says and how a contrast theme looks;
- networks with proxies or NAT.
