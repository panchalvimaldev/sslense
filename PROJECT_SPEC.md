# Project Prompt: IIS Let's Encrypt (ACME) Certificate Manager

Paste this whole file into your VS Code AI agent (Claude Code, Copilot Agent, etc.) as the first message, or save it in the repo root as `PROJECT_SPEC.md` and tell the agent: "Read PROJECT_SPEC.md and build the project phase by phase. Stop after each phase and wait for my confirmation."

---

## 1. Goal

Build a Windows tool in **C# / .NET 8** that automatically obtains, installs, and renews free **Let's Encrypt** SSL certificates for websites hosted on **IIS**. It is a simpler alternative to win-acme / Certify The Web.

Target user: an administrator of a Windows dedicated server with full admin rights, hosting one or more IIS sites (ASP.NET MVC / .NET Core).

The tool ships with **both a GUI (WPF desktop app) and a CLI**. Both are thin front-ends over the same `SSLense.Core` library, so every feature works identically from either one and no business logic lives in the UI or CLI projects.

## 2. Tech stack

- .NET 8, C#, nullable reference types enabled
- ACME client library: **Certes** (NuGet). Before using it, check that it is compatible with .NET 8 and still works against Let's Encrypt. If not, implement RFC 8555 directly using `HttpClient` + JWS (ES256), behind the same interfaces below.
- IIS management: `Microsoft.Web.Administration`
- Certificate store: `System.Security.Cryptography.X509Certificates`
- Logging: Serilog (file + console)
- CLI: `System.CommandLine`
- GUI: **WPF** on .NET 8 (`net8.0-windows`), MVVM pattern with `CommunityToolkit.Mvvm`. Keep styling simple and clean (default Windows look is fine).
- Config/state: JSON files under `%ProgramData%\SSLense\`
- Tests: xUnit + Moq
- Windows Service hosting for renewal: `Microsoft.Extensions.Hosting.WindowsServices`

## 3. Solution structure

```
SSLense.sln
src/
  SSLense.Core/              # domain logic, no UI
    Acme/                    # IAcmeService + implementation (account, order, challenge, finalize)
    Validation/              # IChallengeHandler, Http01Handler (Dns01 later)
    Iis/                     # IIisService (find sites/bindings, add HTTPS binding, attach cert)
    Certificates/            # ICertificateStore (import PFX, find by thumbprint, remove old)
    Renewal/                 # IRenewalService (expiry check, renew, schedule)
    Config/                  # models + JSON persistence
    Notifications/           # INotifier (email via SMTP, webhook)
  SSLense.Cli/               # command-line app (console), thin wrapper over Core
  SSLense.Gui/               # WPF desktop app (MVVM), thin wrapper over Core
  SSLense.Service/           # Windows Service host that runs daily renewal
tests/
  SSLense.Tests/
```

Use dependency injection. Every external system (ACME server, IIS, cert store, file system) sits behind an interface so it can be mocked.

## 4. Features (MVP)

### 4.1 CLI commands

- `list-sites` : list IIS sites and their bindings (host names, ports, current cert).
- `issue --site <name> [--hosts a.com,www.a.com] --email <email> [--staging]` : obtain and install a certificate.
- `renew [--all | --site <name>] [--force]` : renew certificates that are within 30 days of expiry (or all with `--force`).
- `status` : show each managed certificate: hosts, issue date, expiry date, days left, thumbprint, last renewal result.
- `install-service` / `uninstall-service` : register or remove the Windows Service for automatic renewal.

### 4.2 Issue flow (HTTP-01)

1. Validate: running as Administrator, IIS installed, site exists, each host name has an HTTP binding on port 80 on that site.
2. Load or create the ACME account (store the account key securely, encrypted with DPAPI `LocalMachine` scope).
3. Create an order for the host names.
4. For each authorization, get the HTTP-01 challenge. Write the key authorization file to `<site physical path>\.well-known\acme-challenge\<token>` (no file extension, content-type `text/plain`).
5. Make sure IIS actually serves that path. If the site has a `web.config` that blocks extensionless files or routes everything through MVC, create/adjust a `web.config` inside `.well-known\acme-challenge\` that allows static files (`<handlers>` with `StaticFile` for `*`) and disables auth/rewrite for that folder.
6. Self-check by requesting `http://<host>/.well-known/acme-challenge/<token>` before telling Let's Encrypt to validate.
7. Notify the ACME server, poll until the authorization is valid (with timeout and clear error messages from the ACME problem document).
8. Generate a private key + CSR, finalize the order, download the certificate chain.
9. Build a PFX (random password, in memory only) and import into `LocalMachine\My` with `X509KeyStorageFlags.MachineKeySet | PersistKeySet | Exportable` as appropriate. Set a friendly name like `SSLense: example.com (2026-10-27)`.
10. In IIS: add or update the HTTPS binding (port 443) for each host name with SNI enabled (`SslFlags.Sni`), attach the new certificate. Do not touch bindings of other sites.
11. Remove the challenge files and temporary `web.config`.
12. Save the managed-certificate record (hosts, site, thumbprint, dates, ACME account id) to JSON.

### 4.3 Renewal

- The Windows Service wakes once a day (and on start), loads all managed certs, renews any with 30 days or fewer left.
- Renewal repeats the issue flow, then swaps the binding to the new certificate and removes the old certificate from the store only after the new binding is confirmed working.
- On failure: retry with backoff (3 attempts over a few hours), log the full error, and send a notification. Never leave a site without a valid binding: if renewal fails, keep the old certificate bound.

### 4.4 Notifications

- SMTP email (host, port, user, password, from, to) and/or a generic webhook URL.
- Send on: renewal failure, successful renewal (optional), certificate within 14 days of expiry.

### 4.5 GUI (WPF)

A single main window with a left navigation list and these screens:

1. **Dashboard:** table of managed certificates with columns: site, host names, expiry date, days left, status. Rows are color-coded: green (more than 30 days), amber (30 days or fewer), red (expired or last renewal failed). Buttons: Issue New, Renew Selected, Renew All, Refresh.
2. **Issue Certificate wizard** (3 steps):
   - Step 1: pick an IIS site (dropdown filled from `list-sites`) and tick the host names to include. Show a warning icon next to any host without an HTTP binding on port 80.
   - Step 2: enter the email, choose **Staging** or **Production** (Staging is the default, with a clear label), and run a **pre-flight check** (admin rights, binding exists, port 80 reachable, challenge folder writable) showing pass/fail per check.
   - Step 3: live progress log (each ACME step as it happens) and a final success or error screen with the fix suggestion.
3. **Certificate details:** hosts, issuer, thumbprint, issue/expiry dates, bound sites, last 10 log lines, buttons Renew Now and Remove.
4. **Settings:** default email, staging/production default, renewal threshold (days), SMTP and webhook settings with a "Send test notification" button, Windows Service status with Install / Start / Stop / Uninstall buttons.
5. **Logs:** live viewer of the current log file with level filter and "Open log folder".

GUI rules:
- Long operations run asynchronously (`async/await`, `IProgress<T>`) and never freeze the window. Provide a Cancel button where possible.
- The app requires administrator rights: add an app manifest with `requireAdministrator`.
- Show friendly error dialogs using the same error messages the CLI prints (shared from Core).
- Closing the window never stops the renewal service; the service is independent.
- Reads and writes the same JSON state under `%ProgramData%\SSLense\` as the CLI and service, with file locking so they never corrupt each other.

### 4.6 Shared-core rule (important)

- Everything the GUI can do, the CLI can do, and vice versa, by calling the same Core services (`IAcmeService`, `IIisService`, `ICertificateStore`, `IRenewalService`).
- Core exposes progress through `IProgress<ProgressEvent>` so the CLI can print lines and the GUI can show a live log from the same events.
- No `Console.WriteLine` or `MessageBox` calls inside Core.

## 5. Non-functional requirements

- **Safety first:** a `--staging` flag uses the Let's Encrypt staging directory (`https://acme-staging-v02.api.letsencrypt.org/directory`). Default to staging until the user passes `--production`, to avoid rate limits during testing.
- **Idempotent:** running `issue` twice for the same site/hosts must not create duplicate certificates; it should detect an existing valid one and ask or use `--force`.
- **Security:** never log private keys, PFX passwords, or the ACME account key. Encrypt sensitive config (SMTP password, account key) with DPAPI.
- **Clear errors:** every failure explains the likely cause and fix (for example: "Port 80 not reachable from the internet", "Host name not found in IIS bindings").
- **Logging:** rolling daily log files in `%ProgramData%\SSLense\logs`, keep 30 days.
- **Elevation:** exit with a clear message if not run as Administrator.

## 6. Phases (stop after each one)

**Phase 1: Skeleton.** Solution, projects, DI, Serilog, CLI with `list-sites` working against real IIS. Unit tests for config persistence.

**Phase 2: ACME + HTTP-01.** Account creation, order, challenge file writing, self-check, validation, download certificate. Run end-to-end against **staging** and save the PEM/PFX to disk without touching IIS yet.

**Phase 3: IIS + cert store.** Import PFX, create/update HTTPS binding with SNI, `issue` command complete. Manual test on a real site using staging, then production.

**Phase 4: Renewal + Windows Service.** `renew`, `status`, `install-service`, daily timer, safe swap of certificates, retry logic.

**Phase 5: Notifications + hardening.** SMTP/webhook, DPAPI encryption of secrets, better error messages, README with install and usage steps.

**Phase 6: GUI part 1.** WPF project with admin manifest, Dashboard screen (list, colors, Renew buttons) and Logs screen, using the existing Core services and `IProgress<ProgressEvent>`.

**Phase 7: GUI part 2.** Issue Certificate wizard with pre-flight checks and live progress, Certificate details screen, Settings screen (notifications, service control).

**Phase 8: Professional GUI modernization.** Shared WPF design system, professional application shell and navigation, dashboard health summary, status badges, visual issuance stepper, improved information hierarchy, consistent form controls and operation feedback, empty states, and accessible color-independent status presentation. Preserve the existing Core services and ViewModels; do not add business logic to the GUI.

**Phase 9 (optional, later):** DNS-01 challenge with Cloudflare API (wildcard support), HTTP to HTTPS redirect helper (URL Rewrite rule), installer (MSI or Inno Setup) that bundles GUI, CLI, and service.

## 7. Acceptance criteria for the MVP

- On a clean Windows Server with IIS, `SSLense.Cli issue --site "MySite" --email me@example.com --production` results in a working `https://` site with a valid Let's Encrypt certificate and no manual IIS steps.
- `status` shows the certificate and its expiry.
- After `install-service`, simulating an expiring certificate (using `--force` or a test hook) renews it and rebinds without downtime.
- The same certificate can be issued from the GUI wizard and from the CLI, with identical results, and each sees certificates created by the other.
- The GUI Dashboard shows correct days-left and color status, stays responsive during issue/renew, and shows a live progress log.
- All core logic has unit tests with mocked ACME/IIS/store, and tests pass with `dotnet test`.

## 8. Working rules for the AI agent

- Work one phase at a time; summarize what you built and how to run it, then wait.
- Prefer small, readable classes and interfaces. No unnecessary abstractions.
- Explain any decision where a library choice or fallback (Certes vs custom ACME) is made.
- Do not run anything against Let's Encrypt **production** until I explicitly say so.
- Ask me before adding new NuGet packages beyond those listed above.

## 9. Commercial development

The post-MVP security, reliability, packaging, paid-feature, enterprise, and go-to-market development plan is maintained in [COMMERCIAL_ROADMAP.md](COMMERCIAL_ROADMAP.md). Treat its P0 commercial release gates as mandatory before accepting paying production customers.
