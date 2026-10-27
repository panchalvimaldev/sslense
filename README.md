# SSLense

SSLense is a .NET 8 Windows tool for issuing and automatically renewing Let's Encrypt certificates for IIS. The CLI and Windows Service use the same `SSLense.Core` services and the same state under `C:\ProgramData\SSLense`.

The post-MVP productization plan is documented in [COMMERCIAL_ROADMAP.md](COMMERCIAL_ROADMAP.md).

> SSLense currently uses the Let's Encrypt **staging** endpoint only. Staging certificates are for testing and are not trusted by browsers. Production issuance remains disabled until it is explicitly enabled in a later phase.

## Requirements

- Windows Server or Windows with IIS installed
- IIS Management Scripts and Tools
- .NET 8 Runtime when using a framework-dependent publish
- Administrator access
- An IIS HTTP binding on port 80 for every requested host
- Public HTTP access to `/.well-known/acme-challenge/` for HTTP-01 validation

If the IIS machine has no public IP, a Cloudflare Tunnel can route the hostname to the local IIS HTTP binding. The tunnel route must preserve the expected host header.

## Build and test

From an Administrator PowerShell terminal in the repository:

```powershell
dotnet build .\SSLense.sln
dotnet test .\SSLense.sln
```

## CLI usage

List IIS sites and bindings:

```powershell
dotnet run --project .\src\SSLense.Cli -- list-sites
```

Issue and install a staging certificate:

```powershell
dotnet run --project .\src\SSLense.Cli -- issue `
  --site "My IIS Site" `
  --hosts example.com,www.example.com `
  --email admin@example.com `
  --staging
```

Use `--force` to replace an existing valid staging certificate. The command imports the certificate into `LocalMachine\My`, creates or updates SNI bindings, verifies the bindings, and saves the managed-certificate record.

Show managed certificates:

```powershell
dotnet run --project .\src\SSLense.Cli -- status
```

Renew certificates within the configured threshold, which defaults to 30 days:

```powershell
dotnet run --project .\src\SSLense.Cli -- renew --all
dotnet run --project .\src\SSLense.Cli -- renew --site "My IIS Site"
```

Exercise the complete staging renewal and safe-binding swap immediately:

```powershell
dotnet run --project .\src\SSLense.Cli -- renew --site "My IIS Site" --force
```

SSLense removes an old certificate only after the replacement binding is confirmed and no other IIS binding references the old thumbprint.

## Notifications

SMTP and webhook channels may be enabled together or independently. SMTP passwords and webhook URLs are encrypted using Windows DPAPI with `LocalMachine` scope. They are never written to logs or displayed by the CLI.

Configure authenticated SMTP; the password is requested without echoing it:

```powershell
dotnet run --project .\src\SSLense.Cli -- notifications configure `
  --smtp-host smtp.example.com `
  --smtp-port 587 `
  --smtp-user sslense@example.com `
  --smtp-from sslense@example.com `
  --smtp-to admin@example.com
```

Configure a webhook; its URL is requested without echoing it:

```powershell
dotnet run --project .\src\SSLense.Cli -- notifications configure --webhook
```

Pass both SMTP options and `--webhook` in one command to enable both channels. Add `--notify-success` to receive successful-renewal messages. Renewal failures and 14-day expiry warnings are always sent when a channel is configured.

Test or remove the configuration:

```powershell
dotnet run --project .\src\SSLense.Cli -- notifications test
dotnet run --project .\src\SSLense.Cli -- notifications clear
```

## Windows Service

Publish and install the renewal service:

```powershell
dotnet publish .\src\SSLense.Service -c Release -o .\publish\service
dotnet run --project .\src\SSLense.Cli -- install-service `
  --service-path ".\publish\service\SSLense.Service.exe"
```

The `SSLense` service runs a renewal check immediately after startup and every 24 hours. A failed renewal is attempted three times with one-hour and two-hour delays. Existing IIS bindings remain in place when issuance fails.

Check or remove the service:

```powershell
Get-Service SSLense
dotnet run --project .\src\SSLense.Cli -- uninstall-service
```

## Desktop GUI

Start the WPF dashboard from PowerShell or Visual Studio:

```powershell
dotnet run --project .\src\SSLense.Gui
```

Windows displays an administrator elevation prompt because the application manifest requests `requireAdministrator`. The GUI provides:

- A Dashboard showing site, host names, expiry, days remaining, and renewal status
- Green, amber, and red certificate health rows
- Immediate renewal of the selected staging certificate
- Renewal checks for all due certificates
- Cancellable operations with live progress
- A live log viewer with level filtering and access to the log folder
- A three-step staging issuance wizard with IIS selection, pre-flight checks, live progress, and cancellation
- Certificate details, renewal, confirmed removal, bindings, issuer, validity, and recent logs
- General, SMTP/webhook, and Windows Service settings

Production remains visibly disabled until it is explicitly authorized. Use **Issue New** on the Dashboard to open the staging wizard. Removing a certificate requires confirmation and removes only matching HTTPS bindings; a certificate still used by another IIS site is retained in the Windows certificate store.

The Phase 7 Core operations also have CLI equivalents:

```powershell
dotnet run --project .\src\SSLense.Cli -- preflight --site "My IIS Site" --hosts example.com
dotnet run --project .\src\SSLense.Cli -- details --site "My IIS Site"
dotnet run --project .\src\SSLense.Cli -- configure --email admin@example.com --renewal-days 30
dotnet run --project .\src\SSLense.Cli -- service-status
dotnet run --project .\src\SSLense.Cli -- start-service
dotnet run --project .\src\SSLense.Cli -- stop-service
```

Certificate removal is destructive and therefore requires explicit CLI confirmation:

```powershell
dotnet run --project .\src\SSLense.Cli -- remove --site "My IIS Site" --yes
```

## Data and logs

SSLense stores files under `C:\ProgramData\SSLense`:

- `config.json`: non-secret settings and DPAPI-protected notification values
- `managed-certificates.json`: sites, hosts, certificate dates, thumbprints, and renewal results
- `account-key.staging.dat`: DPAPI-protected staging ACME account key
- `certificates\`: saved staging PEM/PFX artifacts
- `logs\sslense-YYYYMMDD.log`: rolling logs retained for 30 days

Private keys, PFX passwords, SMTP passwords, webhook URLs, and the ACME account key must never appear in logs. Restrict access to the ProgramData directory to administrators and the service account.

## Troubleshooting

- **Access denied:** run PowerShell as Administrator.
- **IIS sites cannot be read:** install IIS Management Scripts and Tools.
- **HTTP-01 returns 404:** confirm the hostname's port 80 IIS binding, tunnel host header, and that `/.well-known/acme-challenge/<token>` reaches the same site.
- **HTTP-01 returns unexpected content:** check authentication, URL Rewrite, MVC routing, proxies, and cached responses for the challenge path.
- **ACME validation times out:** confirm public DNS/tunnel routing and that inbound HTTP remains available throughout validation.
- **SMTP test fails:** verify the port, TLS mode, credentials, outbound firewall policy, and provider-specific authentication requirements.
- **Webhook test fails:** verify that the receiving endpoint accepts an HTTP POST containing `kind`, `subject`, `body`, and `occurredAtUtc` JSON fields.

Review the current daily log in `C:\ProgramData\SSLense\logs` for the full exception and remediation context. Sensitive values are excluded.
