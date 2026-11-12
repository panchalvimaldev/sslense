# Design: certificates beyond IIS sites

Status: **approved by delegation** November 12, 2026. The owner asked for this to go ahead with decisions left to judgement; they are recorded in section 7 for review. Target release: 0.18. Branch: `feature/deployment-steps`. Item 1 of the [roadmap](../../ROADMAP.md).

## 1. Problem

SSLense installs a certificate and binds it in IIS. On the same Windows server, other services use certificates too, and today the administrator updates them by hand after every renewal:

- **Remote Desktop**, which must be told the new thumbprint.
- **SQL Server**, which reads its certificate's thumbprint from the registry, needs read access to the private key, and must be restarted.
- **Exchange**, which enables a certificate for its services in its own shell.
- **Applications under IIS** that read the certificate's private key themselves, such as a client-certificate or signing scenario, need their application-pool identity granted access to the key.
- Copying the certificate elsewhere, or anything else a script can do.

With certificate lifetimes moving toward 45 days, doing this by hand every few weeks is not workable.

### Out of scope here

- **Certificates bound to no IIS site.** Every certificate still belongs to an IIS site record. A certificate only for Remote Desktop can use an IIS site, even a stopped one, as its record. Records without a site are a later step (section 6), because every path that assumes a site must change.
- Export to files and other stores, which is roadmap item 2.

## 2. What the administrator gets

**Deployment steps**: a list on each certificate, run in order after every install and renewal.

```powershell
SSLense.Cli deploy add --site "Shop" --grant-key-access "IIS AppPool\Shop"
SSLense.Cli deploy add --site "Mail" --script C:\Scripts\exchange.ps1
SSLense.Cli deploy add --site "Mail" --restart-service MSExchangeTransport
SSLense.Cli deploy list --site "Mail"
SSLense.Cli deploy run --site "Mail"        # run them now, for the certificate in use
SSLense.Cli deploy remove --site "Mail" --step 2
```

| Step | What it does |
|---|---|
| `--grant-key-access <account>` | Gives an account read access to the certificate's private key, such as `IIS AppPool\Shop` or `NT Service\MSSQLSERVER` |
| `--restart-service <name>` | Restarts a Windows service, and waits for it to run again |
| `--script <file.ps1>` | Runs a PowerShell script with the certificate's details, as with DNS scripts: SSLense runs its own copy, checked by hash |

Example scripts installed with SSLense, in `C:\Program Files\SSLense\deploy-scripts\`: **Remote Desktop**, **SQL Server**, and **Exchange**, plus a template.

## 3. How steps run

- **After the certificate is installed and its record saved,** in order. A step that fails stops the ones after it.
- **A failure never undoes the renewal.** The new certificate is valid and bound in IIS. The failure is logged, reported in the result and the notifications, and **retried in every service cycle** until it succeeds.
- **The previous certificate is kept while steps are pending.** Services such as Remote Desktop still use it until their step has run, so it is removed, if no IIS binding uses it, only after every step succeeded.
- A script gets `-Thumbprint`, `-PreviousThumbprint`, `-Hosts` (comma-separated), `-NotAfter` (ISO 8601), and `-Site`, in the same colon form as DNS scripts, and runs with the same rules: SSLense's own copy in its restricted data folder, its hash checked before every run, a timeout, output redacted and limited, and a Windows job object so nothing it starts outlives it.
- **A step added to a certificate runs after its next renewal,** or at once with `deploy run`. It does not count as pending for the certificate already in use, so adding a restart step never restarts a service within the hour unasked.
- A step's state is kept with the record: the thumbprint it last completed for, the last error, and when it last ran. `status` and Certificate Details show it.
- Steps belong to the record and survive renewals. A shared certificate runs its steps once, for the certificate, not once per site.

## 4. Security

- **Scripts** follow the DNS script rules exactly (docs/design/dns-script.md, section 4): an administrator adds them, SSLense copies them into `C:\ProgramData\SSLense\deploy-scripts`, which only Administrators and SYSTEM can change, and runs only the copy with its recorded hash.
- **Key access** adds one allow rule for read access to the private key, for an account the administrator names. It never removes rules and never grants more than read. The account must exist, so a typing mistake fails instead of granting nothing.
- **Service names** are checked against the installed services before a step is saved.

## 5. Data changes

- `ManagedCertificate` gains `DeploymentSteps`, each with an ID, a kind, and its value (account, service name, or script hash and timeout), and `Deployment`, the state in section 3.
- **Managed certificates schema 5 to 6.** The old file is backed up at the first save, and 0.17 refuses the newer file, as before.
- The store carries steps and their state across renewals, as it already does for reminder settings.

## 6. Delivery

| Step | Contents | Ships |
|---|---|---|
| 1 | This design | Docs |
| 2 | Core and CLI: steps, running and retrying them, key access, service restart, scripts, schema 6, the `deploy` commands. Unit tests, and a real-key test for key access. **Built** November 12, 2026: 17 tests, including access granted on a real CNG key file, a changed script copy refused, and a failed step keeping the previous certificate until an hourly retry succeeds | CLI |
| 3 | Example scripts for Remote Desktop, SQL Server, and Exchange; the app; README, roadmap, website; acceptance; release as 0.18. **Built** November 12, 2026, apart from acceptance: the four example scripts in the installer, each run in the tests with SSLense's arguments; **Deployment steps** in Certificate Details; copies of removed steps deleted in the service cycle | Both |
| 4 | Later: certificates with no IIS site, for servers whose only certificate is for Remote Desktop or SQL Server | Both |

## 7. Decisions taken by delegation

1. **Steps are attached to existing certificate records,** and certificates with no IIS site come later. This delivers the most value soonest without changing every path that assumes a site.
2. **Three kinds of step:** key access, service restart, and script. The service-specific ones (Remote Desktop, SQL Server, Exchange) ship as example scripts, because each depends on details of the installed product that a script can adjust and SSLense cannot.
3. **A failed step does not undo the renewal,** and is retried each service cycle; the previous certificate is kept until every step has succeeded.
4. **Scripts reuse the DNS script security model** unchanged.
5. **Service restarts use `sc.exe`,** as SSLense already does for its own service, so no package is added.
6. **Managed certificates schema 6.**
7. **A new step waits for the next renewal or `deploy run`,** rather than running in the next service cycle, so adding a step never restarts a service unasked.
