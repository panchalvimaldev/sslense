# Design: certificates with no IIS site

Status: **approved by delegation** November 12, 2026, with the decisions in section 6 taken by judgement for the owner's review. Target release: 0.19. Branch: `feature/no-site-certificates`. Item 1 of the [roadmap](../../ROADMAP.md), and step 4 of [deployment steps](deployment-steps.md).

## 1. Problem

Deployment steps (0.18) hand a certificate to Remote Desktop, SQL Server, Exchange, or any service a script can reach, but every certificate still belongs to an IIS site. A server whose only certificate is for Remote Desktop or SQL Server has no site to use, and an administrator should not have to create one, or bind a name to a site that has nothing to do with it.

## 2. What the administrator gets

```powershell
SSLense.Cli issue --no-site "RDP" --names rdp.example.com --validation dns --email ops@example.com
SSLense.Cli deploy add --site "RDP" --grant-key-access "NT AUTHORITY\NETWORK SERVICE"
SSLense.Cli deploy add --site "RDP" --script "C:\Program Files\SSLense\deploy-scripts\RemoteDesktop.ps1"
SSLense.Cli deploy run --site "RDP"
```

- **The certificate has a name instead of a site,** chosen by the administrator. Every command that takes `--site` also takes that name, so `status`, `renew`, `details`, `remove`, `deploy`, and the reminders work unchanged.
- **It is validated through DNS,** by a provider, a script, acme-dns, or by hand. HTTP validation needs a site to serve the file, so it is refused, until HTTP validation without a site arrives (roadmap item 5).
- **Nothing is bound in IIS.** The certificate is installed in `LocalMachine\My`, renewed like any other, and handed to its services by its deployment steps.
- In the app, **Issue Certificate** has a **No IIS site** choice with a name, in place of the site.

## 3. Rules

- **The name must not be an IIS site's,** so a command can never mean both. A name with a site in IIS, or a site record with that name, is refused.
- **Checks that look at IIS skip it:** HTTPS bindings, the served-certificate check, wildcard coverage, sharing, and the detection of a certificate replaced outside SSLense. Its expiry, installation, renewal history, DNS, and deployment steps are checked as usual.
- **It cannot be shared,** because sharing binds sites. It has no sites to share with.
- **Removing it stops managing it and keeps the certificate in the store,** because services outside IIS may still use it and SSLense cannot tell which. The administrator deletes it in certlm when they are done with it.
- **Recovery** after an interrupted issue saves the record without touching IIS.
- **A renewal keeps the previous certificate while deployment steps are pending,** as for any certificate.

## 4. Data changes

- `ManagedCertificate` gains `NoSite`. `SiteName` holds the name, and `Hosts` the certificate's names, which deployment scripts receive as `-Hosts`.
- **Managed certificates schema 6 to 7,** because 0.18 would take the record for a site and try to bind it. The old file is backed up at the first save, and 0.18 refuses the newer file.

## 5. Delivery

| Step | Contents | Ships |
|---|---|---|
| 1 | This design | Docs |
| 2 | Core and CLI: `issue --no-site`, renewal, recovery, removal, the checks that skip IIS, schema 7, tests | CLI |
| 3 | The app's Issue Certificate and Certificate Details; README, roadmap, website; release as 0.19 | Both |

## 6. Decisions taken by delegation

1. **A name, not a new kind of record.** The record keeps its shape with one flag, so every command and the reminders work without changes, and `--site` accepts the name.
2. **DNS validation only,** until SSLense can answer HTTP validation itself.
3. **Removal keeps the certificate in the store,** unlike a site's, because services outside IIS may use it.
4. **Managed certificates schema 7.**
