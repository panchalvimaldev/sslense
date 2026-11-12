# Design: certificate export and the IIS Central Certificate Store

Status: **approved by delegation** November 12, 2026, with the decisions in section 6 taken by judgement for the owner's review. Target release: 0.20. Branch: `feature/certificate-export`. Item 1 of the [roadmap](../../ROADMAP.md).

## 1. Problem

SSLense installs every certificate with a non-exportable private key, which is the safe default and all IIS needs. Other uses need the certificate as a file:

- **Web farms** using the IIS Central Certificate Store, a shared folder of PFX files that every server reads.
- **Software that reads files,** such as a reverse proxy, a Java or Node.js application, or an appliance that takes PEM files.
- **Copies for another server,** as a password-protected PFX.

### Out of scope

- **Azure Key Vault and other remote stores.** They need a client library, which is a new package; that is a separate decision.
- Pushing files to other machines by any means other than a path SSLense can write to, such as a share.

## 2. What the administrator gets

```powershell
# An exportable key is a choice made when the certificate is issued, and kept at every renewal.
SSLense.Cli issue --site "Shop" --names "*.example.com" --validation dns --exportable-key --email ops@example.com

SSLense.Cli deploy add --site "Shop" --export-pfx D:\Certs\shop.pfx            # password prompted, hidden
SSLense.Cli deploy add --site "Shop" --export-pem D:\Certs\shop                 # cert.pem, chain.pem, fullchain.pem, key.pem
SSLense.Cli deploy add --site "Shop" --central-store \\fileserver\ccs           # one PFX per name; password prompted
```

Exports are **deployment steps**, so they run after every install and renewal, are retried hourly when they fail, and can run at once with `deploy run`. In the app, they are more kinds of step in **Certificate Details**, and **Exportable private key** is a choice in **Issue Certificate**.

| Step | Writes |
|---|---|
| `--export-pfx <file.pfx>` | The certificate, its intermediates, and its key, protected by the password given |
| `--export-pem <folder>` | `cert.pem`, `chain.pem` (intermediates), `fullchain.pem`, and `key.pem` (unencrypted PKCS#8) |
| `--central-store <folder>` | `<name>.pfx` for every name on the certificate, with `_` for a wildcard's `*`, as the IIS Central Certificate Store expects, protected by the store's password |

## 3. Rules

- **Exportable keys are opt-in, per certificate.** Without `--exportable-key`, an export step is refused when added, with how to issue the certificate again. The choice is kept at every renewal.
- **Passwords** for PFX and the Central Certificate Store are asked for hidden, encrypted with DPAPI like other secrets, never logged, and left out of diagnostic bundles.
- **`key.pem` is written only for Administrators, SYSTEM, and the account that wrote it** (SYSTEM or an elevated administrator), with inherited permissions removed, because it is not protected by a password. Giving another account access is the administrator's decision, made with Windows' own tools.
- **Files are replaced atomically:** written to a temporary file in the same folder, then moved into place, so a reader never sees half a file.
- **Paths must be absolute,** local or UNC. The service runs as SYSTEM, which reaches a share as the computer's account.
- **The thumbprint is not trusted to stay:** the step exports the certificate the record holds at the time it runs, so a retry after a renewal exports the newest one.

## 4. Data changes

- `ManagedCertificate` gains `ExportableKey`. `DeploymentStep` gains its protected password.
- **Managed certificates schema 7 to 8,** because 0.19 would not know the new kinds of step.

## 5. Delivery

| Step | Contents | Ships |
|---|---|---|
| 1 | This design | Docs |
| 2 | Core and CLI: exportable keys at issue and renewal, the three export steps, schema 8, tests with real exported files. **Built** November 12, 2026: 5 tests, writing real PFX, PEM, and Central Certificate Store files and reading them back, checking key.pem's permissions, and refusing a key that cannot be exported | CLI |
| 3 | The app; README, roadmap, website; release as 0.20. **Built** November 12, 2026, apart from acceptance: **Exportable private key** in Issue Certificate, kept when renewing by hand; the three export steps in Certificate Details, with a password box | Both |

## 6. Decisions taken by delegation

1. **Exports are deployment steps,** so they get ordering, retries, notifications, and `deploy run` without new machinery.
2. **Exportable keys are opt-in per certificate,** chosen at issue, never switched on for an existing key.
3. **`key.pem` is restricted to Administrators, SYSTEM, and the account that wrote it;** other access is left to the administrator.
4. **Azure Key Vault is left out** of this release, because it needs a new package.
5. **Managed certificates schema 8.**
