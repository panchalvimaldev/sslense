# Design: several certificates on one IIS site

Status: **approved** November 13, 2026, with the decisions in section 7 taken by judgement for the owner's review. Target release: 0.23 (phase 1). Branch: `feature/multiple-certificates-per-site`.

## 1. Problem

SSLense manages one certificate per IIS site. A common setup has one site serving several domains, each through its own HTTPS binding with SNI and its own certificate, often bought and renewed separately:

| IIS site | HTTPS binding (port 443, SNI) | Certificate |
|---|---|---|
| Main | `www.domain1.co.uk` | bought for domain1 |
| Main | `www.domain2.co.uk` | bought for domain2 |
| Main | `www.domain3.co.uk` | bought for domain3 |

**Other providers → Monitor a certificate already in IIS** lists all three bindings. Only one can be adopted: the second is refused with "IIS site 'Main' is already managed by SSLense", so two of the three certificates get no Dashboard row, no reminders and no safe replacement.

## 2. What the administrator gets

- **Each certificate on the site is managed on its own.** Adopt all three, and the Dashboard shows `Main`, `Main/www.domain2.co.uk` and `Main/www.domain3.co.uk`, each with its own expiry, reminders and history.
- **Replacing one certificate changes only its own bindings.** Importing domain2's renewal leaves domain1 and domain3 as they are. Validation, the HTTPS check and the automatic rollback work as today.
- **Nothing new to choose.** In the app and the CLI, the administrator picks the IIS site and the host names (or the binding) as today. SSLense works out which certificate that is:
  - host names that no certificate on the site has yet: a new certificate;
  - host names of one certificate: that certificate, replaced;
  - host names of several certificates: refused, naming them.
- **A site with one certificate behaves exactly as before.**

```powershell
SSLense.Cli adopt --site "Main" --thumbprint <domain2's thumbprint>      # managed as "Main/www.domain2.co.uk"
SSLense.Cli import --site "Main" --pfx .\domain2-renewed.pfx             # replaces that certificate only
SSLense.Cli status --site "Main/www.domain2.co.uk"
```

## 3. How a certificate is named

- The first certificate on a site keeps the site's name, as today: `Main`.
- **Every other certificate on the site is named `<site>/<its first host name>`,** for example `Main/www.domain2.co.uk`. The name is fixed when the certificate is first managed, so it does not change when the certificate's host names do.
- IIS does not allow `/` in site names, so the site is always the part before the first `/`, and no name can collide with a real site. Names for certificates with no IIS site may no longer contain `/`.
- Everything that already works by name (`status`, `remove`, reminders, the Dashboard, Certificate Details, pending requests, deployment steps) works with these names unchanged.

## 4. Rules

- **Host names on a site belong to one certificate.** No two certificates on the same site may cover the same host name. This keeps every replacement, check and rollback to its own bindings.
- **One lock per IIS site.** Operations on different certificates of the same site run one after the other, because they change the same site's bindings.
- **Fail safe by construction.** Records are found by name, as today. A name with `/` reaches IIS only through one translation in the IIS layer, so any path not yet taught about it fails with "site not found" instead of acting on another certificate.
- **The checks work per certificate.** The served-certificate check, the "replaced outside SSLense" detector and the health checks already compare a record's own host names only. They find the IIS site through the same translation.

## 5. Phases

1. **Certificates from other providers** (0.23): adopt, import a PFX, create and complete a request, reminders, checks, remove. Additional certificates on a site come from other providers in this phase:
   - `issue` (ACME) refuses a name with `/`, and refuses host names that belong to another certificate on the site;
   - sharing a certificate (`share add`) is refused for a site with several certificates, in either direction;
   - the first certificate on the site may still be an ACME one, renewed automatically; its renewals change only its own host names.
2. **ACME certificates** (0.24): issue and automatic renewal of several ACME certificates on one site, including HTTP validation, which serves the challenge through the site, and sharing.

## 6. Data changes

- No new fields: the name carries the site.
- **Managed certificates schema 10 to 11,** because 0.22 would treat `Main/www.domain2.co.uk` as a site that does not exist and report it as a problem in every check.

## 7. Decisions taken by judgement

1. **Name additional certificates `<site>/<first host>`** rather than adding a separate site field, so a record is still found by its name everywhere, and a missed path fails safe (section 4).
2. **Keep the first certificate's name** (`Main`), so existing setups, scripts and reminders do not change.
3. **SSLense chooses the certificate from the host names,** so the app needs no new choice.
4. **One lock per IIS site,** not per certificate.
5. **ACME and sharing wait for phase 2,** so phase 1 can be tested on a production server without changing how anything renews.

## 8. Delivery and testing

| Step | Contents |
|---|---|
| 1 | This design |
| 2 | Core: naming, the host-name rule, the per-site lock, the IIS translation; adopt, import, request and complete for an additional certificate; the checks; the phase 1 refusals; schema 11. Unit tests. **Built** November 13, 2026: 20 tests, including adopting, importing for, requesting and completing a second certificate on a site with real keys and a test CA, and the shared per-site lock |
| 3 | App and CLI: Other providers adopts each selected binding; the Dashboard and Other providers show the names. README, roadmap, website. **Built** November 13, 2026: Other providers shows "Managed as <name>", and Order renewal preselects only the certificate's own host names; `discover` shows the names |
| 4 | Acceptance on the owner's server with the three-domain site, then release as 0.23 |
