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
2. **ACME certificates** (0.24): issue and automatic renewal of several ACME certificates on one site, with HTTP or DNS validation. See section 9. Sharing with a site that has several certificates waits for demand (section 9.5).

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

## 9. Phase 2: several ACME certificates on one site

Status: **approved** November 19, 2026. Target release: 0.24. Branch: `feature/acme-several-certificates-per-site`.

### 9.1 What the administrator gets

- **Add certificate › Free and automatic** works on a site that already has a certificate. Choose the site and the host names, as today:
  - host names that no certificate on the site has: a new certificate, `Main/www.domain2.co.uk`, issued and then renewed automatically;
  - host names of one certificate: that certificate is replaced, including a bought one, which then renews automatically. This needs the existing **Replace the current certificate even if it is still valid** tick when the certificate is not due;
  - host names of several certificates: refused, naming them, as for imports.
- **The wizard says which certificate it will be** before anything is ordered: "Adds a certificate to IIS site Main, named Main/www.domain2.co.uk", or "Replaces the certificate Main/www.domain3.co.uk (bought, expires 27 Nov 2026)".
- **Each certificate renews on its own,** with its own schedule, CA, key, validation method, deployment steps, reminders and history. A renewal changes only that certificate's HTTPS bindings.
- **The CLI does the same:** `issue --site "Main" --hosts www.domain2.co.uk` prints the name the certificate is managed as. `issue --site "Main/www.domain2.co.uk"` renews or replaces that certificate.
- **A site with one certificate behaves exactly as before.**

### 9.2 Rules

- **The phase 1 rules stay:** one certificate per host name on a site, one lock per IIS site, and a name that reaches IIS only through the translation in the IIS layer.
- **The name is chosen the same way as for imports** (`ManagedCertificateNames.Resolve`), after taking the site's lock, so an issue and an import running together cannot both create the site's first certificate.
- **HTTP validation needs nothing new.** Every certificate on the site serves its challenge files from the same site folder. The per-site lock means only one order at a time writes there, and the challenge journal removes what an interrupted one leaves.
- **Host names are taken from the bindings without other certificates' host names** (already the case since 0.23), so issuing on a site never takes a host from another certificate by default.
- **A wildcard is still managed once per CA** (dns-validation.md, section 7). A second certificate on a site may cover `shop.example.com` next to one that has `*.example.com`, but it cannot ask for `*.example.com` too. That is refused, with advice to add the host name to the certificate that has the wildcard. Today the message suggests sharing, which does not apply on the same site.

### 9.3 What changes in Core

- `AcmeService.IssueAsync` resolves the name from the site and the host names, as imports do, in place of using the site name. `ThrowIfOtherCertificateOnSite` no longer refuses an additional name; it keeps the host-name rule and the refusal of `/` in names with no IIS site.
- Renewal passes the record's own name and host names, so a renewal of `Main/www.domain2.co.uk` changes only `www.domain2.co.uk`.
- The checks to verify on additional ACME certificates, with a test for each:
  - the bindings installed and rolled back;
  - the HTTPS verification;
  - the readiness checks in the 30 days before renewal;
  - port 80 in the health check;
  - deployment steps;
  - key reuse;
  - removal, which removes only that certificate's bindings.
- No data change: schema 11 already carries the name.

### 9.4 What changes in the app and CLI

- **Free and automatic:** the host-name list marks the host names of the site's other certificates ("Main/www.domain3.co.uk, bought"). They are unticked by default. The wizard shows which certificate the choice adds or replaces (9.1).
- **The certificate view:** an additional ACME certificate shows **Renew now** like any other.
- **CLI:** `issue` prints the name; `status` and `discover` need no change.
- README, roadmap and website: remove "phase 1" limits.

### 9.5 Sharing waits for demand

**Update, November 19, 2026 (feature 14 of the delivery plan):** a certificate on a site with several certificates can now be shared **from** that site to another, because its record holds only its own host names. Sharing **to** a site that has several certificates of its own stays refused (SSL4026): it would make the host-name checks on that site count hosts held by another site's certificate, the risk this section describes.

Sharing (`share add`) moves whole IIS sites onto another site's certificate, with a trial and a checked move per site. With several certificates on a site, the unit would become the host name, which reopens the most careful code in SSLense for a combination no one has asked for. Proposed: **keep the phase 1 refusal for sharing**, with a clearer message: "Sharing a certificate with a site that has several certificates is not supported. Issue a certificate for the host names instead."

### 9.6 Delivery and testing

| Step | Contents |
|---|---|
| 1 | This section |
| 2 | Core: naming at issue, renewal of additional certificates, the refusals relaxed, the wildcard message. Unit tests for each item in 9.3, and an end-to-end test against Pebble in CI that issues and renews two certificates on one site. **Built** November 19, 2026: the issue path resolves the name as imports do and uses it for the record, its files, the certificate it replaces and its deployment steps; the pre-issue and daily readiness checks find a second certificate's site; the result gives the name. 10 more tests, including the Pebble test |
| 3 | App and CLI as in 9.4; README, roadmap, website. **Built** November 19, 2026: Free and automatic marks the certificate that has each host name, ticks only new host names on a site with several certificates, says what the choice adds or replaces, and refuses host names of two certificates before Continue; renewing a second certificate by hand keeps its name; `issue` prints "Managed as". 6 tests, and an image of the host list |
| 4 | Acceptance on Let's Encrypt staging on a test server with two host names on one site: issue the second certificate, renew each, replace a bought one, remove one. Then release as 0.24 |
