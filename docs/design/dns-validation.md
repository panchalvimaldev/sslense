# Design: DNS-01 validation and wildcard certificates

Status: **approved** November 3, 2026, with decisions 1 to 7 in section 11 accepted as proposed, then decision 7 changed and decision 8 added the same day. Branch: `feature/dns-validation`.

## 1. Problem

SSLense proves control of a host name only through HTTP-01, so it cannot serve three common cases:

- **Wildcard certificates.** Certificate authorities issue wildcard names only through DNS validation.
- **Sites that cannot open port 80,** because of policy, a firewall, or a load balancer that does not forward the challenge.
- **Internal servers,** whose host names are in a public domain but which cannot be reached from the internet.

DNS-01 solves all three: SSLense publishes a TXT record and the certificate authority reads it from public DNS.

### Out of scope

- Script-based validation, and providers other than Cloudflare. They come after this design's first release (section 10).
- dns-persist-01. It needs no DNS credentials on the server, so it is worth adding when available. The latest Let's Encrypt statement found says it will not reach production until an open issue is resolved (June 25, 2026). The provider and method model below leaves room for it.
- Names that do not exist in public DNS, such as `server.local`. No public CA can validate them.
- IIS bindings whose host name is literally `*.example.com` (section 6).

## 2. What the administrator gets

### 2.1 Provider method (automatic renewal)

```powershell
# Once per DNS zone. The token is prompted for, never passed as an argument.
SSLense.Cli dns add --provider cloudflare --name "Main" --zone example.com --zone-id <zone-id>
SSLense.Cli dns test --name "Main"

# A wildcard, bound to two host names on one IIS site.
SSLense.Cli issue --site "Shop" --email ops@example.com --validation dns `
  --names "*.example.com,example.com" --hosts "shop.example.com,example.com"

# A normal certificate for a site without port 80.
SSLense.Cli issue --site "Intranet" --email ops@example.com --validation dns --hosts intranet.example.com
```

Let's Encrypt staging stays the default. Production keeps its existing explicit guard.

`--names` lists what the certificate covers and `--hosts` lists the IIS bindings to create or update. Without `--names`, the certificate covers `--hosts`, as it does today. Without `--hosts`, SSLense uses every named binding on the site that `--names` covers. A host that no name covers is an error before anything is sent to the CA.

In the GUI, the Issue wizard gains a validation choice (HTTP, DNS provider, or DNS manual) and a certificate names field. Settings gains **DNS providers** with add, test, and remove.

### 2.2 Manual method (any DNS provider, no credentials)

```powershell
SSLense.Cli issue --site "Shop" --email ops@example.com --validation dns-manual --names "*.example.com,example.com"
```

SSLense shows each record to create, waits until the administrator confirms, checks that the records are visible, and then continues. It stays attached to the running command or wizard, because the ACME order is held in memory.

**Manual certificates cannot renew automatically.** The service never tries to renew them. The daily digest reminds the administrator using the existing reminder settings:

> **shop.example.com on site 'Shop' (Let's Encrypt): expires 15 Jan 2027, 12 days left.** It uses manual DNS validation, so SSLense cannot renew it on its own. Renew it by hand: `SSLense.Cli issue --site "Shop" --email ops@example.com --validation dns-manual --force --names "*.example.com" --hosts "shop.example.com"`

With certificate lifetimes moving toward 45 days, this is a lot of work. The wizard and documentation say so, and recommend CNAME delegation instead.

### 2.3 CNAME delegation (automatic renewal without API access to the main zone)

The administrator creates one permanent record in the main zone, by hand:

```text
_acme-challenge.example.com  CNAME  example-com.acme.example.net
```

SSLense follows the CNAME and publishes the TXT record at the target, using a token for that zone only. This has two uses:

- The main DNS provider has no API or is not supported, such as many domain registrars.
- The administrator does not want a token that can edit the main zone on a web server. See section 5.

## 3. Validation flow

HTTP-01 prepares and validates each host in turn. DNS-01 cannot, because `example.com` and `*.example.com` use the same record name and propagation takes time per round. The DNS flow runs in batches:

1. **Check before ordering:** names, a matching provider, a valid token, and CAA records (section 8). The rate-limited order is not created until these pass.
2. **Create the order.** Skip authorizations the CA already reports as valid, so reused authorizations change no DNS records.
3. **Journal, then publish.** Record each record's name and value in the journal, then add it. Existing TXT values at that name are left alone.
4. **Wait for propagation** (section 4). If it fails, clean up and stop without asking the CA to validate.
5. **Validate** all authorizations with the CA.
6. **Clean up** as soon as validation ends, whether it worked or not, removing only the records SSLense published.
7. **Finalize, install, bind, verify, and roll back if needed.** These use the existing transaction journal and HTTPS verification, unchanged.

Details that shape the implementation:

- **Wildcard authorizations:** the CA returns the base name (`example.com`) with a wildcard flag. Today's check that each challenge matches a requested host, and its one-challenge-per-host count, must compare the certificate names with that flag.
- **No port 80 requirement:** the port 80 binding check and the site's physical path requirement apply to HTTP-01 only.
- **Cleanup failures do not fail the issuance.** The certificate is already good. SSLense logs a warning, keeps the journal entry, and retries at startup through the existing recovery path.
- **Interrupted runs:** the journal is written before the record is added, so recovery may find a record that was never created. Recovery lists TXT records at that name and removes only an exact value match, which covers both cases.
- **Manual records** cannot be removed by SSLense. The wizard and CLI tell the administrator when they can delete them.

## 4. Propagation check

The check queries **every authoritative name server** for the zone directly, and passes when all of them return the expected value. It adds a short settle delay and then proceeds, up to a default timeout of 5 minutes.

- Querying public recursive resolvers is worse for this purpose: an early query can cache a "no such record" answer and delay validation.
- Name servers are found through public resolvers (1.1.1.1 and 8.8.8.8), not the server's own DNS. Internal servers often use split DNS, which gives different answers from what the CA sees.
- **If outbound port 53 is blocked,** which is common on locked-down servers, the check cannot run. SSLense logs this clearly, waits a fixed time (default 2 minutes), and continues.
- **Honest limit:** a pass shows that the authoritative servers have the record. It does not guarantee that the CA's validation succeeds.

.NET has no API for TXT and NS queries, so this needs the `DnsClient` package (decision 5).

## 5. Credentials

| Rule | Detail |
|---|---|
| Least privilege | The documentation and wizard ask for a Cloudflare token with **Zone → DNS → Edit** on one zone. No account-wide tokens or global API keys. |
| Encryption | Tokens are encrypted with the existing machine-scope DPAPI protector. |
| Entry | Prompted without echo, or read from standard input. There is no command-line option for the token, because arguments end up in shell history and process lists. |
| Never exposed | Never in logs, CLI output, or diagnostic bundles. The seeded-secret bundle test is extended with a DNS token. |
| Zone ID | Entered by the administrator, so the token needs no permission to list zones. |
| Removal | Refused while a certificate uses that provider. |
| Provider selection | The longest zone name that matches the record name, after following any CNAME. No match stops issuance with an explanation. |

**Honest limit:** the token can change **any record in its zone**, because Cloudflare grants DNS permissions per zone. DPAPI machine scope protects against copying the file to another machine, not against an administrator or SYSTEM process on this server. Anyone who takes over the server could therefore redirect that zone's traffic. For important domains, CNAME delegation to a separate zone limits the damage to the challenge records, and the documentation says this plainly.

### Provider interface

Providers are compiled into SSLense behind one internal interface:

```csharp
internal interface IDnsProvider
{
    Task VerifyAccessAsync(DnsProviderProfile profile, CancellationToken cancellationToken);

    Task AddTxtRecordAsync(DnsProviderProfile profile, string name, string value, CancellationToken cancellationToken);

    /// <summary>Removes only the record with this exact value; other values at the name are kept.</summary>
    Task RemoveTxtRecordAsync(DnsProviderProfile profile, string name, string value, CancellationToken cancellationToken);
}
```

The roadmap's "plugin interface" becomes this interface, not loadable plugins. The service runs as SYSTEM with access to certificates and tokens, so it must not load third-party DLLs. New providers arrive as pull requests. Script support (section 10) will cover anything else.

The Cloudflare provider uses the documented REST API with `HttpClient`, so it needs no package. It sets the lowest TTL that Cloudflare allows.

## 6. Certificate names and IIS bindings

Today `Hosts` means both "names on the certificate" and "IIS bindings to manage". A wildcard separates them, so:

- `Hosts` keeps its meaning: real host names with IIS bindings.
- A new `CertificateNames` holds what the certificate covers. When empty, it equals `Hosts`, so existing records and every existing HTTP-01 path are unchanged.

Because `Hosts` stays real names, these all work without changes: SNI binding, HTTPS verification, rollback, the served-certificate check, and health checks. None of them can probe a literal `*.example.com`, and none needs to.

Changes needed where the two meanings separate:

- `RenewalService` must order `CertificateNames`, with the record's validation method.
- `RenewalReadinessCheck` and the health check call the HTTP pre-flight checks for every automatic certificate. They must use the DNS checks for DNS certificates, or they would report false port 80 failures.
- A new host added to the site later is not bound automatically. The Health page reports a host that the wildcard covers but that has no SSLense-managed binding. The administrator then runs `issue` again with the new `--hosts` list.

**Literal `*.example.com` IIS bindings are refused** with an explanation. IIS 10 supports wildcard host headers, but HTTPS verification needs a real name to probe, and combining them with SNI needs testing on real servers first.

## 7. Sharing a wildcard across several IIS sites

This is the most common reason to want a wildcard, and it is the riskiest part: one failed renewal or rollback affects several sites. It ships as its own release (section 10), and nothing in the first release should make it harder.

**In the first release, one certificate belongs to one IIS site:**

- Requesting a wildcard name already managed for another site by the same CA is refused and explains why. `--force` does not override this. Issuing a copy per site is not a workaround. Let's Encrypt allows 5 certificates per week for the same set of names, across all accounts, and SSLense's renewals count toward this because it cannot yet send the ARI `replaces` field.
- **Hand-sharing is detected.** An administrator could bind the certificate to a second site in IIS. Renewal keeps the old certificate in that case, but only reports it as "another IIS binding uses it", and that site would then expire without warning. Renewal must name those sites in its result and notification, and the daily check must report them.

**Planned for the sharing release:**

- A record gains extra site and host targets, with `SiteName` as the first target.
- Operations take every site's lock, in sorted order to avoid deadlock.
- One transaction covers all sites. Any verification failure rolls back all of them, so sites never end up split between old and new certificates.
- If a stopped or misconfigured site blocks a renewal, the other sites and the expiry deadline need a defined behaviour. This needs its own short design section before that release.

## 8. Checks and diagnostics

**Daily readiness checks** (report-only, as today) for DNS certificates, with **no DNS changes**:

| Check | Fails when |
|---|---|
| Provider | The provider is missing, or its token cannot be decrypted or is rejected |
| Delegation | The CNAME is gone or changed |
| CAA | A CAA record blocks the CA, including `issuewild` for wildcards |
| Name servers | The zone's authoritative servers cannot be found or do not answer |

The existing two-failures-in-a-row rule and "likely to fail" wording apply. Manual certificates have no readiness check, because there is nothing to run automatically.

**Rate limits:** Let's Encrypt allows 5 failed authorizations per name per hour, so the checks in section 3 run before the CA is asked to validate. Failures use the existing persisted retry schedule.

**Diagnostic bundles:** `--redact-hosts` must also replace wildcard names, zone names, `_acme-challenge` names, and CNAME targets. The Zone ID is treated as sensitive. Tests cover a `*.` name in raw and JSON-escaped form.

## 9. Data changes

| File | Change | Schema |
|---|---|---|
| `config.json` | `dnsProviders` list: name, provider type, zone name, zone ID, DPAPI-protected token | 5 → 6 |
| `managed-certificates.json` | `validationMethod` (`Http01`, `Dns01Provider`, `Dns01Manual`), `certificateNames` | 3 → 4 |
| `dns-challenges\` (new folder) | One journal file per published record, as for HTTP-01 challenges: name, value, provider name, owner process, created date | 1 |

Migration follows the existing pattern, with a backup first and refusal of newer schemas. Every existing record becomes `Http01` with empty `certificateNames`, so nothing changes for existing installations.

In code, `IAcmeOrderSession` gains DNS challenges alongside `AcmeHttpChallenge`, using Certes's existing DNS challenge support. `IChallengeHandler` remains the HTTP-01 path, and the issue flow branches on the validation method in one place.

## 10. Safety requirements and delivery

Must hold before merge:

1. A failed DNS step never changes a working binding.
2. SSLense removes only TXT records it published, and never touches any other record type or value.
3. DNS tokens never appear in logs, CLI output, or diagnostic bundles.
4. Existing HTTP-01 certificates behave exactly as they do today.
5. The service never waits for a person: a manual certificate is reminded about, not attempted.
6. All development and automated testing uses Let's Encrypt staging or a local test server.

| Step | Contents | Ships |
|---|---|---|
| 1 | This design. **Done.** | Docs |
| 2 | Core: data model and migrations, DNS challenges, Cloudflare and manual methods, CNAME following, propagation check, token storage, journal and recovery; `dns` commands and `issue --validation`. **Done.** Tested November 3, 2026 on Let's Encrypt staging with the real Cloudflare API: `dns add`, `dns test`, `issue --validation dns` and a forced `renew` from the CLI. The renewal reused the valid authorization, so it published no DNS records. | CLI, staging |
| 3 | Wildcards: `--names`, CAA checks, renewal, readiness and health checks, reminders for manual certificates, one-site rule, hand-sharing detection, diagnostics. **Code done; needs a staging test of a wildcard on a real zone.** | CLI |
| 4 | GUI, README, website, roadmap; manual acceptance; release as 0.13 | Both |
| 5 | Sharing one certificate across several sites, after its design section; release as 0.14 | Both |
| 6 | A script method, after its design section: the service runs as SYSTEM, so the design must cover who can configure a script and how the script file is protected | Both |
| 7 | Built-in providers, one at a time: Amazon Route 53, Azure DNS, and GoDaddy first, then whatever users request most | Both |

### Adding providers

The goal is to support as many DNS providers as practical. The script method and CNAME delegation cover providers without built-in support, so built-in providers can be added by demand.

Each built-in provider implements `IDnsProvider` and uses the shared flow, so it only needs its own API tests and one test on a real account. The maintainer does not have accounts with most providers, so a provider stays labelled **untested** in the documentation until the maintainer or a user has run that test on a real account.

### Testing

- Unit tests with a fake DNS provider and fake resolver: batching, same-name values, partial publish failures, propagation timeout, blocked port 53, cleanup after each failure point, recovery, and wildcard authorization matching.
- Cloudflare provider tests against recorded API responses, with no network and no real token.
- Migration tests using real version 3 and version 5 files.
- Pebble with its DNS test server can exercise the full flow locally without contacting a CA. Adding it to CI is optional for this work.
- Manual acceptance on Let's Encrypt staging: a wildcard with its base name, a host without port 80, CNAME delegation, the manual method, a forced renewal through the service, and interrupted runs. Production issuance remains a separate manual test that the maintainer runs.

## 11. Decisions for approval

1. **Release order:** DNS-01 with single-site wildcards in 0.13, then sharing across sites in 0.14 (proposed).
2. **First methods:** Cloudflare, manual, and CNAME delegation. Azure DNS, Route 53, and scripts come later (proposed).
3. **Providers compiled in:** no loadable plugins, because the service runs as SYSTEM (proposed; this changes the roadmap wording).
4. **Propagation:** query authoritative servers directly, with a fixed wait as the fallback when port 53 is blocked (proposed; this changes the roadmap's "several resolvers").
5. **New package:** `DnsClient` for TXT, NS, CNAME, and CAA queries. Its licence and current version are to be confirmed before it is added. The alternative is hand-written DNS packet parsing, which is riskier (proposed: add the package).
6. **Literal `*.example.com` IIS bindings:** refused in this version (proposed).
7. **Test domain:** use a separate domain on Cloudflare for staging tests, so a test token cannot change DNS for `sslense.com` (proposed; the maintainer needs to provide it before step 2's acceptance). **Changed November 3, 2026:** no spare domain is available, so the test uses `sslense.com` with the host `dnstest.sslense.com` and a token limited to that zone, which expires the next day and is deleted after the test.
8. **Provider plan, added November 3, 2026:** support as many providers as practical, in the order in step 6 and step 7 of section 10. This replaces the order in decision 2 after 0.13.

## 12. References

- [Let's Encrypt: challenge types](https://letsencrypt.org/docs/challenge-types/)
- [Let's Encrypt: rate limits](https://letsencrypt.org/docs/rate-limits/)
- [Let's Encrypt: dns-persist-01 announcement](https://letsencrypt.org/2026/02/18/dns-persist-01) and [deployment status](https://community.letsencrypt.org/t/dns-persist-01-deployment-status-and-timeline/246468)
- [Cloudflare: creating API tokens](https://developers.cloudflare.com/api/tokens/create)
- [Microsoft: IIS 10 wildcard host header support](https://learn.microsoft.com/en-us/iis/get-started/whats-new-in-iis-10/wildcard-host-header-support)
