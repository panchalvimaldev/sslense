# Design: one certificate across several IIS sites

Status: **approved** November 4, 2026, with decisions 1 to 8 in section 9 accepted as proposed. Section 5 was changed by the IIS tests before approval of decisions 7 and 8. Target release: 0.14. Branch: `feature/shared-certificates`. This is the design section promised by [dns-validation.md](dns-validation.md), section 7.

## 1. Problem

In 0.13, one certificate belongs to one IIS site. An administrator with `shop.example.com` and `blog.example.com` on separate sites cannot use one `*.example.com` certificate through SSLense. There are two poor workarounds:

- **A copy per site.** SSLense refuses this, because Let's Encrypt allows 5 certificates per week for the same set of names.
- **Binding it by hand in IIS.** Renewal leaves that binding on the old certificate, so the second site expires. SSLense warns about this but cannot fix it.

Sharing is also riskier than anything SSLense does today, because one failed renewal can affect every site that uses the certificate.

### Out of scope

- **Imported certificates,** such as a bought wildcard (decision 1).
- **HTTP-01 certificates.** Validation would have to reach several sites, so sharing needs DNS validation. HTTP-01 paths do not change.
- **Certificates on other machines or load balancers.** These stay on the roadmap as their own item.

## 2. What the administrator gets

```powershell
# Issue as today, for the first site.
SSLense.Cli issue --site "Shop" --email ops@example.com --validation dns `
  --names "*.example.com,example.com" --hosts "shop.example.com,example.com"

# Add another site. The certificate already covers it, so nothing is sent to the certificate authority.
SSLense.Cli share add --from "Shop" --to "Blog" --hosts "blog.example.com"

# Stop managing a site. Its binding stays as it is, so the site keeps working for now.
SSLense.Cli share remove --site "Blog"
```

- Without `--hosts`, `share add` uses every named binding on the site that the certificate covers. A host the certificate does not cover is an error.
- `share add` on a certificate already bound by hand only records it, which is the fix for today's hand-sharing warning.
- `renew --site "Blog"` renews the shared certificate, whichever of its sites is named.
- `issue` on the first site, including `--force`, keeps the other sites and updates them too. Names that would stop covering one of their hosts are refused.
- `issue` for a wildcard managed for another site is still refused, and the message now points to `share add`.

In the GUI, Certificate Details gains **Sites using this certificate**, with Add site and Stop managing. The Dashboard shows one row per certificate, such as `Shop +2 sites`. Status, notifications, and the digest name every site.

## 3. Data model

```csharp
public sealed record CertificateTarget(string SiteName, IReadOnlyList<string> Hosts, DateTimeOffset? PendingSince = null);
```

`ManagedCertificate` gains `AdditionalTargets`, a list that is empty for every existing record. `SiteName` and `Hosts` stay as the first site, so single-site certificates and existing code keep working.

**One site belongs to one certificate record.** This keeps site locks and `--site` unambiguous. These rules follow:

- `issue`, `csr`, `complete`, PFX import, and adoption on an additional site are refused, and name the certificate that manages it.
- A host can belong to only one site in a record. A host already bound on another site is refused before anything changes.
- If the site being added has its own certificate, `share add` is refused unless `--replace-existing` is given. That option swaps the binding and removes the old record in one transaction. An old ACME certificate is removed when no binding uses it, and an imported one always stays in the store.
- `share remove` on the first site promotes the next one and keeps the record's ID. A certificate with one site left is removed with the existing `remove`, which removes that site's bindings.
- `remove` on a shared certificate removes the bindings on every site. The confirmation lists all of them.

| File | Change | Schema |
|---|---|---|
| `managed-certificates.json` | `additionalTargets` | 4 → 5 |
| Transaction journal | The sites included in this operation | 2 → 3 |

Migration follows the existing pattern, with a backup first and refusal of newer schemas. A shared record is unknown to 0.13, so going back to 0.13 needs the backup taken before the upgrade.

## 4. Locks

- `ICertificateOperationLock` gains a way to take several site locks at once, **in sorted order of the normalized site name**, so two processes cannot deadlock. Scheduled checks try every lock without waiting, and skip the certificate until the next run if any is held.
- The list of sites comes from the record, which can change while waiting for the locks. After taking them, SSLense reads the record again. If the sites differ, it releases the locks and stops with the existing "state changed" error, and a scheduled renewal tries again on its next cycle.
- Operations on an additional site, such as a repair or a binding check, take the locks for every site in its record.

## 5. Binding transaction

IIS cannot change several sites in one atomic step (section 5.1), so the transaction is built from separate steps:

1. **Trial first.** Before touching a real site, SSLense adds the new certificate to HTTP.sys under a reserved host name that no site uses, with `netsh http add sslcert`, then deletes the entry. If HTTP.sys refuses the certificate, no real site has changed. Only the exit code is read, because the text is translated.
2. **One site at a time.** Each site gets its own commit, followed by the existing live HTTPS check. A binding that already uses the new certificate is left alone, because rewriting it drops connections for no benefit.
3. **Stop at the first failure and restore.** Every site changed so far goes back to the certificate it had, and the new certificate is removed.
4. **Check every restore.** A restored site gets the same live check. If it does not serve its old certificate, SSLense tries once more by removing and re-adding the binding. If it still fails, it reports that site by name as not restored and keeps the new certificate, as it does today when the binding state is uncertain. It never reports a restore it has not checked.

The current method becomes the one-site case. Steps 1 and 4 also apply to single-site installs, because they only add protection (decision 7).

While a change is running, sites can briefly be on different certificates, normally for under a second per site. Both are valid. Each site also refuses new connections for about 10 to 20 ms as its own binding changes. This already happens on every single-site renewal, and browsers normally retry.

The old certificate is removed only after the record is saved, and only when no binding uses it. The existing cleanup already does this.

**Recovery:** the journal entry lists the sites in the operation, and recovery finishes the bindings on all of them, as it does today for one site. If that fails, the entry stays and is retried at the next start. While it is pending, the old certificate stays in the store. A leftover trial entry is deleted at the next start and before each trial.

### 5.1 What real IIS does

Tested November 4, 2026 on Windows 11 and IIS 10, with three test sites and self-signed certificates. **Windows Server has not been tested** (section 8).

| Finding | Result |
|---|---|
| Where the certificate is stored | In HTTP.sys, not in `applicationHost.config`, so a commit is not one file write |
| Switching three sites in one commit | Sites change one after another, about 10 ms apart. All served the new certificate within about 50 ms, in 6 of 6 runs |
| New connections during a change | Refused for about 10 to 20 ms on each site. Switching one site did not affect the other two. A commit that rewrote an unchanged binding also dropped connections on that site |
| A commit with a certificate missing from the store, or with no private key | The commit fails with error 0x80070520. Earlier sites have already changed, **the failed site loses its HTTP.sys entry and stops serving HTTPS,** and later sites do not change |
| Restoring the failed site | **Depends on how it is done.** Setting the hash, store, then SSL flags worked in 3 of 3 tries, which is what SSLense does today. Removing and re-adding the binding also worked, as did `netsh`. Setting only the store and hash reported success and left the site down, in two variations. The reason is not known, so a restore has to be checked |
| Trial with a bad certificate | Refused by both a stopped IIS site and `netsh`, with real sites unaffected. A good certificate was accepted |
| Stopped site | The commit applies. It still answered TLS with the right certificate because other sites were listening on port 443, so the comment in `IisService` that it has no listener is not always true |
| Sites left on different certificates | Works; each site serves its own certificate |
| A binding that lost its HTTP.sys entry | IIS reports no certificate for it, so it looks unused. Binding it again to any certificate in the store brings it back. Found November 4, 2026, in the staging tests |

`netsh` is chosen for the trial over a stopped IIS site because it changes nothing in IIS, and an interrupted trial leaves nothing an administrator would see in IIS Manager.

## 6. When one site has a problem

This is the behaviour section 7 of the DNS design left open. One broken site must not take the others down at expiry, and a failed attempt must not use up the certificate authority's limit.

SSLense checks every site **before ordering**, and again when it binds:

| Site state | More than 7 days left | 7 days or fewer left |
|---|---|---|
| **Stopped** | Included. Bound, but no live check | Same |
| **Deleted, or the host's binding was removed** | Left out; the others renew | Same |
| **Started, but not answering HTTPS before ordering** | Nothing is ordered or changed; normal retry schedule | Left out; the others renew |
| **HTTP.sys refuses the new certificate in the trial** | Nothing changes on any site; retry after at least 24 hours | Same, because no site can use it |
| **Fails the live check after the swap** | Every site changed so far goes back; retry after at least 24 hours | Only that site goes back; the others continue to the new certificate |

"7 days" means the days left on the certificate in use. It applies however the renewal was started.

- **The pre-order check saves certificates.** A site that is already broken is found before anything is ordered. A failure after the swap has used one of the 5 weekly certificates, which is why it waits at least 24 hours, not the usual 1 to 6.
- **A site left out keeps its working binding** on the old certificate, which stays in the store while any site is left out, even if that site's binding shows no certificate (section 5.1). Its target gets `PendingSince`.
- **Catching up needs no new certificate.** Each service cycle tries to bind pending sites to the current certificate, with the same live check. A success clears `PendingSince`. A manual `renew --site` also tries, whichever site is named.
- **It is reported loudly.** Each result, notification, and digest names the site and its expiry date. Failure notifications for a site with a pending binding are sent whatever the normal failure count, because the renewal itself may look successful.
- **A deleted site stays in the record** until `share remove`, because a rename looks the same as a delete and SSLense should not guess. Its reminder tells the administrator to choose.

**Honest limit:** the last-7-days rule can leave sites on different certificates. The alternative is that every site expires together because of one, which is worse. The rule never applies earlier, and renewal normally starts about a third of the lifetime before expiry, so it needs about two weeks of failures to reach it.

**Honest limit:** the checks run from this server, as they do today. They show what IIS serves, not what visitors receive through a CDN or load balancer.

### Other features that read a record

| Feature | Change |
|---|---|
| Served-certificate check | Checks every site. A site pending or left out is reported with its own expiry |
| Hand-sharing warning | Sites in the record no longer count. The message for others now suggests `share add` |
| Readiness check | Adds the site states above, changing nothing |
| Outside-renewal detector | No change: it only looks at imported certificates, which cannot be shared (decision 1). A site moved to another certificate by hand is reported by the served-certificate check |
| Manual DNS certificates | Can be shared. The renewal command uses the first site, and the reminder names them all |
| Diagnostic bundles | `--redact-hosts` also covers additional sites' host names |

## 7. Safety requirements

Must hold before merge:

1. With more than 7 days left, any failure leaves every site on the certificate it had.
2. No operation removes a certificate that a binding uses, or one needed to roll back.
3. A site never loses a working binding because another site failed. `share remove` never changes a binding.
4. Single-site and HTTP-01 certificates behave exactly as they do today, except for the trial and restore check (decision 7).
5. `share add` and catching up never contact the certificate authority.
6. All development and automated testing uses Let's Encrypt staging.
7. A bad certificate is refused before any real site changes.
8. SSLense never reports a site as restored without checking what it serves.

## 8. Delivery and testing

| Step | Contents | Ships |
|---|---|---|
| 1 | This design | Docs |
| 2 | Spike on real IIS. **Done** November 4, 2026. One commit is not atomic, so section 5 changed (section 5.1). | Nothing |
| 3 | Core: model, migrations, locks, binding transaction, recovery, site-problem rules, catching up; `share` commands; updated checks and notifications. **Built and accepted** November 4, 2026, on Windows 11 and IIS 10 with Let's Encrypt staging: 55 checks on real IIS and 127 with the real commands. The run through the commands found one bug, now fixed (section 5.1, last row). | CLI |
| 4 | GUI, README, website, roadmap; manual acceptance; release as 0.14 | Both |

Unit tests use fake IIS and locks. They cover each row of the table in section 6, lock ordering, a site list changing while waiting, a crash at each journal stage, and migration from real version 4 files.

Manual acceptance on this machine, with Let's Encrypt staging and three local sites:

- `share add`, including a certificate first bound by hand, and `--replace-existing`
- A forced renewal that updates all three sites
- A stopped site, a deleted site, and a broken HTTPS binding, with more and with fewer than 7 days left
- Killing the process during a binding change
- Catching up after the broken site is fixed
- `share remove` on both an additional and the first site
- Upgrading an existing 0.13 installation
- A certificate refused in the trial, and a site whose restore needs the second attempt

The findings in section 5.1 must also be repeated on Windows Server before release, because that is where SSLense runs in production.

Done for step 3, November 4, 2026, except the GUI. Three things are still open: a live-check failure was simulated, because real IIS cannot be made to fail on demand; catching up ran through `renew`, not a real service cycle; and HTTP-01 was covered only by unit tests.

A production test on real sites stays a separate test that the maintainer runs.

## 9. Decisions for approval

1. **ACME certificates only, with DNS validation (proposed).** Bought wildcards shared across sites are common too, and could come next. They go through four other install paths, and SSLense never renews them, so they carry less renewal risk but need their own work.
2. **One site belongs to one certificate record (proposed).**
3. **All sites or none, until the last 7 days (proposed).** The 7 days could be changed. Fewer gives a smaller chance of split sites, but less time to fix what went wrong.
4. **A deleted site or removed binding does not hold back the others (proposed).** It is left out and reported.
5. **`share remove` leaves the binding in place (proposed).** The site keeps working, and the existing hand-sharing warning reports it until the administrator gives it another certificate.
6. **Command names `share add` and `share remove` (proposed).**
7. **Added November 4, 2026, after the IIS tests: use the trial and the restore check on every install, not only shared certificates (proposed).** A bad certificate would take down a single site too. This is the one change to single-site and HTTP-01 behaviour, so safety requirement 4 excludes it. If `netsh` cannot run, or the trial fails for a reason unrelated to the certificate, the install stops with an explanation and the site is unchanged.
8. **Added November 4, 2026: ship this with 0.14, with no 0.13.1 patch (proposed).** SSLense's current restore worked on real IIS in 3 of 3 tries. The gap is that it does not check the result, and it matters only when IIS refuses a certificate SSLense has just installed.
