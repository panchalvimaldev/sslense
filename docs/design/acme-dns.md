# Design: DNS validation through acme-dns

Status: **approved** November 12, 2026, with decisions 1 to 6 in section 7 accepted as proposed. Target release: 0.17. Branch: `feature/acme-dns`. Item 1 of the [roadmap](../../ROADMAP.md).

## 1. Problem

Automatic DNS validation needs SSLense to change a TXT record. Today it can through Cloudflare or the administrator's script. Both need a credential that can change records, and with most DNS services that credential can change **every record in the zone**. Anyone who takes over the web server can then redirect the domain. Many DNS hosts, such as registrars, offer no API at all.

acme-dns is a small DNS server made for this one job. The administrator creates **one CNAME, once**, at their own DNS host: `_acme-challenge.example.com` pointing to a name on the acme-dns server. From then on SSLense updates only that name on the acme-dns server, with a credential that can change nothing else. It works with any DNS host, even one without an API, and the main zone's credentials never touch the web server.

### Out of scope

- Running an acme-dns server. SSLense talks to one; the public server or the administrator's own.
- dns-persist-01, a newer ACME method that needs no record updates at all. Google Trust Services supports it since September 2026; it is a separate roadmap item once Let's Encrypt offers it in production.

## 2. How acme-dns works

Checked against the project's documentation on November 12, 2026.

- `POST /register` creates an account and returns a `username`, a `password`, a `subdomain`, and a `fulldomain` such as `8e57…d1.auth.acme-dns.io`. An optional `allowfrom` list of networks limits where updates may come from.
- `POST /update`, with `X-Api-User` and `X-Api-Key` headers and `{ "subdomain": …, "txt": … }`, sets a TXT value. **The value must be exactly 43 characters**, which every ACME DNS value is.
- Each account keeps **the two most recent values**, enough for a name and its wildcard, which use the same record. There is no delete: old values are simply replaced.
- `GET /health` answers when the server is up.
- The public server, `auth.acme-dns.io`, is free and run by volunteers, with no promise of uptime. It was up on November 12, 2026. The project itself recommends running your own server for anything important, because whoever runs it can answer validations for the names that point to it.

## 3. What the administrator gets

```powershell
# Register an account and get the CNAME to create, once per domain.
SSLense.Cli dns add --provider acme-dns --name "Shop acme-dns" --domain example.com --server https://auth.acme-dns.io
#   Create this record at your DNS host, then run 'dns test':
#   _acme-challenge.example.com  CNAME  8e57…d1.auth.acme-dns.io

SSLense.Cli dns test --name "Shop acme-dns"   # checks the CNAME, updates the value, waits for the acme-dns server to serve it

# Issuing and renewing are unchanged: SSLense follows the CNAME and finds the account.
SSLense.Cli issue --site "Shop" --email ops@example.com --validation dns --names "*.example.com,example.com" --hosts "shop.example.com"
```

- `--allow-from 203.0.113.10/32` limits updates to this server's address.
- `--import` takes an account another tool already registered: SSLense asks for the username, password, subdomain, and full domain, with the password hidden.
- In the app, **Settings → DNS providers** gains **acme-dns**, with the server, the domain, and a **Register** button that shows the CNAME to create.

## 4. Rules

- **One account per domain.** The account's full domain is what SSLense matches after following the CNAME, so the existing provider selection finds it with no new rules. A certificate for `example.com` and `*.example.com` needs one account and one CNAME.
- **At most two values at a time.** A certificate whose names need more than two values from one account at once, such as `a.example.com` and `b.example.com` both pointing at it, is refused before the order, with a message to give each name its own account. Otherwise the third value would push out the first, and validation would fail.
- **Nothing to remove.** `Remove` does nothing for acme-dns, and the cleanup journal treats it as done. The old value stays on the acme-dns server until the next update replaces it; it proves nothing once validation is over.
- **The CNAME is checked.** `dns test`, the check before each order, and the daily readiness check confirm that `_acme-challenge.<domain>` still points to the account. A missing CNAME is reported with the exact record to create.
- **Credentials:** the password is encrypted with DPAPI like a Cloudflare token, never logged, and left out of diagnostic bundles. The server must use HTTPS.
- **Propagation** is checked at the acme-dns server's own name servers, which the existing check already finds by following the CNAME.

## 5. Data changes

- `DnsProviderType` gains `AcmeDns`.
- `DnsProviderProfile` gains the server URL, the username, the subdomain, and the domain the account is for. The password goes in the existing protected token. The profile's zone is the account's full domain, so selection after the CNAME works unchanged.
- **Config schema 7 to 8,** because 0.16 would not recognise the new provider type. The old file is backed up at the first save, as before.
- The test value of `dns test` becomes 43 characters of Base64url for every provider, which acme-dns requires and the others accept.

## 6. Delivery and testing

| Step | Contents | Ships |
|---|---|---|
| 1 | This design | Docs |
| 2 | Core and CLI: the acme-dns provider, `dns add --provider acme-dns` with registration and `--import`, the CNAME check, the two-value rule, schema 8, health and readiness checks. Unit tests against a fake acme-dns server. **Built** November 12, 2026: 21 tests, with a fake server that checks credentials, accepts only 43-character values, and keeps the two newest; the diagnostic bundle test covers the account's username and password | CLI |
| 3 | App, README, roadmap, website; acceptance; release as 0.17 | Both |

Acceptance, with Let's Encrypt staging and the public acme-dns server: register an account for a name under `accept.sslense.com`, create its CNAME in Cloudflare, `dns test`, issue a wildcard with its base name, renew it, refuse a third value, and confirm that the stored password appears nowhere in the logs or a diagnostic bundle.

acme-dns publishes no Windows build, so CI uses the fake server rather than a real one. The acceptance run covers the real public server.

## 7. Decisions for approval

1. **Register through SSLense, and also import an existing account (proposed).** Registering is the easy path; importing lets someone keep an account another tool made.
2. **No default server (proposed).** `--server` is required, and the documentation names the public server with its limits, and recommends a self-hosted one for important domains.
3. **One account per domain, and at most two values at a time, checked before the order (proposed).**
4. **Check the CNAME before each order and daily (proposed),** so a deleted or wrong CNAME shows up before a renewal fails.
5. **Config schema 8 (proposed),** as for the script method in 0.15.
6. **Tests against a fake acme-dns server, and acceptance against the public one (proposed).** There is no Windows build to run a real one in CI.
