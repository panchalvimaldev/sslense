# Manual tests: built-in DNS providers

Features 6 to 10 of [the delivery plan](../delivery-plan.md); design in [docs/design/dns-providers.md](../design/dns-providers.md). Each needs a real account with a test zone; use Let's Encrypt staging. A provider whose steps pass loses its "Not yet tested on a real account" note.

For each of Amazon Route 53, Azure DNS, Google Cloud DNS, DigitalOcean and Hetzner:

| # | Steps | Expected |
|---|---|---|
| 1 | Settings › DNS providers › add the service with least-privilege credentials (see the design's table), or `SSLense.Cli dns add --provider <name> ...` | Added; a wrong zone ID or credentials is refused with SSL3039 or SSL3036, and nothing is saved |
| 2 | Test selected (`dns test --name <name>`) | A temporary TXT record is added, seen at the zone's name servers, and removed |
| 3 | Add another TXT value at `_acme-challenge.<host>` by hand in the service's console, then issue a staging certificate for the host with DNS validation | Issued; the hand-made value is still there afterwards |
| 4 | Issue a wildcard and its base name (`*.zone, zone`) | Both validation values are published at once and removed afterwards |
| 5 | Renew now | Renews through the provider |
| 6 | Revoke the credentials in the service's console, then Test selected | SSL3039, naming the service and the permission needed, without the secret |
