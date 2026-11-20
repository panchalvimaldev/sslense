# Design note: dns-persist-01 and newer DNS methods

Status: **waiting for a certificate authority**, November 19, 2026. Feature 13 of [the delivery plan](../delivery-plan.md): built only once a certificate authority offers the method in production.

## What it is

`dns-persist-01` is an IETF draft for a DNS challenge whose TXT record is created **once** and stays: it names the ACME account (and optionally a policy, such as allowing wildcards), and the certificate authority checks it at every order. No record changes at renewal, so no DNS API credentials are needed on the server.

## What SSLense will do when a CA offers it

- A validation method "DNS (permanent record)", next to DNS provider, acme-dns and manual. SSLense shows the one record to create, with the account URI it must name, and checks it is visible at the zone's name servers before ordering, as it does for acme-dns's CNAME.
- Renewal is then automatic with no DNS credentials at all, so it becomes the recommended DNS method where it is available; manual DNS validation remains for CAs without it.
- The health check confirms the record still names this server's account, so a changed account key or a new account (see [compromise recovery](compromise-recovery.md)) is caught before renewal.
- Certes does not offer the method yet; SSLense would send the challenge response itself, as it does for `replaces` orders, so no package change is expected.

## Until then

Nothing is built. The roadmap keeps the item under "More validation methods", and this note is updated when Let's Encrypt or another CA announces production support.
