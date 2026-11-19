# Design: built-in DNS providers

Status: **built** November 19, 2026; each provider is **untested on a real account** until it has run on one. Features 6 to 10 of [the delivery plan](../delivery-plan.md); ROADMAP section 4, item 3.

## Problem

DNS validation renews automatically only through Cloudflare, acme-dns, or the administrator's own script. The most common other DNS services each needed a script.

## What the administrator gets

Five more services in Settings › DNS providers and `SSLense.Cli dns add --provider`:

| Service | `--provider` | Credentials (prompted, encrypted with DPAPI) | Zone ID (`--zone-id`) | Least privilege |
|---|---|---|---|---|
| Amazon Route 53 | `route53` | Access key ID and secret access key | Hosted zone ID, such as Z0123456789ABCDEFGHIJ | IAM policy with route53:GetHostedZone, ListResourceRecordSets and ChangeResourceRecordSets on this hosted zone |
| Azure DNS | `azure` | Tenant ID, client (application) ID, client secret | `<subscription ID>/<resource group>` | DNS Zone Contributor on this zone |
| Google Cloud DNS | `google` | Service account JSON key (`--key-file`) | Managed zone name, such as example-com | DNS Administrator |
| DigitalOcean | `digitalocean` | Personal access token | none: the zone is the domain | Read and write on Domains |
| Hetzner | `hetzner` | Hetzner Cloud API token | none: the zone is its name | Read and write, in the zone's project |

Adding a provider reads the zone first, so wrong credentials or a wrong zone ID are refused before anything is saved. A refusal from the service is SSL3039, with the service's answer and the permission the credentials need, never the secret.

## How it works

- **No vendor SDKs.** Each provider calls its service's REST API over HTTPS: Route 53 signed with AWS Signature Version 4, Azure with an OAuth client-credentials token from Entra ID, Google with a JWT signed by the service account's RSA key and exchanged for a token (RFC 7523), DigitalOcean and Hetzner with a bearer token.
- **Other values at the name are kept.** Route 53, Azure and Google store all TXT values at a name as one record set, so SSLense reads the set, adds or removes its value, and writes the whole set (Google: deletes the old set and adds the new one in one change). DigitalOcean and Hetzner change single values.
- **The lowest TTL each service accepts**, 60 seconds, or 30 for DigitalOcean; an existing record set keeps its TTL.
- **Compiled in**, like Cloudflare: the service runs as SYSTEM, so it never loads third-party plugins.
- **Config schema 9,** because 0.23 would not recognize the new provider types.

## Tests

Each provider against a fake service that records every request: the address, method, body and authorization, adding to and removing from a set that has other values, deleting the set with its last value. Route 53's signing is checked against AWS's published Signature Version 4 example; Google's JWT is verified with the key's public half. A refusal names the service and permission without the secret. Manual steps, one per service, are in [docs/testing/dns-providers.md](../testing/dns-providers.md); a provider loses its "untested" label once they pass on a real account.
