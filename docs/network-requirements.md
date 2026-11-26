# Firewall, DNS and proxy requirements

What a server running SSLense must be able to reach, and what must be able to reach it.

## Inbound

| Port | When | Why |
|---|---|---|
| TCP 80 | HTTP validation (`--validation http` or `http-self`) | The certificate authority fetches `http://<host>/.well-known/acme-challenge/<token>` from the internet. It must reach this server, or with farm folders any server behind the load balancer. A redirect to HTTPS is fine; SSLense's own redirect rule leaves this path alone |
| TCP 443 | Always, for sites with HTTPS | Visitors. SSLense also checks each binding over HTTPS from the server itself |
| — | DNS validation | Nothing inbound: use it when port 80 cannot be opened, for wildcards, or for servers on an internal network |

## Outbound

| Destination | Port | Used for |
|---|---|---|
| The CA's ACME directory, such as `acme-v02.api.letsencrypt.org` and `acme-staging-v02.api.letsencrypt.org` | TCP 443 | Ordering, renewal information (ARI), revocation |
| Each zone's authoritative name servers | UDP and TCP 53 | Checking that a validation TXT record has propagated, and the pre-check's CAA lookup |
| Your DNS provider's API, such as `api.cloudflare.com`, `route53.amazonaws.com`, `management.azure.com`, `dns.googleapis.com`, `api.digitalocean.com`, the Hetzner DNS API or your acme-dns server | TCP 443 | DNS validation |
| Your SMTP server | TCP 25, 465 or 587 | Email notifications |
| Your chat and push services (Teams, Slack, Discord, `api.telegram.org`, `ntfy.sh`), your webhook and heartbeat URLs | TCP 443, or 80 for internal ones | Notifications |
| `api.github.com` | TCP 443 | The new-version notice; turn it off in Settings › General |
| Shares for the Central Certificate Store or other export folders | TCP 445 | Writing exported certificates |

## DNS

- **The certificate's names:** they must resolve publicly to this server, or to its load balancer, for HTTP validation.
- **CAA records:** a CAA record on a name, or on any parent, must allow the chosen CA. For example, `0 issue "letsencrypt.org"` for Let's Encrypt. The pre-check reports a CAA record that blocks it.
- **Propagation:** split-horizon DNS is fine for DNS validation, because SSLense asks the zone's authoritative servers, as the CA does.

## Proxies

SSLense uses .NET's default proxy:

1. the `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` environment variables, when set;
2. otherwise, the proxy configured for the account it runs as.

The renewal service runs as SYSTEM, which normally has no proxy configured. To send it through a proxy:

- set machine-wide environment variables, for example `setx /M HTTPS_PROXY http://proxy.example.com:8080`, and `setx /M NO_PROXY localhost,.example.local` for internal names;
- restart the SSLense service.

DNS queries to name servers (port 53) and SMTP don't go through an HTTP proxy, so they need their own firewall rules. A proxy that intercepts TLS must be trusted by Windows. Otherwise the CA's certificate fails validation, which is the right outcome.
