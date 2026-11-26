# Manual tests: HTTP validation without a port 80 binding

Feature 5 of [the delivery plan](../delivery-plan.md); design in [docs/design/self-hosted-http-validation.md](../design/self-hosted-http-validation.md). On a server with IIS, SSLense run as Administrator, Let's Encrypt staging, and inbound port 80 open.

| # | Steps | Expected |
|---|---|---|
| 1 | Give a site only an HTTPS binding for a public host name (no port 80 binding). Add certificate › Free and automatic, HTTP, tick "SSLense answers the challenge itself" | The host shows "Ready: SSLense answers on port 80" |
| 2 | Continue and Check | Port 80 passes, and "HTTP reachability" passes: "SSLense answered a test challenge through this host name" |
| 3 | Issue | Issued and bound; while it validated, other paths on port 80 kept being served by IIS (or got IIS's usual 404) |
| 4 | Renew now | Renews the same way |
| 5 | Stop IIS's port 80 use entirely (no site bound to port 80) and repeat 2 and 4 | Still works: HTTP.sys listens on port 80 for SSLense only during validation |
| 6 | Run another web server holding port 80 outside HTTP.sys (for example a test nginx), then Check | Port 80 fails with SSL1028 |
| 7 | `SSLense.Cli issue --no-site "Test" --names <host> --validation http-self --email <you> --staging` for a host that resolves to the server (a certificate with no site takes `--names`, not `--hosts`) | Issued; nothing bound in IIS |
