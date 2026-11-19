# Manual tests: HTTP-to-HTTPS redirect

Feature 16 of [the delivery plan](../delivery-plan.md); design in [docs/design/https-redirect.md](../design/https-redirect.md). A server with IIS and the URL Rewrite module, and a site with an HTTP binding on port 80 and an HTTPS certificate from SSLense.

| # | Steps | Expected |
|---|---|---|
| 1 | Select the certificate; ⋯ › Redirect HTTP to HTTPS | "now redirects HTTP to HTTPS, confirmed for …"; IIS Manager › URL Rewrite shows "SSLense: HTTP to HTTPS" first |
| 2 | Open `http://<host>/some/page?x=1` | 301 to `https://<host>/some/page?x=1` |
| 3 | Renew now (HTTP validation) | Renews: the challenge is not redirected |
| 4 | `SSLense.Cli redirect show --site <name>` | On |
| 5 | ⋯ › Stop redirecting HTTP | The rule is gone; other rules are unchanged |
| 6 | Uninstall URL Rewrite, then ⋯ › Redirect HTTP to HTTPS | SSL1029 |
| 7 | Add a server-level rule that redirects everything, then step 1 | SSL1031, and SSLense's rule is removed again |
