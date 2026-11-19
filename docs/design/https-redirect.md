# Design: HTTP-to-HTTPS redirect helper

Status: **built** November 19, 2026. Feature 16 of [the delivery plan](../delivery-plan.md); ROADMAP section 4, item 6.

## Problem

Once a site has a certificate, administrators usually want plain HTTP sent to HTTPS. Done by hand, the redirect often catches `/.well-known/acme-challenge/` too, and the next HTTP renewal fails.

## What the administrator gets

- **⋯ › Redirect HTTP to HTTPS** on a certificate, and `SSLense.Cli redirect on --site <name>`: SSLense adds one IIS URL Rewrite rule to the site, first in its rules, that redirects plain HTTP to HTTPS permanently (301), keeping the host and path, **except** `/.well-known/acme-challenge/`.
- **Checked before and after.** It is refused without the URL Rewrite module (SSL1029), or without an HTTPS binding with a certificate on the site (SSL1030). Afterwards SSLense requests a challenge path through each host name on port 80; if that is redirected, for example by another rule or module, the rule is removed again (SSL1031). It also reports whether the home page now redirects.
- **⋯ › Stop redirecting HTTP**, and `redirect off`, remove only SSLense's rule, found by its name ("SSLense: HTTP to HTTPS"). Rules the administrator wrote are never touched. `redirect show` tells which is in place.

## How it works

The rule is written to the site's configuration through `Microsoft.Web.Administration`, as bindings are: `match url="(.*)"`, conditions `{HTTPS}` is `OFF` and `{REQUEST_URI}` does not start with `/.well-known/acme-challenge/`, action `Redirect` to `https://{HTTP_HOST}{REQUEST_URI}`. No package: URL Rewrite is an IIS module the administrator installs from Microsoft.

## Tests

The checks and rollback against a fake IIS service and site: added and confirmed; removed again when the challenge path is redirected; refused without URL Rewrite or HTTPS; removal only when present. Writing the rule into IIS is in the manual steps: [docs/testing/https-redirect.md](../testing/https-redirect.md).
