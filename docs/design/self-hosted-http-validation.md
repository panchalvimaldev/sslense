# Design: HTTP validation without a port 80 binding

Status: **built** November 19, 2026. Feature 5 of [the delivery plan](../delivery-plan.md); ROADMAP section 4, item 4.

## Problem

HTTP validation writes the challenge file into the site's folder, so the site needs an HTTP binding on port 80 for each host name. Many sites have only HTTPS bindings, or their port 80 traffic goes to a redirect site. Until now those had to use DNS validation.

## What the administrator gets

- **A choice under HTTP validation:** "SSLense answers the challenge itself, so the site needs no HTTP binding on port 80" in the app, and `--validation http-self` in the CLI, for `issue` and `preflight`.
- **The host needs any HTTP or HTTPS binding** SSLense manages; no port 80 binding and no site folder are needed.
- **Renewals keep the choice,** and the daily readiness check and the health check test it the same way.
- **A certificate with no IIS site** can use it too, for a service with a public name and port 80 open.
- **The pre-issue check** serves a test token and fetches it through each host name on port 80, so it tests the whole path: DNS, firewall, NAT, and SSLense answering.

## How it works

- SSLense registers `http://+:80/.well-known/acme-challenge/` with HTTP.sys (`HttpListener`, part of .NET), only while a certificate is validated, and answers known tokens. HTTP.sys, which IIS also uses, gives a strong wildcard registration with a longer path precedence over the host names IIS registers, so IIS keeps serving every other request.
- One listener per process, shared by concurrent validations; it stops when the last token is released.
- It needs Administrator rights, as SSLense already does. Another program that holds port 80 outside HTTP.sys prevents it: SSL1028.
- The certificate record keeps `SelfHostedHttp`, an optional field: a version that does not know it uses the site's folder, and fails with a clear error if the site has no port 80 binding.

## Tests

The listener on a localhost port: a token is answered only while served, unknown tokens get 404, two tokens at once, release stops it, and a second listener on the same port is refused with SSL1028. The issue path: no port 80 binding or folder needed, for a site and for no site, the choice saved; without it, a port 80 binding is still required. Manual steps: [docs/testing/self-hosted-http-validation.md](../testing/self-hosted-http-validation.md), including the real registration beside IIS, which needs an elevated server.
