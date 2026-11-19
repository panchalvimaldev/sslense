# Design: certificates on other machines

Status: **built** November 19, 2026. Feature 15 of [the delivery plan](../delivery-plan.md); ROADMAP section 4, item 5.

## Problem

A load balancer, firewall or appliance often serves the HTTPS certificate for a site, and nobody is reminded when it expires. SSLense already sends one daily digest for this server's certificates; it should cover those too.

## What the administrator gets

- **Watch a certificate on another machine:** Add certificate › It's already installed in IIS › On another machine (name, host or address, port), or `SSLense.Cli watch --name "Load balancer" --host lb.example.com [--port 443]`. SSLense reads the certificate the host serves over TLS, even an expired or untrusted one, and lists it under "On other machines".
- **Reminders** as for a bought certificate: from the configured days before expiry, telling you to renew it on the machine that serves it.
- **Replacement is noticed:** the daily check reads it again, and a new certificate replaces the record (the reminders start over), with a notification. A host that cannot be reached is reported in the log, and the health check fails for it (SSL4053).
- **Check** reads it at once. **Renew** does not apply: renewal skips it, saying it is renewed on that machine.
- **Removing** it only stops the watching; nothing on the other machine is ever changed.

## How it is stored

A managed certificate with source Remote, no IIS site, its host as the one host name, and the port when it is not 443. Managed certificates schema 13, because 0.23 would try to renew it.

## Tests

The reader against a local TLS server with a self-signed certificate, and against a port nothing answers on; watching and refusing a name in use; the daily check taking over a replaced certificate and reporting an unreachable host; renewal skipping it. Manual steps: [docs/testing/remote-certificates.md](../testing/remote-certificates.md).
