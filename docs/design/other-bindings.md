# Design: HTTPS bindings without a host name, and on other ports

Status: **built** November 20, 2026. ROADMAP section 5.4.

## The problem

SSLense replaced certificates on a site's SNI bindings on port 443, one per host name. Older servers often also have, or only have, other kinds of HTTPS bindings:

- **A binding without a host name:** `*:443:` or `10.0.0.5:443:`, which serves every name that reaches it, without SNI.
- **A binding on another port:** `*:8443:shop.example.com`, for an admin area or an API.

Adoption refused such sites. If SSLense had issued for one anyway, a renewal would have added an SNI binding beside the host-less one, leaving clients that reach the host-less binding on the old certificate. Bindings on other ports would have kept the old certificate until it expired.

## What SSLense does now

All of this happens in the same transaction as the site's other binding changes. Every change is recorded for undo, read back from IIS, and checked over TLS where it listens.

1. **A host served through a binding without a host name:** when the site has no SNI binding on port 443 for the host, but has a host-less binding on port 443, SSLense updates the host-less binding.
   - It keeps its address and stays without SNI.
   - No SNI binding is added beside it.
2. **Bindings that follow the certificate:** every other HTTPS binding of the same site that served the certificate being replaced follows it. That includes another port, or a host-less binding.
   - Each keeps its address, port and flags, such as SNI or DisableHTTP2. Only the Central Certificate Store flag is cleared, because SSLense binds from the machine store.
   - Each is checked on its own port. A host-less one is checked with the certificate's first name.
3. **Undo and recovery:** a changed binding is found again by exactly where it listens (its binding information), not by host name. So an SNI binding that was added and removed again is never confused with a host-less binding.

**Adopting:**
- A certificate bound on port 443 and on other ports is adopted. Its host names come from the port 443 bindings, and the bindings on other ports follow them.
- When the port 443 bindings have no host names, the host names come from the certificate's names. Wildcards are left out.
- A certificate bound **only** on other ports is still refused (SSL4001), because there is nothing on port 443 for those bindings to follow. Add a port 443 binding, then adopt it.

## Limits

- **Same site only:** a binding is followed only within the same IIS site, and only when it served the certificate being replaced. When SSLense has to add the port 443 binding, because the site had none for the host, nothing was replaced there, so nothing follows. Bind the other ports to the new certificate yourself once, and later renewals keep them in step.
- **No served-certificate check on other ports:** the health check and the daily served-certificate check look at port 443. Bindings on other ports are checked when they change.
- **IP-address certificates:** these are bound by address without SNI, as before ([ip-certificates.md](ip-certificates.md)).

## Tests

- **Unit tests:** a certificate on ports 443 and 8443 is adopted with the port 443 names; one only on 8443 is refused; a host-less binding takes its names from the certificate, without wildcards.
- **On real IIS** (`SSLense.Acceptance parta`):
  - A16: a binding on port 8443 follows a switch on 443, serves the new certificate, and goes back on undo.
  - A17: a host-less binding is renewed in place, with no SNI binding added, and goes back on undo.

Manual steps: [docs/testing/other-bindings.md](../testing/other-bindings.md).
