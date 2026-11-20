# Design: HTTPS bindings without a host name, and on other ports

Status: **built** November 20, 2026. ROADMAP section 5.4.

## The problem

SSLense replaced certificates on a site's SNI bindings on port 443, one per host name. Older servers often also have, or only have, other kinds of HTTPS bindings:

- **A binding without a host name:** `*:443:` or `10.0.0.5:443:`, which serves every name that reaches it, without SNI.
- **A binding on another port:** `*:8443:shop.example.com`, for an admin area or an API.

Adoption refused such sites. If SSLense had issued for one anyway, a renewal would have added an SNI binding beside the host-less one, leaving clients that reach the host-less binding on the old certificate. Bindings on other ports would have kept the old certificate until it expired.

## What SSLense does now

All of this happens in the same transaction as the site's other binding changes. Every change is recorded for undo, read back from IIS, and checked over TLS where it listens.

1. **A host served through a binding without a host name:** when the site has no SNI binding on port 443 for the host, but has a host-less binding on port 443, SSLense updates the host-less binding. This happens only when the new certificate covers every name the old certificate on that binding had; otherwise an SNI binding is added for the host, as before.
   - It keeps its address and stays without SNI.
   - No SNI binding is added beside it.
2. **Bindings that follow the certificate:** every other HTTPS binding of the same site that served the certificate being replaced follows it. That includes another port, or a host-less binding.
   - **Only when the new certificate covers it:** a binding with a host name needs that name in the new certificate. One without a host name needs every name and IP address the old certificate had, because it answered for all of them. A binding that is not covered stays on the old certificate, and the clean-up keeps that certificate and names the site still using it, instead of serving a certificate without the binding's name.
   - Each keeps its address, port and flags, such as SNI or DisableHTTP2. Only the Central Certificate Store flag is cleared, because SSLense binds from the machine store.
   - Each is checked on its own port. One without a host name is checked without SNI, as its clients reach it, so the check never reaches an SNI binding for the same name on that port instead. This applies after a change, after an undo, and in the daily served-certificate check.
3. **Undo and recovery:** a changed binding is found again by exactly where it listens (its binding information), not by host name. So an SNI binding that was added and removed again is never confused with a host-less binding.
4. **Monitoring:** the served-certificate check, the health check and outside-renewal detection find a host's binding the same way, through its own binding or else the site's host-less one, so adopted host-less sites are not reported as missing a binding.
5. **Removing:** **Remove certificate and HTTPS bindings** removes every binding of the site that holds the certificate and belongs to its hosts: its own on port 443, those on other ports for its hosts, and one without a host name. Bindings for other names, or with other certificates, are left. An IP address owns its address: when the certificate's hosts include IP addresses, a binding on a specific address is removed only for one of those addresses. A host's own port 443 binding with another certificate still stops the removal, as before.

**Adopting:**
- A certificate bound on port 443 and on other ports is adopted. Its host names come from the port 443 bindings, and the bindings on other ports follow them.
- When the port 443 bindings have no host names, the host names come from the certificate's names. Wildcards are left out.
- A certificate bound **only** on other ports is still refused (SSL4001), because there is nothing on port 443 for those bindings to follow. Add a port 443 binding, then adopt it.

**Issuing and checks:** a host needs "a binding" to be issued for, pre-checked or recovered. A binding without a host name answers for it too: for HTTP validation on port 80, and for DNS validation or HTTP answered by SSLense on any HTTP or HTTPS port. When adopting, names the certificate lists are claimed only if the host-less binding really serves them, so a name with its own SNI binding, holding another certificate, stays with that one.

## Every place that reads bindings

Checked on November 20, 2026, so the new layouts are handled everywhere, not only where a review found them:

| Where | Uses |
|---|---|
| Switching, verifying and undoing (IisService) | Host-less fallback, coverage rule, exact binding information, SNI per binding |
| Removal (IisService) | The certificate's own bindings by host and address |
| Issue and shared-site checks (AcmeService), pre-checks (PreflightService) | `AnswersFor` |
| Already-covered check (AcmeService), recovery (CertificateRecoveryService), served-certificate check, health check, outside renewal detection | `ServingBindings` |
| Adoption (ImportedCertificateService) | Port 443 names, else certificate names that the host-less binding serves |
| Clean-up, replaced-certificate removal, stop managing, deployment conflicts, redirect, discovery | Any binding by thumbprint or by exact address and port, which every layout satisfies |

## Limits

- **Same site only:** a binding is followed only within the same IIS site, and only when it served the certificate being replaced. When SSLense has to add the port 443 binding, because the site had none for the host, nothing was replaced there, so nothing follows. Bind the other ports to the new certificate yourself once, and later renewals keep them in step.
- **The app lists host names from named bindings:** for a site whose bindings have no host names, give the host names with `issue --hosts` in the CLI, or adopt the site first.
- **No served-certificate check on other ports:** the health check and the daily served-certificate check look at port 443. Bindings on other ports are checked when they change.
- **IP-address certificates:** these are bound by address without SNI, as before ([ip-certificates.md](ip-certificates.md)).

## Tests

- **Unit tests:** a certificate on ports 443 and 8443 is adopted with the port 443 names; one only on 8443 is refused; a host-less binding takes its names from the certificate, without wildcards.
- **On real IIS** (`SSLense.Acceptance parta`):
  - A16: a binding on port 8443 follows a switch on 443, serves the new certificate, and goes back on undo.
  - A17: a host-less binding is renewed in place, with no SNI binding added, and goes back on undo.
  - A18: a port 8443 binding for a name the new certificate does not cover keeps the old certificate.
  - A19: removal takes the port 443, port 8443 and host-less bindings that hold the certificate, and leaves a binding for another name.
  - A20: a host-less binding on 8443 that shares the port with an SNI binding for the same name and another certificate is moved and checked without SNI; the SNI binding is left alone.
- **Unit tests for coverage:** which bindings may follow a certificate, and which binding serves a host, including IP addresses.

Manual steps: [docs/testing/other-bindings.md](../testing/other-bindings.md).
