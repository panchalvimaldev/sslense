# Design: certificates for IP addresses

Status: **built** November 19, 2026. Feature 11 of [the delivery plan](../delivery-plan.md); ROADMAP section "Later, by demand".

## What the administrator gets

- **A certificate for an IP address,** such as a server reached as `https://203.0.113.10/`, from a certificate authority that issues them. Let's Encrypt does, with short-lived certificates only:
  ```powershell
  SSLense.Cli issue --site "Default Web Site" --hosts 203.0.113.10 --validation http-self --profile shortlived --email ops@example.com
  ```
- **Validated over HTTP, answered by SSLense** (feature 5). A certificate authority cannot validate an IP address through DNS, and SSLense's listener answers requests to any address on port 80. Any other validation is refused with SSL6027.
- **Bound in IIS by address:** an HTTPS binding `203.0.113.10:443` without SNI (IPv6 in brackets), checked over HTTPS and rolled back like any other. A certificate can cover IP addresses and host names together.
- **Renewed automatically** like any other certificate; a six-day certificate renews every few days, so keep the service running.

## How it works

- Hosts may be IPv4 or IPv6 addresses, kept in their canonical form (`2001:db8::10`).
- Certes orders IP addresses as IP identifiers (RFC 8738) and its request puts them in as IP SANs; SSLense's own request, for key reuse, does the same, and so does its `replaces` order.
- **The common name is never an IP address.** Let's Encrypt refuses such a request ("CSR contains IP address in Common Name"), and a name longer than 64 characters. SSLense builds every request itself, with the first DNS name that fits as the common name, or none for IP addresses only; every name is in the subject alternative names. Found in the combined test: Pebble accepts an IP address there.
- An IP address needs no host binding on the site: SSLense creates the address binding.
- In the app, host names come from the site's bindings, so an IP certificate is issued from the CLI for now; it is then listed, checked and renewed in the app like any other.

## Tests

A Pebble test orders an IP address and checks the certificate has it as an IP SAN and no DNS name. Unit tests: an IP address without HTTP answered by SSLense is refused; with it, the address needs no binding, is ordered in canonical form and bound by address; SSLense's own request uses an IP SAN. Manual steps: [docs/testing/ip-certificates.md](../testing/ip-certificates.md).
