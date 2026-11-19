# Design note: TLS-ALPN-01 validation

Status: **decided** November 19, 2026: **not built**, for the reasons below. Feature 12 of [the delivery plan](../delivery-plan.md), which asked for a design that either finds a safe way or records that there is none.

## What TLS-ALPN-01 needs

The certificate authority connects to the name or address on port 443 and starts a TLS handshake that offers only the `acme-tls/1` application protocol (RFC 8737). The server must answer that handshake with a special self-signed certificate holding the challenge in an `acmeIdentifier` extension, and must keep serving normal visitors meanwhile.

## Why SSLense does not offer it on IIS

- **HTTP.sys owns port 443.** On a server with any HTTPS binding, the Windows kernel driver HTTP.sys terminates TLS on port 443 for IIS. It negotiates only HTTP protocols (HTTP/1.1 and HTTP/2, and HTTP/3 over QUIC); it cannot be told to answer `acme-tls/1` with another certificate.
- **The only way around it is to take port 443 from IIS.** SSLense would have to remove the HTTPS bindings on that address, listen on port 443 itself for the validation, and put them back. Every HTTPS site on that address would be down meanwhile, and a crash or a refused restore in between would leave them down. That breaks the first principle of this project: a failed operation never leaves a site without its working binding.
- **There is a safe alternative for every case it would serve.** A site whose port 80 is closed to everything but validation can use HTTP answered by SSLense (feature 5), which needs port 80 only during validation; a site with no inbound port 80 at all can use DNS validation, which needs no inbound port.

## What SSLense does instead

- The issue wizard and `issue` offer HTTP (from IIS, or answered by SSLense) and DNS validation. The roadmap lists TLS-ALPN-01 as decided against, with a link here.
- If a future Windows version lets HTTP.sys answer `acme-tls/1` per address, this note is revisited.
