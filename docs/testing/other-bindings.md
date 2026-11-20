# Manual tests: bindings without a host name, and on other ports

Design in [docs/design/other-bindings.md](../design/other-bindings.md). On a test server with IIS.

| # | Steps | Expected |
|---|---|---|
| 1 | `SSLense.Acceptance parta` | A16 and A17 pass with the other scenarios |
| 2 | A site with `*:443:shop.<zone>` and `*:8443:shop.<zone>`, both on a bought or self-signed certificate; **Add certificate › already in IIS** | Adopted; hosts list `shop.<zone>` only |
| 3 | Issue a staging certificate for that site with `--force` | Port 443 and port 8443 both serve the new certificate (`Test-NetConnection` and a browser on `https://shop.<zone>:8443`) |
| 4 | **Renew now**, then roll back | Both ports follow each time |
| 5 | A site with only `*:443:` (no host name), on a certificate naming `old.<zone>`; adopt it | Adopted with host `old.<zone>` |
| 6 | Issue a staging certificate for `old.<zone>` with `--force` | The host-less binding holds the new certificate; IIS shows no new SNI binding |
| 7 | A site whose certificate is bound only on port 8443; adopt it | Refused with SSL4001, saying to add a port 443 binding |
