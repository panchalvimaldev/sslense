# Manual tests: sharing from a site with several certificates

Feature 14 of [the delivery plan](../delivery-plan.md); design in [docs/design/multiple-certificates-per-site.md](../design/multiple-certificates-per-site.md), section 9.5. Let's Encrypt staging, DNS validation.

| # | Steps | Expected |
|---|---|---|
| 1 | On site Main with two certificates, issue the second (`Main/www.domain2.example`) with DNS validation and names that also cover a host of site Blog | Issued |
| 2 | `SSLense.Cli share add --from "Main/www.domain2.example" --to "Blog"` | Blog is bound to that certificate; Main's first certificate is untouched |
| 3 | Renew the shared certificate | Both Main's second host and Blog get the new certificate |
| 4 | `SSLense.Cli share add --from "Blog2" --to "Main"` | Refused with SSL4026: Main has several certificates |
