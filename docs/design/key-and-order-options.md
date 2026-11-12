. **Built** November 12, 2026, apart from acceptance: **Advanced** in Issue Certificate, kept when renewing by hand, and the options shown in Certificate Details# Design: key and order options

Status: **approved by delegation** November 12, 2026, with the decisions in section 6 taken by judgement for the owner's review. Target release: 0.21. Branch: `feature/key-options`. Item 2 of the [roadmap](../../ROADMAP.md).

## 1. Problem

Every certificate SSLense issues has an ECDSA P-256 key, the CA's default chain, and the CA's default kind of certificate. That suits most sites, but not all:

- **Older clients and some appliances accept only RSA,** and some policies require RSA 3072 or more, or ECDSA P-384.
- **A CA can offer more than one chain** to different roots, for old devices that trust only one of them.
- **CAs now offer ACME profiles,** such as Let's Encrypt's `shortlived` (certificates valid for about six days) and `tlsserver`. A short-lived certificate limits the harm of a stolen key without revocation.

## 2. What the administrator gets

```powershell
SSLense.Cli issue --site "Shop" --email ops@example.com --key rsa-3072
SSLense.Cli issue --site "Shop" --email ops@example.com --preferred-chain "ISRG Root X1"
SSLense.Cli issue --site "Shop" --email ops@example.com --profile shortlived
SSLense.Cli ca test --id letsencrypt-staging     # lists the profiles the CA offers
```

| Option | Values | Default |
|---|---|---|
| `--key` | `ecdsa-p256`, `ecdsa-p384`, `rsa-2048`, `rsa-3072`, `rsa-4096` | `ecdsa-p256` |
| `--preferred-chain` | The name of the root the chain should end at, as the CA names it | The CA's default |
| `--profile` | A profile the CA lists in its directory | None: the CA's default |

All three are kept with the certificate and used at every renewal. In the app they are under **Advanced** in **Issue Certificate**, and shown in Certificate Details and `status`.

## 3. Rules

- **A profile the CA does not list is refused** before anything is ordered, with the profiles it does list. `ca test` shows them.
- **A preferred chain is a preference:** when the CA offers no chain to that root, the default chain is used, as ACME clients do.
- **Short-lived certificates renew on time without new rules:** renewal already follows the CA's renewal information, or else starts at a third of the lifetime left, so a six-day certificate renews about two days before it expires. The service checks hourly.
- ECDSA P-521 is not offered, because Let's Encrypt and most CAs refuse it.

## 4. Data changes

- `ManagedCertificate` gains `KeyType`, `PreferredChain`, and `Profile`.
- **Managed certificates schema 8 to 9,** because 0.20 would renew such a certificate with the defaults, silently changing its key or profile.

## 5. Delivery

| Step | Contents | Ships |
|---|---|---|
| 1 | This design | Docs |
| 2 | Core and CLI: the three options at issue and renewal, profiles in `ca test`, schema 9, tests. **Built** November 12, 2026: 14 tests, creating each key type, reading profiles from a directory, refusing a profile the CA does not list, and keeping all three at renewal | CLI |
| 3 | The app; README, roadmap, website; release as 0.21 | Both |

## 6. Decisions taken by delegation

1. **Key types:** ECDSA P-256 (default), P-384, and RSA 2048, 3072, and 4096.
2. **Profiles are checked against the CA's directory** before ordering.
3. **Reusing the private key at renewal is left for later.** It needs the certificate request built from the key in the Windows store, which is a larger change, and few sites pin keys.
4. **Managed certificates schema 9.**
