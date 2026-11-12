# Design: private-key reuse at renewal

Status: **approved by delegation** November 12, 2026, with the decisions in section 5 taken by judgement for the owner's review. Target release: 0.22. Branch: `feature/key-reuse`. Item 1 of the [roadmap](../../ROADMAP.md).

## 1. Problem

Every renewal creates a new private key, which is the safer default. Some setups need the key to stay the same:

- **Key pinning,** where a client, a mobile app, or a partner trusts this server's public key itself.
- **DANE TLSA records** that publish a hash of the public key, which must change in DNS before the key does.
- **Access already granted** to the key, by hand or by tools other than SSLense.

## 2. What the administrator gets

```powershell
SSLense.Cli issue --site "Shop" --email ops@example.com --reuse-key
```

- The first certificate gets a new key as usual. **Every renewal after that keeps the same key:** SSLense signs the certificate request with the key already in the Windows store, which never leaves it, and links the new certificate to that key.
- The choice is kept at every renewal. In the app it is **Reuse the private key at renewal** under **Advanced** in **Issue Certificate**, and Certificate Details shows it.

## 3. Rules

- **The key must still match the chosen key type.** A certificate changed from ECDSA to RSA, for example, gets a new key once, and that key is reused from then on.
- **When the key cannot be reused,** because the certificate or its key is gone or no longer readable, the renewal uses a new key rather than fail, and says so in its result and notification. A certificate that expires is worse than a changed key, and pinning setups usually pin a backup key too.
- The key keeps its own export policy and access rules. `--exportable-key` takes effect only when a new key is created.
- Removing the old certificate never deletes the key: SSLense removes certificates from the store, not keys.

## 4. Data changes

- `ManagedCertificate` gains `ReuseKey`.
- **Managed certificates schema 9 to 10,** because 0.21 would renew with a new key.

## 5. Decisions taken by delegation

1. **Opt-in per certificate,** off by default.
2. **Fall back to a new key, and say so,** when the key cannot be reused, instead of failing the renewal.
3. **Managed certificates schema 10.**
