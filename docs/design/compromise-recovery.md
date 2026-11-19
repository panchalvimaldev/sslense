# Design: recovery from a compromised key or ACME account

Status: **approved** November 19, 2026 (the owner approved the whole delivery plan in advance). Feature 3 of [the delivery plan](../delivery-plan.md); ROADMAP section 5.1. The steps for an administrator are in [the runbook](../runbooks/compromised-key-or-account.md).

## 1. Problem

If a certificate's private key may have been copied, for example from a backup, a stolen disk or a server that was broken into, the certificate must be revoked so browsers stop trusting it, and replaced with one that has a new key. If the ACME account key may have been copied, someone else could order or revoke certificates as this server. Until now SSLense offered neither.

## 2. What the administrator gets

- **Revoke and replace** on a certificate SSLense renews automatically: in the app (⋯ › Revoke and replace (key compromised)…) and with `SSLense.Cli revoke --site <name> --yes`.
  - A new certificate with a new key is installed first, through the normal issue path (validation, HTTPS check, rollback, deployment steps), so no site is left serving a revoked certificate.
  - Then the certificate authority revokes the old certificate, for key compromise unless another reason is given (`--reason superseded|cessation|unspecified`).
  - A certificate set to reuse its key keeps doing so with the new key.
- **Revoke only** (`--no-replace`), for a certificate that is no longer used. Its sites keep serving it, and the result says browsers will refuse it.
- **If revocation fails after the replacement,** the sites already use the new certificate, and the old one is saved in the data folder (`revocations\<thumbprint>.cer`) with the exact command to try again: `SSLense.Cli revoke --file <path> --ca <id>`. The error is SSL2030.
- **Replace account key** for a certificate authority: in Settings › Certificate authorities, and with `SSLense.Cli account change-key --ca <id> --yes`. The certificate authority switches the account to a new key; the old key stops working. Certificates are not affected.
- **Not for bought certificates** (SSL4051): their provider revokes them. **Not automatic for manual DNS certificates** (SSL4052): renew by hand first, then revoke the old file.

## 3. Rules

- Replace before revoke, always, unless asked not to.
- The replacement never reuses the old key, whatever the certificate's key setting.
- Revocation is signed with this server's account for the certificate authority, which issued the certificate.
- The account key change holds the certificate authority's exclusive lock, so no order uses the old key while it changes. The new key is saved as soon as the certificate authority accepts it.
- No new package: Certes 4.1 has revocation and key change.

## 4. Delivery and testing

One pull request: `IRevocationService` in Core, the ACME client's revoke and key change, the CLI commands, the app's menu item and Settings action, the runbook. Unit tests cover the order of replace and revoke, the new key, key reuse kept, revoke only, a failed revocation saving the old certificate, bought and manual DNS certificates refused, and the exclusive lock. A Pebble test revokes a real certificate, refuses a second revocation, changes the account key and orders with the new key. Manual steps: [docs/testing/compromise-recovery.md](../testing/compromise-recovery.md).
