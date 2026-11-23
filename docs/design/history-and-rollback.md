# Design: certificate history and one-click rollback

Status: **built** November 19, 2026. Feature 20 of [the delivery plan](../delivery-plan.md); ROADMAP section 6, "Certificate history and one-click rollback".

## What the administrator gets

- **A timeline per certificate:** the certificate's **History** tab, and `SSLense.Cli history --site <name>`, list what happened, newest first: issued, renewed (with the certificate it replaced), renewal failed (with the error), rolled back, and revoked.
- **Going back:** when a renewal produced a certificate that breaks something (a client that pins the old key, an old device that does not trust the new chain, a key type a service cannot read), **⋯ › Roll back to the previous certificate…**, the **Roll back…** button on the History tab, or `SSLense.Cli rollback --site <name>` binds the certificate the renewal replaced again.
- **Going forward again:** the rollback keeps the newer certificate as the one to go back to, so the same command undoes it.

## Keeping the previous certificate

Before this feature, a renewal removed the replaced certificate from `LocalMachine\My` once nothing used it. Now:

- A renewal keeps the certificate it replaces while that certificate is still valid, and records its thumbprint on the managed certificate (`PreviousThumbprint`, managed-certificate schema 14).
- The next renewal removes the certificate kept before (if nothing uses it), so each certificate keeps at most one previous certificate in the store.
- A replaced certificate that has already expired is removed as before.
- Removing the certificate (`remove`, or `share add --replace-existing` replacing a site's own record) removes the one kept for it too, unless an IIS binding or FTP site still uses it, because nothing refers to it once the record is gone.
- **Revoke and replace** never keeps the revoked certificate: a compromised key is not one to go back to.
- The clean-up of unused certificates never suggests the kept certificate, and the deployment steps' clean-up does not remove it.

## When a rollback is refused (SSL4055)

Only to the certificate the last renewal replaced, and only while it:

- is still in `LocalMachine\My` with its private key;
- is valid for more than another day;
- covers every host the site now uses (an IIS wildcard host needs a wildcard name);
- was not revoked (from the history).

Certificates from other providers, certificates on other machines and certificates with no IIS site have no rollback: SSLense does not issue the first two, and the third is handed to services by its deployment steps.

## How the rollback runs

Under the same per-site lock and transaction journal as a renewal, so it cannot overlap one and an interrupted rollback is finished by recovery at the next start:

1. The previous certificate is bound to every site that uses the current one (several sites move one at a time and all go back if one fails, as for a shared certificate); each site is checked over HTTPS.
2. The record swaps the two thumbprints and takes the previous certificate's dates.
3. **Automatic renewal is held** for up to a week, so the service does not replace the certificate again before the problem is fixed, but never closer to expiry than a tenth of the lifetime or two days. A renewal started by hand is not held. When the previous certificate is already that close to expiry, the message says the service will renew it at its next check.
4. Deployment steps are **not** run again; the message says to run them (`deploy run`) if other services use the certificate.

## History storage

`history.json` in the data directory (schema 1), written under its own lock. The newest 50 entries per certificate are kept. Entries are linked to the managed certificate's ID, so the timeline survives a rename. Recording an entry never fails the operation it describes.

## Tests

The store keeps the newest entries per certificate; the timeline is newest first and follows the record ID; rollback binds the previous certificate, swaps the record, holds renewal and records the event; a failed binding changes nothing; no previous, revoked, expiring and not-covering certificates are refused; the hold is at most a week and never too close to expiry; a renewal keeps a valid replaced certificate, removes the one kept before, and removes an expired one; clean-up never suggests the kept certificate. Manual steps: [docs/testing/history-and-rollback.md](../testing/history-and-rollback.md).
