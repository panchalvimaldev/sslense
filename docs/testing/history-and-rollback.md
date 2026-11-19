# Manual tests: certificate history and rollback

Feature 20 of [the delivery plan](../delivery-plan.md); design in [docs/design/history-and-rollback.md](../design/history-and-rollback.md).

| # | Steps | Expected |
|---|---|---|
| 1 | Issue a staging certificate for a test site; open its History tab | "Issued" in the timeline; "No previous certificate is kept…"; **Roll back…** disabled |
| 2 | **Renew now**; open the History tab again | "Renewed" with the replaced thumbprint; the old certificate is still in certlm.msc › Personal; **Roll back…** enabled |
| 3 | **Roll back…**; Yes | The site serves the old certificate (check in a browser); the timeline shows "Rolled back"; the message says automatic renewal waits until a date about a week ahead |
| 4 | `SSLense.Cli renew --all` with the service's schedule (or wait for the service) | The certificate is reported as held until that date and is not renewed |
| 5 | `SSLense.Cli rollback --site <site>` | The site serves the newer certificate again (rolled forward) |
| 6 | **Renew now** twice | After the second renewal only one older certificate is left in the store for the site |
| 7 | Activity › Unused certificates › Find | The certificate kept for rollback is not listed |
| 8 | ⋯ › Revoke and replace…; then History | "Revoked"; rollback is not offered to the revoked certificate |
| 9 | `SSLense.Cli history --site <site>` | The same timeline, newest first, and whether rollback is available |
