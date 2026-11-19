# Manual tests: maintenance windows

Feature 2 of [the delivery plan](../delivery-plan.md); design in [docs/design/maintenance-windows.md](../design/maintenance-windows.md).

| # | Steps | Expected |
|---|---|---|
| 1 | Settings › General › Maintenance window: tick "Renew automatically only during a maintenance window", choose a day that is not today, 01:00 to 02:00, Save | "Maintenance window saved: …" with the days and hours |
| 2 | `SSLense.Cli window show` | The same window |
| 3 | Make a staging certificate due (for example `renew --site <site> --force` once, then wait, or use a short-lived profile) and let the service run its hourly check outside the window | The log and Activity say "Waiting for the maintenance window, which opens …"; the certificate is not renewed |
| 4 | Select that certificate and choose Renew now | It renews at once |
| 5 | With a certificate within 2 days of expiry (a short-lived staging profile), let the service run outside the window | It renews, and the log says it ran outside the maintenance window because it expires too soon |
| 6 | `SSLense.Cli window set --days mon --from 3 --to 3` | Refused with SSL5022 |
| 7 | `SSLense.Cli window off`, then reopen Settings | The window is off; renewals run when due |
