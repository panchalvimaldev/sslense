# Manual tests: maintenance windows

Feature 2 of [the delivery plan](../delivery-plan.md); design in [docs/design/maintenance-windows.md](../design/maintenance-windows.md).

| # | Steps | Expected |
|---|---|---|
| 1 | Settings › General › Maintenance window: tick "Renew automatically only during a maintenance window", choose a day that is not today, 01:00 to 02:00, Save | "Maintenance window saved: …" with the days and hours |
| 2 | `SSLense.Cli window show` | The same window |
| 3 | Make a staging certificate due: `SSLense.Cli revoke --site <site> --no-replace --reason cessation --yes` (the CA's ARI then asks for renewal now); `Restart-Service SSLense` outside the window, and read the newest log | The log and Activity say "Waiting for the maintenance window, which opens …"; the certificate is not renewed |
| 4 | Select that certificate and choose Renew now | It renews at once |
| 5 | Issue with `--profile shortlived` (6 days, expiring before the window next opens), revoke it as in step 3, and restart the service outside the window | It renews, and the log says it ran outside the maintenance window because it expires too soon |
| 6 | `SSLense.Cli window set --days mon --from 3 --to 3` | Refused with SSL5022 |
| 7 | `SSLense.Cli window off`, then reopen Settings | The window is off; renewals run when due |
