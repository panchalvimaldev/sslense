# Manual tests: fleet reports

Feature 27 of [the delivery plan](../delivery-plan.md), first part; design in [docs/design/fleet.md](../design/fleet.md). Needs two servers with SSLense (WEB1, WEB2) and a share `\\files\sslense-fleet` where both computer accounts have modify access.

| # | Steps | Expected |
|---|---|---|
| 1 | On WEB1: `fleet folder --path \\files\nowhere` | SSL6034: cannot be reached |
| 2 | On both: `fleet folder --path \\files\sslense-fleet`; `fleet report` | `WEB1.json` and `WEB2.json` appear in the share; neither contains a thumbprint or secret |
| 3 | Wait for the next hourly check | Both files are rewritten |
| 4 | On WEB1: `fleet status` | Both servers and their certificates, soonest-expiring first |
| 5 | Stop the SSLense service on WEB2 for over three hours; `fleet status` on WEB1 | WEB2 is NOT REPORTING; exit code 1 |
| 6 | Make a renewal fail on WEB2 (for example, stop its site) and run its service | `fleet status` shows RENEWAL FAILED for that certificate |
| 7 | `fleet status --json` | One JSON document with every server as data |
| 8 | `fleet folder --off` on WEB1 | WEB1 stops writing; renewals are unaffected |
