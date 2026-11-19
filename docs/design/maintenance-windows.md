# Design: maintenance windows

Status: **approved** November 19, 2026 (the owner approved the whole delivery plan in advance). Feature 2 of [the delivery plan](../delivery-plan.md); ROADMAP section 5.1.

## 1. Problem

A renewal replaces the certificate in IIS and runs the certificate's deployment steps, which can restart services such as SQL Server or Remote Desktop. Today the service renews whenever a certificate is due, so that can happen during working hours.

## 2. What the administrator gets

- **Settings › General › Maintenance window:** the days and hours, in server time, when automatic renewals may run. A window that ends earlier than it starts runs into the next day, as Saturday 22:00 to 04:00.
- **A due renewal waits for the window,** and the result says until when: "Waiting for the maintenance window, which opens Mon 2026-11-23 01:00 server time."
- **The window can never let a certificate expire.** Within a safety margin before expiry, the renewal runs at once, and the log says it ran outside the window. The margin is 2 days, or a tenth of the certificate's lifetime when that is longer: 9 days for a 90-day certificate, 2 days for a six-day one.
- **A failed renewal's retries follow the same rule.**
- **Renew now, in the app or the CLI, always runs at once.** Only the service waits.
- **CLI:** `SSLense.Cli window show`, `window set --days weekdays --from 1 --to 5`, `window off`.

## 3. Rules

- The window applies to scheduled renewals from the service. It does not delay reminders, checks, or deployment steps retried on their own.
- One window for the server. A per-certificate window can be added if users ask.
- Days are the days the window starts on. Hours are whole hours, 0 to 23.
- An invalid window (no days, an hour out of range, or the same start and end) is refused with SSL5022.
- The setting is optional in `config.json`, so no schema change.

## 4. Delivery and testing

Built in one pull request: the model and the rule in Core (`MaintenanceWindow`), the check in the renewal service, the setting, the CLI command, and the Settings card. Tests cover open and closed times, windows across midnight, the next opening, the safety margin for long and short-lived certificates, refusals, and the renewal service waiting, renewing close to expiry, and ignoring the window for Renew now. Manual steps: [docs/testing/maintenance-windows.md](../testing/maintenance-windows.md).
