# Runbook: the renewal service is not running or not checking

**Signs:** the heartbeat monitor alerts, the app's header shows the service as stopped, `fleet status` says NOT REPORTING, or `SSLense.Cli service-status` is not Running.

1. **State:** `SSLense.Cli service-status` and `SSLense.Cli health`. The health check shows when the last hourly cycle started and finished, and its message.
2. **Start it:** `SSLense.Cli start-service`. If it stops again at once, read the newest file in `C:\ProgramData\SSLense\logs`, and the Windows Application log (source SSLense).
3. **Common causes:**
   - **Data folder permissions changed:** run `SSLense.Cli check-permissions`, then `SSLense.Cli secure-data` as Administrator.
   - **Data written by a newer SSLense** (SSL6023): install that version again. Downgrades are not supported ([upgrading.md](../upgrading.md)).
   - **A damaged state file** (SSL6xxx naming the file): restore it from the `.v<n>.bak` copy next to it, or from your backup.
   - **The service was removed:** reinstall from the MSI, or run `SSLense.Cli install-service`.
4. **Running, but no cycle completes:** the health check names the failing part: renewal, deployment steps or reminders. Each has its own runbook or [errors.md](../errors.md) entry.
5. **Confirm:** within an hour, the heartbeat pings again, the health check shows a recent cycle, and `fleet status` shows the server OK.
