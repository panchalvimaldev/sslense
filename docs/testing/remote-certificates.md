# Manual tests: certificates on other machines

Feature 15 of [the delivery plan](../delivery-plan.md); design in [docs/design/remote-certificates.md](../design/remote-certificates.md).

| # | Steps | Expected |
|---|---|---|
| 1 | Add certificate › It's already installed in IIS › On another machine: name "Router", host of a device on the network that serves HTTPS, port 443; Watch | Listed under "On other machines" as "Elsewhere", with its expiry |
| 2 | Select it; Check | "serves the watched certificate" |
| 3 | `SSLense.Cli watch --name "Public" --host www.example.org` | Watched |
| 4 | Set Start reminding so the certificate is inside the window; Reminders tab › Send sample digest | It appears, saying to renew it on the machine that serves it |
| 5 | Replace the device's certificate, then run the daily check (restart the service, or wait for it) | The record shows the new certificate; a replacement notification is sent |
| 6 | Unplug or firewall the device; Activity › Run health check | "Served by …" fails with SSL4053 |
| 7 | Renew all due | It is skipped: renewed on that machine |
| 8 | ⋯ › Stop managing | Removed from SSLense; nothing changes on the device |
