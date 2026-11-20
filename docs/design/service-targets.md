# Design: Remote Desktop and SQL Server as built-in steps

Status: **built** November 20, 2026. The second part of feature 25 of [the delivery plan](../delivery-plan.md), "Other deployment targets". The first part is [HTTP.sys bindings](httpsys-bindings.md).

## What changes

Until now, Remote Desktop and SQL Server each needed two or three steps: key access, a ready-made script, and for SQL Server a restart. Now each is one built-in step that does all of it:

| Step | CLI | What it does after every install and renewal |
|---|---|---|
| **Use it for Remote Desktop** | `deploy add --site <certificate> --remote-desktop` | Gives `NT AUTHORITY\NETWORK SERVICE` read access to the key, sets the RDP-Tcp listener's certificate, and reads it back. New connections use it at once, and open sessions stay connected |
| **Use it for SQL Server** | `deploy add --site <certificate> --sql-server MSSQLSERVER` (or an instance name such as `SQLEXPRESS`) | Gives the instance's account (`NT Service\MSSQLSERVER` or `NT Service\MSSQL$<name>`) read access to the key, sets the instance's certificate, reads it back, and restarts the instance, because SQL Server reads its certificate only when it starts |

Both work in the registry, where Windows and SQL Server keep these settings:

- Remote Desktop: `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, value `SSLCertificateSHA1Hash`. This is the value the `Win32_TSGeneralSetting` WMI class writes.
- SQL Server: `SuperSocketNetLib\Certificate` under the instance's key. SQL Server Configuration Manager writes the same value.

So neither step needs PowerShell, a WMI package or the SQL Server tools.

When a step is added, a missing listener or instance is refused with SSL4058. When a step runs, a value that doesn't read back fails the step, which is retried hourly like every step.

**Plan for the restart:** the SQL Server step restarts the instance at every renewal, a short interruption. To choose the moment yourself, use the ready-made script `SqlServer.ps1` without a restart step instead.

**Certificate names:**
- SQL Server refuses to start with a certificate that does not include the server's fully qualified name. Check its error log after the first run.
- Remote Desktop uses a certificate without the name people connect to, and they then see a name warning.

**Exchange** stays a ready-made script (`deploy-scripts\Exchange.ps1`). Its settings are reached only through the Exchange Management Shell.

This is managed-certificate schema 18.

## Still to come in feature 25

- Apache, nginx and Tomcat on Windows (files and a reload).
- Azure App Service.

## Tests

- Both steps give the right account the key.
- They set the certificate.
- SQL Server's step restarts the instance's service.
- A missing SQL Server instance is refused.

Manual steps: [docs/testing/service-targets.md](../testing/service-targets.md).
