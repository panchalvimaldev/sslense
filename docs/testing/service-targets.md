# Manual tests: Remote Desktop and SQL Server steps

Part of feature 25 of [the delivery plan](../delivery-plan.md); design in [docs/design/service-targets.md](../design/service-targets.md).

| # | Steps | Expected |
|---|---|---|
| 1 | A certificate for the server's own name; `deploy add --site <certificate> --remote-desktop`; `deploy run` | Connecting with mstsc by that name shows no certificate warning; `Get-CimInstance -Namespace root\cimv2\TerminalServices Win32_TSGeneralSetting` shows the thumbprint |
| 2 | **Renew now** | A new connection gets the renewed certificate; an open session stays connected |
| 3 | On a server with SQL Server Express: `deploy add ... --sql-server sqlexpress`; `deploy run` | The step is "Use it for SQL Server 'SQLEXPRESS', and restart it"; the instance restarts; `SELECT encrypt_option FROM sys.dm_exec_connections` shows TRUE for a client that asks for encryption |
| 4 | `deploy add ... --sql-server NOSUCH` | SSL4058 |
| 5 | Remote Desktop turned off: `deploy add ... --remote-desktop` | SSL4058 |
| 6 | The app: After install › **Use it for SQL Server**, `MSSQLSERVER` | As step 3 for the default instance |
