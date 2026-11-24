# Manual tests: error codes

Feature 1 of [the delivery plan](../delivery-plan.md); design in [docs/design/error-codes.md](../design/error-codes.md). Automated tests cover the catalogue, the documentation page, and every code shown in the app's error banner; these steps check what a person sees.

| # | Steps | Expected |
|---|---|---|
| 1 | In the CLI, run `SSLense.Cli issue --site "No Such Site" --hosts example.com --email admin@example.com` | `Error: SSL1001: IIS site 'No Such Site' was not found.` and a `More:` line with a link to docs/errors.md#ssl1001 |
| 2 | Open the link from step 1 | The SSL1001 entry, with what to do |
| 3 | Give a site a host bound only on another port (`New-WebBinding -Name <site> -Protocol http -Port 8080 -HostHeader <host>`; the app offers only bound hosts). In the app, Add certificate › Free and automatic: choose that site and only that host, then Continue and Check. Remove the binding afterwards | The failed check reads `SSL1003: Add an IIS HTTP binding on port 80 for this host.` |
| 4 | In the app, cause an error banner, for example Settings › DNS providers › add a provider with an empty name | The banner starts with the code as a link; clicking it opens its entry in the browser |
| 5 | Activity › Run health check on a server with the service stopped | The service result starts with `SSL5013` |
| 6 | Make a renewal fail on staging: remove the certificate's HTTP binding on port 80, run `SSLense.Cli renew --site <site> --force`, then put the binding back. (Blocking port 80 is not enough: the CA reuses a recent validation and asks for no new challenge. A scheduled run alerts only after several failures in a row; a renewal started by hand alerts at once) | The CLI's error, the certificate's last renewal message, the failure email or chat message, and the text of Event Log entry 1001 carry the same code |
| 7 | Event Viewer › Windows Logs › Application, source SSLense (or `Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'SSLense' }`) | SSLense's own events use 1000 success, 1001 failure, 1002 and 1003 expiry, and 1900 test. Windows also writes "Service started/stopped successfully" for the service with ID 0, at Information level |
