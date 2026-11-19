# Manual tests: error codes

Feature 1 of [the delivery plan](../delivery-plan.md); design in [docs/design/error-codes.md](../design/error-codes.md). Automated tests cover the catalogue, the documentation page, and every code shown in the app's error banner; these steps check what a person sees.

| # | Steps | Expected |
|---|---|---|
| 1 | In the CLI, run `SSLense.Cli issue --site "No Such Site" --hosts example.com --email admin@example.com` | `Error: SSL1001: IIS site 'No Such Site' was not found.` and a `More:` line with a link to docs/errors.md#ssl1001 |
| 2 | Open the link from step 1 | The SSL1001 entry, with what to do |
| 3 | In the app, Add certificate › Free and automatic: choose a site and a host name that has no HTTP binding on port 80, then Continue and Check | The failed check reads `SSL1003: Add an IIS HTTP binding on port 80 for this host.` |
| 4 | In the app, cause an error banner, for example Settings › DNS providers › add a provider with an empty name | The banner starts with the code as a link; clicking it opens its entry in the browser |
| 5 | Activity › Run health check on a server with the service stopped | The service result starts with `SSL5013` |
| 6 | Make a renewal fail on staging (for example, block port 80 for an HTTP certificate) and let the service retry | The certificate's last renewal message, the failure email or chat message, and the Event Log entry 1001 all start with the same code |
| 7 | Event Viewer › Applications and Services Logs › SSLense | Event IDs are unchanged: 1000 success, 1001 failure, 1002 and 1003 expiry |
