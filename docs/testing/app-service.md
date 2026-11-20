# Manual tests: Azure App Service

Part of feature 25 of [the delivery plan](../delivery-plan.md); design in [docs/design/app-service.md](../design/app-service.md). Needs a test Azure subscription with a web app on a Basic or higher plan and a custom domain.

| # | Steps | Expected |
|---|---|---|
| 1 | Issue a staging certificate with `--exportable-key` for the app's custom domain (DNS validation) | Issued |
| 2 | App registration with Website Contributor on the resource group; `deploy add --site <certificate> --app-service <sub>/<group>/<app> --tenant <t> --client-id <c>`; `deploy run` | The portal shows certificate `sslense-<thumbprint>` and the domain bound with SNI SSL |
| 3 | **Renew now** | A second certificate is uploaded and the binding uses it |
| 4 | Remove the domain from the app; `deploy run` | SSL7011: no custom domain the certificate covers |
| 5 | Remove the role assignment; `deploy run` | SSL7011 naming `AuthorizationFailed`; the secret is not in the log |
| 6 | `deploy add ... --app-service web-rg/app` | Refused: not subscription/group/app |

Not yet run against a real subscription: every step stays open until the combined test.
