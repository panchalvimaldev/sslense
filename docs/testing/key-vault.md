# Manual tests: export to Azure Key Vault

Feature 24 of [the delivery plan](../delivery-plan.md); design in [docs/design/key-vault.md](../design/key-vault.md). Needs a test Azure subscription.

| # | Steps | Expected |
|---|---|---|
| 1 | Issue a staging certificate with `--exportable-key` | Issued |
| 2 | Create a vault with RBAC, an app with a client secret, and give the app Key Vault Certificates Officer on the vault | — |
| 3 | `deploy add --site <certificate> --key-vault <vault>/sslense-test --tenant <tenant> --client-id <app ID>`, enter the secret; `deploy run` | The portal shows certificate `sslense-test` with the same thumbprint |
| 4 | **Renew now** | A second version appears, with the new thumbprint |
| 5 | Remove the role assignment; `deploy run` | SSL7010 naming `Forbidden`; retried hourly; the secret is not in the log |
| 6 | Add the step to a certificate without an exportable key | Refused, naming `--exportable-key` |
| 7 | `deploy add ... --key-vault "bad name/x"` | Refused before anything is stored |
| 8 | The app: After install › **Import into Azure Key Vault**, value `<vault>/sslense-app`, password `tenant:client:secret` | As step 3 |

Not yet run against a real vault: every step stays open until the combined test.
