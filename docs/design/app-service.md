# Design: Azure App Service

Status: **built** November 20, 2026. The last part of feature 25 of [the delivery plan](../delivery-plan.md), "Other deployment targets". It uses the Azure Resource Manager REST API, so it needs no SDK package.

## What the administrator gets

A deployment step, **Use it for Azure App Service**, keeps a web app's custom domains on the certificate SSLense renews. This suits an app whose domain is validated on this server, through DNS validation for example.

- The app: the certificate's After install section. The value is `<subscription ID>/<resource group>/<app>`, and the password box takes `tenant:client ID:client secret`.
- The CLI: `SSLense.Cli deploy add --site <certificate> --app-service <subscription>/<group>/<app> --tenant <tenant> --client-id <app ID>`. The secret is asked for.

## Setting it up in Azure

1. Register an app in Microsoft Entra ID and create a client secret.
2. Give it the **Website Contributor** role on the web app's resource group. The certificate is created in that group, so a role on the app alone is not enough.
3. Add the custom domain to the web app.

## How the step works

1. It signs in with client credentials (scope `https://management.azure.com/.default`).
2. It reads the app: its region, its App Service plan, and its host names.
3. It picks the custom host names the certificate covers. `*.azurewebsites.net` is skipped, and a wildcard covers one label. If none is covered, the step fails with SSL7011.
4. It uploads the certificate as `Microsoft.Web/certificates/sslense-<thumbprint>`. The PFX is made in memory under a one-time password.
5. It sets each covered host name's binding to SNI SSL with the new thumbprint.

**Old certificates:**
- Each renewal uploads a new certificate under a new name.
- The old one stays in the resource group until you delete it.
- App Service refuses to delete a certificate that a binding still uses, so deleting by hand is safe.

**When it fails:** SSL7011 with Azure's error code, and never the key or the secret. The step is retried hourly.

This is managed-certificate schema 20.

## Tests

- The app's identifier is checked when the step is added.
- The step sends the certificate and its names.
- Only host names the certificate covers are bound.
- The client reads the app, uploads the certificate with the app's region, and binds the covered domain with SNI.

Manual steps: [docs/testing/app-service.md](../testing/app-service.md).
