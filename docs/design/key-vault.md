# Design: export to Azure Key Vault

**Removed before 0.24.0 was released** (November 26, 2026), to keep SSLense focused on IIS administrators: it could not be tested end to end. The code is in the git history before that date, and this design is kept so the feature can return if users ask. Open an issue if you need it.

Status: **built** November 20, 2026. Feature 24 of [the delivery plan](../delivery-plan.md). It calls the REST API directly, so it needs no Azure SDK package.

## What the administrator gets

A deployment step, **Import into Azure Key Vault**, puts the certificate and its key into a vault after every install and renewal. Azure services read it from there: App Service, Application Gateway, Front Door and virtual machines.

- The app: the certificate's After install section. The value is `vault/certificate`, and the password box takes `tenant:client ID:client secret`.
- The CLI: `SSLense.Cli deploy add --site <certificate> --key-vault contoso-kv/shop --tenant contoso.onmicrosoft.com --client-id <app ID>`. The client secret is asked for.

## Setting it up in Azure

1. In Microsoft Entra ID, register an app and create a client secret.
2. Give the app the right to import certificates into the vault:
   - in a vault that uses Azure RBAC, the **Key Vault Certificates Officer** role, ideally on the vault only;
   - in a vault with access policies, the certificate permission **Import**.
3. If the vault has a firewall, allow this server's public address.

## How the step works

- **When it is added:**
  - The certificate must have an exportable key. Otherwise the step is refused, as for the other export steps.
  - The vault and certificate names are checked against Key Vault's rules. The certificate's URL from the portal is accepted too.
  - The tenant, client ID and secret are kept together, protected with DPAPI. Settings export includes them only with `--include-secrets`.
- **When it runs:**
  1. SSLense exports a PFX in memory with a new random password used only for this upload, then clears it afterwards.
  2. It signs in with client credentials (scope `https://vault.azure.net/.default`).
  3. It posts the PFX to `https://<vault>.vault.azure.net/certificates/<name>/import?api-version=7.4`.
  4. Each renewal adds a new version of the same certificate, so Azure services that follow the latest version pick it up.
- **When it fails:** SSL7010 with Key Vault's or Entra ID's error code, such as `Forbidden` or `invalid_client`. The message never includes the key or the secret. The step is retried hourly, like every deployment step.

This is managed-certificate schema 16, because 0.23 would not know the step.

## Tests

- The step checks the vault and certificate names and the three-part credentials.
- It stores the credentials protected.
- It imports a PFX made with a one-time password.
- The client signs in with the Key Vault scope and posts the PFX and password.

Manual steps: removed with the feature; they are in the git history.
