# Design: email through Microsoft Graph

**Removed before 0.24.0 was released** (November 26, 2026), to keep SSLense focused on IIS administrators: it could not be tested end to end. The code is in the git history before that date, and this design is kept so the feature can return if users ask. Open an issue if you need it.

Status: **built** November 20, 2026. Part of feature 22 of [the delivery plan](../delivery-plan.md); ROADMAP section 6, "More notification channels". Signed webhooks are in [signed-webhooks.md](signed-webhooks.md).

## Why

Many Microsoft 365 tenants turn off SMTP AUTH, and not every server can use the relay through the tenant's MX endpoint. Microsoft Graph sends mail over HTTPS with an app registration instead. SSLense calls its REST API directly, so it needs no SDK package.

## Setting it up

1. In Microsoft Entra ID, register an app.
2. Add the **Mail.Send** application permission and grant admin consent.
3. Create a client secret.
4. Limit the app to the sending mailbox with an application access policy (Exchange Online `New-ApplicationAccessPolicy`) or RBAC for Applications. Without a limit, Mail.Send can send as any mailbox.
5. In SSLense, choose the email preset **Microsoft 365 through Microsoft Graph**, or run `SSLense.Cli notifications email --auth graph`, and enter:
   - **Host:** the tenant ID or domain, such as `contoso.onmicrosoft.com`;
   - **Username:** the application (client) ID;
   - **Password:** the client secret, which is prompted for and protected with DPAPI;
   - **From:** the mailbox to send as;
   - **To:** the recipients.

## How it sends

- **Signing in:** a client-credentials token from `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token` with the scope `https://graph.microsoft.com/.default`.
- **Sending:** `POST https://graph.microsoft.com/v1.0/users/<from>/sendMail`. The message is plain text, error notifications have high importance, and nothing is saved to Sent Items.
- **When it fails:** the error names the HTTP status and Graph's or Entra ID's error code, such as `ErrorAccessDenied` or `invalid_client`, and says what to check. It never includes the secret.

The configuration reuses the email fields with a new sign-in value, `MicrosoftGraph`. That value is configuration schema 10, which 0.23 would not recognize.

## Tests

The settings need the client ID and secret, and do not need SMTP encryption. Sending signs in with the app and posts to the From mailbox with the bearer token. A refusal shows Graph's error code and never the secret. Manual steps: [docs/testing/more-notifications.md](../testing/more-notifications.md).
