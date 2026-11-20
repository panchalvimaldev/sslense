# Manual tests: signed webhooks and email through Microsoft Graph

Feature 22 of [the delivery plan](../delivery-plan.md). Designs: [signed-webhooks.md](../design/signed-webhooks.md) and [graph-email.md](../design/graph-email.md).

| # | Steps | Expected |
|---|---|---|
| 1 | Settings › Notifications: Type Generic, a webhook.site URL, tick **Sign generic webhook payloads**, **Add channel** | The signing secret is shown once; the channel list shows the webhook |
| 2 | **Send test** | webhook.site shows `X-SSLense-Timestamp` and `X-SSLense-Signature`; the PowerShell check in the design gives the same signature |
| 3 | Type Slack with the box ticked, **Add channel** | Refused: only generic webhooks are signed |
| 4 | `SSLense.Cli notifications chat --type generic --sign`, then `notifications show` | The secret is printed once; the channel is listed as "signed" |
| 5 | In a test Microsoft 365 tenant: an app with Mail.Send (admin consent) and a client secret; preset **Microsoft 365 through Microsoft Graph**; Host the tenant domain, Username the client ID, Password the secret; **Save**, **Send test** | The test email arrives from the From mailbox |
| 6 | As 5, with a wrong secret | SSL7004 naming `invalid_client`; the secret is not in the message or the log |
| 7 | As 5, without admin consent | SSL7004 naming `ErrorAccessDenied` and Mail.Send |
| 8 | `config export --include-secrets` and import on another server | The signed webhook and the Graph email still work there |

Not yet run against a real Microsoft 365 tenant: steps 5–7 stay open until the combined test.
