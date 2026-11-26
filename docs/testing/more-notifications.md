# Manual tests: signed webhooks

Feature 22 of [the delivery plan](../delivery-plan.md). Design: [signed-webhooks.md](../design/signed-webhooks.md). Email through Microsoft Graph was removed before 0.24.0, with its steps.

| # | Steps | Expected |
|---|---|---|
| 1 | Settings › Notifications: Type Generic, a webhook.site URL, tick **Sign generic webhook payloads**, **Add channel** | The signing secret is shown once; the channel list shows the webhook |
| 2 | **Send test** | webhook.site shows `X-SSLense-Timestamp` and `X-SSLense-Signature`; the PowerShell check in the design gives the same signature |
| 3 | Type Slack with the box ticked, **Add channel** | Refused: only generic webhooks are signed |
| 4 | `SSLense.Cli notifications chat --type generic --sign`, then `notifications show` | The secret is printed once; the channel is listed as "signed" |
| 5 | `config export --include-secrets` and import on another server | The signed webhook still works there |
