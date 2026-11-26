# Design: signed webhook payloads

Status: **built** November 20, 2026. Part of feature 22 of [the delivery plan](../delivery-plan.md); ROADMAP section 6, "More notification channels". Email through Microsoft Graph was designed with it and removed before 0.24.0 ([graph-email.md](graph-email.md)).

## What the administrator gets

A generic webhook can sign every payload, so the receiver can check that the request came from SSLense and was not changed or replayed.

- Settings › Notifications: tick **Sign generic webhook payloads** before **Add channel**.
- CLI: `SSLense.Cli notifications chat --type generic --sign`.

SSLense makes a new shared secret: 32 random bytes, in base64url. It shows the secret once, to copy into the receiver. The secret is stored protected with DPAPI, like the URL, and is never logged. To get a new secret, remove the channel and add it again.

## The signature

Each request has two extra headers:

| Header | Value |
|---|---|
| `X-SSLense-Timestamp` | Unix time in seconds when the request was made |
| `X-SSLense-Signature` | `sha256=` and the lowercase hex HMAC-SHA256, keyed with the secret, of `<timestamp>.<body>` |

The receiver checks a request in four steps:

1. Read the raw body.
2. Compute the HMAC of `timestamp + "." + body`.
3. Compare it with the signature in constant time.
4. Reject a timestamp more than five minutes from its own clock.

The body is the generic JSON payload (`kind`, `severity`, `subject`, `body`, `occurredAtUtc`). It is serialized once, so the signature covers exactly the bytes sent.

```powershell
# A receiver's check, in PowerShell
$hmac = [System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($secret))
$expected = 'sha256=' + -join ($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes("$timestamp.$body")) | ForEach-Object { $_.ToString('x2') })
```

Teams, Slack, Discord, Telegram and ntfy check their own URL, which already holds a credential, so only generic webhooks are signed.

## Tests

The headers are present and the signature matches the timestamp and body. An unsigned webhook has no signature. Adding a signed webhook returns the secret once and stores it protected. Other formats are refused. The notifier signs with the saved secret. Manual steps: [docs/testing/more-notifications.md](../testing/more-notifications.md).
