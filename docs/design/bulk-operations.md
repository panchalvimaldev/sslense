# Design: bulk operations

Status: **built** November 19, 2026. Feature 17 of [the delivery plan](../delivery-plan.md); ROADMAP section 4, item 7.

## What the administrator gets

- **Watch every unmanaged certificate at once:** **Tick all** on Add certificate › It's already installed in IIS, then Watch; or `SSLense.Cli bulk watch`. Each certificate is watched once per site, with all its bindings there; nothing in IIS changes.
- **Issue for many sites from a CSV file:** `SSLense.Cli bulk issue --file sites.csv`, one certificate per row, one after another, each through the normal issue path. `--dry-run` runs each row's pre-issue checks and orders nothing; `--accept-production-risk` confirms rows for a trusted certificate authority.
- **One failure stops nothing else.** Every row or certificate gets OK or FAIL with its message and error code, and a total; the exit code is 1 if any failed.

## The CSV file

Columns, in this order unless a header row names them: `site, hosts, validation, names, email, ca, profile, key`.

- `hosts` and `names`: separated by `;`, `|` or spaces. Quote a field that holds a comma.
- `validation`: `http` (the default), `http-self`, or `dns`. Manual DNS needs a person for each certificate, so it is refused in a file (SSL6029).
- `email`: the default ACME email from Settings when empty. `ca`: Let's Encrypt staging when empty.
- Lines starting with `#` and empty lines are skipped.

```csv
site,hosts,validation,names
Shop,shop.example.com;www.shop.example.com,http,
Api,api.example.com,dns,*.example.com example.com
```

## Tests

Line parsing with quotes; a header in another order; a failed row and an unsupported validation not stopping the others; defaults for email and CA; a dry run only checking; watching each unmanaged certificate once per site. Manual steps: [docs/testing/bulk-operations.md](../testing/bulk-operations.md).
