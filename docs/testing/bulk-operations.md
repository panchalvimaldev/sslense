# Manual tests: bulk operations

Feature 17 of [the delivery plan](../delivery-plan.md); design in [docs/design/bulk-operations.md](../design/bulk-operations.md). Let's Encrypt staging.

| # | Steps | Expected |
|---|---|---|
| 1 | With several sites serving certificates SSLense does not manage: Add certificate › It's already installed in IIS › Tick all › Watch | Every one watched; the list shows them |
| 2 | `SSLense.Cli bulk watch` with nothing left to watch | "Nothing to do." |
| 3 | Write a CSV with three staging rows, one of them for a site that does not exist; `bulk issue --file <csv> --dry-run` | Two OK, one FAIL with its code; nothing ordered |
| 4 | `bulk issue --file <csv>` | The two certificates are issued and bound; the third fails; exit code 1 |
| 5 | A row with `ca` set to `letsencrypt` without `--accept-production-risk` | That row fails with the production confirmation; others continue |
