# Design: stable, searchable error codes

Status: **approved** November 19, 2026 (the owner approved the whole delivery plan in advance). Feature 1 of [the delivery plan](../delivery-plan.md); ROADMAP section 5.2.

## 1. Problem

When something goes wrong, SSLense explains it in a sentence: "Host name 'shop.example.com' does not have an HTTP binding on port 80 for IIS site 'Shop'." That helps the administrator in front of it, but:

- the wording changes between releases, so a search, a forum answer or a monitoring rule written for one release misses the next;
- a bug report or a screenshot in another language cannot be matched to the cause;
- the same failure reads differently in the app, the CLI, the log, the email digest and the Event Log, so one cannot be traced to the others.

## 2. What the administrator gets

- **Every error SSLense explains starts with a code,** such as `SSL1203`:
  > SSL1203: Host name 'shop.example.com' does not have an HTTP binding on port 80 for IIS site 'Shop'. Add one in IIS Manager, or choose DNS validation.
- **The code is the same everywhere:** the app, the CLI, the log file, the renewal-failure email and chat message, the daily digest, the Event Log entry, and the diagnostic bundle.
- **[docs/errors.md](../errors.md) lists every code** with what it means, the usual causes, and what to do. The app shows the code as a link to its entry, so one click opens the explanation.
- **Health check and pre-flight results that fail carry a code too,** so "SSL1203" is the same problem whether a check found it or an issue stopped on it.
- **A code never changes meaning.** A code that is no longer used stays reserved and listed as retired.

## 3. The codes

`SSL` and four digits. The first digit is the area, so a code says roughly where to look:

| Range | Area |
|---|---|
| SSL1xxx | IIS: sites, bindings, challenge files, the HTTPS check and rollback |
| SSL2xxx | ACME and certificate authorities: accounts, orders, validation, rate limits |
| SSL3xxx | DNS validation: providers, scripts, acme-dns, propagation, CAA |
| SSL4xxx | Certificates: import, requests, the Windows store, keys, export |
| SSL5xxx | Renewal, reminders, the service, locks and recovery |
| SSL6xxx | Settings and stored data: schemas, permissions, names |
| SSL7xxx | Notifications |
| SSL8xxx | Deployment steps |
| SSL9xxx | Health check, diagnostics and anything unexpected |

`SSL9999` is an unexpected error: one SSLense did not foresee, shown with its original message so it can still be reported.

## 4. How it is built

- **One catalogue in Core,** `ErrorCodes`, with a constant for each code and a one-line title. Codes are added, never renumbered; a test keeps a list of every code ever issued and fails if one disappears or changes.
- **One exception type,** `SslenseException`, derived from `InvalidOperationException`, with a `Code`. Its message starts with the code. Because it is still an `InvalidOperationException`, every existing `catch` keeps working, and the existing types (`IisBindingException`, `CertificateStateChangedException`, `AcmeRateLimitedException`) gain a code the same way.
- **Every message an administrator can see gets a code:** the 191 `InvalidOperationException`s in Core, the `ArgumentException`s that describe input mistakes (not the internal guards), and the failure messages of health and pre-flight checks. `PreflightCheck` and `HealthCheckResult` gain an optional `Code`.
- **Unexpected errors get `SSL9999`** where the app, CLI and service report them, so every error shown has a code.
- **The message keeps its words.** Only the code is added in front, so existing tests that check the wording change little, and stored messages such as a certificate's last renewal message carry the code from the next failure on.
- **Event Log event IDs do not change** (1000 to 1003, and 1900): monitoring rules may use them. The code is in the entry's text.
- **The documentation is checked:** a test fails when a code in the catalogue has no entry in `docs/errors.md`, or the page lists a code that does not exist.

## 5. What is not changed

- Messages that report success or progress have no code.
- The CLI's exit codes stay as they are (0 and 1). Documented exit codes are part of feature 21, Automation.
- No translation. Codes make that possible later, but SSLense stays in English.

## 6. Decisions taken by judgement

1. **`SSL` and four digits, grouped by area,** rather than names like `IIS_BINDING_MISSING`: short, easy to search, and the same in any language.
2. **The code goes in the message text,** not only in a separate field, so it reaches every place a message goes (logs, emails, chat, stored records, screenshots) without changing each of them.
3. **One page for all codes** rather than a page each: easier to keep complete, and still linkable per code.

## 7. Delivery and testing

| Step | Contents |
|---|---|
| 1 | This design |
| 2 | Core: the catalogue, `SslenseException`, codes on every user-facing error and failed check, `docs/errors.md`, and the tests that keep codes stable and documented. **Built** November 19, 2026: 232 codes |
| 3 | App, CLI and service: the code shown as a link in the app, `SSL9999` for unexpected errors, the code in notifications; README section on error codes; manual test steps in `docs/testing/`. **Built** November 19, 2026 |
