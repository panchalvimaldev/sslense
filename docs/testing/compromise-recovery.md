# Manual tests: recovery from a compromised key or account

Feature 3 of [the delivery plan](../delivery-plan.md); design in [docs/design/compromise-recovery.md](../design/compromise-recovery.md). Use Let's Encrypt staging.

| # | Steps | Expected |
|---|---|---|
| 1 | Select a staging certificate SSLense renews automatically; ⋯ › Revoke and replace (key compromised)…; Yes | A new certificate is installed (new thumbprint on the Certificate tab), Check passes, and the message says the old one was revoked |
| 2 | Check the old certificate's status, for example with `certutil -url` on its file | Revoked, reason key compromise |
| 3 | `SSLense.Cli revoke --site "<name>" --no-replace --reason cessation --yes` on a test certificate | Revoked; the message says its sites still serve it |
| 4 | Block outbound HTTPS to the CA after the replacement has started | SSL2030, with the old certificate saved under C:\ProgramData\SSLense\revocations and a command that revokes it when run later |
| 5 | Open the ⋯ menu on a bought certificate; run `revoke --site` for it | The menu item is not shown; the CLI gives SSL4051 |
| 6 | Settings › Certificate authorities › Let's Encrypt staging › Replace account key; Yes | "The account key … was replaced"; issuing a new staging certificate afterwards still works |
| 7 | `SSLense.Cli account change-key --ca zerossl --yes` on a server that never used ZeroSSL | SSL2031 |
