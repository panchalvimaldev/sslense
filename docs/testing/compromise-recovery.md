# Manual tests: recovery from a compromised key or account

Feature 3 of [the delivery plan](../delivery-plan.md); design in [docs/design/compromise-recovery.md](../design/compromise-recovery.md). Use Let's Encrypt staging.

| # | Steps | Expected |
|---|---|---|
| 1 | Select a staging certificate SSLense renews automatically; ⋯ › Revoke and replace (key compromised)…; Yes | A new certificate is installed (new thumbprint on the Certificate tab), Check passes, and the message says the old one was revoked |
| 2 | Check the old certificate in the CA's revocation list: download the CRL named in its CRL Distribution Points (from its `certificate.pem` under `C:\ProgramData\SSLense\certificates\<site>`), then `certutil -dump <file>.crl` and find its serial number. (`certutil -verify -urlfetch` reports "revocation status unknown" for staging, whose root Windows does not trust.) The CA publishes the list periodically, so allow up to an hour | Its serial number is listed with "CRL Reason Code: Key Compromise (1)" |
| 3 | `SSLense.Cli revoke --site "<name>" --no-replace --reason cessation --yes` on a test certificate | Revoked; the message says its sites still serve it |
| 4 | Block outbound HTTPS to the CA after the replacement has started | SSL2030, with the old certificate saved under C:\ProgramData\SSLense\revocations and a command that revokes it when run later |
| 5 | Import a bought certificate (for a test, a self-signed one whose certificate is also added to LocalMachine\Root, since `import` refuses an untrusted root with SSL4016); open its ⋯ menu; run `revoke --site` for it | The menu item is not shown; the CLI gives SSL4051 |
| 6 | Settings › Certificate authorities › Let's Encrypt staging › Replace account key; Yes | "The account key … was replaced"; issuing a new staging certificate afterwards still works |
| 7 | `SSLense.Cli account change-key --ca <id> --yes` for a CA that is configured but never used here, such as `letsencrypt` on a staging-only server (check first that `C:\ProgramData\SSLense\account-key.production.dat` does not exist; the command then stops before contacting the CA) | SSL2031. A CA that was never added gives SSL2015 instead |
