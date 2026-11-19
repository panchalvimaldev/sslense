# Manual tests: clean-up of unused certificates

Feature 19 of [the delivery plan](../delivery-plan.md); design in [docs/design/certificate-cleanup.md](../design/certificate-cleanup.md).

| # | Steps | Expected |
|---|---|---|
| 1 | On a server with old staging certificates from earlier tests: Activity › Unused certificates › Find unused certificates | They are listed with "A test certificate…"; certificates bound in IIS are not |
| 2 | Configure WinRM over HTTPS with a certificate, then Find again | That certificate is not listed |
| 3 | Tick one; Remove ticked…; Yes | It is gone from certlm.msc › Personal; the others stay |
| 4 | `SSLense.Cli cleanup remove --thumbprint <a bound certificate> --yes` | SSL4054; nothing removed |
