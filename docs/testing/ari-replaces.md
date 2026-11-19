# Manual tests: ARI replaces

Feature 4 of [the delivery plan](../delivery-plan.md); design in [docs/design/ari-replaces.md](../design/ari-replaces.md). Covered end to end by the Pebble tests in CI; one check against Let's Encrypt staging:

| # | Steps | Expected |
|---|---|---|
| 1 | Renew a staging certificate with Renew now | It renews as before; the log shows no error |
| 2 | Renew it again at once | It renews as before: the second `replaces` is refused by the CA and the order is created without it |
