# Manual tests: new version notice

Feature 18 of [the delivery plan](../delivery-plan.md); design in [docs/design/version-notice.md](../design/version-notice.md).

| # | Steps | Expected |
|---|---|---|
| 1 | Install a release older than the latest on GitHub; open the app | The header shows "SSLense <latest> is available"; clicking it opens the release page |
| 2 | `SSLense.Cli version` | The installed version and the newer one with its link |
| 3 | Activity › Run health check | "SSLense version" warns with SSL9007 |
| 4 | Settings › General › untick "Tell me when a newer SSLense is available" › Save; reopen the app | No notice; `version` says the check is off |
| 5 | With the latest release installed | No notice |
