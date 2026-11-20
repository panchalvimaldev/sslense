# Manual tests: the winget package

Feature 31 of [the delivery plan](../delivery-plan.md); design in [docs/design/winget.md](../design/winget.md). Run on the release made for the combined test.

| # | Steps | Expected |
|---|---|---|
| 1 | The release has `SSLense-<version>-winget.zip` | Three YAML files with the release's SHA-256 |
| 2 | `winget validate --manifest <folder>` | Manifest validation succeeded |
| 3 | On a clean test VM: `winget install --manifest <folder>` | SSLense installs silently; the service runs; Apps & features lists it by panchalvimal |
| 4 | Install the previous MSI, then `winget install --manifest <folder>` of the new one | Upgraded in place; data kept |
| 5 | `winget uninstall --manifest <folder>` | Removed; `C:\ProgramData\SSLense` stays |
