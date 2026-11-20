# Manual tests: dependency scanning and the SBOM

Feature 29 of [the delivery plan](../delivery-plan.md); design in [docs/design/supply-chain.md](../design/supply-chain.md).

| # | Steps | Expected |
|---|---|---|
| 1 | `./installer/Test-Dependencies.ps1` | "No known vulnerable packages, direct or transitive." |
| 2 | `./installer/Test-Dependencies.ps1 -SbomPath C:\temp\sbom.json`; open it | CycloneDX 1.5; SSLense with this version and Apache-2.0; every component with a `pkg:nuget/…` package URL; no test-only packages such as xunit or Moq |
| 3 | On a branch, reference a package version with a known advisory (for example an old `System.Text.Json`); push | CI fails at "Check dependencies", naming the package and advisory |
| 4 | A CI run on main | The run has an `sbom` artifact |
| 5 | The release made for the combined test | The release has `SSLense-<version>-sbom.cdx.json` next to the MSI |
| 6 | A week after merging | Dependabot pull requests appear for any outdated package or action |
