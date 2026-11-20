# Design: dependency scanning and a software bill of materials

Status: **built** November 20, 2026. Feature 29 of [the delivery plan](../delivery-plan.md); ROADMAP section 5.

## What runs

| Where | What | Fails on |
|---|---|---|
| Every CI run (push and pull request) | `installer/Test-Dependencies.ps1`: `dotnet list package --vulnerable --include-transitive` for every project, against the NuGet advisory database | Any known vulnerability, of any severity, in a direct or transitive package |
| Every CI run | The same script writes a CycloneDX 1.5 SBOM, kept as the run's `sbom` artifact | — |
| Every release | The SBOM is attached to the GitHub release as `SSLense-<version>-sbom.cdx.json`, next to the MSI and its SHA-256 | A vulnerable package stops the release before the MSI is built |
| Weekly | Dependabot opens pull requests for new NuGet package and GitHub Actions versions | — |

## The SBOM

- **What it lists:** every package the shipped apps use (the CLI, the desktop app, the service and Core, but not the tests), directly or transitively.
  - Each component has its name, its resolved version and its package URL (`pkg:nuget/<id>@<version>`).
  - The application itself is listed with its version and its licence, Apache-2.0.
- **How it is made:** from the SDK's own package graph, with no tool or package added (AGENTS.md: no packages without approval). Anyone can make it again from the source with `./installer/Test-Dependencies.ps1 -SbomPath sbom.json`.

## Not used, and why

- **GitHub's dependency graph SBOM, Dependabot alerts and the dependency review action:** they need the repository's dependency graph, which is off for this repository (the API answers 404). The owner can turn it on under Settings › Code security. The checks above don't depend on it.
- **CycloneDX's or Microsoft's SBOM tools:** each is a package, and the SDK's output gives the same list.

## When a package is vulnerable

1. Update it, or the package that brings it in, in its own pull request. A Dependabot pull request counts, after review.
2. If no fixed version exists yet, record the advisory, why SSLense is or isn't affected, and the plan here. Then decide with the owner whether to release.

Manual check: [docs/testing/supply-chain.md](../testing/supply-chain.md).
