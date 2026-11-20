# Design: the winget package

Status: **ready** November 20, 2026, and not submitted yet. Feature 31 of [the delivery plan](../delivery-plan.md). The owner submits it after the first release that follows the combined test.

## What it gives

Once it is accepted into `microsoft/winget-pkgs`, administrators install and upgrade with:

```powershell
winget install panchalvimal.SSLense
winget upgrade panchalvimal.SSLense
```

## How the manifests are made

- **The script:** `installer/New-WingetManifest.ps1 -Version <x.y.z>` writes the three files of winget's multi-file format (version, installer and en-US locale, schema 1.6.0) under `artifacts/winget/manifests/p/panchalvimal/SSLense/<version>/`.
  - It reads the MSI's SHA-256 from the `.sha256` file published with the release, so the manifest matches exactly what users download.
- **Every release:** the release workflow runs the script with the SHA-256 it has just computed, and attaches `SSLense-<version>-winget.zip` to the release.
- **The installer entry:**
  - the WiX MSI, per machine, elevating itself;
  - silent and interactive modes;
  - Windows 10 1809 / Server 2019 or later;
  - matched to installed copies by the MSI's fixed UpgradeCode, so `winget upgrade` finds every earlier version.
- **The publisher:** `panchalvimal`, the MSI's manufacturer, so winget matches the entry in Apps & features.
- **Checked:** generated manifests pass `winget validate`.

## Submitting (owner)

1. Take the manifests from the release's `winget.zip`, or run the script.
2. Run `winget validate --manifest <folder>`, then `winget install --manifest <folder>` on a clean test VM.
3. Open a pull request to `microsoft/winget-pkgs` with the folder under `manifests/p/panchalvimal/SSLense/<version>/`.

**SmartScreen and unsigned installers:** winget-pkgs accepts unsigned installers, but its validation may scan and comment on them. Code signing is not planned.

Manual steps: [docs/testing/winget.md](../testing/winget.md).
