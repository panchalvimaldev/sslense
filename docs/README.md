# SSLense documentation

Start with the [quick start in the main README](../README.md#quick-start).

## Running SSLense

- [Firewall, DNS and proxy requirements](network-requirements.md)
- [Upgrading, versions and known issues](upgrading.md)
- [Moving to SSLense](migration.md) from another ACME client or from certificates installed by hand
- [Automation](automation.md): JSON output, exit codes, settings export and import, PowerShell
- [Error codes](errors.md): every code, what it means and what to do
- [Release notes](release-notes.md)

## When something goes wrong

- [A certificate is about to expire and renewal keeps failing](runbooks/certificate-about-to-expire.md)
- [A site serves the wrong or an old certificate](runbooks/site-serves-wrong-certificate.md)
- [The renewal service is not running](runbooks/service-not-running.md)
- [A key or ACME account may have been copied](runbooks/compromised-key-or-account.md)
- [Moving SSLense to another server, or restoring it](runbooks/move-or-restore-server.md)
- The [troubleshooting section](../README.md#troubleshooting) of the main README, by symptom

## Security

- [Threat model](threat-model.md)
- [Reporting a vulnerability](../SECURITY.md)
- [Dependency scanning and the software bill of materials](design/supply-chain.md)

## Testing

- [Automated tests](testing/automated-tests.md): what runs in CI and on a test server, and what it covers
- [Manual test plan](testing/manual-test-plan.md): the combined test before a release, with sign-off

## How features work

Each feature has a design in [design/](design/) and manual test steps in [testing/](testing/). The [delivery plan](delivery-plan.md) lists them in order.
