# Design: clean-up of unused certificates

Status: **built** November 19, 2026. Feature 19 of [the delivery plan](../delivery-plan.md); ROADMAP section 6, "Existing-certificate discovery".

## What the administrator gets

- **Activity › Unused certificates › Find unused certificates**, and `SSLense.Cli cleanup list`: certificates in `LocalMachine\My` that nothing uses and that are
  - expired;
  - test leftovers, from Let's Encrypt staging or another test CA; or
  - replaced: another certificate covers the same names and expires later.
- **Nothing is removed unless chosen:** tick them and **Remove ticked…** (with a confirmation), or `cleanup remove --thumbprint <a,b> --yes`. Each is checked again at removal; one that has started being used is refused (SSL4054).

## What "in use" means

A certificate is never a candidate when any IIS binding uses it, when HTTP.sys binds it outside IIS (`netsh http show sslcert`: WinRM, ADFS and others), or when SSLense manages it. Other services, such as SQL Server or Exchange, choose their certificate in their own configuration, which SSLense cannot see; the list and the confirmation say to check them, and a valid certificate that is not replaced, test or expired is never suggested.

## Tests

Certificates bound in IIS, bound by HTTP.sys or managed are never candidates; expired, staging and replaced ones are, each with its reason; a valid unrelated one is not; removal checks again and refuses one in use. Manual steps: [docs/testing/certificate-cleanup.md](../testing/certificate-cleanup.md).
