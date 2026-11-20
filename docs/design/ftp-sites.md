# Design: certificates for IIS FTP sites

Status: **built** November 20, 2026. Feature 23 of [the delivery plan](../delivery-plan.md).

## What the administrator gets

An IIS FTP site's certificate for FTP over TLS (FTPS) is renewed like a web site's. A deployment step, **Use it for an IIS FTP site**, sets the certificate on the FTP site after every install and renewal:

- the app: the certificate's After install section;
- the CLI: `SSLense.Cli deploy add --site <certificate> --ftp-site <FTP site>`.

## Getting the certificate

The FTP host name needs a certificate first. Any of these work:

- **The web site's certificate:** when the same host name, such as `files.example.com`, also has an IIS web site, add the step to that certificate.
- **A certificate with no site:** `issue --no-site Files --names ftp.example.com --validation dns`. SSLense publishes the TXT record through a DNS provider, and no web site is needed.
- **HTTP answered by SSLense:** `issue --site <any site> --hosts ftp.example.com --validation http-self`. SSLense answers the challenge on port 80 itself, so the FTP host needs no web site, only port 80 open.

## How the step works

- When it is added, the step checks that the IIS site has an `ftp` binding. Otherwise it is refused with SSL4056.
- When it runs, it sets `ftpServer/security/ssl/serverCertHash` and `serverCertStoreName` (`My`) on the site, commits, and reads the value back.
  - The FTP service reads the certificate for each new connection, so nothing restarts. Connections already open keep the old certificate until they close.
- A failed step is retried hourly, like every deployment step. The replaced certificate is kept while the step is pending.
- The certificate that an FTP site uses counts as in use:
  - renewals never remove it;
  - the unused-certificate clean-up never suggests it.
- The Microsoft FTP Service runs as LocalSystem, which can read machine keys. If it runs as another account, add a **Give an account access to the private key** step for that account.
- After a rollback, run the deployment steps (`deploy run`) to move the FTP site back too.

This is managed-certificate schema 15, because 0.23 would not know the step.

## Tests

- The step is refused for a site without an FTP binding.
- The step takes the FTP site's name as IIS spells it, and sets the certificate when it runs.
- A replaced certificate stays while an FTP site uses it.
- Clean-up treats an FTP site's certificate as in use.

Manual steps: [docs/testing/ftp-sites.md](../testing/ftp-sites.md).
