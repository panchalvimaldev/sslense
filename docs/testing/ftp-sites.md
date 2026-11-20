# Manual tests: IIS FTP sites

Feature 23 of [the delivery plan](../delivery-plan.md); design in [docs/design/ftp-sites.md](../design/ftp-sites.md).

Needs the IIS role service **FTP Server** and an FTP site ("Files") with an `ftp` binding for `ftp.example.com` on port 21, with SSL set to Allow or Require.

| # | Steps | Expected |
|---|---|---|
| 1 | Issue a staging certificate for `ftp.example.com` (DNS, or `--validation http-self`) | Issued |
| 2 | `SSLense.Cli deploy add --site <certificate> --ftp-site Shop` (a web-only site) | SSL4056 |
| 3 | `deploy add --site <certificate> --ftp-site files`, then `deploy run` | The step is listed as "Use it for the IIS FTP site 'Files'"; IIS Manager › Files › FTP SSL Settings shows the certificate |
| 4 | Connect with FileZilla using explicit FTP over TLS | The certificate shown is the new one |
| 5 | **Renew now** | The FTP SSL Settings show the renewed certificate; a new FileZilla connection gets it |
| 6 | Stop the Microsoft FTP Service's configuration access (for example, lock applicationHost.config), **Renew now** | The step fails and is retried; the previous certificate stays in the store while it is pending |
| 7 | Activity › Unused certificates › Find | The FTP site's certificate is not listed |
| 8 | The app: the certificate › After install › **Use it for an IIS FTP site**, value "Files", **Add step** | The same as step 3 |
