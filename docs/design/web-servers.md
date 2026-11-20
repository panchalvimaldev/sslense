# Design: Apache, nginx and Tomcat on Windows

Status: **built** November 20, 2026. The third part of feature 25 of [the delivery plan](../delivery-plan.md), "Other deployment targets".

## What the administrator gets

One deployment step, **Use it for Apache, nginx or Tomcat**, keeps a web server on Windows on the current certificate. After every install and renewal it writes the files the server reads, then restarts its Windows service.

- The app: the certificate's After install section. The value is `server|folder|service`, such as `apache|D:\Certs\shop|Apache2.4`.
- The CLI: `SSLense.Cli deploy add --site <certificate> --web-server apache --folder D:\Certs\shop --service Apache2.4`.

| Server | Files in the folder | Configuration to point at them |
|---|---|---|
| Apache httpd | `cert.pem`, `chain.pem`, `fullchain.pem`, `key.pem` | `SSLCertificateFile fullchain.pem` and `SSLCertificateKeyFile key.pem` |
| nginx | the same | `ssl_certificate fullchain.pem;` and `ssl_certificate_key key.pem;` |
| Tomcat | `certificate.pfx`, a PKCS#12 keystore with the password given when the step is added (kept with DPAPI) | `<Certificate certificateKeystoreFile="…\certificate.pfx" certificateKeystoreType="PKCS12" certificateKeystorePassword="…"/>` |

## Rules

- **Exportable key:** the certificate needs one, like every export.
- **Key file:** `key.pem` is readable only by Administrators and SYSTEM, the same as the PEM export step. Run the service as an account that can read it, or add a **Give an account access to the private key** step only for an account in the machine store. For files, adjust the folder's permissions yourself.
- **Service:** the service must exist when the step is added. The restart is a short interruption at every renewal. nginx on Windows is usually run as a service through a wrapper such as WinSW or NSSM; give that service's name.
- **Password:** a password is refused for Apache and nginx, which read PEM files, and required for Tomcat.
- **When it fails:** a failed write or restart is retried hourly. The replaced certificate is kept in the store while the step is pending.

This is managed-certificate schema 19.

## Still to come in feature 25

Azure App Service.

## Tests

- Unknown servers, relative folders, Tomcat without a password and nginx with one are refused.
- Apache gets PEM files.
- Tomcat gets its keystore under its password.

Manual steps: [docs/testing/web-servers.md](../testing/web-servers.md).
