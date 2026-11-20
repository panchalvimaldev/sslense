# Manual tests: Apache, nginx and Tomcat on Windows

Part of feature 25 of [the delivery plan](../delivery-plan.md); design in [docs/design/web-servers.md](../design/web-servers.md). Each needs a certificate issued with `--exportable-key`.

| # | Steps | Expected |
|---|---|---|
| 1 | Apache Lounge httpd installed as service Apache2.4, `SSLCertificateFile D:/Certs/shop/fullchain.pem`; `deploy add --site <certificate> --web-server apache --folder D:\Certs\shop --service Apache2.4`; `deploy run` | The four PEM files are written; Apache restarts and serves the certificate |
| 2 | nginx run as a service named nginx (WinSW); `--web-server nginx --folder D:\nginx\ssl --service nginx`; `deploy run` | nginx serves the certificate |
| 3 | Tomcat 10 as service Tomcat10 with a PKCS12 connector; `--web-server tomcat --folder D:\Tomcat\conf --service Tomcat10`, enter the keystore password twice; `deploy run` | `certificate.pfx` is written; Tomcat restarts and serves it |
| 4 | **Renew now** | Each server serves the renewed certificate |
| 5 | `--web-server apache --folder certs --service Apache2.4` | Refused: the folder must be a full path |
| 6 | `--service NoSuchService` | Refused, naming the service |
