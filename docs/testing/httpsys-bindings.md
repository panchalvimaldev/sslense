# Manual tests: HTTP.sys bindings outside IIS

Part of feature 25 of [the delivery plan](../delivery-plan.md); design in [docs/design/httpsys-bindings.md](../design/httpsys-bindings.md).

| # | Steps | Expected |
|---|---|---|
| 1 | `deploy add --site <certificate> --http-sys 0.0.0.0:443` on a server where an IIS site binds port 443 | Refused, naming the site |
| 2 | `deploy add --site <certificate> --http-sys 0.0.0.0:8443`; `deploy run` | `netsh http show sslcert ipport=0.0.0.0:8443` shows the certificate and SSLense's application ID |
| 3 | Configure WinRM over HTTPS (`winrm quickconfig -transport:https`) with another certificate; add `--http-sys 0.0.0.0:5986`; `deploy run` | The binding shows the new certificate and keeps WinRM's application ID; `Test-WSMan -UseSSL` works |
| 4 | **Renew now** | Both bindings show the renewed certificate |
| 5 | `deploy add ... --http-sys api.example.com` | Refused: no port |
| 6 | The app: After install › **Bind it in HTTP.sys outside IIS**, `0.0.0.0:9443`, **Add step**, **Run now** | As step 2 |
