# Manual tests: certificates for IP addresses

Feature 11 of [the delivery plan](../delivery-plan.md); design in [docs/design/ip-certificates.md](../design/ip-certificates.md). Needs a server with a public IP address reachable on ports 80 and 443, Let's Encrypt staging, and the service running.

| # | Steps | Expected |
|---|---|---|
| 1 | `SSLense.Cli issue --site "<site>" --hosts <public IP> --validation http-self --profile shortlived --email <you>` | Issued; IIS has an HTTPS binding `<IP>:443` without SNI; the certificate list shows it |
| 2 | Open `https://<public IP>/` from another machine | The staging certificate for the IP address is served |
| 3 | Check on the certificate | Passes |
| 4 | Leave it for a few days with the service running | It renews on its own before the six-day certificate expires |
| 5 | `issue ... --hosts <IP>` with `--validation http` or `dns` | Refused with SSL6027 |
