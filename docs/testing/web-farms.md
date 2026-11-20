# Manual tests: web farms

Feature 26 of [the delivery plan](../delivery-plan.md); design in [docs/design/web-farms.md](../design/web-farms.md). Needs two IIS servers (WEB1 with SSLense, WEB2) behind a load balancer for `shop.example.com`.

| # | Steps | Expected |
|---|---|---|
| 1 | On WEB1: `issue --site Shop --hosts shop.example.com --email … --farm-folders "\\web2\c$\inetpub\shop"` without access to the share | SSL6033: cannot be reached |
| 2 | Give WEB1's computer account write access to `\\web2\c$\inetpub\shop`; repeat step 1 | Issued, whichever server the load balancer sends the CA to; `farm show --site Shop` lists the folder |
| 3 | Watch `\\web2\c$\inetpub\shop\.well-known\acme-challenge` during a renewal | A token file and `web.config` appear and are removed afterwards |
| 4 | Add a Central Certificate Store step on a share both servers use; **Renew now** | Both servers serve the renewed certificate |
| 5 | `farm set --site Shop --folders "inetpub\shop"` | SSL6033: must be a full path |
| 6 | A WebDAV share: `farm set --site Shop --folders "\\dav.example.com@SSL\DavWWWRoot\shop"` with the WebClient service running | Saved; a renewal writes the challenge there |
| 7 | `farm clear --site Shop` | Challenges are written to WEB1 only |
