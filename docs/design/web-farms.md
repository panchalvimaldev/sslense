# Design: web farms

**Removed before 0.24.0 was released** (November 26, 2026), to keep SSLense focused on IIS administrators: it could not be tested end to end. The code is in the git history before that date, and this design is kept so the feature can return if users ask. Open an issue if you need it.

Status: **built** November 20, 2026 (folders, through the CLI). Feature 26 of [the delivery plan](../delivery-plan.md); ROADMAP section 6, "Web farms and load-balanced sites".

## The two problems

A site served by several IIS servers behind a load balancer needs two things:

1. **Validation.** With HTTP validation, the certificate authority's request can reach any server, but only the server running SSLense has the challenge file.
2. **One certificate on every server.** When the certificate is renewed on one server, the others must get it too.

## Decisions

| Option | Decision |
|---|---|
| DNS validation | Already works in a farm, because nothing is served from the servers. The recommended choice where the DNS provider is supported |
| **Challenge copied to shared folders** | **Built.** Every HTTP challenge is also written to the other servers' site folders, given as UNC paths, and removed after validation |
| WebDAV | Covered by the folders: Windows reaches a WebDAV server as a UNC path through its WebClient service (`\\host@SSL\DavWWWRoot\path`), so no WebDAV code is needed |
| SFTP or FTP upload | Not built: SFTP needs a package that PROJECT_SPEC.md does not list, and plain FTP sends credentials in the clear |
| HTTP redirect from the other servers | Not built: it needs a rule on every server, and the CA follows redirects anyway, so a redirect to the SSLense server is a choice you can configure in IIS yourself |
| **Keeping the certificate in step** | **Already built:** the IIS Central Certificate Store step writes one PFX per name to the farm's shared store, which every server reads ([certificate-export.md](certificate-export.md)). Alternatively, Key Vault or a script step on each server |

## Farm folders

- **Setting them:**
  - `SSLense.Cli issue --site Shop --hosts shop.example.com --email … --farm-folders "\\web2\c$\inetpub\shop;\\web3\c$\inetpub\shop"` sets them at the first issue, so that issue can already validate.
  - `SSLense.Cli farm set --site Shop --folders "…"` changes them later, `farm show` lists them, and `farm clear` removes them.
  - They are kept on the certificate and used at every renewal (managed-certificate schema 21).
  - The app shows no farm settings yet. They are set through the CLI.
- **The checks when they are set:**
  - Each folder must be a full path that this server can reach now.
  - There are at most 16 folders.
  - Only certificates validated over HTTP from their IIS site can have farm folders. With DNS, or HTTP answered by SSLense, there is nothing to copy.
- **What a copy holds:** each one is written exactly as the local challenge: the token file and the `web.config` that serves it as plain text. Copies go into the challenge journal, so the next start cleans up any copies an interruption left behind. They are removed after validation, the last first.
- **Access to the shares:** the renewal service runs as SYSTEM, which reaches a share as the computer account (`DOMAIN\SERVER$`). Give that account write access to each server's `.well-known` folder, or its site root.

## Tests

- Folders are saved, deduplicated and cleared.
- Relative and unreachable folders are refused, and so are certificates not validated over HTTP.
- An issue in a farm copies the challenge to each folder, removes the copy, and keeps the folders on the record.

Manual steps: removed with the feature; they are in the git history.
