# Design: several servers from one place

**Removed before 0.24.0 was released** (November 26, 2026), to keep SSLense focused on IIS administrators: it could not be tested end to end. The code is in the git history before that date, and this design is kept so the feature can return if users ask. Open an issue if you need it.

Status: **first part built** November 20, 2026 (fleet reports). The rest is a design for the owner to decide on. Feature 27 of [the delivery plan](../delivery-plan.md); ROADMAP section 6.

## The rule everything follows

Every server keeps renewing on its own. A central part may show, warn and, later, ask a server to do something. A server never waits for it, never takes its certificates or keys from it, and never stops renewing when it is down, unreachable or compromised.

## Part 1: fleet reports (built)

Each server's renewal service writes a report to one shared folder after every hourly check. Any server, or any administrator's machine with SSLense, reads them all.

- **Setting it up:**
  - `SSLense.Cli fleet folder --path \\files\sslense-fleet` sets the folder on each server. It must be reachable when it is set, and `--off` stops the reports.
  - The folder is a general setting, so `config export` and `config import` carry it to new servers.
- **The report:** `<server>.json`, written atomically, holds:
  - the SSLense version and the time the report was written;
  - whether the last hourly cycle succeeded, and its message;
  - for each certificate: its name, hosts, expiry, authority, last renewal result and consecutive failures.

  It holds no key, secret, password, account or thumbprint file, only what `status` shows.
- **Reading the reports:** `SSLense.Cli fleet status` lists every server and its certificates soonest-expiring first.
  - It flags servers whose last cycle had a problem, failed renewals, and servers with no report for three hours (three missed cycles), which may be down.
  - It exits 1 when anything needs attention, so a scheduled task or a monitor can alert on it. `--json` gives the whole list as data.
- **Access:** the share's Windows permissions decide who may write and who may read.
  - The renewal service runs as SYSTEM, so each server's computer account needs modify access.
  - Administrators who only look need read access.
  - Host names are visible to anyone who can read the share, so keep it to administrators.
- **Failures:** a report that cannot be written is logged as a warning and never affects the cycle.

This is configuration schema 11.

## Part 2: a central view (design, not built)

For the owner to decide, because it is close to a second product:

| Topic | Proposal |
|---|---|
| Where it runs | A read-only page in the desktop app ("Fleet"), from the same reports: no new server, no new port |
| Alerts | The existing notification channels, sent by one designated server when a report is stale or shows a failed renewal, at most once a day per item |
| Actions | Later, by a request file in the same share (`requests/<server>/<id>.json`, such as "renew Shop now") that the target server's service reads, checks against a list of allowed actions, and answers with a result file. No remote code, credentials or keys move |
| Roles | Windows groups on the share: *SSLense Fleet Viewers* (read reports), *SSLense Fleet Operators* (write requests). Each server also checks the request file's owner against the operators group before acting |
| What is never central | ACME accounts, private keys, certificate authority and DNS secrets, and the decision to renew |
| Not chosen | A central web service with its own database, an agent protocol over the network, or remote PowerShell: each adds a port, credentials and an attack surface that a file share does not |

## Tests (part 1)

- Each server writes its report, and any server reads them all.
- Reports hold no thumbprint.
- Stale servers and damaged reports are named.
- Nothing is written without a folder, and an unreachable folder is refused.

Manual steps: removed with the feature; they are in the git history.
