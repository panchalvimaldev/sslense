# Design: DNS validation through a script

Status: **approved** November 9, 2026, with decisions 1 to 7 in section 8 accepted as proposed. Target release: 0.15. Branch: `feature/dns-script`. This is the design section promised by [dns-validation.md](dns-validation.md), section 10, and item 1 of the [roadmap](../../ROADMAP.md).

## 1. Problem

SSLense publishes DNS validation records automatically only through Cloudflare. Every other DNS service needs either CNAME delegation to a Cloudflare zone or the manual method, which cannot renew on its own. With certificate lifetimes moving toward 45 days, manual renewal is not workable.

Built-in providers come one at a time and each needs a real account to test. A script method covers almost any DNS service with an API now: the administrator supplies a PowerShell script that adds and removes one TXT record, and SSLense does everything else.

The risk is the reason this needed its own design. The renewal service runs as SYSTEM, so **whoever can change the script can run code as SYSTEM.**

### Out of scope

- Scripts in other languages. A PowerShell script can call any program, so it covers them.
- PowerShell 7 (`pwsh`). Windows PowerShell 5.1 is on every supported Windows version. `pwsh` can be added if users ask (decision 6).
- Hooks before and after a renewal or install. They are roadmap item 4, with their own design.
- Built-in providers for Route 53, Azure DNS, and GoDaddy. They come after this, through the same interface.

## 2. What the administrator gets

```powershell
# Once per zone. SSLense keeps its own copy of the script (section 4).
SSLense.Cli dns add --provider script --name "Registrar" --zone example.com --script C:\Scripts\registrar-dns.ps1 --secret
SSLense.Cli dns test --name "Registrar"

# Issuing and renewing are unchanged: the provider is chosen by zone.
SSLense.Cli issue --site "Shop" --email ops@example.com --validation dns --names "*.example.com,example.com" --hosts "shop.example.com"

# After editing the original script, take a new copy.
SSLense.Cli dns update-script --name "Registrar" --script C:\Scripts\registrar-dns.ps1
```

`--secret` prompts for one secret without echo, such as an API key. It is stored like a Cloudflare token and given to the script when it runs (section 3). A script that needs no secret, or reads its own credentials, leaves it out.

In the GUI, **Settings > DNS providers > Add** gains a **Script** choice with a file picker and an optional secret field. **Test** works as it does for Cloudflare.

SSLense installs two examples in `C:\Program Files\SSLense\dns-scripts\`, which only administrators can change:

- `Template.ps1`: the contract in section 3 with comments, to copy and fill in.
- `Cloudflare.ps1`: a working script for Cloudflare. It is redundant with the built-in provider, but it shows a complete script and lets the maintainer test this method end to end.

## 3. Script contract

SSLense runs:

```text
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass
    -File <copy> -Action <Check|Add|Remove> -Zone example.com -RecordName _acme-challenge.example.com -Value <value>
```

| Action | Must do | Called |
|---|---|---|
| `Check` | Confirm the credentials can change the zone, without changing anything. A script that cannot check may just exit 0 | `dns add`, `dns test`, before each order, and in the daily readiness check |
| `Add` | Add one TXT record with this value. Keep any other values at that name | Before validation |
| `Remove` | Remove only the TXT record with this exact value | After validation, and in recovery |

- **Result:** exit code 0 is success; anything else is failure. The last 20 lines of output are shown with a failure, after redaction (section 4).
- **Secret:** in the environment variable `SSLENSE_DNS_SECRET`, never in the arguments, which other processes can read in the process list.
- **Arguments:** passed as an argument list, never one command string. SSLense also checks that the zone and record name contain only host-name characters and that the value is Base64url, so nothing can be read as PowerShell syntax.
- **Timeout:** 2 minutes per call, configurable per provider. A script that runs longer is stopped with its child processes.
- **No trust in the result:** after `Add`, SSLense still checks the authoritative name servers, as it does for Cloudflare. A script that reports success without adding the record fails there, before the CA is asked.
- **Same records as Cloudflare:** the existing journal records each value before `Add`, so an interrupted validation is cleaned up through `Remove` at the next start.

`dns test` runs `Check`, then `Add` for `_sslense-test.<zone>`, waits until every authoritative name server has it, then runs `Remove`. That is a stronger test than the Cloudflare one, which does not wait for DNS.

`-ExecutionPolicy Bypass` applies to this one process. A Group Policy execution policy still takes precedence, so a server that requires signed scripts needs a signed script. The documentation says so.

## 4. Security

| Risk | Rule |
|---|---|
| Someone changes the script and gains SYSTEM | SSLense copies the script into `C:\ProgramData\SSLense\dns-scripts\<name>-<start of hash>.ps1` when it is added or updated, so an update is checked before the copy it replaces is removed. That folder already allows only Administrators and SYSTEM, and rejects links. SSLense runs only its copy, never the original |
| The copy is changed in place | SSLense stores the copy's SHA-256 and checks it before every run. A mismatch stops the run, says which file changed, and asks for `dns update-script`, which an administrator must run |
| A link or a file outside the folder | Before every run, SSLense checks that the copy is a plain file in that folder, not a link and with one hard link, and that its ACL still allows only Administrators and SYSTEM to change it |
| Someone other than an administrator adds a script | Adding, updating, and removing need elevation, as every SSLense change does. The service never adds or changes a script |
| The secret leaks | DPAPI-protected like tokens. Passed only in the child's environment. The script's output is redacted for the secret's exact value and the existing secret patterns before it is logged or shown. The diagnostic bundle includes the script's name and hash, never its secret. The seeded-secret bundle test is extended |
| A different program runs in place of PowerShell | The full path to `powershell.exe` in the system folder is used, never `PATH` |
| A runaway script | The timeout stops it. Output beyond 64 KB is dropped |

**Honest limits:**

- An administrator can always run code as SYSTEM, so this protects against everyone else, not against a careless administrator. The documentation says to read a script before adding it, and `dns list` shows each script's hash.
- The script runs as **SYSTEM** in the service but as **the signed-in administrator** in the CLI and GUI. A PowerShell module installed for one user only, or a credential stored in a user profile, works in `dns test` and then fails at renewal. The documentation says to install modules for all users. The daily readiness check (section 5) runs `Check` in the service, so this shows up in the digest weeks before a renewal fails.

## 5. Checks and diagnostics

- **Before each order:** `Check`, as the Cloudflare provider checks its token today. A failure stops before the rate-limited order is created.
- **Readiness check:** in the 30 days before each automatic renewal, the service runs `Check` once a day as SYSTEM. Two failures in a row are reported in the digest, like the other readiness checks.
- **Health check:** reports a script whose copy is missing, has the wrong hash, or has a wrong ACL.
- **Diagnostic bundle:** the script's name and the first 16 characters of its hash. The whole hash is long enough that the bundle's redaction removes it as a possible secret, and an exception for hex values would let through API keys that happen to be hex.
- **Errors:** a failed call reports the action, the exit code or timeout, and the script's last 20 lines of output with the secret removed. The CLI, GUI, and service log that message as they log any other failure. Output from a call that worked is not kept.

## 6. Data changes

- `DnsProviderType` gains `Script`.
- `DnsProviderProfile` gains `ScriptSha256` and `ScriptTimeoutSeconds`. The script's path is not stored, because it follows from the provider's name and the hash. A script provider's name must therefore be usable as a file name: letters, digits, spaces, dots, hyphens, and underscores. `ProtectedToken` may be empty, for a script without a secret. `ZoneId` is not used.
- **Config schema 6 to 7.** 0.14 would read a script provider as an unknown type and fail confusingly, so it must refuse the newer file instead. As in earlier releases, the existing file is backed up before the first save in the new version.

## 7. Safety requirements and delivery

Must hold before merge:

1. SSLense never runs a script that is not its own copy, with the stored hash, in the restricted folder.
2. No secret appears in arguments, logs, CLI output, GUI text, or diagnostic bundles.
3. A failed or slow script never leaves a record SSLense added: `Remove` runs after every validation, and the journal retries it at the next start.
4. Cloudflare, manual, and HTTP validation behave exactly as before.

| Step | Contents | Ships |
|---|---|---|
| 1 | This design | Docs |
| 2 | Core and CLI: the script runner, `Script` provider, copy and hash, checks before each run, schema 7, `dns add --provider script`, `dns update-script`, readiness and health checks. Unit tests with a fake runner, and tests that run real PowerShell with a test script that writes to a file. **Built** November 9, 2026, with the two example scripts in `dns-scripts\`, which tests also run. The checks on the copy's owner and ACL need elevation, so only the acceptance run covers them | CLI |
| 3 | GUI, README, the two example scripts in the MSI, roadmap and website; acceptance; release as 0.15 | Both |

Acceptance, with Let's Encrypt staging and `Cloudflare.ps1`:

- `dns add`, `dns test`, and a wildcard issued and renewed through the script
- The renewal run by the installed service as SYSTEM
- A changed copy is refused until `dns update-script`
- A script that exits 1, one that hangs past the timeout, and one that reports success without adding the record
- Killing SSLense after `Add`: the next start runs `Remove`
- A secret printed by the script appears redacted in the log

## 8. Decisions for approval

1. **PowerShell scripts only (proposed).** A `.ps1` can call any other program, and one interpreter keeps the contract and its checks simple.
2. **SSLense keeps its own copy, checked by hash before every run (proposed).** The alternative, running the administrator's file in place, would need its folder and every parent folder checked on every run, and edits would take effect without anyone noticing.
3. **One optional secret, passed in an environment variable (proposed).** Standard input is slightly harder for other processes to read, but harder for script authors to use. Several secrets can be put in one, such as `key:secret`.
4. **`Check` is part of the contract (proposed).** It lets SSLense find a broken script before an order, and as SYSTEM in the readiness check. A script that cannot check may just exit 0.
5. **Example scripts are installed with SSLense (proposed),** in Program Files, so they cannot be changed by other users and are there to copy.
6. **Windows PowerShell 5.1 only for now (proposed).** `pwsh` can be added as a per-provider option if users ask.
7. **Config schema 7 at the first save, as in earlier releases (proposed).** Going back to 0.14 means restoring the backup.
