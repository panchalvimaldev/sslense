# Acceptance checks on real IIS

Unit tests use a fake IIS, so they cannot show what IIS and HTTP.sys really do. This program checks that on a real machine. It is not part of `dotnet test`, and it is not shipped. Run it from an Administrator terminal, on a machine you can test on.

| Command | What it does | Needs |
|---|---|---|
| `parta` | Binding changes, trials, and restores, with self-signed certificates. A few minutes. Live-check failures are simulated, because real IIS cannot be made to fail on demand. Changes no SSLense state | IIS |
| `partb --zone example.com` | The real commands against Let's Encrypt **staging**, including upgrading existing data and killing the process during a change. About 15 minutes | IIS, a Cloudflare zone, a token for it |
| `appsetup --zone example.com` | Prepares three sites and a staging certificate, to try the app by hand | The same as `partb` |
| `servicecheck --zone example.com` | The installed service moves a site left behind, in its first cycle after starting. A few minutes | The same, and the service installed |
| `httpcheck --zone example.com` | Issues and renews one certificate with HTTP validation, then removes it. Uses no token | `site1.accept.<zone>` in public DNS pointing at this machine, and port 80 open to the internet |
| `restore` | Finishes `appsetup`, or recovers from an interrupted run | |

Every command except `parta` uses `C:\ProgramData\SSLense`, because SSLense has no other data folder. They stop the service and back up the folder first, and put everything back when they finish, except `appsetup`, which leaves it ready for you. Never delete `C:\ProgramData\SSLense.acceptance-backup` by hand: run `restore`.

They create temporary TXT records under `accept.<zone>`, and sites named `SSLenseAccept1` to `3`. Use a Cloudflare token limited to that zone that expires the next day, and delete it afterwards. The prompt that asks for it belongs to `SSLense.Cli`, so this program never sees it.

Results are saved as `result-<command>.txt`, in the current folder or `--out`. They contain host names and thumbprints, and the email address is replaced.

## Running it

On a machine with the repository:

```powershell
dotnet build SSLense.sln
.\tests\SSLense.Acceptance\bin\Debug\net10.0-windows\SSLense.Acceptance.exe parta
```

On a server without the .NET SDK, publish it first, copy the folder across, and point `--cli` at the installed SSLense under test:

```powershell
dotnet publish tests\SSLense.Acceptance -c Release -r win-x64 --self-contained -o artifacts\acceptance
.\SSLense.Acceptance.exe partb --zone example.com --cli "C:\Program Files\SSLense\cli\SSLense.Cli.exe"
```

`setup-server.ps1` adds IIS and its management tools to a new Windows Server, and reports what it found.

With a different release installed, `partb` also checks that it refuses the upgraded data. Pass `--installed` if it is not in the default place.
