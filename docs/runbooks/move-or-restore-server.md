# Runbook: move SSLense to another server, or restore it after a rebuild

Private keys never leave the machine store, and DPAPI secrets only open on the server that made them. So a new server gets its settings from an export and its certificates from new orders.

1. **On the old server, if it still runs:**
   ```powershell
   $env:SSLENSE_CONFIG_PASSWORD = [System.Net.NetworkCredential]::new('', (Read-Host -AsSecureString -Prompt Password)).Password
   SSLense.Cli config export --file D:\move\settings.json --include-secrets --certificates D:\move\certificates.csv
   ```
   Keep the file and the password apart. Without `--include-secrets`, only the general settings move.
2. **On the new server:**
   1. Install the MSI, set up the IIS sites and bindings, and open port 80 if you use HTTP validation.
   2. Run, with the same password in `SSLENSE_CONFIG_PASSWORD`:
      ```powershell
      SSLense.Cli config import --file D:\move\settings.json --yes
      ```
   3. Restart the SSLense service.
3. **Issue the certificates again:**
   1. Run `SSLense.Cli bulk issue --file D:\move\certificates.csv --dry-run` and fix whatever the checks report.
   2. Run it again without `--dry-run`. Production certificates need `--accept-production-risk`.
   3. Certificates the file cannot describe are listed when it is exported. Add those by hand:
      - certificates from other providers: install from the provider's files;
      - manual DNS validation;
      - certificates with no site;
      - shared certificates.
4. **Add the deployment steps** again for each certificate (`deploy add`). They are part of each certificate, not of the settings.
5. **Mind the rate limits:** Let's Encrypt allows a limited number of duplicate certificates a week. For many sites, move in batches, or test with staging first.
6. **Retire the old server:**
   1. Run `SSLense.Cli unmanage --site <name>` for each certificate, or uninstall, so it stops renewing.
   2. Revoke nothing unless a key may have been copied ([compromised-key-or-account.md](compromised-key-or-account.md)).

**Restoring the same machine from a full system backup** restores everything as it was, because DPAPI and the machine store come back with it. Run `SSLense.Cli health` afterwards.
