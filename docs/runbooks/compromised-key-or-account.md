# Runbook: a private key or ACME account key may have been copied

Use this when a certificate's private key, or SSLense's ACME account key, may have left the server: a stolen or lost backup, a disk or virtual machine image that was shared, a server that was broken into, or a PFX file sent to the wrong place. Act on the same day: until a certificate is revoked, whoever has its key can impersonate the site.

## A certificate SSLense renews automatically

1. **Revoke and replace it.** In the app, select the certificate, open ⋯ and choose **Revoke and replace (key compromised)…**. Or run:
   ```powershell
   SSLense.Cli revoke --site "<certificate name>" --yes
   ```
   SSLense installs a new certificate with a new key first, checks the site serves it, runs the certificate's deployment steps, then has the certificate authority revoke the old certificate for key compromise.
2. **Check the result.** The message names the new certificate. Choose **Check** on the certificate to confirm every host name serves it.
3. **If the revocation failed** (error SSL2030), the sites already use the new certificate. Run the command the error gives, which points to the old certificate saved under `C:\ProgramData\SSLense\revocations`:
   ```powershell
   SSLense.Cli revoke --file "<path>" --ca <certificate authority> --reason key-compromise --yes
   ```
4. **Repeat for every certificate whose key may have leaked.** A certificate shared by several sites is one certificate: revoking it once covers all of them.
5. **Anything else that held a copy of the key,** such as PFX or PEM files written by export steps, or a load balancer, needs the new certificate too; check the certificate's After install steps.

## A certificate you bought

SSLense cannot revoke it (error SSL4051). Ask your provider to revoke it for key compromise; most have a button for this in their control panel. Get a new certificate with a **new** key: create a new request in SSLense (Add certificate › I bought it and the provider needs a request), so the new key never leaves the server. Install it with **Install renewal**.

## A certificate with manual DNS validation

1. Select it and choose **Renew by hand**, which creates a new key, and complete the DNS records as usual.
2. Revoke the old certificate from its file, or from a copy exported earlier:
   ```powershell
   SSLense.Cli revoke --file "<old certificate>" --ca <certificate authority> --reason key-compromise --yes
   ```

## The ACME account key

The account key is in SSLense's data folder, encrypted for this server. If the data folder, or the server, may have been copied:

1. **Replace the account key** for each certificate authority: Settings › Certificate authorities › **Replace account key**, or:
   ```powershell
   SSLense.Cli account change-key --ca <certificate authority> --yes
   ```
   The certificate authority switches the account to a new key at once; the copied key stops working. Certificates are not affected.
2. **If the server itself was broken into,** assume the certificate keys were copied too: revoke and replace every certificate as above.

## Afterwards

- Run the health check (Activity › Run health check) and fix anything it reports.
- Keep the SSLense log for the incident report: it records each revocation and key change.
