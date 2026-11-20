# Moving to SSLense

From another ACME client, from certificates bought and installed by hand, or from scripts. SSLense manages certificates that are already in IIS without reissuing them first, so a move can be gradual.

## 1. Look at what is there

- **Certificates bound in IIS:** **Add certificate › already in IIS**, or `SSLense.Cli discover`, lists the certificates IIS sites use. Adopt each one, with **Adopt** or `adopt --site`. SSLense then watches it, reminds you before it expires and checks that it is served, without changing anything.
- **Certificates on other machines** (load balancers, appliances): `SSLense.Cli watch --host <name>`.
- **Unused certificates left by the old tool:** Activity › Unused certificates lists expired, test and replaced certificates that nothing uses. Remove them only after the move.

## 2. Hand renewal over to SSLense, one site at a time

For each site:

1. **Stop the old tool renewing that site.** Disable its task, or remove the site from its configuration. Two tools renewing the same names use up the CA's weekly duplicate-certificate limit and fight over the binding.
2. **Issue with SSLense** using the same validation as before:
   - `--validation http` when the site answered HTTP challenges;
   - `--validation dns` with a DNS provider when the old tool used DNS (add the provider first with `dns add`);
   - `--validation dns-manual` when you created the records by hand.
3. **Use the same certificate authority.** For a CA that needs External Account Binding, add it with `ca add --eab`. A CA's account is per tool, so SSLense registers its own; your existing account and its certificates are not affected.
4. **Bring along what else used to run:** services restarted, files exported, scripts run, keys given to accounts. Add each as a deployment step (`deploy add`).
5. **Check:** `SSLense.Cli check --site <name>`, and the certificate's History tab.
6. **Remove the old tool** when every site is moved. Its certificates stay in the store until the clean-up suggests them.

## 3. Many sites

- **Write a CSV for bulk issue:** one row per site, with the columns `site,hosts,validation,names,email,ca,profile,key` (see `bulk issue --help`).
- **Run `bulk issue --dry-run`** to run every pre-check without ordering anything. Then run it without `--dry-run`, in batches that stay inside the CA's rate limits.

## Certificates you buy

Certificates from a commercial CA without ACME stay with that CA:
1. Adopt them, or install them with **Add certificate › a certificate you bought**.
2. When one is due, create the request with `csr --site`.
3. Complete it with the provider's files (`complete`).

If the provider supports ACME, add it as a certificate authority instead, and SSLense renews automatically.
