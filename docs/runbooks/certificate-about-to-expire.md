# Runbook: a certificate is about to expire and renewal keeps failing

**Signs:** renewal-failure notifications, a red certificate in the app, `SSL…` errors in `SSLense.Cli status`, or the reminder digest naming the certificate.

1. **See why.** `SSLense.Cli status` and the certificate's History tab (or `history --site <name>`) show each failure's error code. Look the code up in [errors.md](../errors.md); most say exactly what to fix.
2. **Check what renewal needs:**
   - HTTP validation: `SSLense.Cli preflight --site <site> --hosts <hosts>`. Then, from outside your network, check that `http://<host>/.well-known/acme-challenge/test` reaches this server ([network-requirements.md](../network-requirements.md)).
   - DNS validation: `SSLense.Cli dns test --name <provider>`.
   - Everything: `SSLense.Cli health`.
3. **Fix the first failing check, then renew by hand:** `SSLense.Cli renew --site <name>`. A renewal started by hand runs at once, ignoring the backoff and any rollback hold.
4. **Rate limited** (SSL2xxx naming a rate limit): wait for the time the message gives. Retrying sooner only extends the limit. Don't switch to another account to get around it.
5. **Out of time:**
   - If HTTP validation cannot be fixed before expiry, switch the certificate to DNS validation: issue it again with `--validation dns --force` and a DNS provider.
   - For a single site, a short-term workaround is to issue from another CA you have already set up (`--ca`).
6. **After it renews:**
   - Check that the site serves the new certificate (the certificate's **Check** button, or `SSLense.Cli check --site <name>`).
   - Check that the deployment steps ran: `deploy list --site <name>`.

Escalate with `SSLense.Cli diagnostics` (add `--redact-hosts` if needed) if the cause is unclear.
