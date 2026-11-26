# Runbook: a site serves the wrong or an old certificate

**Signs:** browsers warn after a renewal, the health check's "served certificate" check fails, or clients that pin a key or chain break.

1. **What is served:** the certificate's **Check** button, or `SSLense.Cli check --site <name>`, compares the served certificate with the managed one. `netsh http show sslcert` shows what HTTP.sys binds for each `ip:port` and `host:port`.
2. **The new certificate broke a client** (a pinned key, an old device that doesn't trust the new chain, a key type a service can't read): roll back.
   - Use **⋯ › Roll back to the previous certificate…**, or `SSLense.Cli rollback --site <name>`. This binds the certificate the renewal replaced, while it is valid, and holds automatic renewal for up to a week.
   - Fix the cause: for example `--reuse-key`, `--preferred-chain` or `--key`. Then renew by hand, or roll forward with the same command.
3. **One site of a shared certificate was left behind:** the certificate's Sites section names it. Fix the site in IIS, then **Try moving now**.
4. **A binding outside SSLense** (another site, or a binding added by hand): the health check names it. Bind it to the managed certificate, or let SSLense manage it with **Add certificate › already in IIS**.
5. **Behind a load balancer, CDN or proxy:** each server has its own binding. Check every server, or the Central Certificate Store they share, and that the CDN has the new certificate.
6. **Other services** (Remote Desktop, SQL Server, FTP, HTTP.sys endpoints, Apache, nginx, Tomcat): `deploy list --site <name>` shows whether the steps ran for the current certificate, and `deploy run --site <name>` runs them now. After a rollback, run them so those services go back too.
