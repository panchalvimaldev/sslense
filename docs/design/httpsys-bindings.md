# Design: HTTP.sys bindings outside IIS

Status: **built** November 20, 2026. The first part of feature 25 of [the delivery plan](../delivery-plan.md), "Other deployment targets".

## What the administrator gets

Many Windows services take their certificate from an HTTP.sys binding that IIS doesn't manage:

- WinRM over HTTPS (port 5986);
- Kestrel or self-hosted ASP.NET apps on HTTP.sys;
- the Windows Admin Center gateway;
- reporting and management services on their own port.

A deployment step, **Bind it in HTTP.sys outside IIS**, binds the certificate to such an endpoint after every install and renewal:

- the app: the certificate's After install section;
- the CLI: `SSLense.Cli deploy add --site <certificate> --http-sys 0.0.0.0:5986`.

The endpoint is one of:

- an IP address and port, such as `0.0.0.0:5986`, `[::]:8443` or `10.0.0.5:443` (netsh `ipport`);
- a host name and port for SNI, such as `api.example.com:8443` (netsh `hostnameport`).

## How the step works

- **When it is added:** the endpoint is checked, and one that IIS serves is refused:
  - a host name and port that an IIS site's HTTPS binding uses, because SSLense already changes it with that site's certificate;
  - an IP address and port where an IIS site serves HTTPS, even if all its bindings there have host names. The certificate on such an endpoint answers every visitor whose browser sends no host name, and it would become the certificate of a host-less binding added later. The combined test found this case.
- **When it runs:**
  1. `netsh http show sslcert` looks for the binding.
  2. An existing binding is changed with `update sslcert` and keeps its application ID, so the service that owns it still owns it. A missing binding is added under SSLense's own application ID.
  3. The binding is read back. If it doesn't show the new certificate, the step fails with SSL4057 and is retried hourly.
- **Settings that reset:** `update sslcert` returns options that netsh doesn't receive, such as client certificate negotiation, to their defaults. After the first run, check them with `netsh http show sslcert`, and use a script step instead when a service needs special settings.
- **In use:** the clean-up of unused certificates already treats every HTTP.sys binding as in use, so it never suggests these certificates.

This is managed-certificate schema 17.

## Still to come in feature 25

- Remote Desktop, SQL Server and Exchange as first-class steps; ready-made scripts exist today.
- Apache, nginx and Tomcat on Windows, as files and a reload.

Update: all of these were built, except Exchange, which stays a ready-made script. Azure App Service was built and then removed before 0.24.0 ([app-service.md](app-service.md)).

Each will get its own pull request.

## Tests

- Endpoints are read as netsh names them, and anything else is refused.
- An endpoint that an IIS site binds is refused.
- The step binds the certificate when it runs.

Manual steps: [docs/testing/httpsys-bindings.md](../testing/httpsys-bindings.md).
