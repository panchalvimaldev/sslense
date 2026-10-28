# Security policy

SSLense runs with administrator rights, holds ACME account keys, and changes IIS bindings, so security reports are taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**, or go directly to
<https://github.com/panchalvimaldev/sslense/security/advisories/new>.

Include, where you can:

- the SSLense version and Windows Server / IIS version;
- what an attacker could do, and what access they need first (for example, a local non-administrator account);
- steps to reproduce, ideally against Let's Encrypt **staging**.

Never include real private keys, account keys, passwords, or webhook URLs. Redact them from logs before sharing.

## What to expect

SSLense is maintained by volunteers, so these are goals rather than guarantees:

- acknowledgement within 7 days;
- an initial assessment within 14 days;
- a fix or mitigation as soon as practical, prioritized by severity, with credit in the release notes unless you prefer to stay anonymous.

Please give us reasonable time to release a fix before disclosing the issue publicly.

## Supported versions

Security fixes are released for the latest version only. Upgrade to the newest release before reporting, if you can.

## Scope

In scope: the SSLense GUI, CLI, Windows service, installer, and their handling of keys, secrets, permissions, and IIS configuration.

Out of scope: vulnerabilities in Let's Encrypt, Windows, IIS, or third-party libraries themselves (report those upstream), and attacks that require an account that is already a local administrator.
