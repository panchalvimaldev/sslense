# SSLense Commercial Development Roadmap

## 1. Product vision

SSLense should become the simplest secure certificate lifecycle manager built specifically for Windows and IIS.

The commercial product must retain these principles:

- Certificate renewal is safe, automatic, observable, and recoverable.
- The local agent continues working if any future cloud management service is unavailable.
- Private keys and credentials are never logged or transmitted unexpectedly.
- GUI, CLI, service, PowerShell, and API surfaces call the same Core operations.
- Potentially destructive actions require explicit confirmation and produce audit records.
- Staging remains the default in development and test environments.

## 2. Current status

Phases 1–7 provide:

- IIS site and binding discovery
- Let's Encrypt staging issuance using HTTP-01
- Windows certificate-store installation and SNI binding management
- Managed certificate state and automatic renewal service
- SMTP and webhook notifications
- WPF Dashboard, Logs, Issue Certificate, Certificate Details, and Settings screens
- CLI equivalents for shared Core operations

The current application is suitable for staging evaluation. It is not yet a production-ready commercial release because production ACME, hardened key storage, signed distribution, upgrade recovery, fleet management, and commercial operations remain unfinished.

## 3. External lifecycle requirements

Certificate scheduling must not assume that certificates always have 90-day lifetimes.

- Let's Encrypt moved its staging default to 64-day certificates on October 14, 2026.
- Let's Encrypt plans to move production defaults to 64 days on February 10, 2027.
- Default certificate lifetimes are expected to continue decreasing toward 45 days.
- SSLense should implement ACME Renewal Information (ARI, RFC 9773) and use lifetime-relative scheduling as a fallback.

References:

- [Let's Encrypt: 64-Day Certificate Lifetimes Coming February 2027](https://letsencrypt.org/2026/10/07/64-day-certs)
- [Let's Encrypt: Decreasing Certificate Lifetimes to 45 Days](https://letsencrypt.org/2025/12/02/from-90-to-45)
- [Let's Encrypt: ACME Renewal Information Published as RFC 9773](https://letsencrypt.org/2025/09/16/ari-rfc)
- [CA/Browser Forum Server Certificate Baseline Requirements](https://cabforum.org/working-groups/server/baseline-requirements/requirements/)

## 4. Commercial release gates

SSLense must satisfy every P0 requirement before accepting paying production customers.

### P0.1 Production ACME

- Add an explicit Production environment; never infer it from missing flags.
- Store staging and production accounts, orders, configuration, and state separately.
- Require a strong first-use confirmation in the GUI and CLI.
- Display the active ACME environment on every issuance, renewal, and certificate screen.
- Support Let's Encrypt subscriber agreement changes and account contact updates.
- Add rate-limit-aware errors and retry scheduling.
- Prevent staging certificates from being mistaken for production certificates.
- Add a production dry-run that performs pre-flight validation without creating an order.
- Keep production disabled in automated tests unless a dedicated, explicitly authorized environment is used.

Acceptance criteria:

- It is impossible to contact production accidentally through default settings.
- Staging and production account keys never overwrite one another.
- Production issuance can be enabled only through an explicit user action.
- Integration tests prove environment separation.

### P0.2 Renewal scheduling and ARI

- Implement ACME Renewal Information using RFC 9773.
- Prefer the CA-provided renewal window when available.
- Use approximately two-thirds of the certificate lifetime as the fallback renewal point.
- Add randomized jitter to avoid fleet-wide renewal spikes.
- Persist the next planned attempt and retry schedule.
- Resume missed work after reboot, sleep, service downtime, or upgrade.
- Add independent expiry monitoring so scheduling failures still generate alerts.
- Support configurable maintenance windows without risking expiration.
- Prevent simultaneous renewal of the same certificate by GUI, CLI, and service.

Acceptance criteria:

- Renewal works correctly for 90-, 64-, 45-, and 6-day certificates.
- Restarting the machine during a scheduled renewal does not lose the job.
- Two SSLense processes cannot issue for the same managed certificate concurrently.

### P0.3 Private-key and secret security

- Generate private keys directly in the Windows machine key store where supported.
- Make certificate private keys non-exportable by default.
- Stop writing PFX files by default after successful installation.
- Require an explicit export operation when a PFX is genuinely needed.
- Protect exported PFX files with user-supplied passwords and restricted ACLs.
- Apply explicit administrator and service-account ACLs to `%ProgramData%\SSLense`.
- Review DPAPI `LocalMachine` usage and file ACLs together; DPAPI alone is not the authorization boundary.
- Support Windows Credential Manager or another protected secret provider where appropriate.
- Scrub passwords, account keys, private keys, webhook URLs, tokens, query strings, and authorization headers from logs and diagnostics.
- Zero sensitive byte buffers when practical.
- Define certificate private-key permissions for application-pool identities.
- Add compromised-account and compromised-private-key recovery procedures.

Acceptance criteria:

- Standard issuance leaves no recoverable plaintext PFX or password on disk.
- A non-administrator account cannot read SSLense secrets or private keys.
- Automated tests scan produced logs and support bundles for seeded secrets.

### P0.4 Transaction safety and crash recovery

- Add a durable operation journal for issue, renew, rebind, remove, and upgrade operations.
- Record intended mutations before changing the certificate store or IIS.
- Preserve the previous certificate and binding until replacement verification succeeds.
- Verify the new site over HTTPS after the IIS binding swap.
- Verify hostname, certificate thumbprint, validity period, and chain.
- Restore previous bindings automatically when verification fails.
- Recover interrupted operations when the service or GUI starts.
- Make every operation idempotent.
- Back up configuration and state before schema migration.
- Add versioned state schemas and tested forward migrations.

Acceptance criteria:

- Killing SSLense at every operation boundary never leaves a site without its previous working binding.
- Interrupted operations are either completed or rolled back on restart.
- Downgrades fail safely when state schemas are incompatible.

### P0.5 Professional Windows distribution

- Build an MSI or equivalent enterprise-friendly installer.
- Install GUI, CLI, service, documentation, and required runtime components together.
- Support unattended installation and uninstallation.
- Register Add/Remove Programs metadata.
- Configure ProgramData directories and ACLs during installation.
- Allow the administrator to choose whether the renewal service starts immediately.
- Preserve configuration, accounts, and managed-certificate state during upgrades.
- Roll back failed installations and upgrades.
- Sign executables, DLLs, installers, uninstallers, scripts, and update packages with a trusted Authenticode identity.
- Timestamp signatures.
- Verify update signatures before applying updates.
- Provide release channels such as Stable and Preview.
- Support signed offline installers for restricted environments.

Microsoft references:

- [SmartScreen reputation for Windows application developers](https://learn.microsoft.com/windows/apps/package-and-deploy/smartscreen-reputation)
- [Code signing for Smart App Control](https://learn.microsoft.com/windows/apps/develop/smart-app-control/code-signing-for-smart-app-control)

Acceptance criteria:

- Clean installation, upgrade, repair, and uninstall work on every supported Windows Server version.
- All shipped executable content has a valid trusted signature.
- Failed upgrades restore the previously working version and preserve state.

### P0.6 Quality and compatibility

- Define a supported Windows and IIS version matrix.
- Run integration tests against real IIS virtual machines in CI or a controlled test lab.
- Test clean installation, upgrade, renewal, rollback, removal, and recovery.
- Test HTTP-01 through direct public IPs, reverse proxies, NAT, and Cloudflare Tunnel.
- Test IPv4, IPv6, internationalized domain names, SAN certificates, and large binding sets.
- Test outbound proxies, authenticated proxies, restricted firewalls, and TLS inspection environments.
- Test machines with clock skew and delayed Windows updates.
- Add performance and soak tests for large fleets and thousands of bindings.
- Add accessibility testing, keyboard navigation, high-contrast support, and scalable text.
- Localize UI, CLI messages, documentation, dates, and number formats.

Acceptance criteria:

- A published compatibility matrix is backed by repeatable automated tests.
- Critical issue and renewal scenarios pass on every supported server release.
- No Core workflow depends on English Windows command output.

### P0.7 Supportability and operations

- Generate a diagnostic support bundle with automatic secret redaction.
- Include application version, OS/IIS versions, service status, relevant bindings, certificate metadata, configuration schema version, and recent logs.
- Never include private keys, passwords, tokens, protected blobs, or full webhook URLs.
- Add a one-click health check covering state, service heartbeat, filesystem permissions, IIS access, certificate store access, DNS, HTTP reachability, ACME connectivity, and notification channels.
- Add configuration backup and restore.
- Add log size limits and retention controls.
- Record service heartbeat and last successful daily cycle.
- Publish troubleshooting runbooks and support escalation instructions.

Acceptance criteria:

- A support engineer can diagnose common failures without remote server access.
- Diagnostic bundles pass automated secret-scanning tests.

## 5. Paid product capabilities

### P1.1 DNS-01 and wildcard certificates

- Define a versioned DNS-provider plugin interface.
- Implement Cloudflare first.
- Add Azure DNS, AWS Route 53, DigitalOcean, GoDaddy, and other high-demand providers based on customer feedback.
- Support generic webhook/script integrations for unsupported providers.
- Support wildcard certificates and split-horizon DNS.
- Discover authoritative DNS and verify TXT propagation from multiple resolvers.
- Use provider-scoped least-privilege credentials.
- Encrypt provider secrets and ensure they never appear in logs.
- Clean up TXT records safely after validation.
- Support delegated `_acme-challenge` zones and CNAME-based delegation.

### P1.2 Existing-certificate discovery and adoption

- Scan IIS bindings and `LocalMachine\My` for existing certificates.
- Detect expired, expiring, duplicate, orphaned, self-signed, and staging certificates.
- Match certificates to sites, hosts, and private keys.
- Allow administrators to adopt an existing certificate without immediate reissuance.
- Detect unmanaged IIS bindings continuously.
- Recommend SAN consolidation without changing bindings automatically.
- Import supported external ACME-account or certificate metadata safely.

### P1.3 Multiple certificate authorities

- Support configurable ACME directory URLs.
- Add External Account Binding.
- Support Let's Encrypt, Google Trust Services, ZeroSSL, enterprise ACME services, and internal PKI.
- Store CA accounts and policies separately.
- Allow per-certificate CA selection and fallback policy.
- Validate CA chains and expected issuers.
- Never silently fail over to a different CA without policy authorization.

### P1.4 Broader deployment targets

Keep IIS as the primary experience, then add optional deployment adapters for:

- HTTP.sys
- Kestrel-hosted applications
- Windows services
- Remote Desktop Services
- SQL Server
- Exchange Server
- Network shares and secure file export
- Load balancers and reverse proxies

Each adapter must implement install, verify, rollback, and remove operations behind a shared interface.

### P1.5 Notifications and escalation

- Add Microsoft Teams, Slack, and incident-management integrations.
- Support customizable templates and branding.
- Add repeated escalation for unresolved failures.
- Notify on service heartbeat loss and missed renewal windows.
- Add quiet hours and maintenance windows.
- Support per-certificate owners and routing rules.
- Provide signed webhook payloads with replay protection.

### P1.6 Automation surfaces

- Publish a stable versioned REST API.
- Add a PowerShell module.
- Add machine-readable CLI JSON output.
- Document stable exit codes.
- Support unattended configuration import/export.
- Add webhooks for lifecycle events.
- Publish API contracts and compatibility guarantees.

### P1.7 Certificate policy engine

- Define allowed domains and wildcard policies.
- Define allowed key types, sizes, and signature algorithms.
- Set CA, renewal, notification, and maintenance policies by site or group.
- Add approval requirements for production issuance, removal, and export.
- Detect and report policy drift.
- Support report-only policies before enforcement.

## 6. Multi-server and enterprise roadmap

### P2.1 Central fleet management

- Build a central web console backed by a lightweight Windows agent.
- Keep local renewal autonomous when the central service is unavailable.
- Show certificate inventory, expiry, renewal state, service health, and policy compliance across servers.
- Support safe remote operations with clear target selection and approvals.
- Use mutually authenticated, rotating agent identities.
- Queue commands durably and prevent replay.
- Add staged agent upgrades and rollback.
- Provide fleet-wide search, reporting, and export.

### P2.2 Enterprise identity and authorization

- Support Microsoft Entra ID and standard OIDC.
- Add SAML when customer demand requires it.
- Implement role-based access control.
- Support least-privilege roles such as Viewer, Operator, Approver, Security Administrator, and Tenant Administrator.
- Add approval workflows for production issuance, certificate removal, secret changes, and exports.
- Maintain immutable audit trails with actor, action, target, timestamp, result, and correlation ID.
- Support service principals and short-lived automation credentials.

### P2.3 MSP and multi-tenancy

- Strictly isolate tenant data, credentials, agents, logs, policies, and billing.
- Support delegated customer access.
- Add per-customer branding and reports.
- Add cross-tenant operational views without exposing secrets.
- Support per-tenant data retention and deletion.
- Add usage metering suitable for commercial billing.

### P2.4 Enterprise deployment and governance

- Support Group Policy or policy-file configuration.
- Support software deployment through common enterprise management systems.
- Provide offline activation and offline updates where contractually required.
- Add proxy, private CA, and TLS-inspection configuration.
- Offer configurable telemetry with an explicit opt-in policy.
- Provide data residency and retention controls for hosted services.

## 7. Security and supply-chain program

- Maintain a documented threat model and update it for every major architecture change.
- Add secure coding and peer-review requirements for cryptographic, update, and remote-management code.
- Generate a software bill of materials for every release.
- Scan dependencies, source, binaries, containers, installers, and infrastructure definitions.
- Pin and verify build dependencies.
- Protect release signing through managed signing or hardware-backed keys.
- Separate build, test, signing, and publication permissions.
- Make release builds reproducible where practical.
- Publish checksums and signature-verification instructions.
- Establish a security contact and vulnerability disclosure policy.
- Define severity and response-time targets.
- Arrange independent penetration testing before general availability and after major security-sensitive changes.
- Add backup, restore, disaster-recovery, and incident-response exercises.

## 8. Privacy, legal, and commercial operations

Before a paid release:

- Complete product-name and trademark checks in target markets.
- Publish an EULA and commercial license terms.
- Publish a privacy policy and explain every collected telemetry field.
- Prepare a Data Processing Agreement for business customers if hosted services process customer data.
- Define data retention, export, and deletion procedures.
- Review GDPR, UK GDPR, applicable US privacy laws, and other target-market requirements with qualified counsel.
- Define subprocessors for hosted services.
- Establish refund, cancellation, renewal, and support policies.
- Use a billing system or merchant-of-record service that can handle international taxes, VAT/GST, invoices, and payment compliance.
- Define service levels only after monitoring and support processes can measure them.
- Maintain export-control and sanctions-screening processes where applicable.

This roadmap is engineering guidance, not legal advice. Qualified legal and tax professionals should review commercial obligations before launch.

## 9. Documentation and customer experience

- Create a public installation guide and five-minute quick start.
- Publish migration guides from manual IIS certificates and common ACME clients.
- Document firewall, DNS, proxy, permissions, and service-account requirements.
- Provide task-oriented guides for HTTP-01, DNS-01, wildcard certificates, tunnels, and multi-server deployment.
- Publish a security architecture and secret-storage guide.
- Document backup, recovery, certificate revocation, and disaster recovery.
- Add contextual GUI help and links to exact remediation steps.
- Provide searchable error codes that remain stable across releases.
- Build sample scripts for unattended deployments.
- Maintain release notes, known issues, deprecation notices, and an upgrade compatibility matrix.

## 10. Suggested commercial editions

Licensing should be based primarily on managed servers or nodes rather than certificate count.

### Community

- One server
- Limited managed certificates
- HTTP-01
- Local GUI and CLI
- Community support

### Professional

- Unlimited local certificates on licensed servers
- DNS-provider plugins and wildcard certificates
- Advanced notifications
- Existing-certificate adoption
- Signed automatic updates
- Standard commercial support

### Business

- Central multi-server management
- Enterprise identity and RBAC
- Audit logs and policy engine
- REST API and PowerShell automation
- Reporting and priority support

### MSP

- Multi-tenancy
- Delegated customer access
- Customer branding
- Fleet reporting
- Usage metering and tenant-level controls

Final pricing, limits, and packaging should be validated through customer interviews rather than fixed before the private beta.

## 11. Recommended implementation sequence

### Commercial Phase A — Production safety

1. Production/staging separation
2. ARI and lifetime-relative renewal scheduling
3. Per-certificate concurrency control
4. Non-exportable key model and no default PFX persistence
5. Durable transaction journal and crash recovery

Exit gate: controlled production issuance and renewal can run without risking an existing working IIS binding.

### Commercial Phase B — Distributable beta

1. Signed installer
2. Signed update mechanism
3. ProgramData and key ACL hardening
4. Supported Windows/IIS test matrix
5. Diagnostic bundle and health checks
6. Documentation and support workflow
7. Security review and penetration test

Exit gate: SSLense can be installed, upgraded, supported, and uninstalled safely by external beta customers.

### Commercial Phase C — Paid single-server release

1. Cloudflare DNS-01
2. Wildcard certificates
3. Existing-certificate discovery and adoption
4. Multiple ACME CAs and EAB
5. PowerShell and JSON CLI automation
6. Licensing, billing, privacy, and commercial policies

Exit gate: the product has clear paid differentiation from free ACME clients.

### Commercial Phase D — Business and MSP platform

1. Central management service and agent protocol
2. Entra ID/OIDC and RBAC
3. Audit logs and policy engine
4. Multi-tenancy
5. Reporting, approvals, and fleet automation

Exit gate: SSLense can be sold to organizations and managed-service providers operating multiple servers.

## 12. Private-beta plan

- Recruit 10–20 Windows/IIS administrators from different hosting environments.
- Include direct public servers, NAT, Cloudflare Tunnel, reverse proxies, and restricted enterprise networks.
- Use staging first, followed by explicitly approved low-risk production sites.
- Track installation success, time to first certificate, renewal success, remediation time, support requests, and upgrade reliability.
- Hold structured interviews after installation and after the first automatic renewal.
- Do not enable unattended automatic updates until rollback and signature validation have been proven.
- Convert repeated support issues into health checks, stable error codes, tests, and documentation.

## 13. Definition of commercially ready

SSLense is ready for a general paid release when:

- Production issuance cannot be triggered accidentally.
- Renewal follows ARI or a safe lifetime-relative fallback.
- Private keys are non-exportable by default and PFX files are not persisted by default.
- Issue, renew, remove, and upgrade operations survive interruption safely.
- Every shipped executable is signed.
- Installation and upgrades pass the supported OS/IIS matrix.
- Diagnostic bundles are useful and demonstrably free of secrets.
- Security, privacy, licensing, billing, and support processes are published and operational.
- A private beta has completed real automatic production renewals without binding loss.
- The team can detect, diagnose, communicate, and recover from a failed release.

