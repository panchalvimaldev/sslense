# SSLense error codes

Every error SSLense explains starts with a code, such as `SSL1003`. The code is the same in the app, the command line, the log, notifications, the daily digest and the Windows Event Log, and it never changes meaning, so you can search for it. The first digit says where to look.

This page is generated from `src/SSLense.Core/Errors/ErrorCodes.cs`; do not edit it by hand.

## SSL1xxx: IIS: sites, bindings, challenge files, the HTTPS check and rollback

<a id="ssl1001"></a>

### SSL1001: IIS site not found

Check the site name with 'SSLense.Cli list-sites' or in IIS Manager. A site renamed or deleted in IIS must be managed again under its new name.

<a id="ssl1002"></a>

### SSL1002: IIS site has no physical path

HTTP validation writes the challenge file into the site's folder. Set the site's physical path in IIS Manager, or use DNS validation.

<a id="ssl1003"></a>

### SSL1003: Host name has no suitable binding

Add an HTTP binding on port 80 for the host name in IIS Manager (HTTP validation), or an HTTP or HTTPS binding (DNS validation), then try again.

<a id="ssl1004"></a>

### SSL1004: IIS configuration could not be read

Run SSLense as Administrator. If it still fails, check that IIS is installed and its configuration files are not locked or damaged.

<a id="ssl1005"></a>

### SSL1005: IIS management components are missing

Install 'IIS Management Scripts and Tools' (Server Manager, Web Server role), then start SSLense again.

<a id="ssl1006"></a>

### SSL1006: netsh could not be started

SSLense uses netsh to manage certificate bindings. Check that C:\Windows\System32\netsh.exe exists and is not blocked by policy.

<a id="ssl1007"></a>

### SSL1007: HTTPS binding missing after it was set

IIS did not keep the binding. The previous binding is restored. Check for another tool or script changing bindings at the same time, then try again.

<a id="ssl1008"></a>

### SSL1008: IIS did not keep the certificate on the binding

The previous binding is restored. Check for another tool changing bindings, and that the certificate is in LocalMachine\My with its private key.

<a id="ssl1009"></a>

### SSL1009: HTTPS binding could not be changed

The message says what failed and whether the previous binding was restored. Run SSLense as Administrator and check the log under Activity.

<a id="ssl1010"></a>

### SSL1010: Binding uses another certificate

The binding was changed to another certificate outside SSLense, so it was left alone. Remove it in IIS Manager if it is no longer needed.

<a id="ssl1011"></a>

### SSL1011: Binding removal could not be confirmed

The certificate was kept in the store to be safe. Check the site's bindings in IIS Manager, then remove the certificate if nothing uses it.

<a id="ssl1012"></a>

### SSL1012: Bindings could not be removed

Run SSLense as Administrator and try again.

<a id="ssl1013"></a>

### SSL1013: The site does not serve the new certificate

SSLense connected over HTTPS and got another certificate, so it restored the previous binding. Check for a load balancer, proxy or CDN in front of the server, or another binding on the same IP and port.

<a id="ssl1014"></a>

### SSL1014: Previous binding no longer exists

The binding was removed while SSLense was changing it. Check the site's bindings in IIS Manager and add the HTTPS binding again if needed.

<a id="ssl1015"></a>

### SSL1015: No certificate was served

Nothing answered with a certificate on that host name and port. Check that the site is started and has an HTTPS binding for the host name.

<a id="ssl1016"></a>

### SSL1016: Site not reachable on port 80

SSLense could not reach the host name on port 80 from this server. Check the DNS record, the firewall, and that the site is started. Behind NAT, check that the server can reach its own public address, or use DNS validation.

<a id="ssl1017"></a>

### SSL1017: Challenge file not served

The site answered with an error for the challenge file. Check for a rule that redirects or blocks /.well-known/acme-challenge/, authentication on the site, or a missing static file handler.

<a id="ssl1018"></a>

### SSL1018: Challenge file served with the wrong content

Another server or a rewrite rule answered instead of this site. Check DNS, proxies and URL Rewrite rules for the host name.

<a id="ssl1019"></a>

### SSL1019: Previous bindings not fully restored

A binding change failed and SSLense could not confirm every previous binding was put back. Check the named sites in IIS Manager now: a site may be serving the wrong certificate or none.

<a id="ssl1020"></a>

### SSL1020: IIS returned a binding SSLense cannot read

Check the site's bindings in IIS Manager for a malformed entry.

<a id="ssl1021"></a>

### SSL1021: netsh did not finish in time

Try again; if it repeats, restart the HTTP service or the server.

<a id="ssl1022"></a>

### SSL1022: Site did not answer on port 80 in time

Check the firewall and that the site is started. Behind NAT, check that the server can reach its own public address, or use DNS validation.

<a id="ssl1023"></a>

### SSL1023: HTTPS binding missing

A host name has no HTTPS binding with the managed certificate. Renew the certificate to bind it again, or check the bindings in IIS Manager.

<a id="ssl1024"></a>

### SSL1024: Site serves another certificate

The site does not serve the certificate SSLense installed. Check for a binding changed outside SSLense, another binding on the same IP and port, or a proxy in front of the server.

<a id="ssl1025"></a>

### SSL1025: Host did not answer on port 443

The daily check could not connect to the host name from this server. Check the site is started and the firewall, and DNS for the name on this server.

<a id="ssl1026"></a>

### SSL1026: Challenge folder not writable

SSLense could not write to the site's .well-known\acme-challenge folder. Run SSLense as Administrator, and check the site's physical path and its permissions.

<a id="ssl1027"></a>

### SSL1027: Site serves an expired certificate

The site serves the certificate SSLense expects, but it has expired. Renew it now.

<a id="ssl1028"></a>

### SSL1028: SSLense cannot answer on port 80

SSLense answers the challenge through HTTP.sys, which IIS also uses. Run SSLense as Administrator. If another program, such as Apache or nginx, holds port 80 outside HTTP.sys, stop it during validation or use DNS validation.

<a id="ssl1029"></a>

### SSL1029: IIS URL Rewrite is not installed

The HTTPS redirect is an IIS URL Rewrite rule. Install the URL Rewrite module for IIS from Microsoft, then try again.

<a id="ssl1030"></a>

### SSL1030: Site has no HTTPS binding

Redirecting HTTP to HTTPS would send visitors nowhere. Give the site a certificate first.

<a id="ssl1031"></a>

### SSL1031: Redirect would block validation

After the rule was added, a validation path on the site was still redirected, so SSLense removed the rule. Check for another redirect rule or module on the site, or in its parent configuration.

## SSL2xxx: ACME and certificate authorities

<a id="ssl2001"></a>

### SSL2001: Production certificate authority not confirmed

Try the site with Let's Encrypt staging first, then confirm production in the app or with --accept-production-risk.

<a id="ssl2002"></a>

### SSL2002: Certificate authority not reachable

Check outbound HTTPS (port 443) from this server, DNS, any proxy, and TLS inspection.

<a id="ssl2003"></a>

### SSL2003: Unexpected challenges from the certificate authority

The certificate authority returned something SSLense did not ask for. Try again later; if it keeps happening, report it with the log.

<a id="ssl2004"></a>

### SSL2004: Unexpected authorization from the certificate authority

The certificate authority returned something SSLense did not ask for. Try again later; if it keeps happening, report it with the log.

<a id="ssl2005"></a>

### SSL2005: Profile not offered

Choose one of the profiles the certificate authority lists, or leave the profile empty.

<a id="ssl2006"></a>

### SSL2006: HTTP validation not offered

The certificate authority does not allow HTTP validation for this name, for example for a wildcard. Use DNS validation.

<a id="ssl2007"></a>

### SSL2007: DNS validation not offered

The certificate authority does not allow DNS validation for this name. Use HTTP validation.

<a id="ssl2008"></a>

### SSL2008: External Account Binding key cannot be read

The key was saved on another server or by another account. Remove the certificate authority and add it again with its EAB credentials.

<a id="ssl2009"></a>

### SSL2009: Validation failed

The certificate authority could not confirm control of the name. The message gives its reason; for HTTP validation check port 80 and DNS, for DNS validation check the TXT record.

<a id="ssl2010"></a>

### SSL2010: Certificate not issued

The order did not complete. The message gives its state; try again later, and check the certificate authority's status page.

<a id="ssl2011"></a>

### SSL2011: ACME directory answered with an error

Check the directory address of the certificate authority.

<a id="ssl2012"></a>

### SSL2012: ACME directory not reachable

Check the address, outbound HTTPS, DNS and any proxy.

<a id="ssl2013"></a>

### SSL2013: ACME directory did not answer in time

Check the address, outbound HTTPS and any proxy, then try again.

<a id="ssl2014"></a>

### SSL2014: Not an ACME directory

The address answered, but not with an ACME directory. Check that it is the directory URL the certificate authority documents.

<a id="ssl2015"></a>

### SSL2015: Certificate authority not configured

Add the certificate authority under Settings › Certificate authorities, or with 'SSLense.Cli ca add'.

<a id="ssl2016"></a>

### SSL2016: Certificate authority already exists

Remove the existing one first, or choose another ID.

<a id="ssl2017"></a>

### SSL2017: External Account Binding now required

The certificate authority now asks for EAB credentials. Remove it and add it again with them.

<a id="ssl2018"></a>

### SSL2018: Built-in certificate authority

Let's Encrypt is built in and cannot be removed.

<a id="ssl2019"></a>

### SSL2019: Certificate authority in use

Move the listed certificates to another certificate authority first, or remove them.

<a id="ssl2020"></a>

### SSL2020: Certificate authority busy

Another SSLense operation is using or changing this certificate authority. Try again in a few minutes.

<a id="ssl2021"></a>

### SSL2021: Key cannot be reused

The current key is neither RSA nor ECDSA. Turn key reuse off for this certificate.

<a id="ssl2022"></a>

### SSL2022: Site already has a valid certificate

Tick 'Replace the current certificate even if it is still valid', or use --force, to replace it.

<a id="ssl2023"></a>

### SSL2023: Host name not covered by the certificate names

Add the host name, or a wildcard that covers it, to the certificate names, or leave the host name out.

<a id="ssl2024"></a>

### SSL2024: No host names

Select at least one host name, or add a named binding to the site in IIS Manager.

<a id="ssl2025"></a>

### SSL2025: Rate limit reached

The certificate authority's limit for this account or these names was reached. SSLense waits and tries again at a later scheduled check; retrying sooner only extends the limit.

<a id="ssl2026"></a>

### SSL2026: Validation took too long

The certificate authority did not finish checking in time. Try again; if it repeats, check port 80 or the DNS record from outside your network.

<a id="ssl2027"></a>

### SSL2027: Certificate authority details not valid

Check the preset, name, ID, directory URL and CAA domain; the message says which one.

<a id="ssl2028"></a>

### SSL2028: External Account Binding details missing

Enter both the EAB key ID and the HMAC key from your account at the certificate authority.

<a id="ssl2029"></a>

### SSL2029: EAB HMAC key not valid

Copy the HMAC key again from the certificate authority's account page; it is Base64url text.

<a id="ssl2030"></a>

### SSL2030: Revocation failed

The certificate authority did not revoke the certificate; the message gives its reason. If SSLense already replaced it, the old certificate was saved so you can try again with 'SSLense.Cli revoke --file <path> --ca <id>'.

<a id="ssl2031"></a>

### SSL2031: No ACME account for the certificate authority

SSLense has not created an account with this certificate authority yet; it creates one with the first certificate. There is no key to replace.

## SSL3xxx: DNS validation

<a id="ssl3001"></a>

### SSL3001: DNS validation not available

This SSLense process cannot use DNS validation. Use the app or the CLI on the server, or HTTP validation.

<a id="ssl3002"></a>

### SSL3002: Too many names for one acme-dns account

An acme-dns account keeps two values: a name and its wildcard. Split the names across certificates, or add another acme-dns account.

<a id="ssl3003"></a>

### SSL3003: No public name servers

A public certificate authority can only validate names in public DNS. Check the domain is registered and delegated, or use an internal certificate authority.

<a id="ssl3004"></a>

### SSL3004: DNS record not visible yet

The TXT record was not seen at every authoritative name server in time. Check the record at your DNS host, and try again in a few minutes.

<a id="ssl3005"></a>

### SSL3005: Manual DNS records not confirmed

Nothing was ordered. Create the TXT records shown and confirm, or cancel.

<a id="ssl3006"></a>

### SSL3006: acme-dns CNAME missing

Create the CNAME record shown at your DNS host, wait for it to appear, then try again.

<a id="ssl3007"></a>

### SSL3007: No DNS provider for the name

Add a DNS provider for the zone under Settings › DNS providers, delegate the record with a CNAME, or use manual DNS.

<a id="ssl3008"></a>

### SSL3008: DNS provider type not supported

The provider was added by a newer SSLense version. Update SSLense, or remove the provider and add it again.

<a id="ssl3009"></a>

### SSL3009: Too many CNAME steps

Check the CNAME records for the name at your DNS host: they form a loop or a chain longer than SSLense follows.

<a id="ssl3010"></a>

### SSL3010: DNS provider name already used

Remove the existing provider first, or choose another name.

<a id="ssl3011"></a>

### SSL3011: DNS provider for the zone already exists

Remove the existing provider for the zone first to replace it.

<a id="ssl3012"></a>

### SSL3012: DNS provider added at the same time

Another SSLense window or command added the same provider. Refresh and check the list.

<a id="ssl3013"></a>

### SSL3013: acme-dns not available here

Use the app or the CLI on the server to set up acme-dns.

<a id="ssl3014"></a>

### SSL3014: acme-dns account already used

The account is already set up as another provider. Remove that one first.

<a id="ssl3015"></a>

### SSL3015: acme-dns already set up for the domain

Remove the existing acme-dns account for the domain first to replace it.

<a id="ssl3016"></a>

### SSL3016: Script test record not seen

The script said it added the TXT record, but this server could not see it. Check what the script does, and the record at your DNS host.

<a id="ssl3017"></a>

### SSL3017: acme-dns account busy

A certificate is being validated through this account right now. Test again in a few minutes.

<a id="ssl3018"></a>

### SSL3018: This server cannot query DNS

Allow outbound DNS (UDP and TCP port 53) from this server, so SSLense can confirm records before ordering.

<a id="ssl3019"></a>

### SSL3019: DNS provider does not use a script

Only script providers have a script to update.

<a id="ssl3020"></a>

### SSL3020: Script replaced at the same time

Another update replaced the script while this one was checked. Check the script, then update it again if needed.

<a id="ssl3021"></a>

### SSL3021: DNS provider in use

Move the listed certificates to another validation method first, or remove them.

<a id="ssl3022"></a>

### SSL3022: DNS provider not found

Check the name under Settings › DNS providers, or with 'SSLense.Cli dns list'.

<a id="ssl3023"></a>

### SSL3023: DNS provider removed at the same time

Another SSLense window or command removed the provider. Refresh and check the list.

<a id="ssl3024"></a>

### SSL3024: Script folder is a link

SSLense will not use a link or junction for scripts. Remove it and let SSLense create the folder again.

<a id="ssl3025"></a>

### SSL3025: Script not run

SSLense runs only its own checked copy of a script. The message says what is wrong; update the script with 'SSLense.Cli dns update-script' or in Settings.

<a id="ssl3026"></a>

### SSL3026: DNS provider has no script

Remove the provider and add it again with its script.

<a id="ssl3027"></a>

### SSL3027: DNS script failed

The script ended with an error; its last output is in the message. Run it by hand with the same action to see why.

<a id="ssl3028"></a>

### SSL3028: DNS provider secret cannot be read

The secret was saved on another server or by another account. Replace it with 'SSLense.Cli dns update-token' or in Settings.

<a id="ssl3029"></a>

### SSL3029: Cloudflare zone not found

Check that the token can read the zone, and that the zone name matches the domain on Cloudflare.

<a id="ssl3030"></a>

### SSL3030: Cloudflare refused the request

The message gives Cloudflare's answer. Check the token's permissions (Zone › DNS › Edit) and that it has not expired.

<a id="ssl3031"></a>

### SSL3031: acme-dns account cannot set this name

Each acme-dns account sets one name. Use the account set up for this domain, or add one.

<a id="ssl3032"></a>

### SSL3032: acme-dns server returned no account

Check that the address is an acme-dns server.

<a id="ssl3033"></a>

### SSL3033: acme-dns server not reachable

Check the address, outbound HTTPS and any proxy.

<a id="ssl3034"></a>

### SSL3034: acme-dns server did not answer in time

Check the address, outbound HTTPS and any proxy, then try again.

<a id="ssl3035"></a>

### SSL3035: acme-dns server refused the request

The message gives the server's answer. Check the account's credentials and its allowed networks.

<a id="ssl3036"></a>

### SSL3036: DNS provider details not valid

Check the name, zone, token, script or acme-dns details; the message says which one.

<a id="ssl3037"></a>

### SSL3037: Unexpected input for a DNS script

SSLense refused to pass an unexpected zone, record name or value to the script. Report it with the log.

<a id="ssl3038"></a>

### SSL3038: Host name does not resolve

Add an A or AAAA record for the host name at your DNS host.

<a id="ssl3039"></a>

### SSL3039: The DNS service refused the request

The message gives the service's answer. Check the credentials and that they may change records in this zone: for Route 53 the IAM policy (route53:ChangeResourceRecordSets, ListResourceRecordSets, GetHostedZone), for Azure the DNS Zone Contributor role, for Google the DNS Administrator role, and that the zone ID is right.

## SSL4xxx: Certificates: import, requests, the Windows store, keys and sharing

<a id="ssl4001"></a>

### SSL4001: Certificate served on another port

SSLense manages HTTPS bindings on port 443. Watch it by its port-443 binding, or move the binding to port 443.

<a id="ssl4002"></a>

### SSL4002: No certificate to watch

The site has no HTTPS binding with a certificate. Add one in IIS Manager, or issue a certificate instead.

<a id="ssl4003"></a>

### SSL4003: Site uses several certificates

Choose the certificate to watch: tick its binding in the app, or give --thumbprint.

<a id="ssl4004"></a>

### SSL4004: Bound certificate missing from the store

IIS points to a certificate that is not in LocalMachine\My. Install it again, or bind another certificate.

<a id="ssl4005"></a>

### SSL4005: Certificate has no private key

A certificate needs its private key on this server to be served. Import the PFX that includes the key.

<a id="ssl4006"></a>

### SSL4006: HTTPS bindings without host names

SSLense manages SNI bindings by host name. Add a host name to the binding in IIS Manager.

<a id="ssl4007"></a>

### SSL4007: Host names already managed

These host names are managed as another certificate on the site. Select that certificate instead.

<a id="ssl4008"></a>

### SSL4008: No pending certificate request

Create a request first ('csr', or Add certificate › I bought it and the provider needs a request), or import a PFX.

<a id="ssl4009"></a>

### SSL4009: Request's private key is gone

The key for this request no longer exists on this server. Create a new request and send it to the provider again.

<a id="ssl4010"></a>

### SSL4010: Certificate does not match the request

None of the certificates in the file was issued for this server's request. Check you downloaded the right certificate.

<a id="ssl4011"></a>

### SSL4011: Request key type not supported

Create a new request with an RSA or ECDSA key.

<a id="ssl4012"></a>

### SSL4012: PFX does not hold one certificate with its key

Export the PFX again with the certificate and its private key.

<a id="ssl4013"></a>

### SSL4013: Certificate covers none of the site's host names

Check you chose the right site and file, or add a binding for a name the certificate covers.

<a id="ssl4014"></a>

### SSL4014: Certificate renews automatically

Importing replaces a certificate SSLense renews automatically, and stops that. Confirm with --replace-automatic if that is what you want.

<a id="ssl4015"></a>

### SSL4015: Certificate already installed

This certificate is already installed and bound. Nothing needs to change.

<a id="ssl4016"></a>

### SSL4016: Certificate not installed

The certificate failed a check before anything changed. The message lists the problems: names, dates, purpose, key or chain.

<a id="ssl4017"></a>

### SSL4017: Site shares its certificate

A site that shares a certificate with other sites has only that one. Add the host names to the shared certificate, or stop sharing first.

<a id="ssl4018"></a>

### SSL4018: Several pending requests on the site

Choose the request by its certificate name, such as --site "Main/www.example.com".

<a id="ssl4019"></a>

### SSL4019: Certificate could not be added to the store

Run SSLense as Administrator, and check that LocalMachine\My is not full or locked by policy.

<a id="ssl4020"></a>

### SSL4020: PFX could not be imported

Check the password, and run SSLense as Administrator.

<a id="ssl4021"></a>

### SSL4021: Certificate not linked to its key

The certificate was added without its private key. Import it again from the PFX or complete the request again.

<a id="ssl4022"></a>

### SSL4022: Shared certificate missing from the store

Renew the certificate first, then share it.

<a id="ssl4023"></a>

### SSL4023: Shared certificate has no private key

Renew the certificate first, then share it.

<a id="ssl4024"></a>

### SSL4024: Shared certificate not valid now

Renew the certificate first, then share it.

<a id="ssl4025"></a>

### SSL4025: Certificate not shared

To stop managing it, use Remove or 'SSLense.Cli remove'.

<a id="ssl4026"></a>

### SSL4026: Certificate cannot be shared to a site with several certificates

A site that has several certificates of its own cannot also take a shared one. Issue a certificate for the host names instead, or share a certificate from that site to another.

<a id="ssl4027"></a>

### SSL4027: Only SSLense's own certificates can be shared

Issue a certificate with SSLense for the sites instead.

<a id="ssl4028"></a>

### SSL4028: Sharing needs DNS validation

Issue the certificate again with DNS validation, then share it.

<a id="ssl4029"></a>

### SSL4029: Site already uses this certificate

Nothing needs to change.

<a id="ssl4030"></a>

### SSL4030: Site has its own shared certificate

Stop sharing that one first with 'share remove'.

<a id="ssl4031"></a>

### SSL4031: Site has its own certificate

Add --replace to give the site the shared certificate instead.

<a id="ssl4032"></a>

### SSL4032: No bindings the certificate covers

Add a binding for a name the certificate covers, or name the host names to use.

<a id="ssl4033"></a>

### SSL4033: Certificate does not cover the host name

Choose host names the certificate covers, or issue it again with the name.

<a id="ssl4034"></a>

### SSL4034: Host name bound on another site

The host name already has an HTTPS binding on another IIS site. Remove that binding first.

<a id="ssl4035"></a>

### SSL4035: A sharing site has a problem

The message names the site and its problem. Fix it, or stop sharing with that site.

<a id="ssl4036"></a>

### SSL4036: No site can use the certificate

Every sharing site has a problem, so nothing was ordered. Fix them, then try again.

<a id="ssl4037"></a>

### SSL4037: Wildcard already in another certificate on the site

Add the host names to the certificate that has the wildcard.

<a id="ssl4038"></a>

### SSL4038: Wildcard already managed for another site

Share that certificate with this site instead of issuing a copy.

<a id="ssl4039"></a>

### SSL4039: Site uses another site's certificate

Use 'share remove' to stop managing only this site.

<a id="ssl4040"></a>

### SSL4040: Site shares its certificate

A certificate you import or request cannot replace one shared with other sites. Stop sharing first.

<a id="ssl4041"></a>

### SSL4041: Not a certificate file

Choose a PEM (.crt, .pem) or DER (.cer) certificate. Export a .p7b or .pfx as a Base-64 .cer first.

<a id="ssl4042"></a>

### SSL4042: Shared certificate needs attention

A site sharing the certificate has a problem or was left on its previous certificate. The message names the site; fix it, or stop sharing with it.

<a id="ssl4043"></a>

### SSL4043: Host covered by the wildcard but not managed

The site has a binding the wildcard covers, but SSLense does not manage it, so it keeps its old certificate. Add the host name to the certificate, or remove the binding.

<a id="ssl4044"></a>

### SSL4044: A sharing site no longer exists

Stop sharing with it: 'SSLense.Cli share remove --site <site>'.

<a id="ssl4045"></a>

### SSL4045: Certificate chain incomplete

An intermediate certificate is missing or expired, so some visitors may not trust the site. Install the certificate again with its full chain.

<a id="ssl4046"></a>

### SSL4046: Old pending requests

A certificate request has waited over 30 days. Complete it with the provider's certificate, or delete it.

<a id="ssl4049"></a>

### SSL4049: Certificate belongs to a pending request

The file is the certificate your provider issued for a request SSLense created; its key is already on this server. Use Install renewal, or Complete a request ('SSLense.Cli complete').

<a id="ssl4050"></a>

### SSL4050: Certificate without its private key

A certificate file without its key cannot be installed on its own. Import the PFX that holds both, or complete the request SSLense created.

<a id="ssl4051"></a>

### SSL4051: Bought certificates are revoked by the provider

Ask your provider to revoke it (most have a button for a compromised key), get a new certificate with a new key, and install it with Install renewal.

<a id="ssl4052"></a>

### SSL4052: Manual DNS certificate cannot be replaced automatically

Renew it by hand first (Renew by hand, with a new key), then revoke the old certificate: 'SSLense.Cli revoke --file <old certificate> --ca <id>'.

<a id="ssl4053"></a>

### SSL4053: Certificate on another machine could not be read

SSLense connects to the host and port to read the certificate it serves. Check the name or address, the port, and that this server can reach it through any firewall.

## SSL5xxx: Renewal, reminders and the service

<a id="ssl5001"></a>

### SSL5001: Operation record missing

An operation record disappeared while it was in use. Check the log, and run the health check.

<a id="ssl5002"></a>

### SSL5002: Renewed certificate has no thumbprint

Report this with the log; the previous certificate stays in place.

<a id="ssl5003"></a>

### SSL5003: Service installed but not started

The message gives Windows' reason. Check the Windows Event Log, then start the service from Settings › Service.

<a id="ssl5004"></a>

### SSL5004: Service not installed

Install SSLense with its installer, which adds the service.

<a id="ssl5005"></a>

### SSL5005: Service command failed

Run SSLense as Administrator.

<a id="ssl5006"></a>

### SSL5006: Service control could not start

Check that C:\Windows\System32\sc.exe exists and is not blocked by policy.

<a id="ssl5007"></a>

### SSL5007: Certificate changed while waiting

Another SSLense window, command or the service changed the certificate while this operation waited for it. Refresh, check the certificate, and try again.

<a id="ssl5008"></a>

### SSL5008: Setting out of range

Enter a value in the range the message gives.

<a id="ssl5009"></a>

### SSL5009: Choose all or one certificate

Give either --all or --site, not both or neither.

<a id="ssl5010"></a>

### SSL5010: Service program not found

Install SSLense with its installer, or give the path of SSLense.Service.exe.

<a id="ssl5011"></a>

### SSL5011: Reminders off for a certificate that expires soon

Turn its reminders back on, or renew it.

<a id="ssl5012"></a>

### SSL5012: Interrupted operations

An operation stopped part-way, for example at a restart. SSLense finishes or undoes it when the service starts; restart the service, then check again.

<a id="ssl5013"></a>

### SSL5013: Service stopped

Start the SSLense service under Settings › Service, or in services.msc.

<a id="ssl5014"></a>

### SSL5014: Service in an unusual state

Check the service in services.msc and the Windows Event Log.

<a id="ssl5015"></a>

### SSL5015: No renewal check recorded yet

The service records one an hour after it starts. Check that it is running.

<a id="ssl5016"></a>

### SSL5016: Renewal check overdue

The service has not completed a check recently. Check that it is running, and its log.

<a id="ssl5017"></a>

### SSL5017: Last renewal check reported a problem

The message gives the problem; check the log under Activity.

<a id="ssl5018"></a>

### SSL5018: Bought certificate expires soon

Order the renewal from your provider, then use Install renewal.

<a id="ssl5019"></a>

### SSL5019: Manual DNS certificate expires soon

Renew it by hand: select it and choose Renew by hand.

<a id="ssl5020"></a>

### SSL5020: Automatic certificate not renewed in time

Check the renewal history for the reason, fix it, and renew now.

<a id="ssl5021"></a>

### SSL5021: Renewals failing

The message gives the last error. Fix it; SSLense retries on its schedule.

<a id="ssl5022"></a>

### SSL5022: Maintenance window not valid

Choose at least one day, and hours from 0 to 23 with the end different from the start. An end earlier than the start means the next day, as 22 to 4.

## SSL6xxx: Settings, names and stored data

<a id="ssl6001"></a>

### SSL6001: Host names belong to several certificates

Choose the host names of one certificate on the site.

<a id="ssl6002"></a>

### SSL6002: Certificate name already used

The name is used by a certificate for other host names. Replace that certificate by its name, or choose the host names in another order.

<a id="ssl6003"></a>

### SSL6003: Host names already have a certificate

Each host name on a site has one certificate. Replace that certificate instead.

<a id="ssl6004"></a>

### SSL6004: Name is an IIS site

A certificate with no IIS site needs a name that is not a site's. Choose another name.

<a id="ssl6005"></a>

### SSL6005: Certificate already exists

Use --force to replace it now, or wait for it to renew.

<a id="ssl6006"></a>

### SSL6006: Name is a certificate with no IIS site

Renew it by its name, or remove it first to use the name for a site.

<a id="ssl6007"></a>

### SSL6007: Name contains '/'

A '/' names a second certificate on an IIS site. Choose a name without it.

<a id="ssl6008"></a>

### SSL6008: Data folder is a link

SSLense will not use a link or junction for its data folder. Replace it with a real folder.

<a id="ssl6009"></a>

### SSL6009: Access to SSLense's data denied

Run SSLense as Administrator.

<a id="ssl6010"></a>

### SSL6010: Not managed by SSLense

Check the name in the certificate list.

<a id="ssl6011"></a>

### SSL6011: Email address not valid

Enter a full email address, such as admin@example.com.

<a id="ssl6012"></a>

### SSL6012: Host name not valid

SSLense manages IIS bindings for real host names, such as www.example.com.

<a id="ssl6013"></a>

### SSL6013: No host names given

Select or enter at least one host name.

<a id="ssl6014"></a>

### SSL6014: Names missing for a certificate with no IIS site

Give the names the certificate covers, such as rdp.example.com.

<a id="ssl6015"></a>

### SSL6015: Certificate with no IIS site needs DNS validation

HTTP validation needs a site to serve the file, unless SSLense answers the challenge itself. Choose a DNS validation method, or HTTP answered by SSLense.

<a id="ssl6016"></a>

### SSL6016: Name not allowed

Use letters, digits, spaces, dots, hyphens, underscores and brackets, up to 100 characters.

<a id="ssl6018"></a>

### SSL6018: Certificate names need DNS validation

Wildcards and extra names need DNS validation. With HTTP validation the certificate covers the host names.

<a id="ssl6019"></a>

### SSL6019: Certificate names not valid

Check each name; a wildcard covers one level, as in *.example.com, and a name already covered by a wildcard in the same certificate is not needed.

<a id="ssl6020"></a>

### SSL6020: Unknown key type

Use one of the key types listed in the message.

<a id="ssl6021"></a>

### SSL6021: ACME account key damaged

The saved account key cannot be read. Restore SSLense's data folder from a backup, or remove the account file so SSLense creates a new account (existing certificates keep working).

<a id="ssl6022"></a>

### SSL6022: Data file damaged

One of SSLense's data files is empty or not valid JSON. SSLense keeps a backup next to it (.bak); restore it, or restore the data folder from a backup.

<a id="ssl6023"></a>

### SSL6023: Data from a newer SSLense

The data folder was written by a newer SSLense version. Install that version or newer again.

<a id="ssl6024"></a>

### SSL6024: Secret cannot be read

SSLense's secrets are encrypted for this server. A data folder copied from another server needs its passwords, tokens and keys entered again.

<a id="ssl6025"></a>

### SSL6025: Configuration could not be read

Run SSLense as Administrator. If it persists, check config.json in the data folder.

<a id="ssl6026"></a>

### SSL6026: Data folder permissions not safe

SSLense's data folder should be limited to Administrators and SYSTEM. Run SSLense as Administrator once to restore them, or reinstall.

<a id="ssl6027"></a>

### SSL6027: IP address certificates need HTTP answered by SSLense

A certificate authority validates an IP address over HTTP (or TLS-ALPN), not DNS. Choose HTTP validation with SSLense answering the challenge itself (--validation http-self); Let's Encrypt also needs a short-lived profile, such as --profile shortlived.

<a id="ssl6028"></a>

### SSL6028: Name already used

A certificate on another machine needs a name that no other certificate or IIS site has.

## SSL7xxx: Notifications

<a id="ssl7001"></a>

### SSL7001: Chat message rejected

The chat service refused the message. Check the webhook URL still exists, and send a test.

<a id="ssl7002"></a>

### SSL7002: SMTP username missing

Enter the username for password sign-in, or choose no sign-in for a relay.

<a id="ssl7003"></a>

### SSL7003: SMTP password missing

Enter the password in the email settings.

<a id="ssl7004"></a>

### SSL7004: Email could not be sent

The message gives the mail server's answer. Check the server, port, security and sign-in, then send a test.

<a id="ssl7005"></a>

### SSL7005: No notification channels

Add an email or chat channel, or turn the Event Log back on, under Settings › Notifications.

<a id="ssl7006"></a>

### SSL7006: Heartbeat ping failed

Check the heartbeat check still exists at the monitoring service.

<a id="ssl7007"></a>

### SSL7007: Notification secret damaged

Enter the channel's URL or password again under Settings › Notifications.

<a id="ssl7008"></a>

### SSL7008: Notification settings not valid

Check the URL, port, recipients and sign-in; the message says which one.

<a id="ssl7009"></a>

### SSL7009: Only the Event Log is notified

Add an email or chat channel, or make sure the Windows Event Log is monitored.

## SSL8xxx: Deployment steps

<a id="ssl8001"></a>

### SSL8001: Key type cannot be exported

The key is neither RSA nor ECDSA. Issue the certificate again with a supported key type.

<a id="ssl8002"></a>

### SSL8002: Certificate not in the store

Renew or install the certificate again.

<a id="ssl8003"></a>

### SSL8003: No private key to export

Install the certificate again with its private key.

<a id="ssl8004"></a>

### SSL8004: Export failed

Run SSLense as Administrator, and check the destination folder.

<a id="ssl8005"></a>

### SSL8005: Private key not exportable

Issue the certificate again with an exportable key to write it to files.

<a id="ssl8006"></a>

### SSL8006: Too many deployment steps

Remove a step first.

<a id="ssl8007"></a>

### SSL8007: Certificate removed at the same time

Another SSLense window or command removed the certificate. Refresh the list.

<a id="ssl8008"></a>

### SSL8008: No deployment steps

Add a step under After install on the certificate, or with 'deploy add'.

<a id="ssl8009"></a>

### SSL8009: Unknown deployment step

The step was added by a newer SSLense version. Update SSLense, or remove the step.

<a id="ssl8010"></a>

### SSL8010: Passwords cannot be stored

Use the app or the CLI on the server.

<a id="ssl8011"></a>

### SSL8011: Export not available here

Use the app or the CLI on the server.

<a id="ssl8012"></a>

### SSL8012: Step has no password

Remove the step and add it again.

<a id="ssl8013"></a>

### SSL8013: Step password cannot be read

The password was saved on another server or by another account. Remove the step and add it again.

<a id="ssl8014"></a>

### SSL8014: Step has no script

Remove the step and add it again.

<a id="ssl8015"></a>

### SSL8015: Deployment script failed

The script ended with an error; its last output is in the message. Run it by hand to see why.

<a id="ssl8016"></a>

### SSL8016: Private key file not found

The key is not in a file SSLense can change access to. Install the certificate again, or give access in certlm.msc.

<a id="ssl8017"></a>

### SSL8017: Private key file is a link

SSLense will not change access through a link. Check the machine key folder.

<a id="ssl8018"></a>

### SSL8018: Certificate has no private key

Install the certificate again with its private key.

<a id="ssl8019"></a>

### SSL8019: Private key location unknown

Give access in certlm.msc › Manage Private Keys instead.

<a id="ssl8020"></a>

### SSL8020: Service did not stop

The message gives Windows' reason. Stop it by hand and check the Windows Event Log.

<a id="ssl8021"></a>

### SSL8021: Service did not start

The message gives Windows' reason. Start it by hand and check the Windows Event Log.

<a id="ssl8022"></a>

### SSL8022: Service stopped again after starting

Check the Windows Event Log for the reason; the service may not accept the new certificate.

<a id="ssl8023"></a>

### SSL8023: Service did not respond in time

Check the service in services.msc and the Windows Event Log.

<a id="ssl8024"></a>

### SSL8024: Deployment step details not valid

Check the step's path, password and timeout; the message says which one.

<a id="ssl8025"></a>

### SSL8025: No such Windows service

Use the service's name as 'sc.exe query' or the Services console shows it, such as MSSQLSERVER or TermService.

<a id="ssl8026"></a>

### SSL8026: SSLense cannot restart itself

Choose another service.

<a id="ssl8027"></a>

### SSL8027: No such deployment step

Check the step numbers under After install on the certificate, or with 'deploy list'.

<a id="ssl8028"></a>

### SSL8028: Windows account not found

Check the name, such as 'IIS AppPool\Shop' or 'NT SERVICE\MSSQLSERVER'.

<a id="ssl8029"></a>

### SSL8029: Certificate with no IIS site has no deployment steps

Add a step under After install so a renewal reaches the service that uses the certificate.

<a id="ssl8030"></a>

### SSL8030: Deployment steps have not succeeded

The message gives the last error; SSLense retries hourly and keeps the previous certificate meanwhile. Fix the cause, or run the steps again.

## SSL9xxx: Health check, diagnostics and unexpected errors

<a id="ssl9001"></a>

### SSL9001: Check not available

Use the app or the CLI on the server.

<a id="ssl9002"></a>

### SSL9002: Log lock not available

Run SSLense as Administrator.

<a id="ssl9003"></a>

### SSL9003: No log file yet

SSLense writes the log once it does something. Try again after an operation.

<a id="ssl9004"></a>

### SSL9004: Not an SSLense log file

Choose a file from SSLense's log folder.

<a id="ssl9005"></a>

### SSL9005: Log busy

Another SSLense process is writing to the log. Try again in a moment.

<a id="ssl9006"></a>

### SSL9006: Not running as Administrator

Start SSLense with 'Run as administrator'.

<a id="ssl9999"></a>

### SSL9999: Unexpected error

SSLense did not expect this error. The original message follows the code. Run the health check, and report it with a diagnostic bundle ('SSLense.Cli diagnostics') if it happens again.
