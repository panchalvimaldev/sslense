namespace SSLense.Core.Errors;

/// <summary>
/// Every error code SSLense issues (docs/design/error-codes.md). Codes are added, never renumbered or reused; the
/// tests keep the list of every code ever issued, and docs/errors.md is generated from this catalogue.
/// </summary>
public static class ErrorCodes
{
    public static readonly ErrorCode IisSiteNotFound = new("SSL1001", nameof(IisSiteNotFound), "IIS site not found",
        "Check the site name with 'SSLense.Cli list-sites' or in IIS Manager. A site renamed or deleted in IIS must be managed again under its new name.");

    public static readonly ErrorCode IisSiteNoPhysicalPath = new("SSL1002", nameof(IisSiteNoPhysicalPath), "IIS site has no physical path",
        "HTTP validation writes the challenge file into the site's folder. Set the site's physical path in IIS Manager, or use DNS validation.");

    public static readonly ErrorCode HostHasNoBinding = new("SSL1003", nameof(HostHasNoBinding), "Host name has no suitable binding",
        "Add an HTTP binding on port 80 for the host name in IIS Manager (HTTP validation), or an HTTP or HTTPS binding (DNS validation), then try again.");

    public static readonly ErrorCode IisConfigurationUnreadable = new("SSL1004", nameof(IisConfigurationUnreadable), "IIS configuration could not be read",
        "Run SSLense as Administrator. If it still fails, check that IIS is installed and its configuration files are not locked or damaged.");

    public static readonly ErrorCode IisManagementMissing = new("SSL1005", nameof(IisManagementMissing), "IIS management components are missing",
        "Install 'IIS Management Scripts and Tools' (Server Manager, Web Server role), then start SSLense again.");

    public static readonly ErrorCode NetshUnavailable = new("SSL1006", nameof(NetshUnavailable), "netsh could not be started",
        "SSLense uses netsh to manage certificate bindings. Check that C:\\Windows\\System32\\netsh.exe exists and is not blocked by policy.");

    public static readonly ErrorCode HttpsBindingNotFound = new("SSL1007", nameof(HttpsBindingNotFound), "HTTPS binding missing after it was set",
        "IIS did not keep the binding. The previous binding is restored. Check for another tool or script changing bindings at the same time, then try again.");

    public static readonly ErrorCode HttpsBindingNotRetained = new("SSL1008", nameof(HttpsBindingNotRetained), "IIS did not keep the certificate on the binding",
        "The previous binding is restored. Check for another tool changing bindings, and that the certificate is in LocalMachine\\My with its private key.");

    public static readonly ErrorCode HttpsBindingChangeFailed = new("SSL1009", nameof(HttpsBindingChangeFailed), "HTTPS binding could not be changed",
        "The message says what failed and whether the previous binding was restored. Run SSLense as Administrator and check the log under Activity.");

    public static readonly ErrorCode HttpsBindingUsesOtherCertificate = new("SSL1010", nameof(HttpsBindingUsesOtherCertificate), "Binding uses another certificate",
        "The binding was changed to another certificate outside SSLense, so it was left alone. Remove it in IIS Manager if it is no longer needed.");

    public static readonly ErrorCode HttpsBindingRemovalUnverified = new("SSL1011", nameof(HttpsBindingRemovalUnverified), "Binding removal could not be confirmed",
        "The certificate was kept in the store to be safe. Check the site's bindings in IIS Manager, then remove the certificate if nothing uses it.");

    public static readonly ErrorCode HttpsBindingRemovalFailed = new("SSL1012", nameof(HttpsBindingRemovalFailed), "Bindings could not be removed",
        "Run SSLense as Administrator and try again.");

    public static readonly ErrorCode HttpsCertificateNotServed = new("SSL1013", nameof(HttpsCertificateNotServed), "The site does not serve the new certificate",
        "SSLense connected over HTTPS and got another certificate, so it restored the previous binding. Check for a load balancer, proxy or CDN in front of the server, or another binding on the same IP and port.");

    public static readonly ErrorCode PreviousBindingGone = new("SSL1014", nameof(PreviousBindingGone), "Previous binding no longer exists",
        "The binding was removed while SSLense was changing it. Check the site's bindings in IIS Manager and add the HTTPS binding again if needed.");

    public static readonly ErrorCode NoCertificateServed = new("SSL1015", nameof(NoCertificateServed), "No certificate was served",
        "Nothing answered with a certificate on that host name and port. Check that the site is started and has an HTTPS binding for the host name.");

    public static readonly ErrorCode ChallengeSelfCheckUnreachable = new("SSL1016", nameof(ChallengeSelfCheckUnreachable), "Site not reachable on port 80",
        "SSLense could not reach the host name on port 80 from this server. Check the DNS record, the firewall, and that the site is started. Behind NAT, check that the server can reach its own public address, or use DNS validation.");

    public static readonly ErrorCode ChallengeSelfCheckStatus = new("SSL1017", nameof(ChallengeSelfCheckStatus), "Challenge file not served",
        "The site answered with an error for the challenge file. Check for a rule that redirects or blocks /.well-known/acme-challenge/, authentication on the site, or a missing static file handler.");

    public static readonly ErrorCode ChallengeSelfCheckContent = new("SSL1018", nameof(ChallengeSelfCheckContent), "Challenge file served with the wrong content",
        "Another server or a rewrite rule answered instead of this site. Check DNS, proxies and URL Rewrite rules for the host name.");

    public static readonly ErrorCode BindingsNotRestored = new("SSL1019", nameof(BindingsNotRestored), "Previous bindings not fully restored",
        "A binding change failed and SSLense could not confirm every previous binding was put back. Check the named sites in IIS Manager now: a site may be serving the wrong certificate or none.");

    public static readonly ErrorCode IisBindingUnreadable = new("SSL1020", nameof(IisBindingUnreadable), "IIS returned a binding SSLense cannot read",
        "Check the site's bindings in IIS Manager for a malformed entry.");

    public static readonly ErrorCode NetshTimeout = new("SSL1021", nameof(NetshTimeout), "netsh did not finish in time",
        "Try again; if it repeats, restart the HTTP service or the server.");

    public static readonly ErrorCode ChallengeSelfCheckTimeout = new("SSL1022", nameof(ChallengeSelfCheckTimeout), "Site did not answer on port 80 in time",
        "Check the firewall and that the site is started. Behind NAT, check that the server can reach its own public address, or use DNS validation.");

    public static readonly ErrorCode BindingMissing = new("SSL1023", nameof(BindingMissing), "HTTPS binding missing",
        "A host name has no HTTPS binding with the managed certificate. Renew the certificate to bind it again, or check the bindings in IIS Manager.");

    public static readonly ErrorCode ServedCertificateMismatch = new("SSL1024", nameof(ServedCertificateMismatch), "Site serves another certificate",
        "The site does not serve the certificate SSLense installed. Check for a binding changed outside SSLense, another binding on the same IP and port, or a proxy in front of the server.");

    public static readonly ErrorCode ServedHostUnreachable = new("SSL1025", nameof(ServedHostUnreachable), "Host did not answer on port 443",
        "The daily check could not connect to the host name from this server. Check the site is started and the firewall, and DNS for the name on this server.");

    public static readonly ErrorCode ChallengeFolderNotWritable = new("SSL1026", nameof(ChallengeFolderNotWritable), "Challenge folder not writable",
        "SSLense could not write to the site's .well-known\\acme-challenge folder. Run SSLense as Administrator, and check the site's physical path and its permissions.");

    public static readonly ErrorCode ServedCertificateExpired = new("SSL1027", nameof(ServedCertificateExpired), "Site serves an expired certificate",
        "The site serves the certificate SSLense expects, but it has expired. Renew it now.");

    public static readonly ErrorCode SelfHostedPortUnavailable = new("SSL1028", nameof(SelfHostedPortUnavailable), "SSLense cannot answer on port 80",
        "SSLense answers the challenge through HTTP.sys, which IIS also uses. Run SSLense as Administrator. If another program, such as Apache or nginx, holds port 80 outside HTTP.sys, stop it during validation or use DNS validation.");

    public static readonly ErrorCode UrlRewriteMissing = new("SSL1029", nameof(UrlRewriteMissing), "IIS URL Rewrite is not installed",
        "The HTTPS redirect is an IIS URL Rewrite rule. Install the URL Rewrite module for IIS from Microsoft, then try again.");

    public static readonly ErrorCode RedirectNeedsHttps = new("SSL1030", nameof(RedirectNeedsHttps), "Site has no HTTPS binding",
        "Redirecting HTTP to HTTPS would send visitors nowhere. Give the site a certificate first.");

    public static readonly ErrorCode RedirectBlocksValidation = new("SSL1031", nameof(RedirectBlocksValidation), "Redirect would block validation",
        "After the rule was added, a validation path on the site was still redirected, so SSLense removed the rule. Check for another redirect rule or module on the site, or in its parent configuration.");

    public static readonly ErrorCode ProductionNotConfirmed = new("SSL2001", nameof(ProductionNotConfirmed), "Production certificate authority not confirmed",
        "Try the site with Let's Encrypt staging first, then confirm production in the app or with --accept-production-risk.");

    public static readonly ErrorCode CertificateAuthorityUnreachable = new("SSL2002", nameof(CertificateAuthorityUnreachable), "Certificate authority not reachable",
        "Check outbound HTTPS (port 443) from this server, DNS, any proxy, and TLS inspection.");

    public static readonly ErrorCode AcmeUnexpectedChallenges = new("SSL2003", nameof(AcmeUnexpectedChallenges), "Unexpected challenges from the certificate authority",
        "The certificate authority returned something SSLense did not ask for. Try again later; if it keeps happening, report it with the log.");

    public static readonly ErrorCode AcmeUnexpectedAuthorization = new("SSL2004", nameof(AcmeUnexpectedAuthorization), "Unexpected authorization from the certificate authority",
        "The certificate authority returned something SSLense did not ask for. Try again later; if it keeps happening, report it with the log.");

    public static readonly ErrorCode ProfileNotOffered = new("SSL2005", nameof(ProfileNotOffered), "Profile not offered",
        "Choose one of the profiles the certificate authority lists, or leave the profile empty.");

    public static readonly ErrorCode Http01NotOffered = new("SSL2006", nameof(Http01NotOffered), "HTTP validation not offered",
        "The certificate authority does not allow HTTP validation for this name, for example for a wildcard. Use DNS validation.");

    public static readonly ErrorCode Dns01NotOffered = new("SSL2007", nameof(Dns01NotOffered), "DNS validation not offered",
        "The certificate authority does not allow DNS validation for this name. Use HTTP validation.");

    public static readonly ErrorCode EabKeyUnreadable = new("SSL2008", nameof(EabKeyUnreadable), "External Account Binding key cannot be read",
        "The key was saved on another server or by another account. Remove the certificate authority and add it again with its EAB credentials.");

    public static readonly ErrorCode AcmeValidationFailed = new("SSL2009", nameof(AcmeValidationFailed), "Validation failed",
        "The certificate authority could not confirm control of the name. The message gives its reason; for HTTP validation check port 80 and DNS, for DNS validation check the TXT record.");

    public static readonly ErrorCode AcmeOrderNotIssued = new("SSL2010", nameof(AcmeOrderNotIssued), "Certificate not issued",
        "The order did not complete. The message gives its state; try again later, and check the certificate authority's status page.");

    public static readonly ErrorCode AcmeDirectoryHttpError = new("SSL2011", nameof(AcmeDirectoryHttpError), "ACME directory answered with an error",
        "Check the directory address of the certificate authority.");

    public static readonly ErrorCode AcmeDirectoryUnreachable = new("SSL2012", nameof(AcmeDirectoryUnreachable), "ACME directory not reachable",
        "Check the address, outbound HTTPS, DNS and any proxy.");

    public static readonly ErrorCode AcmeDirectoryTimeout = new("SSL2013", nameof(AcmeDirectoryTimeout), "ACME directory did not answer in time",
        "Check the address, outbound HTTPS and any proxy, then try again.");

    public static readonly ErrorCode NotAnAcmeDirectory = new("SSL2014", nameof(NotAnAcmeDirectory), "Not an ACME directory",
        "The address answered, but not with an ACME directory. Check that it is the directory URL the certificate authority documents.");

    public static readonly ErrorCode CertificateAuthorityNotConfigured = new("SSL2015", nameof(CertificateAuthorityNotConfigured), "Certificate authority not configured",
        "Add the certificate authority under Settings › Certificate authorities, or with 'SSLense.Cli ca add'.");

    public static readonly ErrorCode CertificateAuthorityExists = new("SSL2016", nameof(CertificateAuthorityExists), "Certificate authority already exists",
        "Remove the existing one first, or choose another ID.");

    public static readonly ErrorCode EabNowRequired = new("SSL2017", nameof(EabNowRequired), "External Account Binding now required",
        "The certificate authority now asks for EAB credentials. Remove it and add it again with them.");

    public static readonly ErrorCode CertificateAuthorityBuiltIn = new("SSL2018", nameof(CertificateAuthorityBuiltIn), "Built-in certificate authority",
        "Let's Encrypt is built in and cannot be removed.");

    public static readonly ErrorCode CertificateAuthorityInUse = new("SSL2019", nameof(CertificateAuthorityInUse), "Certificate authority in use",
        "Move the listed certificates to another certificate authority first, or remove them.");

    public static readonly ErrorCode CertificateAuthorityBusy = new("SSL2020", nameof(CertificateAuthorityBusy), "Certificate authority busy",
        "Another SSLense operation is using or changing this certificate authority. Try again in a few minutes.");

    public static readonly ErrorCode ReusedKeyUnsupported = new("SSL2021", nameof(ReusedKeyUnsupported), "Key cannot be reused",
        "The current key is neither RSA nor ECDSA. Turn key reuse off for this certificate.");

    public static readonly ErrorCode AlreadyHasValidCertificate = new("SSL2022", nameof(AlreadyHasValidCertificate), "Site already has a valid certificate",
        "Tick 'Replace the current certificate even if it is still valid', or use --force, to replace it.");

    public static readonly ErrorCode HostNotCovered = new("SSL2023", nameof(HostNotCovered), "Host name not covered by the certificate names",
        "Add the host name, or a wildcard that covers it, to the certificate names, or leave the host name out.");

    public static readonly ErrorCode NoHostNames = new("SSL2024", nameof(NoHostNames), "No host names",
        "Select at least one host name, or add a named binding to the site in IIS Manager.");

    public static readonly ErrorCode AcmeRateLimited = new("SSL2025", nameof(AcmeRateLimited), "Rate limit reached",
        "The certificate authority's limit for this account or these names was reached. SSLense waits and tries again at a later scheduled check; retrying sooner only extends the limit.");

    public static readonly ErrorCode AcmeValidationTimeout = new("SSL2026", nameof(AcmeValidationTimeout), "Validation took too long",
        "The certificate authority did not finish checking in time. Try again; if it repeats, check port 80 or the DNS record from outside your network.");

    public static readonly ErrorCode CertificateAuthorityDetailsInvalid = new("SSL2027", nameof(CertificateAuthorityDetailsInvalid), "Certificate authority details not valid",
        "Check the preset, name, ID, directory URL and CAA domain; the message says which one.");

    public static readonly ErrorCode EabMissing = new("SSL2028", nameof(EabMissing), "External Account Binding details missing",
        "Enter both the EAB key ID and the HMAC key from your account at the certificate authority.");

    public static readonly ErrorCode EabKeyInvalid = new("SSL2029", nameof(EabKeyInvalid), "EAB HMAC key not valid",
        "Copy the HMAC key again from the certificate authority's account page; it is Base64url text.");

    public static readonly ErrorCode RevocationFailed = new("SSL2030", nameof(RevocationFailed), "Revocation failed",
        "The certificate authority did not revoke the certificate; the message gives its reason. If SSLense already replaced it, the old certificate was saved so you can try again with 'SSLense.Cli revoke --file <path> --ca <id>'.");

    public static readonly ErrorCode NoAcmeAccount = new("SSL2031", nameof(NoAcmeAccount), "No ACME account for the certificate authority",
        "SSLense has not created an account with this certificate authority yet; it creates one with the first certificate. There is no key to replace.");

    public static readonly ErrorCode DnsValidationUnavailable = new("SSL3001", nameof(DnsValidationUnavailable), "DNS validation not available",
        "This SSLense process cannot use DNS validation. Use the app or the CLI on the server, or HTTP validation.");

    public static readonly ErrorCode AcmeDnsTooManyValues = new("SSL3002", nameof(AcmeDnsTooManyValues), "Too many names for one acme-dns account",
        "An acme-dns account keeps two values: a name and its wildcard. Split the names across certificates, or add another acme-dns account.");

    public static readonly ErrorCode NoPublicNameServers = new("SSL3003", nameof(NoPublicNameServers), "No public name servers",
        "A public certificate authority can only validate names in public DNS. Check the domain is registered and delegated, or use an internal certificate authority.");

    public static readonly ErrorCode DnsRecordNotVisible = new("SSL3004", nameof(DnsRecordNotVisible), "DNS record not visible yet",
        "The TXT record was not seen at every authoritative name server in time. Check the record at your DNS host, and try again in a few minutes.");

    public static readonly ErrorCode ManualDnsNotConfirmed = new("SSL3005", nameof(ManualDnsNotConfirmed), "Manual DNS records not confirmed",
        "Nothing was ordered. Create the TXT records shown and confirm, or cancel.");

    public static readonly ErrorCode AcmeDnsCnameMissing = new("SSL3006", nameof(AcmeDnsCnameMissing), "acme-dns CNAME missing",
        "Create the CNAME record shown at your DNS host, wait for it to appear, then try again.");

    public static readonly ErrorCode NoDnsProvider = new("SSL3007", nameof(NoDnsProvider), "No DNS provider for the name",
        "Add a DNS provider for the zone under Settings › DNS providers, delegate the record with a CNAME, or use manual DNS.");

    public static readonly ErrorCode DnsProviderTypeUnsupported = new("SSL3008", nameof(DnsProviderTypeUnsupported), "DNS provider type not supported",
        "The provider was added by a newer SSLense version. Update SSLense, or remove the provider and add it again.");

    public static readonly ErrorCode CnameLoop = new("SSL3009", nameof(CnameLoop), "Too many CNAME steps",
        "Check the CNAME records for the name at your DNS host: they form a loop or a chain longer than SSLense follows.");

    public static readonly ErrorCode DnsProviderNameExists = new("SSL3010", nameof(DnsProviderNameExists), "DNS provider name already used",
        "Remove the existing provider first, or choose another name.");

    public static readonly ErrorCode DnsProviderZoneExists = new("SSL3011", nameof(DnsProviderZoneExists), "DNS provider for the zone already exists",
        "Remove the existing provider for the zone first to replace it.");

    public static readonly ErrorCode DnsProviderAddedMeanwhile = new("SSL3012", nameof(DnsProviderAddedMeanwhile), "DNS provider added at the same time",
        "Another SSLense window or command added the same provider. Refresh and check the list.");

    public static readonly ErrorCode AcmeDnsUnavailable = new("SSL3013", nameof(AcmeDnsUnavailable), "acme-dns not available here",
        "Use the app or the CLI on the server to set up acme-dns.");

    public static readonly ErrorCode AcmeDnsAccountInUse = new("SSL3014", nameof(AcmeDnsAccountInUse), "acme-dns account already used",
        "The account is already set up as another provider. Remove that one first.");

    public static readonly ErrorCode AcmeDnsDomainExists = new("SSL3015", nameof(AcmeDnsDomainExists), "acme-dns already set up for the domain",
        "Remove the existing acme-dns account for the domain first to replace it.");

    public static readonly ErrorCode DnsScriptTestUnconfirmed = new("SSL3016", nameof(DnsScriptTestUnconfirmed), "Script test record not seen",
        "The script said it added the TXT record, but this server could not see it. Check what the script does, and the record at your DNS host.");

    public static readonly ErrorCode AcmeDnsBusy = new("SSL3017", nameof(AcmeDnsBusy), "acme-dns account busy",
        "A certificate is being validated through this account right now. Test again in a few minutes.");

    public static readonly ErrorCode DnsQueriesBlocked = new("SSL3018", nameof(DnsQueriesBlocked), "This server cannot query DNS",
        "Allow outbound DNS (UDP and TCP port 53) from this server, so SSLense can confirm records before ordering.");

    public static readonly ErrorCode DnsProviderNotScript = new("SSL3019", nameof(DnsProviderNotScript), "DNS provider does not use a script",
        "Only script providers have a script to update.");

    public static readonly ErrorCode DnsScriptReplacedMeanwhile = new("SSL3020", nameof(DnsScriptReplacedMeanwhile), "Script replaced at the same time",
        "Another update replaced the script while this one was checked. Check the script, then update it again if needed.");

    public static readonly ErrorCode DnsProviderInUse = new("SSL3021", nameof(DnsProviderInUse), "DNS provider in use",
        "Move the listed certificates to another validation method first, or remove them.");

    public static readonly ErrorCode DnsProviderNotFound = new("SSL3022", nameof(DnsProviderNotFound), "DNS provider not found",
        "Check the name under Settings › DNS providers, or with 'SSLense.Cli dns list'.");

    public static readonly ErrorCode DnsProviderRemovedMeanwhile = new("SSL3023", nameof(DnsProviderRemovedMeanwhile), "DNS provider removed at the same time",
        "Another SSLense window or command removed the provider. Refresh and check the list.");

    public static readonly ErrorCode DnsScriptFolderIsLink = new("SSL3024", nameof(DnsScriptFolderIsLink), "Script folder is a link",
        "SSLense will not use a link or junction for scripts. Remove it and let SSLense create the folder again.");

    public static readonly ErrorCode DnsScriptRefused = new("SSL3025", nameof(DnsScriptRefused), "Script not run",
        "SSLense runs only its own checked copy of a script. The message says what is wrong; update the script with 'SSLense.Cli dns update-script' or in Settings.");

    public static readonly ErrorCode DnsScriptMissing = new("SSL3026", nameof(DnsScriptMissing), "DNS provider has no script",
        "Remove the provider and add it again with its script.");

    public static readonly ErrorCode DnsScriptFailed = new("SSL3027", nameof(DnsScriptFailed), "DNS script failed",
        "The script ended with an error; its last output is in the message. Run it by hand with the same action to see why.");

    public static readonly ErrorCode DnsSecretUnreadable = new("SSL3028", nameof(DnsSecretUnreadable), "DNS provider secret cannot be read",
        "The secret was saved on another server or by another account. Replace it with 'SSLense.Cli dns update-token' or in Settings.");

    public static readonly ErrorCode CloudflareZoneNotFound = new("SSL3029", nameof(CloudflareZoneNotFound), "Cloudflare zone not found",
        "Check that the token can read the zone, and that the zone name matches the domain on Cloudflare.");

    public static readonly ErrorCode CloudflareRequestFailed = new("SSL3030", nameof(CloudflareRequestFailed), "Cloudflare refused the request",
        "The message gives Cloudflare's answer. Check the token's permissions (Zone › DNS › Edit) and that it has not expired.");

    public static readonly ErrorCode AcmeDnsWrongName = new("SSL3031", nameof(AcmeDnsWrongName), "acme-dns account cannot set this name",
        "Each acme-dns account sets one name. Use the account set up for this domain, or add one.");

    public static readonly ErrorCode AcmeDnsNoAccount = new("SSL3032", nameof(AcmeDnsNoAccount), "acme-dns server returned no account",
        "Check that the address is an acme-dns server.");

    public static readonly ErrorCode AcmeDnsUnreachable = new("SSL3033", nameof(AcmeDnsUnreachable), "acme-dns server not reachable",
        "Check the address, outbound HTTPS and any proxy.");

    public static readonly ErrorCode AcmeDnsTimeout = new("SSL3034", nameof(AcmeDnsTimeout), "acme-dns server did not answer in time",
        "Check the address, outbound HTTPS and any proxy, then try again.");

    public static readonly ErrorCode AcmeDnsRefused = new("SSL3035", nameof(AcmeDnsRefused), "acme-dns server refused the request",
        "The message gives the server's answer. Check the account's credentials and its allowed networks.");

    public static readonly ErrorCode DnsProviderDetailsInvalid = new("SSL3036", nameof(DnsProviderDetailsInvalid), "DNS provider details not valid",
        "Check the name, zone, token, script or acme-dns details; the message says which one.");

    public static readonly ErrorCode DnsScriptInputRefused = new("SSL3037", nameof(DnsScriptInputRefused), "Unexpected input for a DNS script",
        "SSLense refused to pass an unexpected zone, record name or value to the script. Report it with the log.");

    public static readonly ErrorCode HostDoesNotResolve = new("SSL3038", nameof(HostDoesNotResolve), "Host name does not resolve",
        "Add an A or AAAA record for the host name at your DNS host.");

    public static readonly ErrorCode DnsProviderRequestFailed = new("SSL3039", nameof(DnsProviderRequestFailed), "The DNS service refused the request",
        "The message gives the service's answer. Check the credentials and that they may change records in this zone: for Route 53 the IAM policy (route53:ChangeResourceRecordSets, ListResourceRecordSets, GetHostedZone), for Azure the DNS Zone Contributor role, for Google the DNS Administrator role, and that the zone ID is right.");

    public static readonly ErrorCode AdoptOtherPort = new("SSL4001", nameof(AdoptOtherPort), "Certificate served on another port",
        "SSLense manages HTTPS bindings on port 443. Watch it by its port-443 binding, or move the binding to port 443.");

    public static readonly ErrorCode AdoptNothingBound = new("SSL4002", nameof(AdoptNothingBound), "No certificate to watch",
        "The site has no HTTPS binding with a certificate. Add one in IIS Manager, or issue a certificate instead.");

    public static readonly ErrorCode AdoptSeveralCertificates = new("SSL4003", nameof(AdoptSeveralCertificates), "Site uses several certificates",
        "Choose the certificate to watch: tick its binding in the app, or give --thumbprint.");

    public static readonly ErrorCode BoundCertificateMissing = new("SSL4004", nameof(BoundCertificateMissing), "Bound certificate missing from the store",
        "IIS points to a certificate that is not in LocalMachine\\My. Install it again, or bind another certificate.");

    public static readonly ErrorCode CertificateHasNoPrivateKey = new("SSL4005", nameof(CertificateHasNoPrivateKey), "Certificate has no private key",
        "A certificate needs its private key on this server to be served. Import the PFX that includes the key.");

    public static readonly ErrorCode BindingsWithoutHostNames = new("SSL4006", nameof(BindingsWithoutHostNames), "HTTPS bindings without host names",
        "SSLense manages SNI bindings by host name. Add a host name to the binding in IIS Manager.");

    public static readonly ErrorCode HostsAlreadyManaged = new("SSL4007", nameof(HostsAlreadyManaged), "Host names already managed",
        "These host names are managed as another certificate on the site. Select that certificate instead.");

    public static readonly ErrorCode NoPendingRequest = new("SSL4008", nameof(NoPendingRequest), "No pending certificate request",
        "Create a request first ('csr', or Add certificate › I bought it and the provider needs a request), or import a PFX.");

    public static readonly ErrorCode RequestKeyMissing = new("SSL4009", nameof(RequestKeyMissing), "Request's private key is gone",
        "The key for this request no longer exists on this server. Create a new request and send it to the provider again.");

    public static readonly ErrorCode CertificateNotForRequest = new("SSL4010", nameof(CertificateNotForRequest), "Certificate does not match the request",
        "None of the certificates in the file was issued for this server's request. Check you downloaded the right certificate.");

    public static readonly ErrorCode RequestKeyUnsupported = new("SSL4011", nameof(RequestKeyUnsupported), "Request key type not supported",
        "Create a new request with an RSA or ECDSA key.");

    public static readonly ErrorCode PfxNotOneCertificate = new("SSL4012", nameof(PfxNotOneCertificate), "PFX does not hold one certificate with its key",
        "Export the PFX again with the certificate and its private key.");

    public static readonly ErrorCode PfxCoversNoHost = new("SSL4013", nameof(PfxCoversNoHost), "Certificate covers none of the site's host names",
        "Check you chose the right site and file, or add a binding for a name the certificate covers.");

    public static readonly ErrorCode ImportOverAutomatic = new("SSL4014", nameof(ImportOverAutomatic), "Certificate renews automatically",
        "Importing replaces a certificate SSLense renews automatically, and stops that. Confirm with --replace-automatic if that is what you want.");

    public static readonly ErrorCode CertificateAlreadyInstalled = new("SSL4015", nameof(CertificateAlreadyInstalled), "Certificate already installed",
        "This certificate is already installed and bound. Nothing needs to change.");

    public static readonly ErrorCode CertificateRejected = new("SSL4016", nameof(CertificateRejected), "Certificate not installed",
        "The certificate failed a check before anything changed. The message lists the problems: names, dates, purpose, key or chain.");

    public static readonly ErrorCode SharedSiteSecondCertificate = new("SSL4017", nameof(SharedSiteSecondCertificate), "Site shares its certificate",
        "A site that shares a certificate with other sites has only that one. Add the host names to the shared certificate, or stop sharing first.");

    public static readonly ErrorCode SeveralPendingRequests = new("SSL4018", nameof(SeveralPendingRequests), "Several pending requests on the site",
        "Choose the request by its certificate name, such as --site \"Main/www.example.com\".");

    public static readonly ErrorCode StoreImportFailed = new("SSL4019", nameof(StoreImportFailed), "Certificate could not be added to the store",
        "Run SSLense as Administrator, and check that LocalMachine\\My is not full or locked by policy.");

    public static readonly ErrorCode PfxImportFailed = new("SSL4020", nameof(PfxImportFailed), "PFX could not be imported",
        "Check the password, and run SSLense as Administrator.");

    public static readonly ErrorCode CertificateKeyNotLinked = new("SSL4021", nameof(CertificateKeyNotLinked), "Certificate not linked to its key",
        "The certificate was added without its private key. Import it again from the PFX or complete the request again.");

    public static readonly ErrorCode SharedCertificateMissing = new("SSL4022", nameof(SharedCertificateMissing), "Shared certificate missing from the store",
        "Renew the certificate first, then share it.");

    public static readonly ErrorCode SharedCertificateNoKey = new("SSL4023", nameof(SharedCertificateNoKey), "Shared certificate has no private key",
        "Renew the certificate first, then share it.");

    public static readonly ErrorCode SharedCertificateNotValidNow = new("SSL4024", nameof(SharedCertificateNotValidNow), "Shared certificate not valid now",
        "Renew the certificate first, then share it.");

    public static readonly ErrorCode CertificateNotShared = new("SSL4025", nameof(CertificateNotShared), "Certificate not shared",
        "To stop managing it, use Remove or 'SSLense.Cli remove'.");

    public static readonly ErrorCode SeveralCertificatesCannotShare = new("SSL4026", nameof(SeveralCertificatesCannotShare), "Certificate cannot be shared to a site with several certificates",
        "A site that has several certificates of its own cannot also take a shared one. Issue a certificate for the host names instead, or share a certificate from that site to another.");

    public static readonly ErrorCode SharingNeedsAcme = new("SSL4027", nameof(SharingNeedsAcme), "Only SSLense's own certificates can be shared",
        "Issue a certificate with SSLense for the sites instead.");

    public static readonly ErrorCode SharingNeedsDns = new("SSL4028", nameof(SharingNeedsDns), "Sharing needs DNS validation",
        "Issue the certificate again with DNS validation, then share it.");

    public static readonly ErrorCode SiteAlreadyShares = new("SSL4029", nameof(SiteAlreadyShares), "Site already uses this certificate",
        "Nothing needs to change.");

    public static readonly ErrorCode SiteHasSharedCertificate = new("SSL4030", nameof(SiteHasSharedCertificate), "Site has its own shared certificate",
        "Stop sharing that one first with 'share remove'.");

    public static readonly ErrorCode SiteHasOwnCertificate = new("SSL4031", nameof(SiteHasOwnCertificate), "Site has its own certificate",
        "Add --replace to give the site the shared certificate instead.");

    public static readonly ErrorCode SiteHasNoCoveredBindings = new("SSL4032", nameof(SiteHasNoCoveredBindings), "No bindings the certificate covers",
        "Add a binding for a name the certificate covers, or name the host names to use.");

    public static readonly ErrorCode SharedHostNotCovered = new("SSL4033", nameof(SharedHostNotCovered), "Certificate does not cover the host name",
        "Choose host names the certificate covers, or issue it again with the name.");

    public static readonly ErrorCode HostBoundElsewhere = new("SSL4034", nameof(HostBoundElsewhere), "Host name bound on another site",
        "The host name already has an HTTPS binding on another IIS site. Remove that binding first.");

    public static readonly ErrorCode SharedSiteHasProblem = new("SSL4035", nameof(SharedSiteHasProblem), "A sharing site has a problem",
        "The message names the site and its problem. Fix it, or stop sharing with that site.");

    public static readonly ErrorCode NoSiteCanUseCertificate = new("SSL4036", nameof(NoSiteCanUseCertificate), "No site can use the certificate",
        "Every sharing site has a problem, so nothing was ordered. Fix them, then try again.");

    public static readonly ErrorCode WildcardOnSameSite = new("SSL4037", nameof(WildcardOnSameSite), "Wildcard already in another certificate on the site",
        "Add the host names to the certificate that has the wildcard.");

    public static readonly ErrorCode WildcardManagedElsewhere = new("SSL4038", nameof(WildcardManagedElsewhere), "Wildcard already managed for another site",
        "Share that certificate with this site instead of issuing a copy.");

    public static readonly ErrorCode SiteSharesCertificate = new("SSL4039", nameof(SiteSharesCertificate), "Site uses another site's certificate",
        "Use 'share remove' to stop managing only this site.");

    public static readonly ErrorCode SharedFirstSite = new("SSL4040", nameof(SharedFirstSite), "Site shares its certificate",
        "A certificate you import or request cannot replace one shared with other sites. Stop sharing first.");

    public static readonly ErrorCode NotACertificateFile = new("SSL4041", nameof(NotACertificateFile), "Not a certificate file",
        "Choose a PEM (.crt, .pem) or DER (.cer) certificate. Export a .p7b or .pfx as a Base-64 .cer first.");

    public static readonly ErrorCode SharingNeedsAttention = new("SSL4042", nameof(SharingNeedsAttention), "Shared certificate needs attention",
        "A site sharing the certificate has a problem or was left on its previous certificate. The message names the site; fix it, or stop sharing with it.");

    public static readonly ErrorCode WildcardBindingUnmanaged = new("SSL4043", nameof(WildcardBindingUnmanaged), "Host covered by the wildcard but not managed",
        "The site has a binding the wildcard covers, but SSLense does not manage it, so it keeps its old certificate. Add the host name to the certificate, or remove the binding.");

    public static readonly ErrorCode SharingSiteGone = new("SSL4044", nameof(SharingSiteGone), "A sharing site no longer exists",
        "Stop sharing with it: 'SSLense.Cli share remove --site <site>'.");

    public static readonly ErrorCode ChainProblem = new("SSL4045", nameof(ChainProblem), "Certificate chain incomplete",
        "An intermediate certificate is missing or expired, so some visitors may not trust the site. Install the certificate again with its full chain.");

    public static readonly ErrorCode StalePendingRequests = new("SSL4046", nameof(StalePendingRequests), "Old pending requests",
        "A certificate request has waited over 30 days. Complete it with the provider's certificate, or delete it.");

    public static readonly ErrorCode CertificateIsForPendingRequest = new("SSL4049", nameof(CertificateIsForPendingRequest), "Certificate belongs to a pending request",
        "The file is the certificate your provider issued for a request SSLense created; its key is already on this server. Use Install renewal, or Complete a request ('SSLense.Cli complete').");

    public static readonly ErrorCode CertificateWithoutKey = new("SSL4050", nameof(CertificateWithoutKey), "Certificate without its private key",
        "A certificate file without its key cannot be installed on its own. Import the PFX that holds both, or complete the request SSLense created.");

    public static readonly ErrorCode RevokeBoughtCertificate = new("SSL4051", nameof(RevokeBoughtCertificate), "Bought certificates are revoked by the provider",
        "Ask your provider to revoke it (most have a button for a compromised key), get a new certificate with a new key, and install it with Install renewal.");

    public static readonly ErrorCode RevokeManualDnsCertificate = new("SSL4052", nameof(RevokeManualDnsCertificate), "Manual DNS certificate cannot be replaced automatically",
        "Renew it by hand first (Renew by hand, with a new key), then revoke the old certificate: 'SSLense.Cli revoke --file <old certificate> --ca <id>'.");

    public static readonly ErrorCode RemoteUnreachable = new("SSL4053", nameof(RemoteUnreachable), "Certificate on another machine could not be read",
        "SSLense connects to the host and port to read the certificate it serves. Check the name or address, the port, and that this server can reach it through any firewall.");

    public static readonly ErrorCode CleanupRefused = new("SSL4054", nameof(CleanupRefused), "Certificate not removed",
        "Only a certificate that nothing uses, that SSLense does not manage, and that is expired, a test leftover or replaced is removed. List the candidates again.");

    public static readonly ErrorCode RollbackNotAvailable = new("SSL4055", nameof(RollbackNotAvailable), "Cannot roll back",
        "SSLense goes back only to the certificate the last renewal replaced, while it is still in LocalMachine\\My with its private key, valid for at least another day, covers the site's names and was not revoked. Renew the certificate instead, or fix the setting that made the new one fail.");

    public static readonly ErrorCode FtpSiteNotFound = new("SSL4056", nameof(FtpSiteNotFound), "FTP site not usable",
        "The step needs an IIS site with an FTP binding, from the FTP Server role service of IIS. Check the site's name in IIS Manager and that it has an ftp binding.");

    public static readonly ErrorCode HttpSysBindingFailed = new("SSL4057", nameof(HttpSysBindingFailed), "HTTP.sys binding not changed",
        "SSLense binds the certificate with 'netsh http add sslcert' or 'update sslcert' and reads it back. Run SSLense as Administrator, check the endpoint with 'netsh http show sslcert', and that the certificate has its private key.");

    public static readonly ErrorCode ServiceTargetMissing = new("SSL4058", nameof(ServiceTargetMissing), "Service not found on this server",
        "The step sets the certificate of a Windows feature on this server. Turn on Remote Desktop, or check the SQL Server instance's name (MSSQLSERVER for the default instance) in SQL Server Configuration Manager.");

    public static readonly ErrorCode JournalEntryMissing = new("SSL5001", nameof(JournalEntryMissing), "Operation record missing",
        "An operation record disappeared while it was in use. Check the log, and run the health check.");

    public static readonly ErrorCode RenewedWithoutThumbprint = new("SSL5002", nameof(RenewedWithoutThumbprint), "Renewed certificate has no thumbprint",
        "Report this with the log; the previous certificate stays in place.");

    public static readonly ErrorCode ServiceDidNotStart = new("SSL5003", nameof(ServiceDidNotStart), "Service installed but not started",
        "The message gives Windows' reason. Check the Windows Event Log, then start the service from Settings › Service.");

    public static readonly ErrorCode ServiceNotInstalled = new("SSL5004", nameof(ServiceNotInstalled), "Service not installed",
        "Install SSLense with its installer, which adds the service.");

    public static readonly ErrorCode ServiceCommandFailed = new("SSL5005", nameof(ServiceCommandFailed), "Service command failed",
        "Run SSLense as Administrator.");

    public static readonly ErrorCode ServiceControlUnavailable = new("SSL5006", nameof(ServiceControlUnavailable), "Service control could not start",
        "Check that C:\\Windows\\System32\\sc.exe exists and is not blocked by policy.");

    public static readonly ErrorCode CertificateStateChanged = new("SSL5007", nameof(CertificateStateChanged), "Certificate changed while waiting",
        "Another SSLense window, command or the service changed the certificate while this operation waited for it. Refresh, check the certificate, and try again.");

    public static readonly ErrorCode SettingOutOfRange = new("SSL5008", nameof(SettingOutOfRange), "Setting out of range",
        "Enter a value in the range the message gives.");

    public static readonly ErrorCode RenewChooseAllOrSite = new("SSL5009", nameof(RenewChooseAllOrSite), "Choose all or one certificate",
        "Give either --all or --site, not both or neither.");

    public static readonly ErrorCode ServiceExecutableMissing = new("SSL5010", nameof(ServiceExecutableMissing), "Service program not found",
        "Install SSLense with its installer, or give the path of SSLense.Service.exe.");

    public static readonly ErrorCode RemindersMutedBeforeExpiry = new("SSL5011", nameof(RemindersMutedBeforeExpiry), "Reminders off for a certificate that expires soon",
        "Turn its reminders back on, or renew it.");

    public static readonly ErrorCode InterruptedOperations = new("SSL5012", nameof(InterruptedOperations), "Interrupted operations",
        "An operation stopped part-way, for example at a restart. SSLense finishes or undoes it when the service starts; restart the service, then check again.");

    public static readonly ErrorCode ServiceStopped = new("SSL5013", nameof(ServiceStopped), "Service stopped",
        "Start the SSLense service under Settings › Service, or in services.msc.");

    public static readonly ErrorCode ServiceStateUnusual = new("SSL5014", nameof(ServiceStateUnusual), "Service in an unusual state",
        "Check the service in services.msc and the Windows Event Log.");

    public static readonly ErrorCode NoRenewalCheckYet = new("SSL5015", nameof(NoRenewalCheckYet), "No renewal check recorded yet",
        "The service records one an hour after it starts. Check that it is running.");

    public static readonly ErrorCode RenewalCheckOverdue = new("SSL5016", nameof(RenewalCheckOverdue), "Renewal check overdue",
        "The service has not completed a check recently. Check that it is running, and its log.");

    public static readonly ErrorCode RenewalCheckProblem = new("SSL5017", nameof(RenewalCheckProblem), "Last renewal check reported a problem",
        "The message gives the problem; check the log under Activity.");

    public static readonly ErrorCode BoughtCertificateExpiring = new("SSL5018", nameof(BoughtCertificateExpiring), "Bought certificate expires soon",
        "Order the renewal from your provider, then use Install renewal.");

    public static readonly ErrorCode ManualDnsCertificateExpiring = new("SSL5019", nameof(ManualDnsCertificateExpiring), "Manual DNS certificate expires soon",
        "Renew it by hand: select it and choose Renew by hand.");

    public static readonly ErrorCode AutomaticCertificateNotRenewed = new("SSL5020", nameof(AutomaticCertificateNotRenewed), "Automatic certificate not renewed in time",
        "Check the renewal history for the reason, fix it, and renew now.");

    public static readonly ErrorCode RenewalFailing = new("SSL5021", nameof(RenewalFailing), "Renewals failing",
        "The message gives the last error. Fix it; SSLense retries on its schedule.");

    public static readonly ErrorCode MaintenanceWindowInvalid = new("SSL5022", nameof(MaintenanceWindowInvalid), "Maintenance window not valid",
        "Choose at least one day, and hours from 0 to 23 with the end different from the start. An end earlier than the start means the next day, as 22 to 4.");

    public static readonly ErrorCode HostsOfSeveralCertificates = new("SSL6001", nameof(HostsOfSeveralCertificates), "Host names belong to several certificates",
        "Choose the host names of one certificate on the site.");

    public static readonly ErrorCode CertificateNameTaken = new("SSL6002", nameof(CertificateNameTaken), "Certificate name already used",
        "The name is used by a certificate for other host names. Replace that certificate by its name, or choose the host names in another order.");

    public static readonly ErrorCode HostsTaken = new("SSL6003", nameof(HostsTaken), "Host names already have a certificate",
        "Each host name on a site has one certificate. Replace that certificate instead.");

    public static readonly ErrorCode NameIsIisSite = new("SSL6004", nameof(NameIsIisSite), "Name is an IIS site",
        "A certificate with no IIS site needs a name that is not a site's. Choose another name.");

    public static readonly ErrorCode NoSiteCertificateExists = new("SSL6005", nameof(NoSiteCertificateExists), "Certificate already exists",
        "Use --force to replace it now, or wait for it to renew.");

    public static readonly ErrorCode NameIsNoSiteCertificate = new("SSL6006", nameof(NameIsNoSiteCertificate), "Name is a certificate with no IIS site",
        "Renew it by its name, or remove it first to use the name for a site.");

    public static readonly ErrorCode NoSiteNameHasSlash = new("SSL6007", nameof(NoSiteNameHasSlash), "Name contains '/'",
        "A '/' names a second certificate on an IIS site. Choose a name without it.");

    public static readonly ErrorCode DataDirectoryIsLink = new("SSL6008", nameof(DataDirectoryIsLink), "Data folder is a link",
        "SSLense will not use a link or junction for its data folder. Replace it with a real folder.");

    public static readonly ErrorCode StateAccessDenied = new("SSL6009", nameof(StateAccessDenied), "Access to SSLense's data denied",
        "Run SSLense as Administrator.");

    public static readonly ErrorCode NotManaged = new("SSL6010", nameof(NotManaged), "Not managed by SSLense",
        "Check the name in the certificate list.");

    public static readonly ErrorCode InvalidEmail = new("SSL6011", nameof(InvalidEmail), "Email address not valid",
        "Enter a full email address, such as admin@example.com.");

    public static readonly ErrorCode InvalidHostName = new("SSL6012", nameof(InvalidHostName), "Host name not valid",
        "SSLense manages IIS bindings for real host names, such as www.example.com.");

    public static readonly ErrorCode NoHostNamesGiven = new("SSL6013", nameof(NoHostNamesGiven), "No host names given",
        "Select or enter at least one host name.");

    public static readonly ErrorCode NoSiteNamesMissing = new("SSL6014", nameof(NoSiteNamesMissing), "Names missing for a certificate with no IIS site",
        "Give the names the certificate covers, such as rdp.example.com.");

    public static readonly ErrorCode NoSiteNeedsDns = new("SSL6015", nameof(NoSiteNeedsDns), "Certificate with no IIS site needs DNS validation",
        "HTTP validation needs a site to serve the file, unless SSLense answers the challenge itself. Choose a DNS validation method, or HTTP answered by SSLense.");

    public static readonly ErrorCode InvalidCertificateName = new("SSL6016", nameof(InvalidCertificateName), "Name not allowed",
        "Use letters, digits, spaces, dots, hyphens, underscores and brackets, up to 100 characters.");

    public static readonly ErrorCode NamesNeedDns = new("SSL6018", nameof(NamesNeedDns), "Certificate names need DNS validation",
        "Wildcards and extra names need DNS validation. With HTTP validation the certificate covers the host names.");

    public static readonly ErrorCode InvalidCertificateNames = new("SSL6019", nameof(InvalidCertificateNames), "Certificate names not valid",
        "Check each name; a wildcard covers one level, as in *.example.com, and a name already covered by a wildcard in the same certificate is not needed.");

    public static readonly ErrorCode InvalidKeyType = new("SSL6020", nameof(InvalidKeyType), "Unknown key type",
        "Use one of the key types listed in the message.");

    public static readonly ErrorCode AccountKeyDamaged = new("SSL6021", nameof(AccountKeyDamaged), "ACME account key damaged",
        "The saved account key cannot be read. Restore SSLense's data folder from a backup, or remove the account file so SSLense creates a new account (existing certificates keep working).");

    public static readonly ErrorCode DataFileDamaged = new("SSL6022", nameof(DataFileDamaged), "Data file damaged",
        "One of SSLense's data files is empty or not valid JSON. SSLense keeps a backup next to it (.bak); restore it, or restore the data folder from a backup.");

    public static readonly ErrorCode DataFromNewerVersion = new("SSL6023", nameof(DataFromNewerVersion), "Data from a newer SSLense",
        "The data folder was written by a newer SSLense version. Install that version or newer again.");

    public static readonly ErrorCode SecretUnreadable = new("SSL6024", nameof(SecretUnreadable), "Secret cannot be read",
        "SSLense's secrets are encrypted for this server. A data folder copied from another server needs its passwords, tokens and keys entered again.");

    public static readonly ErrorCode ConfigurationUnreadable = new("SSL6025", nameof(ConfigurationUnreadable), "Configuration could not be read",
        "Run SSLense as Administrator. If it persists, check config.json in the data folder.");

    public static readonly ErrorCode DataFolderPermissions = new("SSL6026", nameof(DataFolderPermissions), "Data folder permissions not safe",
        "SSLense's data folder should be limited to Administrators and SYSTEM. Run SSLense as Administrator once to restore them, or reinstall.");

    public static readonly ErrorCode IpCertificateNeedsHttpSelf = new("SSL6027", nameof(IpCertificateNeedsHttpSelf), "IP address certificates need HTTP answered by SSLense",
        "A certificate authority validates an IP address over HTTP (or TLS-ALPN), not DNS. Choose HTTP validation with SSLense answering the challenge itself (--validation http-self); Let's Encrypt also needs a short-lived profile, such as --profile shortlived.");

    public static readonly ErrorCode RemoteNameTaken = new("SSL6028", nameof(RemoteNameTaken), "Name already used",
        "A certificate on another machine needs a name that no other certificate or IIS site has.");

    public static readonly ErrorCode BulkFileInvalid = new("SSL6029", nameof(BulkFileInvalid), "Bulk file not valid",
        "Each row needs a site and an email (or the default ACME email in Settings), and a validation of http, http-self or dns. A header row may name the columns: site, hosts, validation, names, email, ca, profile, key.");

    public static readonly ErrorCode ConfigFileInvalid = new("SSL6030", nameof(ConfigFileInvalid), "Settings file not valid",
        "The file must be one SSLense wrote with 'config export', from this version or an older one. Export it again on the source server.");

    public static readonly ErrorCode ConfigPasswordMissingOrWrong = new("SSL6031", nameof(ConfigPasswordMissingOrWrong), "Settings file password missing or wrong",
        "Secrets in an exported settings file are encrypted with a password. Set the environment variable SSLENSE_CONFIG_PASSWORD to the password used at export, in the same terminal, and try again.");

    public static readonly ErrorCode ConfigImportRefused = new("SSL6032", nameof(ConfigImportRefused), "Settings not imported",
        "Importing would leave a certificate without the certificate authority that renews it. Add that authority to the source server and export again, or stop managing the certificate first.");

    public static readonly ErrorCode ChatRejected = new("SSL7001", nameof(ChatRejected), "Chat message rejected",
        "The chat service refused the message. Check the webhook URL still exists, and send a test.");

    public static readonly ErrorCode SmtpUsernameMissing = new("SSL7002", nameof(SmtpUsernameMissing), "SMTP username missing",
        "Enter the username for password sign-in, or choose no sign-in for a relay.");

    public static readonly ErrorCode SmtpPasswordMissing = new("SSL7003", nameof(SmtpPasswordMissing), "SMTP password missing",
        "Enter the password in the email settings.");

    public static readonly ErrorCode EmailFailed = new("SSL7004", nameof(EmailFailed), "Email could not be sent",
        "The message gives the mail server's answer. Check the server, port, security and sign-in, then send a test.");

    public static readonly ErrorCode NoNotificationChannels = new("SSL7005", nameof(NoNotificationChannels), "No notification channels",
        "Add an email or chat channel, or turn the Event Log back on, under Settings › Notifications.");

    public static readonly ErrorCode HeartbeatFailed = new("SSL7006", nameof(HeartbeatFailed), "Heartbeat ping failed",
        "Check the heartbeat check still exists at the monitoring service.");

    public static readonly ErrorCode NotificationSecretDamaged = new("SSL7007", nameof(NotificationSecretDamaged), "Notification secret damaged",
        "Enter the channel's URL or password again under Settings › Notifications.");

    public static readonly ErrorCode NotificationSettingsInvalid = new("SSL7008", nameof(NotificationSettingsInvalid), "Notification settings not valid",
        "Check the URL, port, recipients and sign-in; the message says which one.");

    public static readonly ErrorCode OnlyEventLog = new("SSL7009", nameof(OnlyEventLog), "Only the Event Log is notified",
        "Add an email or chat channel, or make sure the Windows Event Log is monitored.");

    public static readonly ErrorCode KeyVaultFailed = new("SSL7010", nameof(KeyVaultFailed), "Azure Key Vault import failed",
        "SSLense signs in with the step's app registration and imports the certificate as a new version. Check the tenant, client ID and secret, the vault's name and firewall, and that the app has the Key Vault Certificates Officer role or the Import certificate permission.");

    public static readonly ErrorCode AppServiceFailed = new("SSL7011", nameof(AppServiceFailed), "Azure App Service not updated",
        "SSLense signs in with the step's app registration, uploads the certificate and binds the app's custom domains it covers. Check the tenant, client ID and secret, the subscription, resource group and app, that the domain is added to the app, and that the app registration has the Website Contributor role.");

    public static readonly ErrorCode ExportKeyUnsupported = new("SSL8001", nameof(ExportKeyUnsupported), "Key type cannot be exported",
        "The key is neither RSA nor ECDSA. Issue the certificate again with a supported key type.");

    public static readonly ErrorCode CertificateNotInStore = new("SSL8002", nameof(CertificateNotInStore), "Certificate not in the store",
        "Renew or install the certificate again.");

    public static readonly ErrorCode ExportNoPrivateKey = new("SSL8003", nameof(ExportNoPrivateKey), "No private key to export",
        "Install the certificate again with its private key.");

    public static readonly ErrorCode ExportFailed = new("SSL8004", nameof(ExportFailed), "Export failed",
        "Run SSLense as Administrator, and check the destination folder.");

    public static readonly ErrorCode KeyNotExportable = new("SSL8005", nameof(KeyNotExportable), "Private key not exportable",
        "Issue the certificate again with an exportable key to write it to files.");

    public static readonly ErrorCode TooManySteps = new("SSL8006", nameof(TooManySteps), "Too many deployment steps",
        "Remove a step first.");

    public static readonly ErrorCode CertificateRemovedMeanwhile = new("SSL8007", nameof(CertificateRemovedMeanwhile), "Certificate removed at the same time",
        "Another SSLense window or command removed the certificate. Refresh the list.");

    public static readonly ErrorCode NoDeploymentSteps = new("SSL8008", nameof(NoDeploymentSteps), "No deployment steps",
        "Add a step under After install on the certificate, or with 'deploy add'.");

    public static readonly ErrorCode DeploymentStepUnknown = new("SSL8009", nameof(DeploymentStepUnknown), "Unknown deployment step",
        "The step was added by a newer SSLense version. Update SSLense, or remove the step.");

    public static readonly ErrorCode PasswordStorageUnavailable = new("SSL8010", nameof(PasswordStorageUnavailable), "Passwords cannot be stored",
        "Use the app or the CLI on the server.");

    public static readonly ErrorCode ExportUnavailable = new("SSL8011", nameof(ExportUnavailable), "Export not available here",
        "Use the app or the CLI on the server.");

    public static readonly ErrorCode StepPasswordMissing = new("SSL8012", nameof(StepPasswordMissing), "Step has no password",
        "Remove the step and add it again.");

    public static readonly ErrorCode StepPasswordUnreadable = new("SSL8013", nameof(StepPasswordUnreadable), "Step password cannot be read",
        "The password was saved on another server or by another account. Remove the step and add it again.");

    public static readonly ErrorCode StepScriptMissing = new("SSL8014", nameof(StepScriptMissing), "Step has no script",
        "Remove the step and add it again.");

    public static readonly ErrorCode DeploymentScriptFailed = new("SSL8015", nameof(DeploymentScriptFailed), "Deployment script failed",
        "The script ended with an error; its last output is in the message. Run it by hand to see why.");

    public static readonly ErrorCode PrivateKeyFileMissing = new("SSL8016", nameof(PrivateKeyFileMissing), "Private key file not found",
        "The key is not in a file SSLense can change access to. Install the certificate again, or give access in certlm.msc.");

    public static readonly ErrorCode PrivateKeyFileIsLink = new("SSL8017", nameof(PrivateKeyFileIsLink), "Private key file is a link",
        "SSLense will not change access through a link. Check the machine key folder.");

    public static readonly ErrorCode NoPrivateKey = new("SSL8018", nameof(NoPrivateKey), "Certificate has no private key",
        "Install the certificate again with its private key.");

    public static readonly ErrorCode PrivateKeyLocationUnknown = new("SSL8019", nameof(PrivateKeyLocationUnknown), "Private key location unknown",
        "Give access in certlm.msc › Manage Private Keys instead.");

    public static readonly ErrorCode ServiceStopFailed = new("SSL8020", nameof(ServiceStopFailed), "Service did not stop",
        "The message gives Windows' reason. Stop it by hand and check the Windows Event Log.");

    public static readonly ErrorCode ServiceStartFailed = new("SSL8021", nameof(ServiceStartFailed), "Service did not start",
        "The message gives Windows' reason. Start it by hand and check the Windows Event Log.");

    public static readonly ErrorCode ServiceStoppedAgain = new("SSL8022", nameof(ServiceStoppedAgain), "Service stopped again after starting",
        "Check the Windows Event Log for the reason; the service may not accept the new certificate.");

    public static readonly ErrorCode ServiceTimeout = new("SSL8023", nameof(ServiceTimeout), "Service did not respond in time",
        "Check the service in services.msc and the Windows Event Log.");

    public static readonly ErrorCode DeploymentStepInvalid = new("SSL8024", nameof(DeploymentStepInvalid), "Deployment step details not valid",
        "Check the step's path, password and timeout; the message says which one.");

    public static readonly ErrorCode ServiceNameUnknown = new("SSL8025", nameof(ServiceNameUnknown), "No such Windows service",
        "Use the service's name as 'sc.exe query' or the Services console shows it, such as MSSQLSERVER or TermService.");

    public static readonly ErrorCode CannotRestartSslense = new("SSL8026", nameof(CannotRestartSslense), "SSLense cannot restart itself",
        "Choose another service.");

    public static readonly ErrorCode DeploymentStepNotFound = new("SSL8027", nameof(DeploymentStepNotFound), "No such deployment step",
        "Check the step numbers under After install on the certificate, or with 'deploy list'.");

    public static readonly ErrorCode AccountUnknown = new("SSL8028", nameof(AccountUnknown), "Windows account not found",
        "Check the name, such as 'IIS AppPool\\Shop' or 'NT SERVICE\\MSSQLSERVER'.");

    public static readonly ErrorCode NoSiteNoSteps = new("SSL8029", nameof(NoSiteNoSteps), "Certificate with no IIS site has no deployment steps",
        "Add a step under After install so a renewal reaches the service that uses the certificate.");

    public static readonly ErrorCode DeploymentPending = new("SSL8030", nameof(DeploymentPending), "Deployment steps have not succeeded",
        "The message gives the last error; SSLense retries hourly and keeps the previous certificate meanwhile. Fix the cause, or run the steps again.");

    public static readonly ErrorCode CheckUnavailable = new("SSL9001", nameof(CheckUnavailable), "Check not available",
        "Use the app or the CLI on the server.");

    public static readonly ErrorCode LogLockUnavailable = new("SSL9002", nameof(LogLockUnavailable), "Log lock not available",
        "Run SSLense as Administrator.");

    public static readonly ErrorCode NoLogFile = new("SSL9003", nameof(NoLogFile), "No log file yet",
        "SSLense writes the log once it does something. Try again after an operation.");

    public static readonly ErrorCode NotALogFile = new("SSL9004", nameof(NotALogFile), "Not an SSLense log file",
        "Choose a file from SSLense's log folder.");

    public static readonly ErrorCode LogBusy = new("SSL9005", nameof(LogBusy), "Log busy",
        "Another SSLense process is writing to the log. Try again in a moment.");

    public static readonly ErrorCode NotAdministrator = new("SSL9006", nameof(NotAdministrator), "Not running as Administrator",
        "Start SSLense with 'Run as administrator'.");

    public static readonly ErrorCode UpdateAvailable = new("SSL9007", nameof(UpdateAvailable), "A newer SSLense is available",
        "Download it from the release page in the message and run its installer; it upgrades in place and keeps your settings. SSLense never installs anything by itself. Turn the notice off under Settings › General.");

    public static readonly ErrorCode Unexpected = new("SSL9999", nameof(Unexpected), "Unexpected error",
        "SSLense did not expect this error. The original message follows the code. Run the health check, and report it with a diagnostic bundle ('SSLense.Cli diagnostics') if it happens again.");

    /// <summary>Every code, in code order.</summary>
    public static IReadOnlyList<ErrorCode> All { get; } =
    [
        IisSiteNotFound,
        IisSiteNoPhysicalPath,
        HostHasNoBinding,
        IisConfigurationUnreadable,
        IisManagementMissing,
        NetshUnavailable,
        HttpsBindingNotFound,
        HttpsBindingNotRetained,
        HttpsBindingChangeFailed,
        HttpsBindingUsesOtherCertificate,
        HttpsBindingRemovalUnverified,
        HttpsBindingRemovalFailed,
        HttpsCertificateNotServed,
        PreviousBindingGone,
        NoCertificateServed,
        ChallengeSelfCheckUnreachable,
        ChallengeSelfCheckStatus,
        ChallengeSelfCheckContent,
        BindingsNotRestored,
        IisBindingUnreadable,
        NetshTimeout,
        ChallengeSelfCheckTimeout,
        BindingMissing,
        ServedCertificateMismatch,
        ServedHostUnreachable,
        ChallengeFolderNotWritable,
        ServedCertificateExpired,
        SelfHostedPortUnavailable,
        UrlRewriteMissing,
        RedirectNeedsHttps,
        RedirectBlocksValidation,
        ProductionNotConfirmed,
        CertificateAuthorityUnreachable,
        AcmeUnexpectedChallenges,
        AcmeUnexpectedAuthorization,
        ProfileNotOffered,
        Http01NotOffered,
        Dns01NotOffered,
        EabKeyUnreadable,
        AcmeValidationFailed,
        AcmeOrderNotIssued,
        AcmeDirectoryHttpError,
        AcmeDirectoryUnreachable,
        AcmeDirectoryTimeout,
        NotAnAcmeDirectory,
        CertificateAuthorityNotConfigured,
        CertificateAuthorityExists,
        EabNowRequired,
        CertificateAuthorityBuiltIn,
        CertificateAuthorityInUse,
        CertificateAuthorityBusy,
        ReusedKeyUnsupported,
        AlreadyHasValidCertificate,
        HostNotCovered,
        NoHostNames,
        AcmeRateLimited,
        AcmeValidationTimeout,
        CertificateAuthorityDetailsInvalid,
        EabMissing,
        EabKeyInvalid,
        RevocationFailed,
        NoAcmeAccount,
        DnsValidationUnavailable,
        AcmeDnsTooManyValues,
        NoPublicNameServers,
        DnsRecordNotVisible,
        ManualDnsNotConfirmed,
        AcmeDnsCnameMissing,
        NoDnsProvider,
        DnsProviderTypeUnsupported,
        CnameLoop,
        DnsProviderNameExists,
        DnsProviderZoneExists,
        DnsProviderAddedMeanwhile,
        AcmeDnsUnavailable,
        AcmeDnsAccountInUse,
        AcmeDnsDomainExists,
        DnsScriptTestUnconfirmed,
        AcmeDnsBusy,
        DnsQueriesBlocked,
        DnsProviderNotScript,
        DnsScriptReplacedMeanwhile,
        DnsProviderInUse,
        DnsProviderNotFound,
        DnsProviderRemovedMeanwhile,
        DnsScriptFolderIsLink,
        DnsScriptRefused,
        DnsScriptMissing,
        DnsScriptFailed,
        DnsSecretUnreadable,
        CloudflareZoneNotFound,
        CloudflareRequestFailed,
        AcmeDnsWrongName,
        AcmeDnsNoAccount,
        AcmeDnsUnreachable,
        AcmeDnsTimeout,
        AcmeDnsRefused,
        DnsProviderDetailsInvalid,
        DnsScriptInputRefused,
        HostDoesNotResolve,
        DnsProviderRequestFailed,
        AdoptOtherPort,
        AdoptNothingBound,
        AdoptSeveralCertificates,
        BoundCertificateMissing,
        CertificateHasNoPrivateKey,
        BindingsWithoutHostNames,
        HostsAlreadyManaged,
        NoPendingRequest,
        RequestKeyMissing,
        CertificateNotForRequest,
        RequestKeyUnsupported,
        PfxNotOneCertificate,
        PfxCoversNoHost,
        ImportOverAutomatic,
        CertificateAlreadyInstalled,
        CertificateRejected,
        SharedSiteSecondCertificate,
        SeveralPendingRequests,
        StoreImportFailed,
        PfxImportFailed,
        CertificateKeyNotLinked,
        SharedCertificateMissing,
        SharedCertificateNoKey,
        SharedCertificateNotValidNow,
        CertificateNotShared,
        SeveralCertificatesCannotShare,
        SharingNeedsAcme,
        SharingNeedsDns,
        SiteAlreadyShares,
        SiteHasSharedCertificate,
        SiteHasOwnCertificate,
        SiteHasNoCoveredBindings,
        SharedHostNotCovered,
        HostBoundElsewhere,
        SharedSiteHasProblem,
        NoSiteCanUseCertificate,
        WildcardOnSameSite,
        WildcardManagedElsewhere,
        SiteSharesCertificate,
        SharedFirstSite,
        NotACertificateFile,
        SharingNeedsAttention,
        WildcardBindingUnmanaged,
        SharingSiteGone,
        ChainProblem,
        StalePendingRequests,
        CertificateIsForPendingRequest,
        CertificateWithoutKey,
        RevokeBoughtCertificate,
        RevokeManualDnsCertificate,
        RemoteUnreachable,
        CleanupRefused,
        RollbackNotAvailable,
        FtpSiteNotFound,
        HttpSysBindingFailed,
        ServiceTargetMissing,
        JournalEntryMissing,
        RenewedWithoutThumbprint,
        ServiceDidNotStart,
        ServiceNotInstalled,
        ServiceCommandFailed,
        ServiceControlUnavailable,
        CertificateStateChanged,
        SettingOutOfRange,
        RenewChooseAllOrSite,
        ServiceExecutableMissing,
        RemindersMutedBeforeExpiry,
        InterruptedOperations,
        ServiceStopped,
        ServiceStateUnusual,
        NoRenewalCheckYet,
        RenewalCheckOverdue,
        RenewalCheckProblem,
        BoughtCertificateExpiring,
        ManualDnsCertificateExpiring,
        AutomaticCertificateNotRenewed,
        RenewalFailing,
        MaintenanceWindowInvalid,
        HostsOfSeveralCertificates,
        CertificateNameTaken,
        HostsTaken,
        NameIsIisSite,
        NoSiteCertificateExists,
        NameIsNoSiteCertificate,
        NoSiteNameHasSlash,
        DataDirectoryIsLink,
        StateAccessDenied,
        NotManaged,
        InvalidEmail,
        InvalidHostName,
        NoHostNamesGiven,
        NoSiteNamesMissing,
        NoSiteNeedsDns,
        InvalidCertificateName,
        NamesNeedDns,
        InvalidCertificateNames,
        InvalidKeyType,
        AccountKeyDamaged,
        DataFileDamaged,
        DataFromNewerVersion,
        SecretUnreadable,
        ConfigurationUnreadable,
        DataFolderPermissions,
        IpCertificateNeedsHttpSelf,
        RemoteNameTaken,
        BulkFileInvalid,
        ConfigFileInvalid,
        ConfigPasswordMissingOrWrong,
        ConfigImportRefused,
        ChatRejected,
        SmtpUsernameMissing,
        SmtpPasswordMissing,
        EmailFailed,
        NoNotificationChannels,
        HeartbeatFailed,
        NotificationSecretDamaged,
        NotificationSettingsInvalid,
        OnlyEventLog,
        KeyVaultFailed,
        AppServiceFailed,
        ExportKeyUnsupported,
        CertificateNotInStore,
        ExportNoPrivateKey,
        ExportFailed,
        KeyNotExportable,
        TooManySteps,
        CertificateRemovedMeanwhile,
        NoDeploymentSteps,
        DeploymentStepUnknown,
        PasswordStorageUnavailable,
        ExportUnavailable,
        StepPasswordMissing,
        StepPasswordUnreadable,
        StepScriptMissing,
        DeploymentScriptFailed,
        PrivateKeyFileMissing,
        PrivateKeyFileIsLink,
        NoPrivateKey,
        PrivateKeyLocationUnknown,
        ServiceStopFailed,
        ServiceStartFailed,
        ServiceStoppedAgain,
        ServiceTimeout,
        DeploymentStepInvalid,
        ServiceNameUnknown,
        CannotRestartSslense,
        DeploymentStepNotFound,
        AccountUnknown,
        NoSiteNoSteps,
        DeploymentPending,
        CheckUnavailable,
        LogLockUnavailable,
        NoLogFile,
        NotALogFile,
        LogBusy,
        NotAdministrator,
        UpdateAvailable,
        Unexpected
    ];
}
