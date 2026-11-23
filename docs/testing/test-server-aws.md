# Setting up a test server on AWS

A step-by-step setup for the [combined test](manual-test-plan.md): one Windows Server on Amazon EC2, a domain on Cloudflare, and a subdomain on Route 53, so the Route 53 DNS provider is tested on a real account too. Replace `<domain>` with your test domain, one nothing else uses.

**Let's Encrypt staging only.** Browsers show staging certificates as untrusted; that is expected.

## 1. The server

1. **Launch an instance:**
   - EC2 › Launch instance › **Microsoft Windows Server 2022 Base**.
   - **Instance type:** `t3.micro` or `t2.micro` (free tier, 1 GB RAM) runs IIS and the service. The desktop app over Remote Desktop is slow at that size; a `t3.small` or `t3.medium` is much smoother. Stop the instance whenever you are not testing.
   - **Storage:** 30 GB.
2. **Security group, inbound:**

   | Port | Source | Why |
   |---|---|---|
   | TCP 80 | 0.0.0.0/0 and ::/0 | Let's Encrypt fetches HTTP challenges |
   | TCP 443 | 0.0.0.0/0 and ::/0 | Checking the sites from outside |
   | TCP 3389 | **your own IP only** | Remote Desktop |

3. **Elastic IP:** EC2 › Elastic IPs › Allocate, then associate it with the instance. The address then survives stops and starts, which DNS records and the IP-address certificate test need. AWS charges a small hourly amount for public IPv4 addresses; check what your free tier covers.
4. **Sign in:** get the Administrator password (Connect › RDP client › Get password, with the key pair) and connect with Remote Desktop.
5. **Prepare Windows:** run `tests\SSLense.Acceptance\setup-server.ps1` from an Administrator PowerShell. It adds IIS and its management tools, and reports what it found. Then:
   - add **FTP Server** (Server Manager › Web Server › FTP Server) for the FTP tests;
   - add **URL Rewrite** for the redirect tests;
   - install **SQL Server Express** for the SQL Server step, if memory allows.
6. **Windows firewall:** IIS opens 80 and 443 itself; check with `Get-NetFirewallRule -DisplayGroup "World Wide Web Services (HTTP)"`.

## 2. DNS on Cloudflare

In Cloudflare › `<domain>` › DNS, add these records, all **DNS only** (grey cloud, not proxied, so Let's Encrypt reaches the server itself):

| Type | Name | Value | Used by |
|---|---|---|---|
| A | `test` | the Elastic IP | Issuing with HTTP validation |
| A | `www.test` | the Elastic IP | Several names on one certificate |
| A | `*.accept` | the Elastic IP | The acceptance checks (`accept1`, `site1.accept` and the rest) |
| A | `ftp.test` | the Elastic IP | The FTP site |

**A token for SSLense:**
1. Cloudflare › My Profile › API Tokens › Create token, **Edit zone DNS**, Zone Resources: only `<domain>`.
2. Set an expiry, such as the end of the test week. Note the zone ID from the domain's Overview page.

## 3. A subdomain on Route 53

This tests the Route 53 provider without moving the domain:

1. Route 53 › Hosted zones › Create hosted zone: `r53.<domain>`, public. Note its **hosted zone ID**, such as `Z0123456789ABCDEFGHIJ`, and its four **name servers**.
2. Cloudflare › `<domain>` › DNS: add four **NS** records named `r53`, one for each Route 53 name server. This delegates `r53.<domain>` to Route 53.
3. Check: `Resolve-DnsName -Type NS r53.<domain>` returns the AWS name servers.
4. **An IAM user for SSLense:** IAM › Users › Create user `sslense-test`, no console access. Attach this inline policy, with your hosted zone ID:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "route53:GetHostedZone",
           "route53:ListResourceRecordSets",
           "route53:ChangeResourceRecordSets"
         ],
         "Resource": "arn:aws:route53:::hostedzone/Z0123456789ABCDEFGHIJ"
       }
     ]
   }
   ```

   These are exactly the three calls SSLense makes, on that one zone. Create an **access key** for the user (Security credentials › Create access key › Third-party service). Type it only into SSLense's prompt; never paste it into a chat, a script or the repository. Delete the key when testing ends.
5. Route 53 charges a small monthly amount for the hosted zone; delete it after testing.

## 4. Install and run

1. Install SSLense **0.23.0**, then upgrade to the release candidate (manual test plan, section 2).
2. Add the DNS providers:

   ```powershell
   SSLense.Cli dns add --provider cloudflare --name "Cloudflare" --zone <domain> --zone-id <zone ID>       # token prompted
   SSLense.Cli dns add --provider route53 --name "Route 53" --zone r53.<domain> --zone-id Z0123456789ABCDEFGHIJ   # access key ID, then secret
   ```

3. Run the acceptance checks from an Administrator terminal (section 3 of the plan): `parta`, `partb --zone <domain>`, `httpcheck --zone <domain>`, `scriptcheck --zone <domain>`, `servicecheck --zone <domain>`.
4. Work through the feature sections. On this server, these can run:
   - HTTP validation, with IIS and with SSLense answering (`test.<domain>`);
   - DNS validation and wildcards through Cloudflare (`*.test.<domain>`) and Route 53 (`*.r53.<domain>`), which marks Route 53 as tested;
   - an IP-address certificate for the Elastic IP (`--validation http-self`);
   - rollback, maintenance windows, the redirect, bulk operations, clean-up, FTP, Remote Desktop, SQL Server Express, HTTP.sys bindings, bindings without a host name and on port 8443, automation and accessibility.
5. **A second, smaller instance** in the same security group adds the web farm and fleet tests (a share both can reach).

**Not testable here:** Azure Key Vault, Azure App Service, email through Microsoft Graph, and the Azure, Google Cloud, DigitalOcean and Hetzner DNS providers. They need those accounts, and stay listed as untested in the known issues.

## 5. Afterwards

- Record the results in the plan's tables and sign-off.
- **Clean up:**
  - delete the IAM access key and the Cloudflare token;
  - delete the Route 53 hosted zone and the NS records;
  - stop or terminate the instance and release the Elastic IP, so nothing keeps costing money.
