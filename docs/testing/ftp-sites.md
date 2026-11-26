# Manual tests: IIS FTP sites

Feature 23 of [the delivery plan](../delivery-plan.md); design in [docs/design/ftp-sites.md](../design/ftp-sites.md).

Needs the IIS role service **FTP Server** and an FTP site ("Files") with an `ftp` binding for `ftp.example.com` on port 21, with SSL set to Allow or Require. Anonymous authentication with read access is enough; the tests never sign in.

To see the certificate the FTP site really serves, without an FTP client, define this in the PowerShell window. It asks for explicit TLS (`AUTH TLS`) and prints the certificate's thumbprint:

```powershell
function Get-FtpCert {
    $tcp = New-Object Net.Sockets.TcpClient('127.0.0.1', 21)
    $stream = $tcp.GetStream()
    $reader = New-Object IO.StreamReader($stream)
    $writer = New-Object IO.StreamWriter($stream); $writer.AutoFlush = $true
    $null = $reader.ReadLine()
    $writer.WriteLine('AUTH TLS'); $null = $reader.ReadLine()
    $ssl = New-Object Net.Security.SslStream($stream, $false, { $true })
    $ssl.AuthenticateAsClient('ftp.example.com')
    $ssl.RemoteCertificate.GetCertHashString()
    $ssl.Dispose(); $tcp.Dispose()
}
```

| # | Steps | Expected |
|---|---|---|
| 1 | Issue a staging certificate for `ftp.example.com` (DNS, or `--validation http-self`) | Issued |
| 2 | `SSLense.Cli deploy add --site <certificate> --ftp-site Shop` (a web-only site) | SSL4056 |
| 3 | `deploy add --site <certificate> --ftp-site files`, then `deploy run` | The step is listed as "Use it for the IIS FTP site 'Files'"; IIS Manager › Files › FTP SSL Settings shows the certificate |
| 4 | `Get-FtpCert` (or FileZilla with explicit FTP over TLS) | The certificate's thumbprint |
| 5 | **Renew now** (or `renew --site <certificate> --force`) | The FTP SSL Settings and `Get-FtpCert` show the renewed certificate |
| 6 | `Rename-Item IIS:\Sites\Files FilesAway`, then `renew --force` and `deploy list`; rename it back and `deploy run` | The renewal succeeds but the step fails and is pending; the previous certificate stays in the store while it is pending; after the rename back, `deploy run` succeeds and `Get-FtpCert` shows the newest certificate |
| 7 | Activity › Unused certificates › Find | The FTP site's certificate is not listed |
| 8 | `deploy remove --site <certificate> --step 1`, then in the app: the certificate › After install › **Use it for an IIS FTP site**, value "Files", **Add step** | The same as step 3 |
