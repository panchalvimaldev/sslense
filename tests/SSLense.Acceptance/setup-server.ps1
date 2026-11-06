# Prepares a new Windows Server for the acceptance checks: IIS and the management tools SSLense needs.
# Run it from an Administrator PowerShell. It changes nothing else.
$ErrorActionPreference = 'Stop'
$result = Install-WindowsFeature Web-Server, Web-Scripting-Tools, Web-Mgmt-Console
Write-Host "IIS installed: $($result.Success). Restart needed: $($result.RestartNeeded)"

$os = Get-CimInstance Win32_OperatingSystem
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
Write-Host "Windows: $($os.Caption), build $($os.BuildNumber)"
Write-Host "IIS: $((Get-ItemProperty HKLM:\SOFTWARE\Microsoft\InetStp).VersionString)"
Write-Host ("Memory: {0:N1} GB in all, {1:N1} GB free" -f ($os.TotalVisibleMemorySize / 1MB), ($os.FreePhysicalMemory / 1MB))
Write-Host ("Disk C: {0:N0} GB free" -f ($disk.FreeSpace / 1GB))
Write-Host "Port 443 already in use by: $((Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { (Get-Process -Id $_.OwningProcess).ProcessName }) -join ', ')"
