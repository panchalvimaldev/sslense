@{
    RootModule        = 'SSLense.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '5d0f3a52-8a0e-4c1b-9b8e-3f2a6c7d4e11'
    Author            = 'SSLense contributors'
    Description       = 'Automate SSLense certificates for IIS from PowerShell: a script module over SSLense.Cli --json.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-Sslense', 'Get-SslenseCertificate', 'Get-SslenseSite', 'Get-SslenseHistory', 'Test-SslenseHealth',
        'Invoke-SslenseRenewal', 'Undo-SslenseCertificate', 'Export-SslenseConfig', 'Import-SslenseConfig')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{ PSData = @{ LicenseUri = 'https://github.com/panchalvimaldev/sslense/blob/main/LICENSE'; ProjectUri = 'https://github.com/panchalvimaldev/sslense' } }
}
