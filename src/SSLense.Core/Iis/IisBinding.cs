namespace SSLense.Core.Iis;

public sealed record IisBinding(
    string Protocol,
    string IpAddress,
    int Port,
    string HostName,
    string? CertificateThumbprint,
    string? CertificateStoreName,
    bool UsesSni);
