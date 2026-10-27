namespace SSLense.Core.Acme;

public sealed record CertificateBundle(string CertificatePem, byte[] PfxBytes);
