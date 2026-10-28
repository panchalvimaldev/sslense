using SSLense.Core.Config;

namespace SSLense.Core.Certificates;

public enum CertificateTransactionStage
{
    Prepared = 0,
    CertificateImported = 1,
    BindingsUpdated = 2,
    StateSaved = 3
}

public sealed record CertificateTransaction(
    Guid Id,
    ManagedCertificate Certificate,
    string? PreviousThumbprint,
    CertificateTransactionStage Stage,
    DateTimeOffset StartedAt);
