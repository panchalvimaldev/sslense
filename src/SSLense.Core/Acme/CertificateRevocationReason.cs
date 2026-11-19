namespace SSLense.Core.Acme;

/// <summary>Why a certificate is revoked; the RFC 5280 reasons Let's Encrypt and most ACME CAs accept.</summary>
public enum CertificateRevocationReason
{
    Unspecified = 0,

    /// <summary>The private key was exposed: the CA may also block the key from future certificates.</summary>
    KeyCompromise = 1,

    /// <summary>Replaced by another certificate, for example after a name change.</summary>
    Superseded = 4,

    /// <summary>No longer used.</summary>
    CessationOfOperation = 5
}
