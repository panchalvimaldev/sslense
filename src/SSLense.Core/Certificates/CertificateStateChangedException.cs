using SSLense.Core.Errors;

namespace SSLense.Core.Certificates;

public sealed class CertificateStateChangedException : SslenseException
{
    public CertificateStateChangedException(string message) : base(ErrorCodes.CertificateStateChanged, message)
    {
    }
}
