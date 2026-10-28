namespace SSLense.Core.Certificates;

public sealed class CertificateStateChangedException : InvalidOperationException
{
    public CertificateStateChangedException(string message) : base(message)
    {
    }
}
