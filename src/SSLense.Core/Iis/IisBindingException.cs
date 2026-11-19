using SSLense.Core.Errors;

namespace SSLense.Core.Iis;

/// <summary>
/// A binding change that failed: SSL1009 when the previous bindings were restored, SSL1019 when they could not all be.
/// </summary>
public sealed class IisBindingException : SslenseException
{
    public IisBindingException(string message, bool previousBindingsRestored, Exception innerException)
        : base(previousBindingsRestored ? ErrorCodes.HttpsBindingChangeFailed : ErrorCodes.BindingsNotRestored, message, innerException)
    {
        PreviousBindingsRestored = previousBindingsRestored;
    }

    public bool PreviousBindingsRestored { get; }
}
