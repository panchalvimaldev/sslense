namespace SSLense.Core.Iis;

public sealed class IisBindingException : InvalidOperationException
{
    public IisBindingException(string message, bool previousBindingsRestored, Exception innerException)
        : base(message, innerException)
    {
        PreviousBindingsRestored = previousBindingsRestored;
    }

    public bool PreviousBindingsRestored { get; }
}
