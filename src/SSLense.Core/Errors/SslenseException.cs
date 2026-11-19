namespace SSLense.Core.Errors;

/// <summary>
/// An error SSLense explains, with its code in front of the message (docs/design/error-codes.md). It is an
/// <see cref="InvalidOperationException"/>, so code that catches those keeps working.
/// </summary>
public class SslenseException : InvalidOperationException
{
    public SslenseException(ErrorCode errorCode, string message, Exception? innerException = null)
        : base(errorCode.Format(message), innerException)
    {
        ErrorCode = errorCode;
    }

    public ErrorCode ErrorCode { get; }

    public string Code => ErrorCode.Code;
}
