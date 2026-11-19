using System.Text.RegularExpressions;

namespace SSLense.Core.Errors;

/// <summary>
/// A stable code for one kind of error, such as SSL1003, with what it means and what to do
/// (docs/design/error-codes.md). The code starts every message of that kind, so it reaches the app, the CLI, the log,
/// notifications and the Event Log unchanged.
/// </summary>
/// <param name="Code">SSL and four digits; the first digit is the area.</param>
/// <param name="Name">The catalogue entry's name, for the documentation.</param>
/// <param name="Title">A short name for the error.</param>
/// <param name="Help">What usually causes it and what to do.</param>
public sealed partial record ErrorCode(string Code, string Name, string Title, string Help)
{
    /// <summary>Where docs/errors.md is published; each code is an anchor on it.</summary>
    public const string DocumentationUrl = "https://github.com/panchalvimaldev/sslense/blob/main/docs/errors.md";

    /// <summary>The message with this code in front, unless it already starts with a code.</summary>
    public string Format(string message) => StartsWithCode(message) ? message : $"{Code}: {message}";

    /// <summary>The link to this code's entry in the documentation.</summary>
    public Uri Link => new($"{DocumentationUrl}#{Code.ToLowerInvariant()}");

    public override string ToString() => Code;

    /// <summary>The code a message starts with, such as SSL1003, or null.</summary>
    public static string? CodeOf(string? message) =>
        message is not null && Prefix().Match(message) is { Success: true } match ? match.Groups[1].Value : null;

    /// <summary>The catalogue entry for the code a message starts with, or null.</summary>
    public static ErrorCode? Of(string? message) =>
        CodeOf(message) is { } code ? ErrorCodes.All.FirstOrDefault(value => value.Code == code) : null;

    /// <summary>
    /// The message of an error to show: with its code, or as SSL9999 when SSLense did not expect it, so every error
    /// shown has a code.
    /// </summary>
    public static string Describe(Exception exception) => ErrorCodes.Unexpected.Format(exception.Message);

    private static bool StartsWithCode(string message) => Prefix().IsMatch(message);

    [GeneratedRegex(@"^(SSL\d{4}): ")]
    private static partial Regex Prefix();
}
