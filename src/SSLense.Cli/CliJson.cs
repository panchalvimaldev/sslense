using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace SSLense.Cli;

/// <summary>What every command exits with (docs/automation.md). Scripts can rely on these.</summary>
internal static class CliExitCodes
{
    public const int Success = 0;

    /// <summary>The command ran and failed, or found a problem; the error says why, with its SSL code.</summary>
    public const int Failed = 1;

    /// <summary>The command line was not valid: an unknown command or option, or a missing or wrong value.</summary>
    public const int InvalidCommandLine = 2;

    /// <summary>The command must run as an administrator.</summary>
    public const int NotAdministrator = 3;
}

/// <summary>
/// The <c>--json</c> output: one JSON document for any command, with what it printed, its exit code, the error code if
/// one was shown, and for the main read commands its result as data (docs/automation.md).
/// </summary>
internal static partial class CliJson
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>The command's result, set by commands that have one to give.</summary>
    public static object? Data { get; set; }

    public static string Envelope(string command, int exitCode, string output, string errors)
    {
        return JsonSerializer.Serialize(
            new
            {
                Command = command,
                ExitCode = exitCode,
                Succeeded = exitCode == CliExitCodes.Success,
                ErrorCode = ErrorCodePattern().Match(errors) is { Success: true } match ? match.Value : null,
                Data,
                Output = Lines(output),
                Errors = Lines(errors)
            },
            SerializerOptions);
    }

    private static string[] Lines(string text) =>
        text.Split('\n').Select(line => line.TrimEnd('\r')).Where(line => line.Length > 0).ToArray();

    [GeneratedRegex(@"\bSSL\d{4}\b")]
    private static partial Regex ErrorCodePattern();
}
