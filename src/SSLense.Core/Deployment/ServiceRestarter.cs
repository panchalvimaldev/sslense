using System.Diagnostics;
using System.Text.RegularExpressions;

namespace SSLense.Core.Deployment;

/// <summary>Restarts Windows services for deployment steps.</summary>
internal interface IServiceRestarter
{
    /// <summary>Whether a service with this name is installed.</summary>
    Task<bool> ExistsAsync(string serviceName, CancellationToken cancellationToken);

    /// <summary>Stops the service if it runs, starts it, and waits until it runs. Throws when it does not.</summary>
    Task RestartAsync(string serviceName, TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>Uses <c>sc.exe</c>, as SSLense does for its own service, so no package is needed.</summary>
internal sealed partial class ScServiceRestarter : IServiceRestarter
{
    private const int ServiceDoesNotExist = 1060;
    private const int ServiceNotActive = 1062;
    private const int ServiceAlreadyRunning = 1056;
    private const int Stopped = 1;
    private const int Running = 4;

    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(1);

    public static void ValidateName(string serviceName)
    {
        if (!SafeName().IsMatch(serviceName))
        {
            throw new ArgumentException(
                $"'{serviceName}' is not a service name. Use the service's name, such as 'MSSQLSERVER' or 'TermService', " +
                "not its display name.");
        }
    }

    public async Task<bool> ExistsAsync(string serviceName, CancellationToken cancellationToken)
    {
        ValidateName(serviceName);
        var (exitCode, _) = await RunScAsync(["query", serviceName], cancellationToken).ConfigureAwait(false);
        return exitCode != ServiceDoesNotExist;
    }

    public async Task RestartAsync(string serviceName, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ValidateName(serviceName);
        var (stopCode, stopOutput) = await RunScAsync(["stop", serviceName], cancellationToken).ConfigureAwait(false);
        if (stopCode is not (0 or ServiceNotActive))
        {
            throw new InvalidOperationException(Failure(serviceName, "stop", stopCode, stopOutput));
        }

        await WaitForStateAsync(serviceName, Stopped, "stop", timeout, cancellationToken).ConfigureAwait(false);

        var (startCode, startOutput) = await RunScAsync(["start", serviceName], cancellationToken).ConfigureAwait(false);
        if (startCode is not (0 or ServiceAlreadyRunning))
        {
            throw new InvalidOperationException(Failure(serviceName, "start", startCode, startOutput));
        }

        await WaitForStateAsync(serviceName, Running, "start", timeout, cancellationToken).ConfigureAwait(false);
    }

    private static async Task WaitForStateAsync(
        string serviceName,
        int wanted,
        string action,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (true)
        {
            var (exitCode, output) = await RunScAsync(["query", serviceName], cancellationToken).ConfigureAwait(false);
            var state = exitCode == 0 ? ParseState(output) : null;
            if (state == wanted)
            {
                return;
            }

            // A service that stops again while starting has failed; waiting longer would not help.
            if (wanted == Running && state == Stopped)
            {
                throw new InvalidOperationException(
                    $"The service '{serviceName}' stopped again after starting. Check the Windows Event Log for the reason.");
            }

            if (DateTimeOffset.UtcNow >= deadline)
            {
                throw new InvalidOperationException(
                    $"The service '{serviceName}' did not {action} within {timeout.TotalSeconds:0} seconds.");
            }

            await Task.Delay(PollInterval, cancellationToken).ConfigureAwait(false);
        }
    }

    internal static int? ParseState(string output)
    {
        var match = StateLine().Match(output);
        return match.Success ? int.Parse(match.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture) : null;
    }

    private static string Failure(string serviceName, string action, int exitCode, string output) =>
        $"The service '{serviceName}' could not {action} (sc.exe exit code {exitCode}). {output}".Trim();

    private static async Task<(int ExitCode, string Output)> RunScAsync(
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "sc.exe"),
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not start the Windows Service Control command.");
        var standardOutput = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var standardError = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        var output = string.Join(' ', await standardOutput.ConfigureAwait(false), await standardError.ConfigureAwait(false)).Trim();
        return (process.ExitCode, output);
    }

    [GeneratedRegex(@"^[A-Za-z0-9_.$-][A-Za-z0-9 _.$#@-]{0,255}$")]
    private static partial Regex SafeName();

    [GeneratedRegex(@"STATE\s*:\s*(\d+)")]
    private static partial Regex StateLine();
}
