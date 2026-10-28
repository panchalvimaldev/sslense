using System.Diagnostics;
using SSLense.Core.Config;

namespace SSLense.Core.WindowsServices;

internal sealed class WindowsServiceManager(IFileSystem fileSystem) : IWindowsServiceManager
{
    public const string ServiceName = "SSLense";

    public async Task<WindowsServiceStatus> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        var result = await RunScAsync(["query", ServiceName], cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            return WindowsServiceStatus.NotInstalled;
        }

        if (result.Output.Contains("RUNNING", StringComparison.OrdinalIgnoreCase))
        {
            return WindowsServiceStatus.Running;
        }

        if (result.Output.Contains("STOPPED", StringComparison.OrdinalIgnoreCase))
        {
            return WindowsServiceStatus.Stopped;
        }

        if (result.Output.Contains("PENDING", StringComparison.OrdinalIgnoreCase))
        {
            return WindowsServiceStatus.Pending;
        }

        return WindowsServiceStatus.Unknown;
    }

    public async Task InstallAsync(
        string executablePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        var fullPath = Path.GetFullPath(executablePath);
        if (!fileSystem.FileExists(fullPath))
        {
            throw new FileNotFoundException(
                "The SSLense service executable was not found. Publish SSLense.Service first, then pass its path with --service-path.",
                fullPath);
        }

        var query = await RunScAsync(["query", ServiceName], cancellationToken).ConfigureAwait(false);
        var verb = query.ExitCode == 0 ? "config" : "create";
        await RunRequiredScAsync(
            [verb, ServiceName, "binPath=", $"\"{fullPath}\"", "start=", "auto", "DisplayName=", "SSLense Renewal Service"],
            cancellationToken).ConfigureAwait(false);
        await RunRequiredScAsync(
            ["description", ServiceName, "Renews SSLense-managed IIS certificates using Let's Encrypt."],
            cancellationToken).ConfigureAwait(false);

        // Restart one minute after each of the first three unexpected exits; reset the count daily.
        // Matches the MSI (util:ServiceConfig supports a single delay).
        await RunRequiredScAsync(
            ["failure", ServiceName, "reset=", "86400", "actions=", "restart/60000/restart/60000/restart/60000"],
            cancellationToken).ConfigureAwait(false);

        var start = await RunScAsync(["start", ServiceName], cancellationToken).ConfigureAwait(false);
        if (start.ExitCode != 0 && !start.Output.Contains("1056", StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"The service was installed but could not be started. {start.Output}".Trim());
        }
    }

    public async Task UninstallAsync(CancellationToken cancellationToken = default)
    {
        var query = await RunScAsync(["query", ServiceName], cancellationToken).ConfigureAwait(false);
        if (query.ExitCode != 0)
        {
            return;
        }

        _ = await RunScAsync(["stop", ServiceName], cancellationToken).ConfigureAwait(false);
        await RunRequiredScAsync(["delete", ServiceName], cancellationToken).ConfigureAwait(false);
    }

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        var status = await GetStatusAsync(cancellationToken).ConfigureAwait(false);
        if (status == WindowsServiceStatus.NotInstalled)
        {
            throw new InvalidOperationException("The SSLense service is not installed.");
        }

        if (status != WindowsServiceStatus.Running)
        {
            await RunRequiredScAsync(["start", ServiceName], cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        var status = await GetStatusAsync(cancellationToken).ConfigureAwait(false);
        if (status == WindowsServiceStatus.NotInstalled || status == WindowsServiceStatus.Stopped)
        {
            return;
        }

        await RunRequiredScAsync(["stop", ServiceName], cancellationToken).ConfigureAwait(false);
    }

    private static async Task RunRequiredScAsync(
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        var result = await RunScAsync(arguments, cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"Windows service command failed. Run SSLense as Administrator. {result.Output}".Trim());
        }
    }

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
}
