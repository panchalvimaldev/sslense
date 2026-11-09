using System.Diagnostics;
using System.Text;

namespace SSLense.Core.DnsValidation;

/// <param name="Output">Standard output and error, interleaved, up to <see cref="PowerShellScriptRunner.MaxOutputChars"/>.</param>
/// <param name="TimedOut">True when the script was stopped for running too long; the exit code is then meaningless.</param>
internal sealed record ScriptRunResult(int ExitCode, string Output, bool TimedOut, TimeSpan Duration);

internal interface IScriptRunner
{
    /// <param name="arguments">Passed as a list, never parsed as one command line.</param>
    /// <param name="secret">Given to the script in <c>SSLENSE_DNS_SECRET</c>, never as an argument.</param>
    Task<ScriptRunResult> RunAsync(
        string scriptPath,
        IReadOnlyList<string> arguments,
        string? secret,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}

/// <summary>Runs a script with Windows PowerShell 5.1, which every supported Windows version has.</summary>
internal sealed class PowerShellScriptRunner : IScriptRunner
{
    public const string SecretVariable = "SSLENSE_DNS_SECRET";
    public const int MaxOutputChars = 64 * 1024;

    // The full path, so a powershell.exe earlier on PATH can never run in its place.
    private static string PowerShellPath =>
        Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");

    public async Task<ScriptRunResult> RunAsync(
        string scriptPath,
        IReadOnlyList<string> arguments,
        string? secret,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo(PowerShellPath)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(scriptPath)!
        };

        // A Group Policy execution policy still takes precedence over this per-process setting.
        foreach (var argument in (string[])["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scriptPath, .. arguments])
        {
            startInfo.ArgumentList.Add(argument);
        }

        startInfo.Environment.Remove(SecretVariable);
        if (!string.IsNullOrEmpty(secret))
        {
            startInfo.Environment[SecretVariable] = secret;
        }

        var output = new StringBuilder();
        void Append(object sender, DataReceivedEventArgs line)
        {
            if (line.Data is null)
            {
                return;
            }

            lock (output)
            {
                if (output.Length < MaxOutputChars)
                {
                    output.AppendLine(line.Data.Length > MaxOutputChars - output.Length ? line.Data[..(MaxOutputChars - output.Length)] : line.Data);
                }
            }
        }

        var stopwatch = Stopwatch.StartNew();
        using var process = new Process { StartInfo = startInfo };
        process.OutputDataReceived += Append;
        process.ErrorDataReceived += Append;
        process.Start();
        process.StandardInput.Close();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        var timedOut = false;
        try
        {
            await process.WaitForExitAsync(timeoutSource.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Child processes too: a script may have started a program that would otherwise keep running.
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
                // It exited at the same moment.
            }

            await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            timedOut = true;
        }

        // Waits for the last lines of redirected output.
        process.WaitForExit();
        string text;
        lock (output)
        {
            text = output.ToString();
        }

        return new ScriptRunResult(timedOut ? -1 : process.ExitCode, text, timedOut, stopwatch.Elapsed);
    }
}
