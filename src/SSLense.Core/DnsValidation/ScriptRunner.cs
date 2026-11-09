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
        using var process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
        var exited = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        process.Exited += (_, _) => exited.TrySetResult();
        process.OutputDataReceived += Append;
        process.ErrorDataReceived += Append;

        // Everything the script starts joins this job, so it can all be stopped, even after the script itself exits.
        using var job = new ProcessJob();
        process.Start();
        try
        {
            job.Add(process);
        }
        catch
        {
            process.Kill(entireProcessTree: true);
            throw;
        }

        process.StandardInput.Close();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        // Waits for the script itself, not for its output to end: a program it left running can hold the output open.
        var timedOut = false;
        var deadline = Task.Delay(timeout, cancellationToken);
        if (await Task.WhenAny(exited.Task, deadline).ConfigureAwait(false) != exited.Task)
        {
            job.Terminate();
            try
            {
                await exited.Task.WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None).ConfigureAwait(false);
            }
            catch (System.TimeoutException)
            {
                // Windows did not end it in time; the job closing below ends it.
            }

            cancellationToken.ThrowIfCancellationRequested();
            timedOut = true;
        }

        // Anything the script left running is stopped, which also closes the output, so the last lines arrive.
        job.Terminate();
        try
        {
            await process.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }
        catch (System.TimeoutException)
        {
            // The output stays incomplete rather than letting the wait run on.
        }

        string text;
        lock (output)
        {
            text = output.ToString();
        }

        return new ScriptRunResult(timedOut ? -1 : process.ExitCode, text, timedOut, stopwatch.Elapsed);
    }
}
