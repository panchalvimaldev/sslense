using SSLense.Core;

namespace SSLense.Cli;

internal sealed class ConsoleProgress : IProgress<ProgressEvent>
{
    public void Report(ProgressEvent value) =>
        Console.WriteLine($"[{value.Step}] {value.Message}");
}
