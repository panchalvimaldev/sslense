using System.Security.Principal;
using SSLense.Acceptance;

// Checks on real IIS that unit tests cannot make. See README.md in this folder.
var command = args.FirstOrDefault()?.ToLowerInvariant();
if (command is not ("parta" or "partb" or "appsetup" or "servicecheck" or "httpcheck" or "restore"))
{
    Console.WriteLine("Usage: SSLense.Acceptance parta");
    Console.WriteLine("       SSLense.Acceptance partb --zone example.com [--cli path] [--installed path] [--out folder]");
    Console.WriteLine("       SSLense.Acceptance appsetup --zone example.com [--cli path] [--out folder]");
    Console.WriteLine("       SSLense.Acceptance servicecheck --zone example.com [--cli path] [--out folder]");
    Console.WriteLine("       SSLense.Acceptance httpcheck --zone example.com [--cli path] [--out folder]");
    Console.WriteLine("       SSLense.Acceptance restore [--cli path] [--out folder]");
    return 2;
}

string? Option(string name)
{
    var index = Array.IndexOf(args, name);
    return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
}

using var identity = WindowsIdentity.GetCurrent();
if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
{
    Console.WriteLine("Run this from an Administrator terminal.");
    return 2;
}

var resultFile = Path.Combine(Option("--out") ?? Environment.CurrentDirectory, $"result-{command}.txt");
Report.Open(resultFile);
try
{
    if (command != "parta")
    {
        PartB.Configure(Option("--zone"), Option("--cli"), Option("--installed"));
    }

    switch (command)
    {
        case "parta":
            await PartA.RunAsync();
            break;
        case "partb":
            await PartB.RunAsync();
            break;
        case "appsetup":
            await PartB.SetUpForAppAsync();
            break;
        case "servicecheck":
            await PartB.ServiceCheckAsync();
            break;
        case "httpcheck":
            await PartB.HttpCheckAsync();
            break;
        default:
            await PartB.RestoreAsync();
            break;
    }
}
catch (Exception exception)
{
    Report.Check("Run finished without an unexpected error", false, $"{exception.GetType().Name}: {exception.Message}");
}

var exitCode = Report.Finish();
Console.WriteLine($"Saved to {resultFile}");
return exitCode;
