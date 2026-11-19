using System.IO;
using System.Text;
using SSLense.Core.Errors;
using Xunit;

namespace SSLense.Tests.Errors;

/// <summary>Error codes stay stable, documented and used (docs/design/error-codes.md).</summary>
public sealed class ErrorCodeTests
{
    private static readonly string Root = FindRoot();

    private static readonly Dictionary<char, string> Areas = new()
    {
        ['1'] = "IIS: sites, bindings, challenge files, the HTTPS check and rollback",
        ['2'] = "ACME and certificate authorities",
        ['3'] = "DNS validation",
        ['4'] = "Certificates: import, requests, the Windows store, keys and sharing",
        ['5'] = "Renewal, reminders and the service",
        ['6'] = "Settings, names and stored data",
        ['7'] = "Notifications",
        ['8'] = "Deployment steps",
        ['9'] = "Health check, diagnostics and unexpected errors"
    };

    [Fact]
    public void EveryCode_IsWellFormed_AndUnique()
    {
        Assert.All(ErrorCodes.All, code => Assert.Matches("^SSL[1-9][0-9]{3}$", code.Code));
        Assert.Equal(ErrorCodes.All.Count, ErrorCodes.All.Select(code => code.Code).Distinct().Count());
        Assert.Equal(ErrorCodes.All.Count, ErrorCodes.All.Select(code => code.Name).Distinct().Count());
        Assert.All(ErrorCodes.All, code => Assert.False(string.IsNullOrWhiteSpace(code.Title) || string.IsNullOrWhiteSpace(code.Help), code.Code));
        Assert.Equal(ErrorCodes.All.OrderBy(code => code.Code, StringComparer.Ordinal), ErrorCodes.All);
    }

    /// <summary>
    /// Every code ever issued keeps its meaning. A new code is added to issued-error-codes.txt; a line there is never
    /// changed or removed, because forum answers, monitoring rules and bug reports refer to it.
    /// </summary>
    [Fact]
    public void NoCodeIsEverRemovedOrRenamed_AndEveryNewOneIsRecorded()
    {
        var issued = File.ReadAllLines(Path.Combine(Root, "tests", "SSLense.Tests", "Errors", "issued-error-codes.txt"))
            .Where(line => line.Length > 0 && !line.StartsWith('#'))
            .Select(line => line.Split(' ', 2))
            .ToDictionary(parts => parts[0], parts => parts[1]);

        foreach (var (code, name) in issued)
        {
            var current = ErrorCodes.All.SingleOrDefault(value => value.Code == code);
            Assert.True(current is not null, $"{code} ({name}) was issued and must stay in the catalogue.");
            Assert.True(current!.Name == name, $"{code} was issued as {name}; it is now {current.Name}. Add a new code instead.");
        }

        var missing = ErrorCodes.All.Where(code => !issued.ContainsKey(code.Code)).Select(code => $"{code.Code} {code.Name}").ToArray();
        Assert.True(missing.Length == 0, "Add these lines to issued-error-codes.txt:\n" + string.Join("\n", missing));
    }

    /// <summary>docs/errors.md is generated from the catalogue. Run with SSLENSE_UPDATE_ERROR_DOCS=1 to write it.</summary>
    [Fact]
    public void TheErrorsPage_ListsExactlyTheCatalogue()
    {
        var path = Path.Combine(Root, "docs", "errors.md");
        var expected = RenderPage();
        if (Environment.GetEnvironmentVariable("SSLENSE_UPDATE_ERROR_DOCS") == "1")
        {
            File.WriteAllText(path, expected, new UTF8Encoding(false));
        }

        var actual = File.Exists(path) ? File.ReadAllText(path).ReplaceLineEndings("\n") : string.Empty;
        Assert.True(actual == expected, "docs/errors.md is out of date: run the tests with SSLENSE_UPDATE_ERROR_DOCS=1.");
    }

    /// <summary>New code in Core explains its errors with a code; a plain InvalidOperationException would have none.</summary>
    [Fact]
    public void Core_ThrowsNoErrorWithoutACode()
    {
        var offenders = Directory.EnumerateFiles(Path.Combine(Root, "src", "SSLense.Core"), "*.cs", SearchOption.AllDirectories)
            .Where(file => !file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .SelectMany(file => File.ReadLines(file).Select((line, index) => (file, line, index)))
            .Where(item => item.line.Contains("throw new InvalidOperationException(", StringComparison.Ordinal))
            .Select(item => $"{Path.GetRelativePath(Root, item.file)}:{item.index + 1}")
            .ToArray();

        Assert.True(offenders.Length == 0, "Throw an SslenseException with a code from ErrorCodes instead:\n" + string.Join("\n", offenders));
    }

    [Fact]
    public void AMessage_StartsWithItsCode_Once()
    {
        var exception = new SslenseException(ErrorCodes.IisSiteNotFound, "IIS site 'Shop' was not found.");

        Assert.Equal("SSL1001: IIS site 'Shop' was not found.", exception.Message);
        Assert.Equal("SSL1001", exception.Code);
        Assert.Equal(exception.Message, ErrorCodes.Unexpected.Format(exception.Message));
        Assert.Equal("SSL9999: Something odd.", ErrorCode.Describe(new IOException("Something odd.")));
        Assert.Same(ErrorCodes.IisSiteNotFound, ErrorCode.Of(exception.Message));
        Assert.Null(ErrorCode.Of("No code here."));
        Assert.EndsWith("errors.md#ssl1001", ErrorCodes.IisSiteNotFound.Link.ToString(), StringComparison.Ordinal);
    }

    private static string RenderPage()
    {
        var page = new StringBuilder();
        page.Append("# SSLense error codes\n\n")
            .Append("Every error SSLense explains starts with a code, such as `SSL1003`. The code is the same in the app, the command line, ")
            .Append("the log, notifications, the daily digest and the Windows Event Log, and it never changes meaning, so you can search ")
            .Append("for it. The first digit says where to look.\n\n")
            .Append("This page is generated from `src/SSLense.Core/Errors/ErrorCodes.cs`; do not edit it by hand.\n\n");
        foreach (var area in ErrorCodes.All.GroupBy(code => code.Code[3]))
        {
            page.Append($"## SSL{area.Key}xxx: {Areas[area.Key]}\n\n");
            foreach (var code in area)
            {
                page.Append($"<a id=\"{code.Code.ToLowerInvariant()}\"></a>\n\n### {code.Code}: {code.Title}\n\n{code.Help}\n\n");
            }
        }

        return page.ToString().TrimEnd('\n') + "\n";
    }

    private static string FindRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "SSLense.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new DirectoryNotFoundException("The repository root was not found.");
    }
}
