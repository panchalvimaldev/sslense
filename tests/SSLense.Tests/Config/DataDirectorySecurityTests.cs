using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using SSLense.Core.Config;
using Xunit;

namespace SSLense.Tests.Config;

/// <summary>
/// Runs against real NTFS directories. The test process is usually not elevated, so it keeps itself
/// in the ACL (to clean up) and skips taking ownership, which needs elevation.
/// </summary>
public sealed class DataDirectorySecurityTests : IDisposable
{
    private static readonly SecurityIdentifier CurrentUser = WindowsIdentity.GetCurrent().User!;
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);

    private readonly string _workspace = Path.Combine(Path.GetTempPath(), $"sslense-acl-{Guid.NewGuid():N}");
    private readonly string _dataDirectory;

    public DataDirectorySecurityTests()
    {
        _dataDirectory = Path.Combine(_workspace, "data");
        Directory.CreateDirectory(_dataDirectory);
    }

    [Fact]
    public void Secure_RestrictsRootAndResetsChildrenToInherit()
    {
        Directory.CreateDirectory(Path.Combine(_dataDirectory, "logs"));
        var secret = Path.Combine(_dataDirectory, "account-key.staging.dat");
        File.WriteAllText(secret, "protected");
        GrantUsersRead(secret);

        var skipped = Secure();

        Assert.Empty(skipped);
        Assert.Empty(DataDirectorySecurity.Verify(_dataDirectory, [CurrentUser]));
        Assert.True(new DirectoryInfo(_dataDirectory).GetAccessControl().AreAccessRulesProtected);
        Assert.Empty(new FileInfo(secret).GetAccessControl().GetAccessRules(true, false, typeof(SecurityIdentifier)));
    }

    [Fact]
    public void Verify_DefaultInheritedDirectory_ReportsProblems()
    {
        var problems = DataDirectorySecurity.Verify(_dataDirectory, []);

        Assert.Contains(problems, problem => problem.Contains("inherits permissions", StringComparison.Ordinal));
        Assert.Contains(problems, problem => problem.Contains(CurrentUser.Value, StringComparison.Ordinal));
    }

    [Fact]
    public void Secure_PlantedJunction_IsReportedAndItsTargetIsUntouched()
    {
        var outside = Directory.CreateDirectory(Path.Combine(_workspace, "outside")).FullName;
        var outsideFile = Path.Combine(outside, "victim.txt");
        File.WriteAllText(outsideFile, "outside");
        GrantUsersRead(outsideFile);
        var before = Sddl(outsideFile);
        RunCmd($"mklink /J \"{Path.Combine(_dataDirectory, "planted")}\" \"{outside}\"");

        var skipped = Secure();

        Assert.Contains(skipped, problem => problem.Contains("link or junction", StringComparison.Ordinal));
        AssertNothingChanged(skipped);
        Assert.Equal(before, Sddl(outsideFile));
    }

    [Fact]
    public void Secure_PlantedHardLink_IsReportedAndTheSharedFileIsUntouched()
    {
        var outsideFile = Path.Combine(Directory.CreateDirectory(Path.Combine(_workspace, "outside")).FullName, "victim.txt");
        File.WriteAllText(outsideFile, "outside");
        GrantUsersRead(outsideFile);
        var before = Sddl(outsideFile);
        RunCmd($"mklink /H \"{Path.Combine(_dataDirectory, "planted.dat")}\" \"{outsideFile}\"");

        var skipped = Secure();

        Assert.Contains(skipped, problem => problem.Contains("hard link", StringComparison.Ordinal));
        AssertNothingChanged(skipped);
        Assert.Equal(before, Sddl(outsideFile));
    }

    public void Dispose()
    {
        if (!Directory.Exists(_workspace))
        {
            return;
        }

        try
        {
            Directory.Delete(_workspace, recursive: true);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or IOException)
        {
            // Directory.Delete cannot remove mklink /J junctions; depending on the Windows build it fails with
            // "access denied" or "the parameter is incorrect". rmdir removes the link without following it.
            RunCmd($"rmdir /s /q \"{_workspace}\"");
        }
    }

    private void AssertNothingChanged(IReadOnlyList<string> result)
    {
        Assert.Contains(result, problem => problem.Contains("No permissions were changed", StringComparison.Ordinal));
        Assert.False(new DirectoryInfo(_dataDirectory).GetAccessControl().AreAccessRulesProtected);
    }

    private IReadOnlyList<string> Secure() =>
        DataDirectorySecurity.Secure(_dataDirectory, takeOwnership: false, additionalPrincipals: [CurrentUser]);

    private static void GrantUsersRead(string path)
    {
        var file = new FileInfo(path);
        var security = file.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.Read, AccessControlType.Allow));
        file.SetAccessControl(security);
    }

    private static string Sddl(string path) =>
        new FileInfo(path).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access);

    private static void RunCmd(string command)
    {
        using var process = Process.Start(new ProcessStartInfo("cmd.exe", $"/c {command}")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        })!;
        process.WaitForExit();
        Assert.True(process.ExitCode == 0, process.StandardError.ReadToEnd());
    }
}
