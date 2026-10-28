using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace SSLense.Core.Config;

/// <summary>
/// Restricts <see cref="AppPaths.DataDirectory"/> to Administrators and SYSTEM. DPAPI LocalMachine
/// protection lets any local account decrypt a blob it can read, so these ACLs are the real boundary
/// protecting the ACME account keys and notification secrets.
/// </summary>
public static class DataDirectorySecurity
{
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);

    /// <summary>
    /// Applies the restricted ACL to the data directory and resets everything inside it to inherit that ACL.
    /// Requires elevation. If the directory contains links or multi-link files, nothing is changed and they
    /// are returned for an administrator to remove; otherwise the result is empty.
    /// </summary>
    public static IReadOnlyList<string> Secure() =>
        Secure(AppPaths.DataDirectory, takeOwnership: true, additionalPrincipals: []);

    /// <summary>
    /// Startup entry point for the service, GUI, and CLI: secures the directory when elevated and never throws.
    /// Returns warnings to log once logging is available.
    /// </summary>
    public static IReadOnlyList<string> SecureAtStartup()
    {
        if (!WindowsElevation.IsAdministrator())
        {
            return [];
        }

        try
        {
            return Secure();
        }
        catch (Exception exception)
        {
            return [$"The SSLense data directory '{AppPaths.DataDirectory}' could not be secured: {exception.Message}"];
        }
    }

    /// <summary>Reports every deviation from the restricted ACL without changing anything.</summary>
    public static IReadOnlyList<string> Verify() => Verify(AppPaths.DataDirectory, additionalPrincipals: []);

    internal static IReadOnlyList<string> Secure(
        string path,
        bool takeOwnership,
        IReadOnlyList<SecurityIdentifier> additionalPrincipals)
    {
        var root = Directory.CreateDirectory(path);
        ThrowIfReparsePoint(root);

        // Windows propagates a directory's inheritable ACEs through the whole tree on its own, including into
        // junction targets and hard-linked files. If anything inside could reach outside, change nothing.
        var blocked = new List<string>();
        var entries = EnumerateSafely(root, blocked).ToList();
        if (blocked.Count > 0)
        {
            blocked.Add($"No permissions were changed under '{root.FullName}'. Remove the items above, then start SSLense again.");
            return blocked;
        }

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var principal in AllowedPrincipals(additionalPrincipals))
        {
            security.AddAccessRule(new FileSystemAccessRule(
                principal,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        if (takeOwnership)
        {
            security.SetOwner(Administrators);
        }

        root.SetAccessControl(security);

        // Parents first, so each directory is readable through its new inherited rules before its children change.
        foreach (var entry in entries)
        {
            ResetToInherited(entry, takeOwnership);
        }

        return [];
    }

    internal static IReadOnlyList<string> Verify(string path, IReadOnlyList<SecurityIdentifier> additionalPrincipals)
    {
        var problems = new List<string>();
        var root = new DirectoryInfo(path);
        if (!root.Exists)
        {
            return problems;
        }

        ThrowIfReparsePoint(root);
        var allowed = AllowedPrincipals(additionalPrincipals).ToHashSet();
        var rootSecurity = root.GetAccessControl();
        if (!rootSecurity.AreAccessRulesProtected)
        {
            problems.Add($"'{root.FullName}' inherits permissions from its parent folder.");
        }

        CheckSecurity(root.FullName, rootSecurity, allowed, problems);
        foreach (var entry in EnumerateSafely(root, problems))
        {
            CheckSecurity(
                entry.FullName,
                entry is DirectoryInfo directory ? directory.GetAccessControl() : ((FileInfo)entry).GetAccessControl(),
                allowed,
                problems);
        }

        return problems;
    }

    private static IEnumerable<SecurityIdentifier> AllowedPrincipals(IReadOnlyList<SecurityIdentifier> additional) =>
        new[] { Administrators, LocalSystem }.Concat(additional).Distinct();

    private static void CheckSecurity(
        string path,
        FileSystemSecurity security,
        IReadOnlySet<SecurityIdentifier> allowed,
        List<string> problems)
    {
        if (security.GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier owner && !allowed.Contains(owner))
        {
            problems.Add($"'{path}' is owned by {Describe(owner)}, which can change its permissions.");
        }

        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow &&
                rule.IdentityReference is SecurityIdentifier sid &&
                !allowed.Contains(sid))
            {
                problems.Add($"'{path}' grants {rule.FileSystemRights} to {Describe(sid)}.");
            }
        }
    }

    /// <summary>
    /// Walks the tree without following reparse points, and holds back files with more than one hard link.
    /// Changing either would change the ACL of an object outside the data directory.
    /// </summary>
    private static IEnumerable<FileSystemInfo> EnumerateSafely(DirectoryInfo root, List<string> skipped)
    {
        var pending = new Stack<DirectoryInfo>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            foreach (var entry in pending.Pop().EnumerateFileSystemInfos())
            {
                if (entry.Attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    skipped.Add($"'{entry.FullName}' is a link or junction. SSLense never creates links in its data directory; remove it.");
                    continue;
                }

                if (entry is FileInfo file && GetLinkCount(file.FullName) > 1)
                {
                    skipped.Add($"'{entry.FullName}' has more than one hard link, so its permissions are shared with another path. SSLense never creates hard links; remove it.");
                    continue;
                }

                if (entry is DirectoryInfo directory)
                {
                    pending.Push(directory);
                }

                yield return entry;
            }
        }
    }

    private static void ResetToInherited(FileSystemInfo entry, bool takeOwnership)
    {
        // An empty, unprotected DACL leaves only the rules inherited from the restricted root.
        FileSystemSecurity security = entry is DirectoryInfo ? new DirectorySecurity() : new FileSecurity();
        security.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
        if (takeOwnership)
        {
            // A previous owner keeps implicit rights to rewrite the DACL, so ownership must move too.
            security.SetOwner(Administrators);
        }

        if (entry is DirectoryInfo directory)
        {
            directory.SetAccessControl((DirectorySecurity)security);
        }
        else
        {
            ((FileInfo)entry).SetAccessControl((FileSecurity)security);
        }
    }

    private static void ThrowIfReparsePoint(DirectoryInfo directory)
    {
        if (directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidOperationException(
                $"The SSLense data directory '{directory.FullName}' is a link or junction. " +
                "Remove it and let SSLense recreate the directory.");
        }
    }

    private static string Describe(SecurityIdentifier sid)
    {
        try
        {
            return $"{sid.Translate(typeof(NTAccount)).Value} ({sid.Value})";
        }
        catch (IdentityNotMappedException)
        {
            return sid.Value;
        }
    }

    private static uint GetLinkCount(string path)
    {
        // Attribute-only access never conflicts with lock files that other SSLense processes hold open.
        using var handle = CreateFile(
            path,
            FileReadAttributes,
            FileShareAll,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid || !GetFileInformationByHandle(handle, out var information))
        {
            throw new IOException(
                $"Could not inspect '{path}' while securing the SSLense data directory.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }

        return information.NumberOfLinks;
    }

    private const uint FileReadAttributes = 0x80;
    private const uint FileShareAll = 0x1 | 0x2 | 0x4;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;

    // FILETIME is two DWORDs, so the native struct is 4-byte aligned; Pack = 4 keeps the longs at those offsets.
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private readonly struct ByHandleFileInformation
    {
        public readonly uint FileAttributes;
        public readonly long CreationTime;
        public readonly long LastAccessTime;
        public readonly long LastWriteTime;
        public readonly uint VolumeSerialNumber;
        public readonly uint FileSizeHigh;
        public readonly uint FileSizeLow;
        public readonly uint NumberOfLinks;
        public readonly uint FileIndexHigh;
        public readonly uint FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation information);
}
