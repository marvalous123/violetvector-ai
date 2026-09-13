using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace WARRoom.WindowsSensor;

public sealed record Security4663OneShotResultFileSlotPlan(
    int SchemaVersion,
    string Checkpoint,
    string ResultPath,
    string ParentRoot,
    int MaximumDocumentBytes,
    string OwnerSid,
    IReadOnlyList<string> FullControlSids,
    string ServiceSid,
    int ServiceRightsMask,
    bool RequiresAdministratorToCreate,
    bool RequiresPrecreatedEmptyFile,
    bool RequiresProtectedDacl,
    bool RejectsInheritedRules,
    bool RejectsReparsePoints,
    bool RejectsStaleContent,
    bool UsesOpenExisting,
    bool UsesOneExclusiveWriteThroughHandle,
    bool AllowsOverwrite,
    bool AllowsServiceCreate,
    bool AllowsServiceDelete,
    bool AllowsServiceAclChange,
    bool AllowsServiceDirectoryAccess,
    bool RetryEnabled,
    bool PollingEnabled,
    bool TransportEnabled,
    bool CommandChannelEnabled,
    bool RuntimeWired);

internal sealed record Security4663ResultFileRule(
    string Sid,
    int RightsMask,
    bool IsInherited,
    AccessControlType Type,
    InheritanceFlags Inheritance,
    PropagationFlags Propagation);

internal sealed record Security4663ResultFileAcl(
    string OwnerSid,
    bool IsProtected,
    IReadOnlyList<Security4663ResultFileRule> Rules);

internal static class Security4663OneShotResultFilePolicy
{
    internal const int MappedFullControl = 0x001F01FF;
    internal const int GenericAll = 0x10000000;
    internal const int LocalServiceWriteData = 0x00000002;

    internal static Security4663OneShotResultFileSlotPlan BuildPlan() => new(
        1,
        Readiness.Security4663OneShotMachinePlan.Checkpoint,
        NativeSecurity4663OneShotResultFileSlot.ResultPath,
        Readiness.Security4663ReadinessCeremony.FixtureRoot,
        Security4663OneShotResultLifecycle.MaximumDocumentBytes,
        "S-1-5-32-544",
        Array.AsReadOnly(["S-1-5-18", "S-1-5-32-544"]),
        "S-1-5-19",
        LocalServiceWriteData,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false);

    internal static void ValidatePlan(
        Security4663OneShotResultFileSlotPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var expected = BuildPlan();
        if (
            plan with { FullControlSids = expected.FullControlSids } != expected ||
            !plan.FullControlSids.SequenceEqual(
                expected.FullControlSids,
                StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_RESULT_SLOT_PLAN_INVALID");
        }
    }

    internal static FileSecurity CreateFileSecurity()
    {
        var security = new FileSecurity();
        // Use a raw mask for LocalService so the managed ACL constructor cannot
        // silently add Synchronize or any generic write authority.
        security.SetSecurityDescriptorSddlForm(
            "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x2;;;LS)",
            AccessControlSections.Access | AccessControlSections.Owner);
        return security;
    }

    internal static Security4663ResultFileAcl Snapshot(FileSecurity security)
    {
        ArgumentNullException.ThrowIfNull(security);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as
            SecurityIdentifier ?? throw InvalidAcl();
        var rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().Select(
                rule => new Security4663ResultFileRule(
                    rule.IdentityReference.Value,
                    unchecked((int)rule.FileSystemRights),
                    rule.IsInherited,
                    rule.AccessControlType,
                    rule.InheritanceFlags,
                    rule.PropagationFlags)).ToArray();
        return new Security4663ResultFileAcl(
            owner.Value,
            security.AreAccessRulesProtected,
            rules);
    }

    internal static void ValidateFileAcl(Security4663ResultFileAcl acl)
    {
        ArgumentNullException.ThrowIfNull(acl);
        if (
            acl.OwnerSid != "S-1-5-32-544" ||
            !acl.IsProtected ||
            acl.Rules.Count != 3)
        {
            throw InvalidAcl();
        }
        var expected = new Dictionary<string, Func<int, bool>>(
            StringComparer.Ordinal)
        {
            ["S-1-5-18"] = IsExactFullControl,
            ["S-1-5-32-544"] = IsExactFullControl,
            ["S-1-5-19"] = rights => rights == LocalServiceWriteData
        };
        foreach (var rule in acl.Rules)
        {
            if (
                rule.IsInherited ||
                rule.Type != AccessControlType.Allow ||
                rule.Inheritance != InheritanceFlags.None ||
                rule.Propagation != PropagationFlags.None ||
                !expected.Remove(rule.Sid, out var validateRights) ||
                !validateRights(rule.RightsMask))
            {
                throw InvalidAcl();
            }
        }
        if (expected.Count != 0)
        {
            throw InvalidAcl();
        }
    }

    internal static void AssertProtectedRoot()
    {
        var expectedRoot = Readiness.Security4663ReadinessCeremony.FixtureRoot;
        var parent = Path.GetDirectoryName(
            NativeSecurity4663OneShotResultFileSlot.ResultPath);
        if (!string.Equals(parent, expectedRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_SLOT_ROOT_INVALID");
        }
        var directory = new DirectoryInfo(expectedRoot);
        if (!directory.Exists ||
            directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_SLOT_ROOT_INVALID");
        }
        var security = directory.GetAccessControl(
            AccessControlSections.Access | AccessControlSections.Owner);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as
            SecurityIdentifier;
        var rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            "S-1-5-18", "S-1-5-32-544"
        };
        if (
            owner?.Value != "S-1-5-32-544" ||
            !security.AreAccessRulesProtected ||
            rules.Length != 2 ||
            rules.Any(rule =>
                rule.IsInherited ||
                rule.AccessControlType != AccessControlType.Allow ||
                !expected.Remove(rule.IdentityReference.Value) ||
                rule.InheritanceFlags !=
                    (InheritanceFlags.ContainerInherit |
                        InheritanceFlags.ObjectInherit) ||
                rule.PropagationFlags != PropagationFlags.None ||
                unchecked((int)rule.FileSystemRights) is not
                    (MappedFullControl or GenericAll)) ||
            expected.Count != 0)
        {
            throw Invalid(
                "SENSOR_C2E_SECURITY_4663_RESULT_SLOT_ROOT_ACL_INVALID");
        }
    }

    internal static void AssertProtectedFile(bool mustBeEmpty)
    {
        var file = new FileInfo(
            NativeSecurity4663OneShotResultFileSlot.ResultPath);
        if (
            !file.Exists ||
            file.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            file.Length < 0 ||
            file.Length > Security4663OneShotResultLifecycle.MaximumDocumentBytes ||
            (mustBeEmpty && file.Length != 0))
        {
            throw Invalid(
                "SENSOR_C2E_SECURITY_4663_RESULT_SLOT_FILE_INVALID");
        }
        ValidateFileAcl(Snapshot(file.GetAccessControl(
            AccessControlSections.Access | AccessControlSections.Owner)));
    }

    internal static void ValidateNativeFileState(
        uint attributes,
        long endOfFile,
        uint numberOfLinks,
        bool deletePending,
        bool directory)
    {
        const uint fileAttributeReparsePoint = 0x00000400;
        if (
            (attributes & fileAttributeReparsePoint) != 0 ||
            endOfFile != 0 ||
            numberOfLinks != 1 ||
            deletePending ||
            directory)
        {
            throw Invalid(
                "SENSOR_C2E_SECURITY_4663_RESULT_SLOT_STATE_INVALID");
        }
    }

    private static bool IsExactFullControl(int rights) => rights is
        MappedFullControl or GenericAll;

    private static InvalidDataException InvalidAcl() => new(
        "SENSOR_C2E_SECURITY_4663_RESULT_SLOT_ACL_INVALID");

    private static InvalidDataException Invalid(string code) => new(code);
}

// Elevated-only lifecycle for the fixed, pre-created empty result slot. The
// protected parent grants LocalService no directory authority; the file grants
// it only FILE_WRITE_DATA. Runtime code does not call this manager.
public sealed class NativeSecurity4663OneShotResultFileSlot
{
    public const string ResultPath =
        @"C:\ProgramData\WAR-R00M\Windows Sensor\C2\security-4663-one-shot-result.json";
    public const bool RuntimeWired = false;

    public void Prepare()
    {
        AssertAdministrator();
        Security4663OneShotResultFilePolicy.AssertProtectedRoot();
        if (PathExists())
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_SLOT_ALREADY_EXISTS");
        }
        var created = false;
        try
        {
            using (var stream = new FileStream(
                ResultPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                1,
                FileOptions.WriteThrough))
            {
                created = true;
                stream.Flush(flushToDisk: true);
            }
            new FileInfo(ResultPath).SetAccessControl(
                Security4663OneShotResultFilePolicy.CreateFileSecurity());
            Security4663OneShotResultFilePolicy.AssertProtectedFile(
                mustBeEmpty: true);
        }
        catch
        {
            if (created)
            {
                DeleteFailedCreation();
            }
            throw;
        }
    }

    public bool RemoveForRecovery()
    {
        return new NativeSecurity4663OneShotResultOperatorStore()
            .CleanupBoundedProtected();
    }

    private static void AssertAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(
            WindowsBuiltInRole.Administrator))
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_SLOT_ADMIN_REQUIRED");
        }
    }

    private static bool PathExists() =>
        File.Exists(ResultPath) || Directory.Exists(ResultPath);

    private static void DeleteFailedCreation()
    {
        try
        {
            if (File.Exists(ResultPath) &&
                !File.GetAttributes(ResultPath).HasFlag(
                    FileAttributes.ReparsePoint))
            {
                File.Delete(ResultPath);
            }
        }
        catch
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_SLOT_CLEANUP_INVALID");
        }
    }

    private static InvalidDataException Invalid(string code) => new(code);
}

// LocalService write boundary for the pre-created slot. ReadExisting is a
// deliberate no-I/O empty-slot sentinel used by the pure lifecycle; WriteNew
// performs all native validation and persistence through one exclusive,
// write-through OPEN_EXISTING handle. Validation is completed externally.
public sealed class NativeSecurity4663OneShotResultFileStore :
    ISecurity4663OneShotResultStore
{
    public const bool RuntimeWired = false;

    private const uint FileWriteData = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FileFlagWriteThrough = 0x80000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const int FileAttributeTagInfoClass = 9;
    private const int FileStandardInfoClass = 1;

    public string? ReadExisting() => null;

    public void WriteNew(string json)
    {
        var bytes = ValidateDocument(json);
        try
        {
            using var handle = CreateFileW(
                NativeSecurity4663OneShotResultFileSlot.ResultPath,
                FileWriteData,
                0,
                IntPtr.Zero,
                OpenExisting,
                FileFlagWriteThrough | FileFlagOpenReparsePoint,
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_SLOT_OPEN_INVALID");
            }
            if (
                !GetFileInformationByHandleEx(
                    handle,
                    FileAttributeTagInfoClass,
                    out FileAttributeTagInfo tag,
                    Marshal.SizeOf<FileAttributeTagInfo>()) ||
                !GetFileInformationByHandleEx(
                    handle,
                    FileStandardInfoClass,
                    out FileStandardInfo standard,
                    Marshal.SizeOf<FileStandardInfo>()))
            {
                throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_SLOT_STATE_INVALID");
            }
            Security4663OneShotResultFilePolicy.ValidateNativeFileState(
                tag.FileAttributes,
                standard.EndOfFile,
                standard.NumberOfLinks,
                standard.DeletePending,
                standard.Directory);
            if (!WriteFile(
                    handle,
                    bytes,
                    checked((uint)bytes.Length),
                    out var written,
                    IntPtr.Zero) ||
                written != (uint)bytes.Length ||
                !FlushFileBuffers(handle))
            {
                throw new InvalidDataException(
                    "SENSOR_C2E_SECURITY_4663_RESULT_SLOT_WRITE_INVALID",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public void ConsumeExact(string expectedJson) => throw Invalid(
        "SENSOR_C2E_SECURITY_4663_RESULT_SLOT_CONSUME_FORBIDDEN");

    private static byte[] ValidateDocument(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_SLOT_INPUT_INVALID");
        }
        var bytes = new UTF8Encoding(
            encoderShouldEmitUTF8Identifier: false,
            throwOnInvalidBytes: true).GetBytes(json);
        if (
            bytes.Length is < 1 or >
                Security4663OneShotResultLifecycle.MaximumDocumentBytes ||
            HasUtf8Bom(bytes))
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_SLOT_INPUT_INVALID");
        }
        return bytes;
    }

    private static bool HasUtf8Bom(ReadOnlySpan<byte> bytes) =>
        bytes.Length >= 3 &&
        bytes[0] == 0xEF &&
        bytes[1] == 0xBB &&
        bytes[2] == 0xBF;

    private static InvalidDataException Invalid(string code) => new(code);

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo
    {
        internal uint FileAttributes;
        internal uint ReparseTag;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileStandardInfo
    {
        internal long AllocationSize;
        internal long EndOfFile;
        internal uint NumberOfLinks;
        [MarshalAs(UnmanagedType.U1)]
        internal bool DeletePending;
        [MarshalAs(UnmanagedType.U1)]
        internal bool Directory;
    }

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true,
        ExactSpelling = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle hFile,
        int fileInformationClass,
        out FileAttributeTagInfo lpFileInformation,
        int dwBufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle hFile,
        int fileInformationClass,
        out FileStandardInfo lpFileInformation,
        int dwBufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WriteFile(
        SafeFileHandle hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToWrite,
        out uint lpNumberOfBytesWritten,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlushFileBuffers(SafeFileHandle hFile);
}
