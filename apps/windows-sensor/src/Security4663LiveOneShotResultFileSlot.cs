using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace WARRoom.WindowsSensor;

public sealed record Security4663LiveOneShotResultFileSlotPlan(
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
    bool RejectsHardLinks,
    bool RejectsStaleContent,
    bool UsesOpenExisting,
    bool UsesOneExclusiveWriteThroughHandle,
    bool ServiceCallsFlushFileBuffers,
    bool AllowsOverwrite,
    bool AllowsServiceRead,
    bool AllowsServiceAttributeRead,
    bool AllowsServiceCreate,
    bool AllowsServiceDelete,
    bool AllowsServiceAclChange,
    bool AllowsServiceDirectoryAccess,
    bool RetryEnabled,
    bool PollingEnabled,
    bool TransportEnabled,
    bool CommandChannelEnabled,
    bool RuntimeWired);

internal sealed record Security4663LiveResultFileRule(
    string Sid,
    int RightsMask,
    bool IsInherited,
    AccessControlType Type,
    InheritanceFlags Inheritance,
    PropagationFlags Propagation);

internal sealed record Security4663LiveResultFileAcl(
    string OwnerSid,
    bool IsProtected,
    IReadOnlyList<Security4663LiveResultFileRule> Rules);

internal sealed record Security4663LiveResultNativeFileState(
    uint Attributes,
    long Length,
    uint NumberOfLinks,
    bool DeletePending,
    bool Directory);

internal static class Security4663LiveOneShotResultFilePolicy
{
    internal const int MappedFullControl = 0x001F01FF;
    internal const int GenericAll = 0x10000000;
    internal const int LocalServiceSynchronousWriteAndReadAttributes =
        0x00100082;
    private const uint FileAttributeReparsePoint = 0x00000400;

    internal static Security4663LiveOneShotResultFileSlotPlan BuildPlan() =>
        new(
            1,
            Security4663LiveOneShotResultLifecycle.Checkpoint,
            NativeSecurity4663LiveOneShotResultFileSlot.ResultPath,
            Readiness.Security4663ReadinessCeremony.FixtureRoot,
            Security4663LiveOneShotResultLifecycle.MaximumDocumentBytes,
            "S-1-5-32-544",
            Array.AsReadOnly(["S-1-5-18", "S-1-5-32-544"]),
            "S-1-5-19",
            LocalServiceSynchronousWriteAndReadAttributes,
            true,
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
            true,
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
        Security4663LiveOneShotResultFileSlotPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var expected = BuildPlan();
        if (
            plan with { FullControlSids = expected.FullControlSids } != expected ||
            !plan.FullControlSids.SequenceEqual(
                expected.FullControlSids,
                StringComparer.Ordinal))
        {
            throw Invalid(
                "SENSOR_C2F_SECURITY_4663_RESULT_SLOT_PLAN_INVALID");
        }
    }

    internal static FileSecurity CreateFileSecurity()
    {
        var security = new FileSecurity();
        security.SetSecurityDescriptorSddlForm(
            "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x100082;;;LS)",
            AccessControlSections.Access | AccessControlSections.Owner);
        return security;
    }

    internal static Security4663LiveResultFileAcl Snapshot(
        FileSecurity security)
    {
        ArgumentNullException.ThrowIfNull(security);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as
            SecurityIdentifier ?? throw Invalid(
                "SENSOR_C2F_SECURITY_4663_RESULT_SLOT_ACL_INVALID");
        var rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().Select(
                rule => new Security4663LiveResultFileRule(
                    rule.IdentityReference.Value,
                    unchecked((int)rule.FileSystemRights),
                    rule.IsInherited,
                    rule.AccessControlType,
                    rule.InheritanceFlags,
                    rule.PropagationFlags)).ToArray();
        return new(owner.Value, security.AreAccessRulesProtected, rules);
    }

    internal static void ValidateFileAcl(Security4663LiveResultFileAcl acl)
    {
        ArgumentNullException.ThrowIfNull(acl);
        if (
            acl.OwnerSid != "S-1-5-32-544" ||
            !acl.IsProtected ||
            acl.Rules.Count != 3)
        {
            throw Invalid(
                "SENSOR_C2F_SECURITY_4663_RESULT_SLOT_ACL_INVALID");
        }
        var expected = new Dictionary<string, Func<int, bool>>(
            StringComparer.Ordinal)
        {
            ["S-1-5-18"] = IsExactFullControl,
            ["S-1-5-32-544"] = IsExactFullControl,
            ["S-1-5-19"] = rights =>
                rights == LocalServiceSynchronousWriteAndReadAttributes
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
                throw Invalid(
                    "SENSOR_C2F_SECURITY_4663_RESULT_SLOT_ACL_INVALID");
            }
        }
        if (expected.Count != 0)
        {
            throw Invalid(
                "SENSOR_C2F_SECURITY_4663_RESULT_SLOT_ACL_INVALID");
        }
    }

    internal static void ValidateNativeFileState(
        Security4663LiveResultNativeFileState state,
        bool? requireEmpty)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (
            (state.Attributes & FileAttributeReparsePoint) != 0 ||
            state.Length < 0 ||
            state.Length >
                Security4663LiveOneShotResultLifecycle.MaximumDocumentBytes ||
            state.NumberOfLinks != 1 ||
            state.DeletePending ||
            state.Directory ||
            (requireEmpty == true && state.Length != 0) ||
            (requireEmpty == false && state.Length == 0))
        {
            throw Invalid(
                "SENSOR_C2F_SECURITY_4663_RESULT_SLOT_STATE_INVALID");
        }
    }

    internal static void AssertProtectedRoot()
    {
        var root = Readiness.Security4663ReadinessCeremony.FixtureRoot;
        if (!string.Equals(
            Path.GetDirectoryName(
                NativeSecurity4663LiveOneShotResultFileSlot.ResultPath),
            root,
            StringComparison.OrdinalIgnoreCase))
        {
            throw Invalid(
                "SENSOR_C2F_SECURITY_4663_RESULT_SLOT_ROOT_INVALID");
        }
        var directory = new DirectoryInfo(root);
        if (!directory.Exists ||
            directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw Invalid(
                "SENSOR_C2F_SECURITY_4663_RESULT_SLOT_ROOT_INVALID");
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
                "SENSOR_C2F_SECURITY_4663_RESULT_SLOT_ROOT_ACL_INVALID");
        }
    }

    internal static void AssertProtectedFile(bool? requireEmpty)
    {
        var file = new FileInfo(
            NativeSecurity4663LiveOneShotResultFileSlot.ResultPath);
        if (!file.Exists ||
            file.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw Invalid(
                "SENSOR_C2F_SECURITY_4663_RESULT_SLOT_FILE_INVALID");
        }
        ValidateNativeFileState(
            new(
                (uint)file.Attributes,
                file.Length,
                1,
                false,
                false),
            requireEmpty);
        ValidateFileAcl(Snapshot(file.GetAccessControl(
            AccessControlSections.Access | AccessControlSections.Owner)));
    }

    private static bool IsExactFullControl(int rights) => rights is
        MappedFullControl or GenericAll;

    private static InvalidDataException Invalid(string code) => new(code);
}

// Elevated-only atomic creation of the fixed empty result slot.
public sealed class NativeSecurity4663LiveOneShotResultFileSlot
{
    public const string ResultPath =
        @"C:\ProgramData\WAR-R00M\Windows Sensor\C2\security-4663-live-one-shot-result.json";
    public const bool RuntimeWired = false;

    private const uint GenericWrite = 0x40000000;
    private const uint CreateNewDisposition = 1;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint FileFlagWriteThrough = 0x80000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;

    public void Prepare()
    {
        RequireAdministrator();
        Security4663LiveOneShotResultFilePolicy.AssertProtectedRoot();
        if (PathExists())
        {
            throw Invalid(
                "SENSOR_C2F_SECURITY_4663_RESULT_SLOT_ALREADY_EXISTS");
        }
        var descriptor = Security4663LiveOneShotResultFilePolicy
            .CreateFileSecurity().GetSecurityDescriptorBinaryForm();
        var pinned = GCHandle.Alloc(descriptor, GCHandleType.Pinned);
        try
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = pinned.AddrOfPinnedObject(),
                InheritHandle = false
            };
            using var handle = CreateFileW(
                ResultPath,
                GenericWrite,
                0,
                ref attributes,
                CreateNewDisposition,
                FileAttributeNormal | FileFlagWriteThrough |
                    FileFlagOpenReparsePoint,
                IntPtr.Zero);
            if (handle.IsInvalid || !FlushFileBuffers(handle))
            {
                throw Invalid(
                    "SENSOR_C2F_SECURITY_4663_RESULT_SLOT_CREATE_INVALID");
            }
        }
        finally
        {
            pinned.Free();
        }
        Security4663LiveOneShotResultFilePolicy.AssertProtectedFile(
            requireEmpty: true);
    }

    private static bool PathExists() =>
        File.Exists(ResultPath) || Directory.Exists(ResultPath);

    private static void RequireAdministrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("SENSOR_WINDOWS_REQUIRED");
        }
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(
            WindowsBuiltInRole.Administrator))
        {
            throw new UnauthorizedAccessException(
                "SENSOR_ADMINISTRATOR_REQUIRED");
        }
    }

    private static InvalidDataException Invalid(string code) => new(code);

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        internal int Length;
        internal IntPtr SecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] internal bool InheritHandle;
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
        ref SecurityAttributes lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlushFileBuffers(SafeFileHandle hFile);
}

// LocalService one-shot writer. It can only write the already-prepared file;
// it cannot read, create, delete or alter ACLs and is not service-registered.
public sealed class NativeSecurity4663LiveOneShotResultFileStore :
    ISecurity4663LiveOneShotResultStore
{
    public const bool RuntimeWired = true;
    public const bool ServiceRegistered = true;

    private const uint FileWriteData = 0x00000002;
    private const uint FileReadAttributes = 0x00000080;
    private const uint Synchronize = 0x00100000;
    private const uint OpenExisting = 3;
    private const uint FileFlagWriteThrough = 0x80000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const int FileAttributeTagInfoClass = 9;
    private const int FileStandardInfoClass = 1;

    public string? ReadExisting() => null;

    public void WriteNew(string json)
    {
        var bytes = EncodeDocument(json);
        try
        {
            using var handle = CreateFileW(
                NativeSecurity4663LiveOneShotResultFileSlot.ResultPath,
                FileWriteData | FileReadAttributes | Synchronize,
                0,
                IntPtr.Zero,
                OpenExisting,
                FileFlagWriteThrough | FileFlagOpenReparsePoint,
                IntPtr.Zero);
            if (handle.IsInvalid ||
                !TryReadState(handle, out var state))
            {
                throw Invalid(
                    "SENSOR_C2F_SECURITY_4663_RESULT_SLOT_OPEN_INVALID");
            }
            Security4663LiveOneShotResultFilePolicy.ValidateNativeFileState(
                state,
                requireEmpty: true);
            // FILE_FLAG_WRITE_THROUGH makes this single bounded write durable.
            // FILE_READ_ATTRIBUTES is limited to validating this already-open
            // exact slot. SYNCHRONIZE is required by this non-overlapped I/O
            // handle; neither right grants file-content read authority.
            // FlushFileBuffers requires a GENERIC_WRITE handle and therefore
            // cannot be used at this least-privilege service boundary.
            if (!WriteFile(
                    handle,
                    bytes,
                    checked((uint)bytes.Length),
                    out var written,
                    IntPtr.Zero) ||
                written != (uint)bytes.Length)
            {
                throw new InvalidDataException(
                    "SENSOR_C2F_SECURITY_4663_RESULT_SLOT_WRITE_INVALID",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static byte[] EncodeDocument(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            throw Invalid(
                "SENSOR_C2F_SECURITY_4663_RESULT_SLOT_INPUT_INVALID");
        }
        var bytes = new UTF8Encoding(false, true).GetBytes(json);
        if (bytes.Length is < 1 or >
                Security4663LiveOneShotResultLifecycle.MaximumDocumentBytes ||
            HasBom(bytes))
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw Invalid(
                "SENSOR_C2F_SECURITY_4663_RESULT_SLOT_INPUT_INVALID");
        }
        return bytes;
    }

    private static bool TryReadState(
        SafeFileHandle handle,
        out Security4663LiveResultNativeFileState state)
    {
        state = new(0, 0, 0, false, false);
        if (!GetFileAttributeTagInformationByHandle(
                handle,
                FileAttributeTagInfoClass,
                out var tag,
                Marshal.SizeOf<FileAttributeTagInfo>()) ||
            !GetFileStandardInformationByHandle(
                handle,
                FileStandardInfoClass,
                out var standard,
                Marshal.SizeOf<FileStandardInfo>()))
        {
            return false;
        }
        state = new(
            tag.FileAttributes,
            standard.EndOfFile,
            standard.NumberOfLinks,
            standard.DeletePending,
            standard.Directory);
        return true;
    }

    internal static bool HasBom(ReadOnlySpan<byte> bytes) =>
        bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB &&
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
        [MarshalAs(UnmanagedType.U1)] internal bool DeletePending;
        [MarshalAs(UnmanagedType.U1)] internal bool Directory;
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

    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetFileInformationByHandleEx",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileAttributeTagInformationByHandle(
        SafeFileHandle hFile,
        int fileInformationClass,
        out FileAttributeTagInfo lpFileInformation,
        int dwBufferSize);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetFileInformationByHandleEx",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileStandardInformationByHandle(
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

}
