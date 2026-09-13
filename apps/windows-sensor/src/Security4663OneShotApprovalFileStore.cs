using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace WARRoom.WindowsSensor;

public interface ISecurity4663OneShotApprovalAbsenceVerifier
{
    bool VerifyAbsent();
}

public sealed record Security4663OneShotApprovalFileStorePlan(
    int SchemaVersion,
    string Checkpoint,
    string ApprovalPath,
    string ParentRoot,
    int MaximumDocumentBytes,
    string OwnerSid,
    IReadOnlyList<string> FullControlSids,
    string ServiceSid,
    int ServiceRightsMask,
    bool RequiresProtectedDacl,
    bool RequiresCreateNew,
    bool RejectsReparsePoints,
    bool UsesExclusiveConsumeHandle,
    bool UsesHandleDispositionDelete,
    bool AllowsOverwrite,
    bool AllowsServiceWrite,
    bool RetryEnabled,
    bool PollingEnabled,
    bool TransportEnabled,
    bool CommandChannelEnabled,
    bool RuntimeWired);

internal sealed record Security4663ApprovalFileRule(
    string Sid,
    int RightsMask,
    bool IsInherited,
    AccessControlType Type,
    InheritanceFlags Inheritance,
    PropagationFlags Propagation);

internal sealed record Security4663ApprovalFileAcl(
    string OwnerSid,
    bool IsProtected,
    IReadOnlyList<Security4663ApprovalFileRule> Rules);

internal static class Security4663OneShotApprovalFilePolicy
{
    internal const int MappedFullControl = 0x001F01FF;
    internal const int GenericAll = 0x10000000;
    internal const int LocalServiceReadDelete = 0x00130089;
    internal const int LocalServiceReadDeleteWithoutSynchronize = 0x00030089;

    internal static Security4663OneShotApprovalFileStorePlan BuildPlan() =>
        new(
            1,
            Readiness.Security4663OneShotMachinePlan.Checkpoint,
            NativeSecurity4663OneShotApprovalFileStore.ApprovalPath,
            Readiness.Security4663ReadinessCeremony.FixtureRoot,
            Security4663OneShotApprovalLifecycle.MaximumDocumentBytes,
            "S-1-5-32-544",
            Array.AsReadOnly(["S-1-5-18", "S-1-5-32-544"]),
            "S-1-5-19",
            LocalServiceReadDelete,
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
            true);

    internal static void ValidatePlan(
        Security4663OneShotApprovalFileStorePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var expected = BuildPlan();
        if (
            plan with { FullControlSids = expected.FullControlSids } !=
                expected ||
            !plan.FullControlSids.SequenceEqual(
                expected.FullControlSids,
                StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_APPROVAL_FILE_PLAN_INVALID");
        }
    }

    internal static FileSecurity CreateFileSecurity()
    {
        var security = new FileSecurity();
        security.SetOwner(new SecurityIdentifier(
            WellKnownSidType.BuiltinAdministratorsSid,
            null));
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(
                WellKnownSidType.BuiltinAdministratorsSid,
                null),
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null),
            FileSystemRights.Read | FileSystemRights.Delete,
            AccessControlType.Allow));
        return security;
    }

    internal static void ValidateFileAcl(Security4663ApprovalFileAcl acl)
    {
        ArgumentNullException.ThrowIfNull(acl);
        if (
            acl.OwnerSid != "S-1-5-32-544" ||
            !acl.IsProtected ||
            acl.Rules.Count != 3)
        {
            throw Invalid();
        }
        var expected = new Dictionary<string, Func<int, bool>>(
            StringComparer.Ordinal)
        {
            ["S-1-5-18"] = IsExactFullControl,
            ["S-1-5-32-544"] = IsExactFullControl,
            ["S-1-5-19"] = rights => rights is
                LocalServiceReadDelete or
                LocalServiceReadDeleteWithoutSynchronize
        };
        foreach (var rule in acl.Rules)
        {
            if (
                rule.IsInherited ||
                rule.Type != AccessControlType.Allow ||
                rule.Inheritance != InheritanceFlags.None ||
                rule.Propagation != PropagationFlags.None ||
                !expected.Remove(rule.Sid, out var rightsValidator) ||
                !rightsValidator(rule.RightsMask))
            {
                throw Invalid();
            }
        }
        if (expected.Count != 0)
        {
            throw Invalid();
        }
    }

    internal static Security4663ApprovalFileAcl Snapshot(FileSecurity security)
    {
        ArgumentNullException.ThrowIfNull(security);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as
            SecurityIdentifier;
        if (owner is null)
        {
            throw Invalid();
        }
        var rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().Select(
                rule => new Security4663ApprovalFileRule(
                    rule.IdentityReference.Value,
                    unchecked((int)rule.FileSystemRights),
                    rule.IsInherited,
                    rule.AccessControlType,
                    rule.InheritanceFlags,
                    rule.PropagationFlags)).ToArray();
        return new Security4663ApprovalFileAcl(
            owner.Value,
            security.AreAccessRulesProtected,
            rules);
    }

    private static bool IsExactFullControl(int rights) => rights is
        MappedFullControl or GenericAll;

    private static InvalidDataException Invalid() => new(
        "SENSOR_C2E_SECURITY_4663_APPROVAL_FILE_ACL_INVALID");
}

// Native protected-file store for the approval lifecycle. The fixed path is
// the only filesystem authority and atomic consumption uses one exclusive
// read/delete handle. Only the disabled consume-proof startup mode registers it.
public sealed class NativeSecurity4663OneShotApprovalFileStore :
    ISecurity4663OneShotApprovalStore,
    ISecurity4663OneShotApprovalAbsenceVerifier
{
    public const string ApprovalPath =
        @"C:\ProgramData\WAR-R00M\Windows Sensor\C2\security-4663-one-shot-approval.json";
    public const bool RuntimeWired = true;

    private const uint GenericRead = 0x80000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint OpenExisting = 3;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const int FileAttributeTagInfoClass = 9;
    private const int FileDispositionInfoClass = 4;

    public string? ReadExisting()
    {
        if (!PathExists())
        {
            return null;
        }
        AssertProtectedFile();
        return ReadExclusive(allowDelete: false, deleteAfterRead: false, null);
    }

    public void WriteNew(string json)
    {
        var bytes = ValidateDocument(json);
        var created = false;
        try
        {
            AssertProtectedRoot();
            if (PathExists())
            {
                throw Invalid(
                    "SENSOR_C2E_SECURITY_4663_APPROVAL_ALREADY_EXISTS");
            }
            using (var stream = new FileStream(
                ApprovalPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough))
            {
                created = true;
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            new FileInfo(ApprovalPath).SetAccessControl(
                Security4663OneShotApprovalFilePolicy.CreateFileSecurity());
            AssertProtectedFile();
            var persisted = ReadExclusive(
                allowDelete: false,
                deleteAfterRead: false,
                null);
            if (!string.Equals(persisted, json, StringComparison.Ordinal))
            {
                throw Invalid(
                    "SENSOR_C2E_SECURITY_4663_APPROVAL_FILE_WRITE_INVALID");
            }
        }
        catch
        {
            if (created)
            {
                DeleteFailedCreation();
            }
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public void ConsumeExact(string expectedJson)
    {
        var expected = ValidateDocument(expectedJson);
        try
        {
            AssertProtectedRoot();
            AssertProtectedFile();
            _ = ReadExclusive(
                allowDelete: true,
                deleteAfterRead: true,
                expected);
            if (PathExists())
            {
                throw Invalid(
                    "SENSOR_C2E_SECURITY_4663_APPROVAL_FILE_CONSUME_INVALID");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    public bool RemoveForRecovery()
    {
        AssertProtectedRoot();
        if (!PathExists())
        {
            return false;
        }
        AssertProtectedFile();
        _ = ReadExclusive(
            allowDelete: true,
            deleteAfterRead: true,
            expected: null);
        if (PathExists())
        {
            throw Invalid(
                "SENSOR_C2E_SECURITY_4663_APPROVAL_FILE_CLEANUP_INVALID");
        }
        return true;
    }

    public bool VerifyAbsent()
    {
        AssertProtectedRoot();
        return !PathExists();
    }

    private static string ReadExclusive(
        bool allowDelete,
        bool deleteAfterRead,
        byte[]? expected)
    {
        var desiredAccess = GenericRead | (allowDelete ? DeleteAccess : 0U);
        using var handle = CreateFileW(
            ApprovalPath,
            desiredAccess,
            0,
            IntPtr.Zero,
            OpenExisting,
            FileFlagSequentialScan | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid ||
            !GetFileInformationByHandleEx(
                handle,
                FileAttributeTagInfoClass,
                out var tag,
                Marshal.SizeOf<FileAttributeTagInfo>()) ||
            (tag.FileAttributes & FileAttributeReparsePoint) != 0)
        {
            throw Invalid(
                "SENSOR_C2E_SECURITY_4663_APPROVAL_FILE_OPEN_INVALID");
        }
        using var stream = new FileStream(
            handle,
            FileAccess.Read,
            4096,
            isAsync: false);
        var bytes = ReadBounded(stream);
        try
        {
            if (expected is not null &&
                !CryptographicOperations.FixedTimeEquals(bytes, expected))
            {
                throw Invalid(
                    "SENSOR_C2E_SECURITY_4663_APPROVAL_FILE_CHANGED");
            }
            var json = DecodeStrictUtf8(bytes);
            if (deleteAfterRead)
            {
                var disposition = new FileDispositionInfo
                {
                    DeleteFile = true
                };
                if (!SetFileInformationByHandle(
                    handle,
                    FileDispositionInfoClass,
                    ref disposition,
                    Marshal.SizeOf<FileDispositionInfo>()))
                {
                    throw Invalid(
                        "SENSOR_C2E_SECURITY_4663_APPROVAL_FILE_CONSUME_INVALID");
                }
            }
            return json;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static byte[] ReadBounded(FileStream stream)
    {
        if (stream.Length is < 1 or >
            Security4663OneShotApprovalLifecycle.MaximumDocumentBytes)
        {
            throw Invalid(
                "SENSOR_C2E_SECURITY_4663_APPROVAL_FILE_SIZE_INVALID");
        }
        var bytes = new byte[checked((int)stream.Length)];
        var offset = 0;
        while (offset < bytes.Length)
        {
            var read = stream.Read(bytes, offset, bytes.Length - offset);
            if (read == 0)
            {
                throw Invalid(
                    "SENSOR_C2E_SECURITY_4663_APPROVAL_FILE_READ_INVALID");
            }
            offset += read;
        }
        return bytes;
    }

    private static byte[] ValidateDocument(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            throw Invalid(
                "SENSOR_C2E_SECURITY_4663_APPROVAL_FILE_INPUT_INVALID");
        }
        var bytes = new UTF8Encoding(
            encoderShouldEmitUTF8Identifier: false,
            throwOnInvalidBytes: true).GetBytes(json);
        if (
            bytes.Length is < 1 or >
                Security4663OneShotApprovalLifecycle.MaximumDocumentBytes ||
            HasUtf8Bom(bytes))
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw Invalid(
                "SENSOR_C2E_SECURITY_4663_APPROVAL_FILE_INPUT_INVALID");
        }
        return bytes;
    }

    private static string DecodeStrictUtf8(byte[] bytes)
    {
        if (HasUtf8Bom(bytes))
        {
            throw Invalid(
                "SENSOR_C2E_SECURITY_4663_APPROVAL_FILE_INPUT_INVALID");
        }
        try
        {
            return new UTF8Encoding(
                encoderShouldEmitUTF8Identifier: false,
                throwOnInvalidBytes: true).GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            throw Invalid(
                "SENSOR_C2E_SECURITY_4663_APPROVAL_FILE_INPUT_INVALID");
        }
    }

    private static bool HasUtf8Bom(ReadOnlySpan<byte> bytes) =>
        bytes.Length >= 3 &&
        bytes[0] == 0xEF &&
        bytes[1] == 0xBB &&
        bytes[2] == 0xBF;

    private static void AssertProtectedRoot()
    {
        var expectedRoot =
            Readiness.Security4663ReadinessCeremony.FixtureRoot;
        var parent = Path.GetDirectoryName(ApprovalPath);
        if (!string.Equals(
            parent,
            expectedRoot,
            StringComparison.OrdinalIgnoreCase))
        {
            throw Invalid(
                "SENSOR_C2E_SECURITY_4663_APPROVAL_ROOT_INVALID");
        }
        var directory = new DirectoryInfo(expectedRoot);
        if (!directory.Exists ||
            directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw Invalid(
                "SENSOR_C2E_SECURITY_4663_APPROVAL_ROOT_INVALID");
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
            "S-1-5-18",
            "S-1-5-32-544"
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
                    (Security4663OneShotApprovalFilePolicy.MappedFullControl or
                        Security4663OneShotApprovalFilePolicy.GenericAll)) ||
            expected.Count != 0)
        {
            throw Invalid(
                "SENSOR_C2E_SECURITY_4663_APPROVAL_ROOT_ACL_INVALID");
        }
    }

    private static void AssertProtectedFile()
    {
        var file = new FileInfo(ApprovalPath);
        if (!file.Exists ||
            file.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            file.Length is < 1 or >
                Security4663OneShotApprovalLifecycle.MaximumDocumentBytes)
        {
            throw Invalid(
                "SENSOR_C2E_SECURITY_4663_APPROVAL_FILE_INVALID");
        }
        var security = file.GetAccessControl(
            AccessControlSections.Access | AccessControlSections.Owner);
        Security4663OneShotApprovalFilePolicy.ValidateFileAcl(
            Security4663OneShotApprovalFilePolicy.Snapshot(security));
    }

    private static bool PathExists() =>
        File.Exists(ApprovalPath) || Directory.Exists(ApprovalPath);

    private static void DeleteFailedCreation()
    {
        try
        {
            if (File.Exists(ApprovalPath) &&
                !File.GetAttributes(ApprovalPath).HasFlag(
                    FileAttributes.ReparsePoint))
            {
                File.Delete(ApprovalPath);
            }
        }
        catch
        {
            throw Invalid(
                "SENSOR_C2E_SECURITY_4663_APPROVAL_FILE_CLEANUP_INVALID");
        }
    }

    private static InvalidDataException Invalid(string code) => new(code);

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo
    {
        internal uint FileAttributes;
        internal uint ReparseTag;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInfo
    {
        [MarshalAs(UnmanagedType.Bool)]
        internal bool DeleteFile;
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
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle hFile,
        int fileInformationClass,
        ref FileDispositionInfo lpFileInformation,
        int dwBufferSize);
}
