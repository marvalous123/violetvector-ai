using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace WARRoom.WindowsSensor;

public sealed record AuditHeadFileShape(
    bool Exists,
    bool IsDirectory,
    bool IsReparsePoint,
    int HardLinkCount,
    long Length);

public static class AuditHeadWriterFilePolicy
{
    public const string LocalSystemSid = "S-1-5-18";
    public const string AdministratorsSid = "S-1-5-32-544";
    public const string UsersSid = "S-1-5-32-545";
    public const int MaximumStateBytes = 8_192;

    public static void ValidatePendingShape(AuditHeadFileShape shape)
    {
        if (!shape.Exists || shape.IsDirectory || shape.IsReparsePoint ||
            shape.HardLinkCount != 1 || shape.Length is < 1 or >
                NativeAuditHeadWriter.MaximumPendingBytes)
        {
            throw new InvalidDataException(
                "SENSOR_AUDIT_HEAD_PENDING_FILE_INVALID");
        }
    }

    public static void ValidateStateShape(AuditHeadFileShape shape)
    {
        if (!shape.Exists || shape.IsDirectory || shape.IsReparsePoint ||
            shape.HardLinkCount != 1 || shape.Length is < 1 or >
                MaximumStateBytes)
        {
            throw new InvalidDataException(
                "SENSOR_AUDIT_HEAD_STATE_FILE_INVALID");
        }
    }

    public static FileSecurity CreateStateSecurity()
    {
        var security = new FileSecurity();
        security.SetOwner(new SecurityIdentifier(
            WellKnownSidType.BuiltinAdministratorsSid,
            null));
        security.SetAccessRuleProtection(true, false);
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
            new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            FileSystemRights.Read,
            AccessControlType.Allow));
        return security;
    }

    public static void ValidateStateSecurity(FileSecurity security)
    {
        ArgumentNullException.ThrowIfNull(security);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as
            SecurityIdentifier;
        var rules = security.GetAccessRules(
            true,
            true,
            typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            LocalSystemSid, AdministratorsSid, UsersSid
        };
        if (owner?.Value != AdministratorsSid ||
            !security.AreAccessRulesProtected || rules.Length != 3 ||
            rules.Any(rule => rule.IsInherited ||
                rule.AccessControlType != AccessControlType.Allow ||
                !expected.Remove(rule.IdentityReference.Value) ||
                (rule.IdentityReference.Value == UsersSid
                    ? !IsReadOnly(rule.FileSystemRights)
                    : !IsFullControl(rule.FileSystemRights))) ||
            expected.Count != 0)
        {
            throw new InvalidDataException(
                "SENSOR_AUDIT_HEAD_STATE_ACL_INVALID");
        }
    }

    private static bool IsFullControl(FileSystemRights rights) =>
        unchecked((int)rights) is 0x001F01FF or 0x10000000;

    private static bool IsReadOnly(FileSystemRights rights)
    {
        var value = unchecked((int)rights);
        const int writeMask = 0x00000116;
        const int deleteMask = 0x00010000;
        return (value & (writeMask | deleteMask)) == 0 &&
            value is 0x00120089 or unchecked((int)0x80000000);
    }
}

public static class NativeAuditHeadWriterStorage
{
    public const string BaseRoot = @"C:\ProgramData\Project15 Audit Head";
    public static string ProtectedRoot { get; } =
        Path.GetDirectoryName(NativeAuditHeadWriter.StatePath) ??
        throw new InvalidOperationException(
            "SENSOR_AUDIT_HEAD_STATE_ROOT_INVALID");
    public static string PendingRoot { get; } =
        Path.GetDirectoryName(NativeAuditHeadWriter.PendingPath) ??
        throw new InvalidOperationException(
            "SENSOR_AUDIT_HEAD_PENDING_ROOT_INVALID");

    public static void PrepareFixedRoots()
    {
        PrepareRoot(BaseRoot, usersMayWrite: false);
        PrepareRoot(ProtectedRoot, usersMayWrite: false);
        PrepareRoot(PendingRoot, usersMayWrite: true);
    }

    public static void ValidateFixedRoots()
    {
        ValidateRoot(BaseRoot, usersMayWrite: false);
        ValidateRoot(ProtectedRoot, usersMayWrite: false);
        ValidateRoot(PendingRoot, usersMayWrite: true);
    }

    private static void PrepareRoot(string path, bool usersMayWrite)
    {
        var directory = Directory.CreateDirectory(path);
        if (directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidDataException(
                "SENSOR_AUDIT_HEAD_STORAGE_ROOT_INVALID");
        }
        var security = CreateDirectorySecurity(usersMayWrite);
        directory.SetAccessControl(security);
        ValidateDirectorySecurity(
            directory.GetAccessControl(
                AccessControlSections.Access |
                AccessControlSections.Owner),
            usersMayWrite);
    }

    internal static DirectorySecurity CreateDirectorySecurity(
        bool usersMayWrite)
    {
        var security = new DirectorySecurity();
        security.SetOwner(new SecurityIdentifier(
            WellKnownSidType.BuiltinAdministratorsSid,
            null));
        security.SetAccessRuleProtection(true, false);
        AddDirectoryRule(
            security,
            WellKnownSidType.LocalSystemSid,
            FileSystemRights.FullControl);
        AddDirectoryRule(
            security,
            WellKnownSidType.BuiltinAdministratorsSid,
            FileSystemRights.FullControl);
        AddDirectoryRule(
            security,
            WellKnownSidType.BuiltinUsersSid,
            usersMayWrite
                ? FileSystemRights.ReadAndExecute | FileSystemRights.Write
                : FileSystemRights.ReadAndExecute);
        return security;
    }

    internal static void ValidateDirectorySecurity(
        DirectorySecurity security,
        bool usersMayWrite)
    {
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as
            SecurityIdentifier;
        var rules = security.GetAccessRules(
            true,
            true,
            typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            AuditHeadWriterFilePolicy.LocalSystemSid,
            AuditHeadWriterFilePolicy.AdministratorsSid,
            AuditHeadWriterFilePolicy.UsersSid
        };
        if (
            owner?.Value != AuditHeadWriterFilePolicy.AdministratorsSid ||
            !security.AreAccessRulesProtected ||
            rules.Length != expected.Count ||
            rules.Any(rule =>
                rule.IsInherited ||
                rule.AccessControlType != AccessControlType.Allow ||
                rule.InheritanceFlags !=
                    (InheritanceFlags.ContainerInherit |
                        InheritanceFlags.ObjectInherit) ||
                rule.PropagationFlags != PropagationFlags.None ||
                !expected.Remove(rule.IdentityReference.Value) ||
                !HasExpectedDirectoryRights(
                    rule.IdentityReference.Value,
                    rule.FileSystemRights,
                    usersMayWrite)) ||
            expected.Count != 0)
        {
            throw new InvalidDataException(
                "SENSOR_AUDIT_HEAD_STORAGE_ROOT_ACL_INVALID");
        }
    }

    private static bool HasExpectedDirectoryRights(
        string sid,
        FileSystemRights rights,
        bool usersMayWrite)
    {
        if (sid is AuditHeadWriterFilePolicy.LocalSystemSid or
            AuditHeadWriterFilePolicy.AdministratorsSid)
        {
            return (rights & FileSystemRights.FullControl) ==
                FileSystemRights.FullControl;
        }
        var required = usersMayWrite
            ? FileSystemRights.ReadAndExecute | FileSystemRights.Write
            : FileSystemRights.ReadAndExecute;
        var forbidden = FileSystemRights.Delete |
            FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions |
            FileSystemRights.TakeOwnership;
        if (!usersMayWrite)
        {
            forbidden |= FileSystemRights.Write;
        }
        return (rights & required) == required &&
            (rights & forbidden) == 0;
    }

    private static void ValidateRoot(string path, bool usersMayWrite)
    {
        var directory = new DirectoryInfo(path);
        if (
            !directory.Exists ||
            directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidDataException(
                "SENSOR_AUDIT_HEAD_STORAGE_ROOT_INVALID");
        }
        ValidateDirectorySecurity(
            directory.GetAccessControl(
                AccessControlSections.Access |
                AccessControlSections.Owner),
            usersMayWrite);
    }

    private static void AddDirectoryRule(
        DirectorySecurity security,
        WellKnownSidType sid,
        FileSystemRights rights) =>
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(sid, null),
            rights,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
}

public sealed class NativeAuditHeadPendingProofStore :
    IAuditHeadPendingProofStore
{
    public string ReadFixed()
    {
        AssertExactPath(NativeAuditHeadWriter.PendingPath);
        var file = new FileInfo(NativeAuditHeadWriter.PendingPath);
        return ReadStrict(file, NativeAuditHeadWriter.MaximumPendingBytes);
    }

    private static void AssertExactPath(string path)
    {
        if (path != NativeAuditHeadWriter.PendingPath)
        {
            throw new InvalidDataException(
                "SENSOR_AUDIT_HEAD_PENDING_PATH_INVALID");
        }
    }

    internal static string ReadStrict(FileInfo file, int maximumBytes)
    {
        using var handle = CreateFileW(
            file.FullName,
            0x80000000,
            0x00000001,
            IntPtr.Zero,
            3,
            0x00200000,
            IntPtr.Zero);
        if (
            handle.IsInvalid ||
            !GetFileInformationByHandle(handle, out var information) ||
            (information.FileAttributes & 0x00000400) != 0 ||
            information.NumberOfLinks != 1)
        {
            throw new InvalidDataException(
                "SENSOR_AUDIT_HEAD_FILE_IDENTITY_INVALID");
        }
        var length = ((ulong)information.FileSizeHigh << 32) |
            information.FileSizeLow;
        if (length is < 1 || length > (ulong)maximumBytes)
        {
            throw new InvalidDataException(
                "SENSOR_AUDIT_HEAD_FILE_SIZE_INVALID");
        }
        var bytes = new byte[checked((int)length)];
        try
        {
            using (var stream = new FileStream(
                handle,
                FileAccess.Read,
                4096,
                isAsync: false))
            {
                var offset = 0;
                while (offset < bytes.Length)
                {
                    var read = stream.Read(bytes, offset, bytes.Length - offset);
                    if (read == 0)
                    {
                        throw new InvalidDataException(
                            "SENSOR_AUDIT_HEAD_FILE_SIZE_INVALID");
                    }
                    offset += read;
                }
                if (stream.ReadByte() != -1)
                {
                    throw new InvalidDataException(
                        "SENSOR_AUDIT_HEAD_FILE_SIZE_INVALID");
                }
            }
            if (HasBom(bytes))
            {
                throw new InvalidDataException(
                    "SENSOR_AUDIT_HEAD_FILE_ENCODING_INVALID");
            }
            return new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (DecoderFallbackException error)
        {
            throw new InvalidDataException(
                "SENSOR_AUDIT_HEAD_FILE_ENCODING_INVALID",
                error);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static bool HasBom(ReadOnlySpan<byte> bytes) =>
        bytes.Length >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb &&
        bytes[2] == 0xbf;

    internal static AuditHeadFileShape Shape(FileInfo file) => new(
        file.Exists,
        false,
        file.Exists && file.Attributes.HasFlag(FileAttributes.ReparsePoint),
        file.Exists ? ReadHardLinkCount(file.FullName) : 0,
        file.Exists ? file.Length : 0);

    private static int ReadHardLinkCount(string path)
    {
        using var handle = CreateFileW(
            path,
            0x80000000,
            0x00000001,
            IntPtr.Zero,
            3,
            0x00200000,
            IntPtr.Zero);
        if (handle.IsInvalid ||
            !GetFileInformationByHandle(handle, out var information))
        {
            throw new InvalidDataException(
                "SENSOR_AUDIT_HEAD_FILE_IDENTITY_INVALID");
        }
        return checked((int)information.NumberOfLinks);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        internal uint FileAttributes;
        internal System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        internal uint VolumeSerialNumber;
        internal uint FileSizeHigh;
        internal uint FileSizeLow;
        internal uint NumberOfLinks;
        internal uint FileIndexHigh;
        internal uint FileIndexLow;
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
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle hFile,
        out ByHandleFileInformation lpFileInformation);
}

public sealed class NativeAuditHeadCheckpointStateStore :
    IAuditHeadCheckpointStateStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public AuditHeadProtectedState? Read()
    {
        var document = ReadDocument();
        return document is null
            ? null
            : AuditHeadCheckpoint.ValidateProtectedDocument(document);
    }

    public AuditHeadProtectedDocument? ReadDocument()
    {
        if (!File.Exists(NativeAuditHeadWriter.StatePath))
        {
            if (Directory.Exists(NativeAuditHeadWriter.StatePath))
            {
                throw Invalid("SENSOR_AUDIT_HEAD_STATE_PATH_INVALID");
            }
            return null;
        }
        var file = new FileInfo(NativeAuditHeadWriter.StatePath);
        AuditHeadWriterFilePolicy.ValidateStateShape(
            NativeAuditHeadPendingProofStore.Shape(file));
        AuditHeadWriterFilePolicy.ValidateStateSecurity(
            file.GetAccessControl(
                AccessControlSections.Access |
                AccessControlSections.Owner));
        return ParseDocument(NativeAuditHeadPendingProofStore.ReadStrict(
            file,
            AuditHeadWriterFilePolicy.MaximumStateBytes));
    }

    public bool TryCommit(
        AuditHeadProtectedState? expected,
        AuditHeadProtectedDocument next)
    {
        ArgumentNullException.ThrowIfNull(next);
        _ = AuditHeadCheckpoint.ValidateProtectedDocument(next);
        if (Read() != expected)
        {
            return false;
        }
        var temporary = NativeAuditHeadWriter.StatePath + ".new";
        if (File.Exists(temporary) || Directory.Exists(temporary))
        {
            throw Invalid("SENSOR_AUDIT_HEAD_STATE_TEMP_INVALID");
        }
        var json = JsonSerializer.Serialize(next, JsonOptions);
        var bytes = new UTF8Encoding(false, true).GetBytes(json);
        try
        {
            using (var stream = new FileStream(
                temporary,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(true);
            }
            new FileInfo(temporary).SetAccessControl(
                AuditHeadWriterFilePolicy.CreateStateSecurity());
            AuditHeadWriterFilePolicy.ValidateStateSecurity(
                new FileInfo(temporary).GetAccessControl(
                    AccessControlSections.Access |
                    AccessControlSections.Owner));
            File.Move(
                temporary,
                NativeAuditHeadWriter.StatePath,
                overwrite: expected is not null);
            return ReadDocument() == next;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private static AuditHeadProtectedDocument ParseDocument(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(
                json,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 8
                });
            var root = document.RootElement;
            RequireFields(root, ["signer", "checkpoint"]);
            RequireFields(
                root.GetProperty("signer"),
                [
                    "profile", "chainId", "algorithm",
                    "publicKeyFormat", "publicKeySpkiBase64",
                    "publicKeyFingerprintSha256", "keyPersistence"
                ]);
            RequireFields(
                root.GetProperty("checkpoint"),
                [
                    "schemaVersion", "purpose", "chainId",
                    "priorSequence", "priorEventHash",
                    "priorCheckpointHash", "sequence", "eventHash",
                    "signerProfile", "signerAlgorithm",
                    "signerPublicKeyFingerprintSha256", "checkpointHash",
                    "signatureBase64"
                ]);
            var result = JsonSerializer.Deserialize<AuditHeadProtectedDocument>(
                json,
                JsonOptions) ??
                throw Invalid("SENSOR_AUDIT_HEAD_STATE_INVALID");
            _ = AuditHeadCheckpoint.ValidateProtectedDocument(result);
            return result;
        }
        catch (Exception error) when (
            error is JsonException or InvalidOperationException or
            KeyNotFoundException or FormatException or OverflowException)
        {
            throw Invalid("SENSOR_AUDIT_HEAD_STATE_INVALID", error);
        }
    }

    private static void RequireFields(
        JsonElement element,
        IReadOnlyList<string> expected)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw Invalid("SENSOR_AUDIT_HEAD_STATE_INVALID");
        }
        var fields = element.EnumerateObject().Select(value => value.Name)
            .ToArray();
        if (
            fields.Length != expected.Count ||
            fields.Distinct(StringComparer.Ordinal).Count() != fields.Length ||
            !fields.ToHashSet(StringComparer.Ordinal).SetEquals(expected))
        {
            throw Invalid("SENSOR_AUDIT_HEAD_STATE_INVALID");
        }
    }

    private static InvalidDataException Invalid(
        string code,
        Exception? error = null) => new(code, error);
}
