using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace WARRoom.WindowsSensor;

public sealed record AuditWitnessProtectedFileStatus(
    string BaseRootPath,
    string RootPath,
    string FilePath,
    string Claim,
    long FileLength,
    int HardLinkCount,
    string FileIdentity,
    bool BaseRootAclVerified,
    bool RootAclVerified,
    bool FileAclVerified,
    bool FileIdentityVerified,
    bool RuntimeWiringEnabled,
    bool TelemetryEnabled,
    bool TransportEnabled,
    bool CommandChannelEnabled);

public sealed record AuditWitnessEffectiveAccessPlan(
    string FilePath,
    uint RequiredAppendDataAccess,
    uint DeniedWriteDataAccess,
    uint DeniedDeleteAccess,
    uint DeniedWriteDacAccess,
    uint DeniedWriteOwnerAccess,
    bool RequiresStandardUser,
    bool WritesBytes,
    bool RuntimeWiringEnabled);

public sealed record AuditWitnessEffectiveAccessProof(
    string FilePath,
    string FileIdentity,
    long FileLengthBefore,
    long FileLengthAfter,
    bool StandardUserValidated,
    bool AppendDataOpenAllowed,
    bool WriteDataOpenDenied,
    bool DeleteOpenDenied,
    bool WriteDacOpenDenied,
    bool WriteOwnerOpenDenied,
    bool BytesWritten,
    bool FileIdentityStable,
    bool FileLengthStable,
    bool RuntimeWiringEnabled,
    bool TelemetryEnabled,
    bool TransportEnabled,
    bool CommandChannelEnabled);

public static class AuditWitnessProtectedFileChecker
{
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const uint FileAppendData = 0x00000004;
    private const uint FileWriteData = 0x00000002;
    private const uint DeleteAccess = 0x00010000;
    private const uint WriteDac = 0x00040000;
    private const uint WriteOwner = 0x00080000;
    private const int ErrorAccessDenied = 5;

    public static AuditWitnessEffectiveAccessPlan BuildEffectiveAccessPlan() =>
        new(
            AuditWitnessAppendFilePolicy.FilePath,
            FileAppendData,
            FileWriteData,
            DeleteAccess,
            WriteDac,
            WriteOwner,
            RequiresStandardUser: true,
            WritesBytes: false,
            RuntimeWiringEnabled: false);

    public static AuditWitnessProtectedFileStatus Check()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "SENSOR_WINDOWS_REQUIRED");
        }
        ValidateDirectory(AuditWitnessAppendFilePolicy.BaseRootPath);
        ValidateDirectory(AuditWitnessAppendFilePolicy.RootPath);

        var path = AuditWitnessAppendFilePolicy.FilePath;
        if (!File.Exists(path) || Directory.Exists(path))
        {
            throw Invalid("SENSOR_AUDIT_WITNESS_FILE_INVALID");
        }
        using var handle = CreateFileW(
            path,
            GenericRead,
            FileShareRead | FileShareWrite,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid ||
            !GetFileInformationByHandle(handle, out var before))
        {
            throw Invalid("SENSOR_AUDIT_WITNESS_FILE_IDENTITY_INVALID");
        }
        var length = Length(before);
        AuditWitnessAppendFilePolicy.ValidateFileShape(new(
            Exists: true,
            IsDirectory: false,
            IsReparsePoint:
                (before.FileAttributes & FileAttributeReparsePoint) != 0,
            HardLinkCount: checked((int)before.NumberOfLinks),
            Length: length));

        var file = new FileInfo(path);
        AuditWitnessAppendFilePolicy.ValidateFileSecurity(
            file.GetAccessControl(
                AccessControlSections.Access |
                AccessControlSections.Owner));
        if (!GetFileInformationByHandle(handle, out var after) ||
            before.VolumeSerialNumber != after.VolumeSerialNumber ||
            before.FileIndexHigh != after.FileIndexHigh ||
            before.FileIndexLow != after.FileIndexLow ||
            before.NumberOfLinks != after.NumberOfLinks ||
            length != Length(after))
        {
            throw Invalid("SENSOR_AUDIT_WITNESS_FILE_IDENTITY_INVALID");
        }

        return new(
            AuditWitnessAppendFilePolicy.BaseRootPath,
            AuditWitnessAppendFilePolicy.RootPath,
            path,
            AuditWitnessAppendFilePolicy.Claim,
            length,
            checked((int)before.NumberOfLinks),
            $"{before.VolumeSerialNumber:x8}:" +
                $"{before.FileIndexHigh:x8}{before.FileIndexLow:x8}",
            BaseRootAclVerified: true,
            RootAclVerified: true,
            FileAclVerified: true,
            FileIdentityVerified: true,
            RuntimeWiringEnabled: false,
            TelemetryEnabled: false,
            TransportEnabled: false,
            CommandChannelEnabled: false);
    }

    public static AuditWitnessEffectiveAccessProof CheckEffectiveAccess()
    {
        RequireStandardUser();
        var before = Check();
        using (var appendHandle = CreateFileW(
            AuditWitnessAppendFilePolicy.FilePath,
            FileAppendData,
            FileShareRead | FileShareWrite,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint,
            IntPtr.Zero))
        {
            if (appendHandle.IsInvalid ||
                !GetFileInformationByHandle(appendHandle, out var appendState) ||
                Identity(appendState) != before.FileIdentity ||
                Length(appendState) != before.FileLength)
            {
                throw Invalid(
                    "SENSOR_AUDIT_WITNESS_APPEND_ACCESS_INVALID");
            }
        }

        RequireAccessDenied(
            FileWriteData,
            "SENSOR_AUDIT_WITNESS_WRITE_DATA_NOT_DENIED");
        RequireAccessDenied(
            DeleteAccess,
            "SENSOR_AUDIT_WITNESS_DELETE_NOT_DENIED");
        RequireAccessDenied(
            WriteDac,
            "SENSOR_AUDIT_WITNESS_WRITE_DAC_NOT_DENIED");
        RequireAccessDenied(
            WriteOwner,
            "SENSOR_AUDIT_WITNESS_WRITE_OWNER_NOT_DENIED");

        var after = Check();
        if (after.FileIdentity != before.FileIdentity ||
            after.FileLength != before.FileLength)
        {
            throw Invalid("SENSOR_AUDIT_WITNESS_ACCESS_PROOF_DRIFT");
        }
        return new(
            before.FilePath,
            before.FileIdentity,
            before.FileLength,
            after.FileLength,
            StandardUserValidated: true,
            AppendDataOpenAllowed: true,
            WriteDataOpenDenied: true,
            DeleteOpenDenied: true,
            WriteDacOpenDenied: true,
            WriteOwnerOpenDenied: true,
            BytesWritten: false,
            FileIdentityStable: true,
            FileLengthStable: true,
            RuntimeWiringEnabled: false,
            TelemetryEnabled: false,
            TransportEnabled: false,
            CommandChannelEnabled: false);
    }

    private static void RequireStandardUser()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        if (principal.IsInRole(WindowsBuiltInRole.Administrator) ||
            !principal.IsInRole(WindowsBuiltInRole.User))
        {
            throw new InvalidOperationException(
                "SENSOR_AUDIT_WITNESS_STANDARD_USER_REQUIRED");
        }
    }

    private static void RequireAccessDenied(uint desiredAccess, string error)
    {
        using var handle = CreateFileW(
            AuditWitnessAppendFilePolicy.FilePath,
            desiredAccess,
            FileShareRead | FileShareWrite,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (!handle.IsInvalid ||
            Marshal.GetLastWin32Error() != ErrorAccessDenied)
        {
            throw Invalid(error);
        }
    }

    internal static void ValidateDirectory(string path)
    {
        var directory = new DirectoryInfo(path);
        if (!directory.Exists ||
            directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw Invalid("SENSOR_AUDIT_WITNESS_ROOT_INVALID");
        }
        AuditWitnessAppendFilePolicy.ValidateRootSecurity(
            directory.GetAccessControl(
                AccessControlSections.Access |
                AccessControlSections.Owner));
    }

    private static long Length(ByHandleFileInformation information) =>
        checked(((long)information.FileSizeHigh << 32) |
            information.FileSizeLow);

    private static string Identity(ByHandleFileInformation information) =>
        $"{information.VolumeSerialNumber:x8}:" +
        $"{information.FileIndexHigh:x8}{information.FileIndexLow:x8}";

    private static InvalidDataException Invalid(string code) => new(code);

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
