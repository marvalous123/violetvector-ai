using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace WARRoom.WindowsSensor;

public enum Security4663LiveOneShotResultOperatorCommand
{
    Plan,
    PrepareSlot,
    EmptyCheck,
    Check,
    Consume,
    AbsentCheck,
    Cleanup
}

public static class Security4663LiveOneShotResultOperatorCommandParser
{
    public static Security4663LiveOneShotResultOperatorCommand Parse(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Length != 1)
        {
            throw Invalid();
        }

        return args[0] switch
        {
            "plan" => Security4663LiveOneShotResultOperatorCommand.Plan,
            "prepare-slot" => Security4663LiveOneShotResultOperatorCommand.PrepareSlot,
            "empty-check" => Security4663LiveOneShotResultOperatorCommand.EmptyCheck,
            "check" => Security4663LiveOneShotResultOperatorCommand.Check,
            "consume" => Security4663LiveOneShotResultOperatorCommand.Consume,
            "absent-check" => Security4663LiveOneShotResultOperatorCommand.AbsentCheck,
            "cleanup" => Security4663LiveOneShotResultOperatorCommand.Cleanup,
            _ => throw Invalid()
        };
    }

    private static InvalidDataException Invalid() => new(
        "SENSOR_C2F_SECURITY_4663_RESULT_OPERATOR_COMMAND_INVALID");
}

public sealed record Security4663LiveOneShotResultOperatorPlan(
    int SchemaVersion,
    string Checkpoint,
    IReadOnlyList<string> Commands,
    string ResultPath,
    int MaximumDocumentBytes,
    int MaximumResultAgeSeconds,
    bool RequiresAdministrator,
    bool ChecksProtectedRootAndFileAcl,
    bool RejectsReparsePoints,
    bool RejectsHardLinks,
    bool RequiresStrictUtf8,
    bool ValidatesManifestIdentitySignatureAndFreshness,
    bool CheckIsReadOnly,
    bool ConsumeUsesExactAtomicHandleDelete,
    bool CleanupIsFixedPathAndIdempotent,
    bool CleanupAllowsBoundedEmptyPartialOrValidFile,
    bool ReadsEvents,
    bool SignsData,
    bool StartsOrMutatesService,
    bool MutatesRegistry,
    bool MutatesAuditPolicy,
    bool RetryEnabled,
    bool PollingEnabled,
    bool TransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    bool ResponseActionEnabled,
    bool RuntimeWired);

public sealed record Security4663LiveOneShotResultOperatorResult(
    int SchemaVersion,
    string Checkpoint,
    string Operation,
    string State,
    string? InstalledCommit,
    string? IdentityFingerprintSha256,
    string? ReadState,
    int EventsRead,
    bool ResultPresent,
    bool ResultConsumed,
    bool RecoveryRemoved,
    bool EventContentRead,
    bool DataSigned,
    bool ServiceMutated,
    bool RegistryMutated,
    bool AuditPolicyMutated,
    bool TransportEnabled,
    bool CommandChannelEnabled,
    bool RuntimeWired);

public interface ISecurity4663LiveOneShotResultOperatorStore
{
    void PrepareEmpty();
    bool VerifyEmpty();
    string? ReadExisting();
    void ConsumeExact(string expectedJson);
    bool VerifyAbsent();
    bool CleanupBoundedProtected();
}

// Pure external C2f result operator. It never reads Windows events and never
// obtains a signing interface; all native authority is fixed-path and bounded.
public static class Security4663LiveOneShotResultOperator
{
    public const bool RuntimeWired = false;

    private static readonly IReadOnlyList<string> Commands = Array.AsReadOnly([
        "plan", "prepare-slot", "empty-check", "check", "consume",
        "absent-check", "cleanup"
    ]);

    public static Security4663LiveOneShotResultOperatorPlan BuildPlan() => new(
        1,
        Security4663LiveOneShotResultLifecycle.Checkpoint,
        Commands,
        NativeSecurity4663LiveOneShotResultFileSlot.ResultPath,
        Security4663LiveOneShotResultLifecycle.MaximumDocumentBytes,
        Security4663LiveOneShotResultLifecycle.MaximumResultAgeSeconds,
        true,
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
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false);

    public static void ValidatePlan(Security4663LiveOneShotResultOperatorPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var expected = BuildPlan();
        if (
            plan with { Commands = expected.Commands } != expected ||
            !plan.Commands.SequenceEqual(expected.Commands, StringComparer.Ordinal))
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_OPERATOR_PLAN_INVALID");
        }
    }

    public static Security4663LiveOneShotResultOperatorResult PrepareSlot(
        ISecurity4663LiveOneShotResultOperatorStore store,
        SensorIdentityDescriptor identity,
        InstallManifestBinding manifest,
        DateTimeOffset now)
    {
        ValidateContext(store, identity, manifest, now);
        store.PrepareEmpty();
        if (!store.VerifyEmpty())
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_SLOT_EMPTY_INVALID");
        }
        return Result("prepare-slot", "empty", manifest, identity, null, true, false, false);
    }

    public static Security4663LiveOneShotResultOperatorResult EmptyCheck(
        ISecurity4663LiveOneShotResultOperatorStore store,
        SensorIdentityDescriptor identity,
        InstallManifestBinding manifest,
        DateTimeOffset now)
    {
        ValidateContext(store, identity, manifest, now);
        if (!store.VerifyEmpty())
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_SLOT_EMPTY_INVALID");
        }
        return Result("empty-check", "empty", manifest, identity, null, true, false, false);
    }

    public static Security4663LiveOneShotResultOperatorResult Check(
        ISecurity4663LiveOneShotResultOperatorStore store,
        SensorIdentityDescriptor identity,
        InstallManifestBinding manifest,
        DateTimeOffset now)
    {
        ValidateContext(store, identity, manifest, now);
        var result = ValidateExisting(store, identity, manifest, now, out _);
        return Result("check", "valid", manifest, identity, result, true, false, false);
    }

    public static Security4663LiveOneShotResultOperatorResult Consume(
        ISecurity4663LiveOneShotResultOperatorStore store,
        SensorIdentityDescriptor identity,
        InstallManifestBinding manifest,
        DateTimeOffset now)
    {
        ValidateContext(store, identity, manifest, now);
        var result = ValidateExisting(store, identity, manifest, now, out var json);
        store.ConsumeExact(json);
        if (!store.VerifyAbsent())
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_CONSUME_INVALID");
        }
        return Result("consume", "consumed", manifest, identity, result, false, true, false);
    }

    public static Security4663LiveOneShotResultOperatorResult AbsentCheck(
        ISecurity4663LiveOneShotResultOperatorStore store,
        SensorIdentityDescriptor identity,
        InstallManifestBinding manifest,
        DateTimeOffset now)
    {
        ValidateContext(store, identity, manifest, now);
        if (!store.VerifyAbsent())
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_STILL_PRESENT");
        }
        return Result("absent-check", "absent", manifest, identity, null, false, false, false);
    }

    // Recovery is deliberately independent of identity, manifest and time so
    // an interrupted ceremony cannot strand the protected slot.
    public static Security4663LiveOneShotResultOperatorResult Cleanup(
        ISecurity4663LiveOneShotResultOperatorStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        var removed = store.CleanupBoundedProtected();
        return new(
            1,
            Security4663LiveOneShotResultLifecycle.Checkpoint,
            "cleanup",
            removed ? "removed" : "absent",
            null,
            null,
            null,
            0,
            false,
            false,
            removed,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false);
    }

    private static SignedSecurity4663LiveOneShotResult ValidateExisting(
        ISecurity4663LiveOneShotResultOperatorStore store,
        SensorIdentityDescriptor identity,
        InstallManifestBinding manifest,
        DateTimeOffset now,
        out string json)
    {
        json = store.ReadExisting() ?? throw Invalid(
            "SENSOR_C2F_SECURITY_4663_RESULT_MISSING");
        if (Security4663LiveOneShotFailureReceiptLifecycle.TryRead(
            json, out var failureCode))
        {
            throw Invalid(failureCode);
        }
        return Security4663LiveOneShotResultLifecycle.Validate(
            json, identity, manifest.Commit, now);
    }

    private static void ValidateContext(
        ISecurity4663LiveOneShotResultOperatorStore store,
        SensorIdentityDescriptor identity,
        InstallManifestBinding manifest,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(manifest);
        if (
            now.Offset != TimeSpan.Zero ||
            manifest.Fingerprint != identity.CertificateFingerprintSha256)
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_OPERATOR_CONTEXT_INVALID");
        }
    }

    private static Security4663LiveOneShotResultOperatorResult Result(
        string operation,
        string state,
        InstallManifestBinding manifest,
        SensorIdentityDescriptor identity,
        SignedSecurity4663LiveOneShotResult? result,
        bool present,
        bool consumed,
        bool recoveryRemoved) => new(
        1,
        Security4663LiveOneShotResultLifecycle.Checkpoint,
        operation,
        state,
        manifest.Commit,
        identity.CertificateFingerprintSha256,
        result?.ReadState,
        result?.EventsRead ?? 0,
        present,
        consumed,
        recoveryRemoved,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false);

    private static InvalidDataException Invalid(string code) => new(code);
}

// Elevated fixed-path implementation. Validation is read-only; consume and
// recovery delete only the exact file held by a single exclusive handle.
public sealed class NativeSecurity4663LiveOneShotResultOperatorStore :
    ISecurity4663LiveOneShotResultOperatorStore
{
    public const bool RuntimeWired = false;

    private const uint GenericRead = 0x80000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint OpenExisting = 3;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const int FileAttributeTagInfoClass = 9;
    private const int FileStandardInfoClass = 1;
    private const int FileDispositionInfoClass = 4;

    public void PrepareEmpty()
    {
        RequireAdministrator();
        new NativeSecurity4663LiveOneShotResultFileSlot().Prepare();
    }

    public bool VerifyEmpty()
    {
        RequireAdministrator();
        Security4663LiveOneShotResultFilePolicy.AssertProtectedRoot();
        if (!PathExists())
        {
            return false;
        }
        Security4663LiveOneShotResultFilePolicy.AssertProtectedFile(requireEmpty: true);
        _ = ReadExclusive(false, false, null, true, false);
        return true;
    }

    public string? ReadExisting()
    {
        RequireAdministrator();
        Security4663LiveOneShotResultFilePolicy.AssertProtectedRoot();
        if (!PathExists())
        {
            return null;
        }
        Security4663LiveOneShotResultFilePolicy.AssertProtectedFile(requireEmpty: false);
        return ReadExclusive(false, false, null, false, true);
    }

    public void ConsumeExact(string expectedJson)
    {
        RequireAdministrator();
        var expected = EncodeDocument(expectedJson);
        try
        {
            Security4663LiveOneShotResultFilePolicy.AssertProtectedRoot();
            Security4663LiveOneShotResultFilePolicy.AssertProtectedFile(requireEmpty: false);
            _ = ReadExclusive(true, true, expected, false, true);
            if (PathExists())
            {
                throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_CONSUME_INVALID");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    public bool VerifyAbsent()
    {
        RequireAdministrator();
        var root = Readiness.Security4663ReadinessCeremony.FixtureRoot;
        if (!TryGetAttributes(root, out var rootAttributes))
        {
            if (PathExists())
            {
                throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_CLEANUP_PATH_INVALID");
            }
            return true;
        }
        _ = EvaluateCleanupPathState(rootAttributes,
            TryGetAttributes(NativeSecurity4663LiveOneShotResultFileSlot.ResultPath,
                out var resultAttributes) ? resultAttributes : null);
        Security4663LiveOneShotResultFilePolicy.AssertProtectedRoot();
        return !PathExists();
    }

    public bool CleanupBoundedProtected()
    {
        RequireAdministrator();
        var root = Readiness.Security4663ReadinessCeremony.FixtureRoot;
        if (!TryGetAttributes(root, out var rootAttributes))
        {
            return EvaluateCleanupPathState(null,
                PathExists() ? File.GetAttributes(
                    NativeSecurity4663LiveOneShotResultFileSlot.ResultPath) : null);
        }
        Security4663LiveResultCleanupPathState(rootAttributes,
            TryGetAttributes(NativeSecurity4663LiveOneShotResultFileSlot.ResultPath,
                out var resultAttributes) ? resultAttributes : null);
        Security4663LiveOneShotResultFilePolicy.AssertProtectedRoot();
        if (!PathExists())
        {
            return false;
        }
        Security4663LiveOneShotResultFilePolicy.AssertProtectedFile(requireEmpty: null);
        _ = ReadExclusive(true, true, null, null, false);
        if (PathExists())
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_CLEANUP_INVALID");
        }
        return true;
    }

    internal static bool EvaluateCleanupPathState(
        FileAttributes? rootAttributes,
        FileAttributes? resultAttributes)
    {
        if (rootAttributes is null)
        {
            if (resultAttributes is not null)
            {
                throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_CLEANUP_PATH_INVALID");
            }
            return false;
        }
        if (!rootAttributes.Value.HasFlag(FileAttributes.Directory) ||
            rootAttributes.Value.HasFlag(FileAttributes.ReparsePoint))
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_SLOT_ROOT_INVALID");
        }
        if (resultAttributes is null)
        {
            return false;
        }
        if (resultAttributes.Value.HasFlag(FileAttributes.Directory) ||
            resultAttributes.Value.HasFlag(FileAttributes.ReparsePoint))
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_SLOT_FILE_INVALID");
        }
        return true;
    }

    private static void Security4663LiveResultCleanupPathState(
        FileAttributes rootAttributes,
        FileAttributes? resultAttributes) =>
        _ = EvaluateCleanupPathState(rootAttributes, resultAttributes);

    private static string ReadExclusive(
        bool allowDelete,
        bool deleteAfterRead,
        byte[]? expected,
        bool? requireEmpty,
        bool decode)
    {
        using var handle = CreateFileW(
            NativeSecurity4663LiveOneShotResultFileSlot.ResultPath,
            GenericRead | (allowDelete ? DeleteAccess : 0U),
            0,
            IntPtr.Zero,
            OpenExisting,
            FileFlagSequentialScan | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid ||
            !GetFileInformationByHandleEx(handle, FileAttributeTagInfoClass,
                out FileAttributeTagInfo tag, Marshal.SizeOf<FileAttributeTagInfo>()) ||
            !GetFileInformationByHandleEx(handle, FileStandardInfoClass,
                out FileStandardInfo standard, Marshal.SizeOf<FileStandardInfo>()))
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_OPEN_INVALID");
        }
        ValidateState(tag.FileAttributes, standard, requireEmpty);

        using var stream = new FileStream(handle, FileAccess.Read, 4096, false);
        var bytes = ReadBounded(stream, requireEmpty is not false);
        try
        {
            if (expected is not null &&
                !CryptographicOperations.FixedTimeEquals(bytes, expected))
            {
                throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_CHANGED");
            }
            var json = decode ? DecodeStrictUtf8(bytes) : string.Empty;
            if (deleteAfterRead)
            {
                var disposition = new FileDispositionInfo { DeleteFile = true };
                if (!SetFileInformationByHandle(handle, FileDispositionInfoClass,
                    ref disposition, Marshal.SizeOf<FileDispositionInfo>()))
                {
                    throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_CONSUME_INVALID");
                }
            }
            return json;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static void ValidateState(uint attributes, FileStandardInfo state,
        bool? requireEmpty)
    {
        if ((attributes & FileAttributeReparsePoint) != 0 ||
            state.NumberOfLinks != 1 || state.DeletePending || state.Directory ||
            state.EndOfFile < 0 ||
            state.EndOfFile > Security4663LiveOneShotResultLifecycle.MaximumDocumentBytes ||
            (requireEmpty == true && state.EndOfFile != 0) ||
            (requireEmpty == false && state.EndOfFile == 0))
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_STATE_INVALID");
        }
    }

    private static byte[] ReadBounded(FileStream stream, bool allowEmpty)
    {
        if (stream.Length < (allowEmpty ? 0 : 1) ||
            stream.Length > Security4663LiveOneShotResultLifecycle.MaximumDocumentBytes)
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_SIZE_INVALID");
        }
        var bytes = new byte[checked((int)stream.Length)];
        var offset = 0;
        while (offset < bytes.Length)
        {
            var read = stream.Read(bytes, offset, bytes.Length - offset);
            if (read == 0)
            {
                throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_READ_INVALID");
            }
            offset += read;
        }
        return bytes;
    }

    private static byte[] EncodeDocument(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_INPUT_INVALID");
        }
        var bytes = new UTF8Encoding(false, true).GetBytes(json);
        if (bytes.Length is < 1 or >
            Security4663LiveOneShotResultLifecycle.MaximumDocumentBytes || HasBom(bytes))
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_INPUT_INVALID");
        }
        return bytes;
    }

    private static string DecodeStrictUtf8(byte[] bytes)
    {
        if (HasBom(bytes))
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_INPUT_INVALID");
        }
        try
        {
            return new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_INPUT_INVALID");
        }
    }

    private static bool HasBom(ReadOnlySpan<byte> bytes) =>
        bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;

    private static bool PathExists() =>
        File.Exists(NativeSecurity4663LiveOneShotResultFileSlot.ResultPath) ||
        Directory.Exists(NativeSecurity4663LiveOneShotResultFileSlot.ResultPath);

    private static bool TryGetAttributes(string path, out FileAttributes attributes)
    {
        try
        {
            attributes = File.GetAttributes(path);
            return true;
        }
        catch (FileNotFoundException)
        {
            attributes = default;
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            attributes = default;
            return false;
        }
    }

    private static void RequireAdministrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("SENSOR_WINDOWS_REQUIRED");
        }
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            throw new UnauthorizedAccessException("SENSOR_ADMINISTRATOR_REQUIRED");
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
    private struct FileStandardInfo
    {
        internal long AllocationSize;
        internal long EndOfFile;
        internal uint NumberOfLinks;
        [MarshalAs(UnmanagedType.U1)] internal bool DeletePending;
        [MarshalAs(UnmanagedType.U1)] internal bool Directory;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInfo
    {
        [MarshalAs(UnmanagedType.Bool)] internal bool DeleteFile;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true,
        ExactSpelling = true)]
    private static extern SafeFileHandle CreateFileW(string lpFileName,
        uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle hFile,
        int fileInformationClass, out FileAttributeTagInfo lpFileInformation,
        int dwBufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle hFile,
        int fileInformationClass, out FileStandardInfo lpFileInformation,
        int dwBufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle hFile,
        int fileInformationClass, ref FileDispositionInfo lpFileInformation,
        int dwBufferSize);
}
