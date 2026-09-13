using System.Security.AccessControl;
using WARRoom.WindowsSensor;

namespace WARRoom.WindowsSensor.AuditWitnessInstaller;

public sealed record AuditWitnessProtectedFileInstallResult(
    AuditWitnessProtectedFileStatus Status,
    bool BaseRootCreated,
    bool RootCreated,
    bool FileCreated,
    bool ExistingHistoryPreserved,
    bool IndependentlyChecked);

public sealed record AuditWitnessProtectedFileInstallPlan(
    string BaseRootPath,
    string RootPath,
    string FilePath,
    string Claim,
    int MaximumBytes,
    int UsersAppendFileMask,
    bool RequiresAdministrator,
    bool ExistingFileNeverTruncated,
    bool ExistingFileNeverReplaced,
    bool FailedInstallRemovesOnlyNewEmptyObjects,
    bool RuntimeWiringEnabled,
    bool TelemetryEnabled,
    bool TransportEnabled,
    bool CommandChannelEnabled);

public static class AuditWitnessProtectedFileInstaller
{
    public static AuditWitnessProtectedFileInstallPlan BuildPlan() => new(
        AuditWitnessAppendFilePolicy.BaseRootPath,
        AuditWitnessAppendFilePolicy.RootPath,
        AuditWitnessAppendFilePolicy.FilePath,
        AuditWitnessAppendFilePolicy.Claim,
        AuditWitnessAppendFilePolicy.MaximumBytes,
        AuditWitnessAppendFilePolicy.UsersAppendFileMask,
        RequiresAdministrator: true,
        ExistingFileNeverTruncated: true,
        ExistingFileNeverReplaced: true,
        FailedInstallRemovesOnlyNewEmptyObjects: true,
        RuntimeWiringEnabled: false,
        TelemetryEnabled: false,
        TransportEnabled: false,
        CommandChannelEnabled: false);

    public static AuditWitnessProtectedFileInstallResult Install()
    {
        var baseCreated = false;
        var rootCreated = false;
        var fileCreated = false;
        try
        {
            EnsureProtectedDirectory(
                AuditWitnessAppendFilePolicy.BaseRootPath,
                ref baseCreated);
            EnsureProtectedDirectory(
                AuditWitnessAppendFilePolicy.RootPath,
                ref rootCreated);

            var filePath = AuditWitnessAppendFilePolicy.FilePath;
            if (Directory.Exists(filePath))
            {
                throw Invalid("SENSOR_AUDIT_WITNESS_FILE_INVALID");
            }
            if (!File.Exists(filePath))
            {
                using (var stream = new FileStream(
                    filePath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    4096,
                    FileOptions.WriteThrough))
                {
                    stream.Flush(true);
                }
                fileCreated = true;
                new FileInfo(filePath).SetAccessControl(
                    AuditWitnessAppendFilePolicy.CreateFileSecurity());
            }

            var status = AuditWitnessProtectedFileChecker.Check();
            return new(
                status,
                baseCreated,
                rootCreated,
                fileCreated,
                ExistingHistoryPreserved: !fileCreated,
                IndependentlyChecked: true);
        }
        catch
        {
            RollBackNewEmptyObjects(fileCreated, rootCreated, baseCreated);
            throw;
        }
    }

    private static void EnsureProtectedDirectory(
        string path,
        ref bool created)
    {
        if (File.Exists(path))
        {
            throw Invalid("SENSOR_AUDIT_WITNESS_ROOT_INVALID");
        }
        if (!Directory.Exists(path))
        {
            var directory = Directory.CreateDirectory(path);
            created = true;
            if (directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                throw Invalid("SENSOR_AUDIT_WITNESS_ROOT_INVALID");
            }
            directory.SetAccessControl(
                AuditWitnessAppendFilePolicy.CreateRootSecurity());
        }
        AuditWitnessProtectedFileChecker.ValidateDirectory(path);
    }

    private static void RollBackNewEmptyObjects(
        bool fileCreated,
        bool rootCreated,
        bool baseCreated)
    {
        try
        {
            if (fileCreated && File.Exists(
                AuditWitnessAppendFilePolicy.FilePath))
            {
                var file = new FileInfo(
                    AuditWitnessAppendFilePolicy.FilePath);
                if (!file.Attributes.HasFlag(FileAttributes.ReparsePoint) &&
                    file.Length == 0)
                {
                    file.Delete();
                }
            }
            RemoveNewEmptyDirectory(
                AuditWitnessAppendFilePolicy.RootPath,
                rootCreated);
            RemoveNewEmptyDirectory(
                AuditWitnessAppendFilePolicy.BaseRootPath,
                baseCreated);
        }
        catch (Exception error)
        {
            throw new InvalidOperationException(
                "SENSOR_AUDIT_WITNESS_INSTALL_ROLLBACK_FAILED",
                error);
        }
    }

    private static void RemoveNewEmptyDirectory(string path, bool created)
    {
        if (!created || !Directory.Exists(path))
        {
            return;
        }
        var directory = new DirectoryInfo(path);
        if (directory.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            directory.EnumerateFileSystemInfos().Any())
        {
            throw Invalid("SENSOR_AUDIT_WITNESS_INSTALL_ROLLBACK_FAILED");
        }
        directory.Delete();
    }

    private static InvalidDataException Invalid(string code) => new(code);
}
