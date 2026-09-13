using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WARRoom.WindowsSensor.Readiness;

public sealed record Security4663CeremonyPlan(
    int SchemaVersion,
    string Checkpoint,
    string StatePath,
    bool RequiresElevation,
    bool TemporarilyEnablesOperatorSecurityPrivilege,
    bool AssignsPrivilegeToService,
    bool RequiresExactLocalServiceIdentity,
    bool RequiresFixtureRootAbsent,
    bool PreservesOriginalChannelDescriptor,
    bool PreservesOriginalAuditPolicy,
    bool AppliesLocalServiceReadOnlyChannelAce,
    bool AppliesAuditSuccessOnly,
    bool CreatesOnlyFixedInertTargets,
    bool RollbackRequired,
    bool ReadsEvents,
    long EventsRead,
    bool RuntimeCollectionEnabled,
    bool TransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled);

public sealed record Security4663CeremonySnapshot(
    int SchemaVersion,
    string Checkpoint,
    string OriginalChannelSddl,
    uint OriginalAuditPolicy,
    string StateHashSha256);

public sealed record Security4663CeremonyResult(
    int SchemaVersion,
    string Checkpoint,
    string Operation,
    bool Completed,
    bool ServiceIdentityValidated,
    bool OriginalStateProtected,
    bool ChannelChanged,
    bool AuditPolicyChanged,
    bool TargetSaclChanged,
    bool OriginalStateRestored,
    bool ReadsEvents,
    long EventsRead,
    bool RuntimeCollectionEnabled,
    bool TransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled);

public sealed record Security4663CeremonyExerciseResult(
    int SchemaVersion,
    string Checkpoint,
    bool Completed,
    bool Applied,
    bool ReadyBeforeRollback,
    bool OriginalStateRestored,
    bool ReadsEvents,
    long EventsRead,
    bool RuntimeCollectionEnabled,
    bool TransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled);

public interface ISecurity4663CeremonyStore
{
    void RequireAdministrator();
    void ValidateServiceIdentity();
    void ValidateApplyPreconditions();
    Security4663CeremonySnapshot CaptureOriginalState();
    void WriteProtectedState(Security4663CeremonySnapshot snapshot);
    void ApplyChannelReadOnlyAce();
    void ApplyAuditSuccessOnly();
    void CreateFixedTargets();
    Security4663ReadinessCheckResult CheckReadiness();
    void RecoverFailedApply(Security4663CeremonySnapshot snapshot);
    Security4663CeremonySnapshot ReadProtectedState();
    void ValidateRollbackPreconditions(Security4663CeremonySnapshot snapshot);
    void RestoreOriginalState(Security4663CeremonySnapshot snapshot);
    void RemoveFixedTargetsAndState();
}

public static class Security4663ReadinessCeremony
{
    public const string Checkpoint =
        "gate-c2d-security-4663-machine-readiness";
    public const string FixtureRoot =
        @"C:\ProgramData\WAR-R00M\Windows Sensor\C2";
    public const string StatePath =
        @"C:\ProgramData\WAR-R00M\Windows Sensor\C2\security-4663-ceremony-state.json";

    public static Security4663CeremonyPlan BuildPlan() => new(
        1,
        Checkpoint,
        StatePath,
        true,
        true,
        false,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        false,
        0,
        false,
        false,
        false,
        false);

    public static void ValidatePlan(Security4663CeremonyPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (plan != BuildPlan())
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_CEREMONY_PLAN_INVALID");
        }
    }

    public static Security4663CeremonyResult Apply(
        ISecurity4663CeremonyStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        ValidatePlan(BuildPlan());
        store.RequireAdministrator();
        store.ValidateServiceIdentity();
        store.ValidateApplyPreconditions();
        var snapshot = store.CaptureOriginalState();
        ValidateSnapshot(snapshot);
        try
        {
            store.WriteProtectedState(snapshot);
            store.ApplyChannelReadOnlyAce();
            store.ApplyAuditSuccessOnly();
            store.CreateFixedTargets();
            var readiness = store.CheckReadiness();
            if (!readiness.Ready || readiness.ReadsEvents || readiness.EventsRead != 0)
            {
                throw new InvalidDataException(
                    "SENSOR_C2D_SECURITY_4663_APPLY_CHECK_FAILED");
            }
        }
        catch
        {
            try
            {
                store.RecoverFailedApply(snapshot);
            }
            catch (Exception recoveryError)
            {
                throw new InvalidDataException(
                    "SENSOR_C2D_SECURITY_4663_APPLY_RECOVERY_FAILED",
                    recoveryError);
            }
            throw;
        }

        return Result("apply", originalStateRestored: false);
    }

    public static Security4663CeremonyResult Rollback(
        ISecurity4663CeremonyStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        ValidatePlan(BuildPlan());
        store.RequireAdministrator();
        store.ValidateServiceIdentity();
        var snapshot = store.ReadProtectedState();
        ValidateSnapshot(snapshot);
        store.ValidateRollbackPreconditions(snapshot);
        store.RestoreOriginalState(snapshot);
        store.RemoveFixedTargetsAndState();
        return Result("rollback", originalStateRestored: true);
    }

    public static Security4663CeremonyExerciseResult Exercise(
        ISecurity4663CeremonyStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        var applied = Apply(store);
        if (!applied.Completed)
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_EXERCISE_APPLY_FAILED");
        }
        var rolledBack = Rollback(store);
        if (!rolledBack.Completed || !rolledBack.OriginalStateRestored)
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_EXERCISE_ROLLBACK_FAILED");
        }
        return new Security4663CeremonyExerciseResult(
            1,
            Checkpoint,
            true,
            true,
            true,
            true,
            false,
            0,
            false,
            false,
            false,
            false);
    }

    public static Security4663CeremonySnapshot CreateSnapshot(
        string channelSddl,
        uint auditPolicy)
    {
        if (string.IsNullOrWhiteSpace(channelSddl) || channelSddl.Length > 16_384)
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_STATE_INVALID");
        }
        _ = new RawSecurityDescriptor(channelSddl);
        var hash = CalculateSnapshotHash(channelSddl, auditPolicy);
        return new Security4663CeremonySnapshot(
            1,
            Checkpoint,
            channelSddl,
            auditPolicy,
            hash);
    }

    public static void ValidateSnapshot(Security4663CeremonySnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        if (
            snapshot.SchemaVersion != 1 ||
            snapshot.Checkpoint != Checkpoint ||
            string.IsNullOrWhiteSpace(snapshot.OriginalChannelSddl) ||
            snapshot.OriginalChannelSddl.Length > 16_384 ||
            snapshot.StateHashSha256.Length != 64 ||
            !CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(snapshot.StateHashSha256),
                Encoding.ASCII.GetBytes(CalculateSnapshotHash(
                    snapshot.OriginalChannelSddl,
                    snapshot.OriginalAuditPolicy))))
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_STATE_INVALID");
        }
        _ = new RawSecurityDescriptor(snapshot.OriginalChannelSddl);
    }

    private static string CalculateSnapshotHash(
        string channelSddl,
        uint auditPolicy)
    {
        var encodedSddl = Convert.ToBase64String(
            Encoding.UTF8.GetBytes(channelSddl));
        var canonical = string.Join(
            '\n',
            "1",
            Checkpoint,
            encodedSddl,
            auditPolicy.ToString(CultureInfo.InvariantCulture),
            string.Empty);
        return Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(canonical)))
            .ToLowerInvariant();
    }

    private static Security4663CeremonyResult Result(
        string operation,
        bool originalStateRestored) => new(
            1,
            Checkpoint,
            operation,
            true,
            true,
            true,
            operation == "apply",
            operation == "apply",
            operation == "apply",
            originalStateRestored,
            false,
            0,
            false,
            false,
            false,
            false);
}

public sealed class NativeSecurity4663CeremonyStore :
    ISecurity4663CeremonyStore
{
    private const uint AuditSuccess = 0x00000001;
    private const uint AuditFailure = 0x00000002;
    private const uint AuditNone = 0x00000004;
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint TokenQuery = 0x0008;
    private const uint SePrivilegeEnabled = 0x00000002;
    private const int ErrorNotAllAssigned = 1300;
    private static readonly Guid FileSystemAuditSubcategory =
        new("0CCE921D-69AE-11D9-BED3-505054503030");
    private static readonly SecurityIdentifier LocalSystem = new("S-1-5-18");
    private static readonly SecurityIdentifier Administrators =
        new("S-1-5-32-544");
    private static readonly SecurityIdentifier LocalService = new("S-1-5-19");
    private static readonly SecurityIdentifier Everyone = new("S-1-1-0");
    private static readonly JsonSerializerOptions StateJson = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public void RequireAdministrator()
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
        EnablePrivilege(
            "SeSecurityPrivilege",
            "SENSOR_SECURITY_PRIVILEGE_UNAVAILABLE");
    }

    public void ValidateServiceIdentity()
    {
        using var machine = RegistryKey.OpenBaseKey(
            RegistryHive.LocalMachine,
            RegistryView.Registry64);
        using var service = machine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Services\WARRoomWindowsSensor",
            writable: false);
        var objectName = service?.GetValue(
            "ObjectName",
            null,
            RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
        if (!string.Equals(
            objectName,
            @"NT AUTHORITY\LocalService",
            StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SERVICE_IDENTITY_INVALID");
        }
    }

    public void ValidateApplyPreconditions()
    {
        if (Directory.Exists(Security4663ReadinessCeremony.FixtureRoot) ||
            File.Exists(Security4663ReadinessCeremony.FixtureRoot))
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_FIXTURE_ROOT_NOT_ABSENT");
        }
        var channel = new NativeSecurity4663ReadinessProbe().InspectChannel();
        if (!channel.Accessible || channel.LocalServiceReadOnly)
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_CHANNEL_PRECONDITION_INVALID");
        }
        var descriptor = ReadChannelDescriptor();
        if (descriptor.DiscretionaryAcl is null ||
            descriptor.DiscretionaryAcl.Cast<GenericAce>().Any(ace =>
                ace is CommonAce common &&
                common.SecurityIdentifier.Equals(LocalService)))
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_CHANNEL_PRECONDITION_INVALID");
        }
    }

    public Security4663CeremonySnapshot CaptureOriginalState()
    {
        var sddl = ReadChannelSddl();
        var auditPolicy = QueryAuditPolicy();
        return Security4663ReadinessCeremony.CreateSnapshot(sddl, auditPolicy);
    }

    public void WriteProtectedState(Security4663CeremonySnapshot snapshot)
    {
        Security4663ReadinessCeremony.ValidateSnapshot(snapshot);
        var directory = new DirectoryInfo(
            Security4663ReadinessCeremony.FixtureRoot);
        var directorySecurity = CreateProtectedDirectorySecurity();
        directory.Create(directorySecurity);
        directory.SetAccessControl(directorySecurity);
        AssertProtectedDirectory();
        var bytes = JsonSerializer.SerializeToUtf8Bytes(snapshot, StateJson);
        using (var stream = new FileStream(
            Security4663ReadinessCeremony.StatePath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            4096,
            FileOptions.WriteThrough))
        {
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }
        new FileInfo(Security4663ReadinessCeremony.StatePath)
            .SetAccessControl(CreateProtectedFileSecurity(includeAudit: false));
        AssertProtectedStateFile();
    }

    public void ApplyChannelReadOnlyAce()
    {
        using var configuration = new EventLogConfiguration("Security");
        var descriptor = new RawSecurityDescriptor(
            configuration.SecurityDescriptor);
        var dacl = descriptor.DiscretionaryAcl ?? throw new InvalidDataException(
            "SENSOR_C2D_SECURITY_4663_CHANNEL_DACL_INVALID");
        if (dacl.Cast<GenericAce>().Any(ace =>
            ace is CommonAce common &&
            common.SecurityIdentifier.Equals(LocalService)))
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_CHANNEL_PRECONDITION_INVALID");
        }
        var insertAt = dacl.Count;
        for (var index = 0; index < dacl.Count; index++)
        {
            if (dacl[index].IsInherited)
            {
                insertAt = index;
                break;
            }
        }
        dacl.InsertAce(insertAt, new CommonAce(
            AceFlags.None,
            AceQualifier.AccessAllowed,
            0x1,
            LocalService,
            isCallback: false,
            opaque: null));
        configuration.SecurityDescriptor = descriptor.GetSddlForm(
            AccessControlSections.All);
        configuration.SaveChanges();
    }

    public void ApplyAuditSuccessOnly() => SetAuditPolicy(AuditSuccess);

    public void CreateFixedTargets()
    {
        foreach (var target in Security4663MachineReadiness.BuildPlan().Targets)
        {
            if (!string.Equals(
                Path.GetDirectoryName(target.InertTargetPath),
                Security4663ReadinessCeremony.FixtureRoot,
                StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "SENSOR_C2D_SECURITY_4663_TARGET_PATH_INVALID");
            }
            using (new FileStream(
                target.InertTargetPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                1,
                FileOptions.WriteThrough))
            {
            }
            new FileInfo(target.InertTargetPath).SetAccessControl(
                CreateProtectedFileSecurity(
                    includeAudit: true,
                    target.RequiredAccessMask));
        }
    }

    public Security4663ReadinessCheckResult CheckReadiness() =>
        Security4663ReadinessCheck.Check(
            new NativeSecurity4663ReadinessProbe());

    public void RecoverFailedApply(Security4663CeremonySnapshot snapshot)
    {
        RestoreOriginalState(snapshot);
        RemoveKnownCeremonyFiles(requireAllTargets: false);
    }

    public Security4663CeremonySnapshot ReadProtectedState()
    {
        AssertProtectedStateFile();
        var file = new FileInfo(Security4663ReadinessCeremony.StatePath);
        if (file.Length is < 1 or > 32_768)
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_STATE_INVALID");
        }
        var snapshot = JsonSerializer.Deserialize<Security4663CeremonySnapshot>(
            File.ReadAllBytes(file.FullName),
            StateJson) ?? throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_STATE_INVALID");
        Security4663ReadinessCeremony.ValidateSnapshot(snapshot);
        return snapshot;
    }

    public void ValidateRollbackPreconditions(
        Security4663CeremonySnapshot snapshot)
    {
        Security4663ReadinessCeremony.ValidateSnapshot(snapshot);
        AssertProtectedStateFile();
        var root = new DirectoryInfo(Security4663ReadinessCeremony.FixtureRoot);
        if (!root.Exists || root.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            root.EnumerateDirectories().Any())
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_ROLLBACK_SCOPE_INVALID");
        }
        AssertProtectedDirectory();
        var allowedFiles = Security4663MachineReadiness.BuildPlan().Targets
            .Select(target => target.InertTargetPath)
            .Append(Security4663ReadinessCeremony.StatePath)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var actualFiles = root.EnumerateFiles().Select(file => file.FullName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!actualFiles.SetEquals(allowedFiles))
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_ROLLBACK_SCOPE_INVALID");
        }
        var probe = new NativeSecurity4663ReadinessProbe();
        if (Security4663MachineReadiness.BuildPlan().Targets.Any(target =>
        {
            var result = probe.InspectTarget(target);
            return !result.Exists || !result.ZeroLength || result.ReparsePoint ||
                !result.SaclAccessible || !result.ExactSuccessAudit;
        }))
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_ROLLBACK_TARGET_INVALID");
        }
    }

    public void RestoreOriginalState(Security4663CeremonySnapshot snapshot)
    {
        Security4663ReadinessCeremony.ValidateSnapshot(snapshot);
        using (var configuration = new EventLogConfiguration("Security"))
        {
            configuration.SecurityDescriptor = snapshot.OriginalChannelSddl;
            configuration.SaveChanges();
        }
        SetAuditPolicy(ToSettableAuditPolicy(snapshot.OriginalAuditPolicy));
        if (!DescriptorsEqual(
                ReadChannelSddl(),
                snapshot.OriginalChannelSddl) ||
            CanonicalAuditBehavior(QueryAuditPolicy()) !=
                CanonicalAuditBehavior(snapshot.OriginalAuditPolicy))
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_ROLLBACK_VERIFY_FAILED");
        }
    }

    public void RemoveFixedTargetsAndState() =>
        RemoveKnownCeremonyFiles(requireAllTargets: true);

    private static void RemoveKnownCeremonyFiles(bool requireAllTargets)
    {
        var targets = Security4663MachineReadiness.BuildPlan().Targets;
        foreach (var target in targets)
        {
            if (!File.Exists(target.InertTargetPath))
            {
                if (requireAllTargets)
                {
                    throw new InvalidDataException(
                        "SENSOR_C2D_SECURITY_4663_ROLLBACK_TARGET_INVALID");
                }
                continue;
            }
            var file = new FileInfo(target.InertTargetPath);
            if (file.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
                file.Length != 0)
            {
                throw new InvalidDataException(
                    "SENSOR_C2D_SECURITY_4663_ROLLBACK_TARGET_INVALID");
            }
            file.Delete();
        }
        if (File.Exists(Security4663ReadinessCeremony.StatePath))
        {
            var state = new FileInfo(Security4663ReadinessCeremony.StatePath);
            if (state.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                throw new InvalidDataException(
                    "SENSOR_C2D_SECURITY_4663_STATE_INVALID");
            }
            state.Delete();
        }
        if (Directory.Exists(Security4663ReadinessCeremony.FixtureRoot))
        {
            var root = new DirectoryInfo(Security4663ReadinessCeremony.FixtureRoot);
            if (root.EnumerateFileSystemInfos().Any())
            {
                throw new InvalidDataException(
                    "SENSOR_C2D_SECURITY_4663_ROLLBACK_SCOPE_INVALID");
            }
            root.Delete(recursive: false);
        }
    }

    private static FileSecurity CreateProtectedFileSecurity(
        bool includeAudit,
        string? accessMask = null)
    {
        var security = new FileSecurity();
        security.SetOwner(Administrators);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            LocalSystem,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            Administrators,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        security.SetAuditRuleProtection(isProtected: true, preserveInheritance: false);
        if (includeAudit)
        {
            var rights = accessMask switch
            {
                "0x00000001" => FileSystemRights.ReadData,
                "0x00000100" => FileSystemRights.WriteAttributes,
                _ => throw new InvalidDataException(
                    "SENSOR_C2D_SECURITY_4663_TARGET_MASK_INVALID")
            };
            security.AddAuditRule(new FileSystemAuditRule(
                Everyone,
                rights,
                AuditFlags.Success));
        }
        return security;
    }

    private static DirectorySecurity CreateProtectedDirectorySecurity()
    {
        var security = new DirectorySecurity();
        security.SetOwner(Administrators);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inheritance =
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(
            LocalSystem,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            Administrators,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        return security;
    }

    private static void AssertProtectedStateFile()
    {
        var file = new FileInfo(Security4663ReadinessCeremony.StatePath);
        if (!file.Exists || file.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_STATE_INVALID");
        }
        var security = file.GetAccessControl(
            AccessControlSections.Access | AccessControlSections.Owner);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as
            SecurityIdentifier;
        var rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            LocalSystem.Value,
            Administrators.Value
        };
        if (!IsAllowedCeremonyOwner(owner))
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_STATE_OWNER_INVALID");
        }
        if (!security.AreAccessRulesProtected)
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_STATE_DACL_PROTECTION_INVALID");
        }
        if (rules.Length != 2)
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_STATE_RULE_COUNT_INVALID");
        }
        if (
            rules.Any(rule =>
                rule.IsInherited ||
                rule.AccessControlType != AccessControlType.Allow ||
                !expected.Remove(rule.IdentityReference.Value) ||
                !IsExactFullControl(rule.FileSystemRights)) ||
            expected.Count != 0)
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_STATE_ACL_INVALID");
        }
    }

    private static void AssertProtectedDirectory()
    {
        var directory = new DirectoryInfo(
            Security4663ReadinessCeremony.FixtureRoot);
        if (!directory.Exists ||
            directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_ROOT_ACL_INVALID");
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
            LocalSystem.Value,
            Administrators.Value
        };
        if (!IsAllowedCeremonyOwner(owner))
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_ROOT_OWNER_INVALID");
        }
        if (!security.AreAccessRulesProtected)
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_ROOT_DACL_PROTECTION_INVALID");
        }
        if (rules.Length != 2)
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_ROOT_RULE_COUNT_INVALID");
        }
        if (
            rules.Any(rule =>
                rule.IsInherited ||
                rule.AccessControlType != AccessControlType.Allow ||
                !expected.Remove(rule.IdentityReference.Value) ||
                !IsExactFullControl(rule.FileSystemRights) ||
                rule.PropagationFlags != PropagationFlags.None) ||
            expected.Count != 0)
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_ROOT_RULE_SCOPE_INVALID");
        }
    }

    internal static bool IsExactFullControl(FileSystemRights rights)
    {
        const int mappedFullControl = 0x001F01FF;
        const int genericAll = 0x10000000;
        var mask = unchecked((int)rights);
        return mask is mappedFullControl or genericAll;
    }

    private static bool IsAllowedCeremonyOwner(SecurityIdentifier? owner)
    {
        if (owner is null)
        {
            return false;
        }
        if (owner.Equals(Administrators))
        {
            return true;
        }
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User is not null &&
            owner.Equals(identity.User) &&
            new WindowsPrincipal(identity).IsInRole(
                WindowsBuiltInRole.Administrator);
    }

    private static string ReadChannelSddl()
    {
        using var configuration = new EventLogConfiguration("Security");
        return configuration.SecurityDescriptor;
    }

    private static RawSecurityDescriptor ReadChannelDescriptor() =>
        new(ReadChannelSddl());

    private static bool DescriptorsEqual(string left, string right)
    {
        var leftDescriptor = new RawSecurityDescriptor(left);
        var rightDescriptor = new RawSecurityDescriptor(right);
        var leftBytes = new byte[leftDescriptor.BinaryLength];
        var rightBytes = new byte[rightDescriptor.BinaryLength];
        leftDescriptor.GetBinaryForm(leftBytes, 0);
        rightDescriptor.GetBinaryForm(rightBytes, 0);
        return leftBytes.AsSpan().SequenceEqual(rightBytes);
    }

    private static uint QueryAuditPolicy()
    {
        IntPtr buffer = IntPtr.Zero;
        try
        {
            if (!AuditQuerySystemPolicy(
                [FileSystemAuditSubcategory],
                1,
                out buffer))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            var information = Marshal.PtrToStructure<AuditPolicyInformation>(
                buffer);
            if (information.AuditSubCategoryGuid != FileSystemAuditSubcategory)
            {
                throw new InvalidDataException(
                    "SENSOR_C2D_SECURITY_4663_AUDIT_POLICY_INVALID");
            }
            return information.AuditingInformation;
        }
        finally
        {
            if (buffer != IntPtr.Zero) AuditFree(buffer);
        }
    }

    private static void SetAuditPolicy(uint auditingInformation)
    {
        var information = new AuditPolicyInformation
        {
            AuditSubCategoryGuid = FileSystemAuditSubcategory,
            AuditingInformation = auditingInformation,
            AuditCategoryGuid = Guid.Empty
        };
        if (!AuditSetSystemPolicy([information], 1))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    public static uint CanonicalAuditBehavior(uint auditingInformation) =>
        auditingInformation & (AuditSuccess | AuditFailure);

    public static uint ToSettableAuditPolicy(uint auditingInformation)
    {
        var behavior = CanonicalAuditBehavior(auditingInformation);
        return behavior == 0 ? AuditNone : behavior;
    }

    private static void EnablePrivilege(
        string privilegeName,
        string unavailableErrorCode)
    {
        if (!OpenProcessToken(
            Process.GetCurrentProcess().Handle,
            TokenAdjustPrivileges | TokenQuery,
            out var token))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        using (token)
        {
            if (!LookupPrivilegeValue(null, privilegeName, out var luid))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            var privileges = new TokenPrivileges
            {
                PrivilegeCount = 1,
                Privileges = new LuidAndAttributes
                {
                    Luid = luid,
                    Attributes = SePrivilegeEnabled
                }
            };
            if (!AdjustTokenPrivileges(
                token,
                disableAllPrivileges: false,
                ref privileges,
                0,
                IntPtr.Zero,
                IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            var error = Marshal.GetLastWin32Error();
            if (error == ErrorNotAllAssigned)
            {
                throw new UnauthorizedAccessException(
                    unavailableErrorCode);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AuditPolicyInformation
    {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LuidAndAttributes
    {
        public Luid Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public uint PrivilegeCount;
        public LuidAndAttributes Privileges;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AuditQuerySystemPolicy(
        [In] Guid[] subCategoryGuids,
        uint policyCount,
        out IntPtr auditPolicy);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AuditSetSystemPolicy(
        [In] AuditPolicyInformation[] auditPolicy,
        uint policyCount);

    [DllImport("advapi32.dll")]
    private static extern void AuditFree(IntPtr buffer);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out SafeAccessTokenHandle tokenHandle);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValue(
        string? systemName,
        string name,
        out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(
        SafeAccessTokenHandle tokenHandle,
        [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
        ref TokenPrivileges newState,
        uint bufferLength,
        IntPtr previousState,
        IntPtr returnLength);
}
