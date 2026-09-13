using System.ComponentModel;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;

namespace WARRoom.WindowsSensor.Readiness;

public sealed record Security4663ChannelObservation(
    bool Accessible,
    bool LocalServiceReadOnly,
    string? ErrorCode);

public sealed record Security4663AuditPolicyObservation(
    bool Accessible,
    bool SuccessEnabled,
    bool FailureEnabled,
    string? ErrorCode);

public sealed record Security4663TargetObservation(
    string ProfileId,
    bool Exists,
    bool ZeroLength,
    bool ReparsePoint,
    bool SaclAccessible,
    bool ExactSuccessAudit,
    string? ErrorCode);

public sealed record Security4663ReadinessCheckResult(
    int SchemaVersion,
    string Checkpoint,
    bool Ready,
    bool ServiceIdentityValidated,
    bool ChangesChannelAccess,
    bool ChangesAuditPolicy,
    bool ChangesTargetSacl,
    bool ReadsEvents,
    long EventsRead,
    bool RuntimeCollectionEnabled,
    bool TransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    Security4663ChannelObservation Channel,
    Security4663AuditPolicyObservation AuditPolicy,
    IReadOnlyList<Security4663TargetObservation> Targets);

public interface ISecurity4663ReadinessProbe
{
    Security4663ChannelObservation InspectChannel();
    Security4663AuditPolicyObservation InspectAuditPolicy();
    Security4663TargetObservation InspectTarget(
        Security4663TargetReadinessDefinition target);
}

public sealed class NativeSecurity4663ReadinessProbe :
    ISecurity4663ReadinessProbe
{
    private const uint AuditSuccess = 0x00000001;
    private const uint AuditFailure = 0x00000002;
    private static readonly Guid FileSystemAuditSubcategory =
        new("0CCE921D-69AE-11D9-BED3-505054503030");

    public Security4663ChannelObservation InspectChannel()
    {
        try
        {
            using var configuration = new EventLogConfiguration("Security");
            var descriptor = new RawSecurityDescriptor(
                configuration.SecurityDescriptor);
            var localService = new SecurityIdentifier("S-1-5-19");
            var exactReadAllowCount = 0;
            var additionalAllow = false;
            var denied = false;
            if (descriptor.DiscretionaryAcl is not null)
            {
                foreach (GenericAce ace in descriptor.DiscretionaryAcl)
                {
                    if (
                        ace is not CommonAce common ||
                        !common.SecurityIdentifier.Equals(localService))
                    {
                        continue;
                    }

                    if (
                        common.AceQualifier == AceQualifier.AccessDenied &&
                        (common.AccessMask & 0x1) != 0)
                    {
                        denied = true;
                    }
                    if (
                        common.AceQualifier == AceQualifier.AccessAllowed &&
                        common.AccessMask == 0x1)
                    {
                        exactReadAllowCount++;
                    }
                    else if (common.AceQualifier == AceQualifier.AccessAllowed)
                    {
                        additionalAllow = true;
                    }
                }
            }

            var exactReadOnly =
                exactReadAllowCount == 1 && !additionalAllow && !denied;

            return new Security4663ChannelObservation(
                true,
                exactReadOnly,
                exactReadOnly ? null : "localservice-read-only-ace-mismatch");
        }
        catch (UnauthorizedAccessException)
        {
            return ChannelUnavailable("access-denied");
        }
        catch (SecurityException)
        {
            return ChannelUnavailable("access-denied");
        }
        catch (EventLogException)
        {
            return ChannelUnavailable("channel-unavailable");
        }
        catch (ArgumentException)
        {
            return ChannelUnavailable("channel-sddl-invalid");
        }
    }

    public Security4663AuditPolicyObservation InspectAuditPolicy()
    {
        IntPtr buffer = IntPtr.Zero;
        try
        {
            if (!AuditQuerySystemPolicy(
                [FileSystemAuditSubcategory],
                1,
                out buffer))
            {
                var error = Marshal.GetLastWin32Error();
                return AuditUnavailable(error switch
                {
                    5 => "access-denied",
                    1314 => "privilege-not-held",
                    _ => $"native-error-{error}"
                });
            }

            var information = Marshal.PtrToStructure<AuditPolicyInformation>(
                buffer);
            if (information.AuditSubCategoryGuid != FileSystemAuditSubcategory)
            {
                return AuditUnavailable("subcategory-mismatch");
            }

            return new Security4663AuditPolicyObservation(
                true,
                (information.AuditingInformation & AuditSuccess) != 0,
                (information.AuditingInformation & AuditFailure) != 0,
                null);
        }
        finally
        {
            if (buffer != IntPtr.Zero) AuditFree(buffer);
        }
    }

    public Security4663TargetObservation InspectTarget(
        Security4663TargetReadinessDefinition target)
    {
        ArgumentNullException.ThrowIfNull(target);
        try
        {
            var file = new FileInfo(target.InertTargetPath);
            if (!file.Exists)
            {
                return TargetUnavailable(target.ProfileId, "target-absent");
            }

            var reparse = file.Attributes.HasFlag(FileAttributes.ReparsePoint);
            var zeroLength = file.Length == 0;
            var security = file.GetAccessControl(AccessControlSections.Audit);
            var rules = security.GetAuditRules(
                includeExplicit: true,
                includeInherited: true,
                typeof(SecurityIdentifier));
            var expectedRights = target.RequiredAccessMask switch
            {
                "0x00000001" => FileSystemRights.ReadData,
                "0x00000100" => FileSystemRights.WriteAttributes,
                _ => throw new InvalidDataException(
                    "SENSOR_C2D_SECURITY_4663_TARGET_MASK_INVALID")
            };
            var everyone = new SecurityIdentifier(target.AuditPrincipalSid);
            var matching = rules.Cast<FileSystemAuditRule>().Where(rule =>
                rule.IdentityReference.Equals(everyone) &&
                rule.AuditFlags == AuditFlags.Success &&
                rule.InheritanceFlags == InheritanceFlags.None &&
                rule.PropagationFlags == PropagationFlags.None &&
                rule.FileSystemRights == expectedRights).ToArray();
            var exact = rules.Count == 1 && matching.Length == 1;
            return new Security4663TargetObservation(
                target.ProfileId,
                true,
                zeroLength,
                reparse,
                true,
                exact,
                exact ? null : "target-sacl-mismatch");
        }
        catch (PrivilegeNotHeldException)
        {
            return TargetUnavailable(target.ProfileId, "sacl-access-denied");
        }
        catch (UnauthorizedAccessException)
        {
            return TargetUnavailable(target.ProfileId, "sacl-access-denied");
        }
        catch (SecurityException)
        {
            return TargetUnavailable(target.ProfileId, "sacl-access-denied");
        }
        catch (IOException)
        {
            return TargetUnavailable(target.ProfileId, "target-metadata-unavailable");
        }
    }

    private static Security4663ChannelObservation ChannelUnavailable(
        string errorCode) => new(false, false, errorCode);

    private static Security4663AuditPolicyObservation AuditUnavailable(
        string errorCode) => new(false, false, false, errorCode);

    private static Security4663TargetObservation TargetUnavailable(
        string profileId,
        string errorCode) =>
        new(profileId, false, false, false, false, false, errorCode);

    [StructLayout(LayoutKind.Sequential)]
    private struct AuditPolicyInformation
    {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AuditQuerySystemPolicy(
        [In] Guid[] subCategoryGuids,
        uint policyCount,
        out IntPtr auditPolicy);

    [DllImport("advapi32.dll")]
    private static extern void AuditFree(IntPtr buffer);
}

public static class Security4663ReadinessCheck
{
    public static Security4663ReadinessCheckResult Check(
        ISecurity4663ReadinessProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        var plan = Security4663MachineReadiness.BuildPlan();
        Security4663MachineReadiness.ValidatePlan(plan);
        var channel = probe.InspectChannel();
        var auditPolicy = probe.InspectAuditPolicy();
        var targets = plan.Targets.Select(probe.InspectTarget).ToArray();
        var ready =
            channel.Accessible &&
            channel.LocalServiceReadOnly &&
            channel.ErrorCode is null &&
            auditPolicy.Accessible &&
            auditPolicy.SuccessEnabled &&
            !auditPolicy.FailureEnabled &&
            auditPolicy.ErrorCode is null &&
            targets.All(target =>
                target.Exists &&
                target.ZeroLength &&
                !target.ReparsePoint &&
                target.SaclAccessible &&
                target.ExactSuccessAudit &&
                target.ErrorCode is null);

        return new Security4663ReadinessCheckResult(
            1,
            plan.Checkpoint,
            ready,
            false,
            false,
            false,
            false,
            false,
            0,
            false,
            false,
            false,
            false,
            channel,
            auditPolicy,
            Array.AsReadOnly(targets));
    }
}
