using System.Collections.ObjectModel;

namespace WARRoom.WindowsSensor.Readiness;

public sealed record Security4663TargetReadinessDefinition(
    string ProfileId,
    string InertTargetPath,
    string RequiredAccessMask,
    string AuditPrincipalSid,
    bool SuccessAuditRequired,
    bool FailureAuditRequired);

public sealed record Security4663MachineReadinessPlan(
    int SchemaVersion,
    string Checkpoint,
    string ServiceName,
    string StartIdentity,
    string LocalServiceSid,
    string LogName,
    string ProviderName,
    int EventId,
    int Level,
    string RequiredChannelReadAce,
    string AuditSubcategory,
    bool RequiresElevation,
    bool RequiresSecurityLogReadAccess,
    bool SecurityLogWriteAllowed,
    bool SecurityLogClearAllowed,
    bool EventLogReadersMembershipAllowed,
    bool SeSecurityPrivilegeAssignmentAllowed,
    bool AuditSuccessRequired,
    bool AuditFailureRequired,
    bool RealCredentialLocationsAllowed,
    bool ReparsePointsAllowed,
    bool ChangesChannelAccess,
    bool ChangesAuditPolicy,
    bool ChangesTargetSacl,
    bool ReadsEvents,
    long EventsRead,
    bool RuntimeCollectionEnabled,
    bool TransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    IReadOnlyList<Security4663TargetReadinessDefinition> Targets);

public static class Security4663MachineReadiness
{
    private static readonly IReadOnlyList<Security4663TargetReadinessDefinition>
        TargetDefinitions =
            new ReadOnlyCollection<Security4663TargetReadinessDefinition>(
            [
                new(
                    "credential-store-read",
                    @"C:\ProgramData\WAR-R00M\Windows Sensor\C2\credential-store.fixture",
                    "0x00000001",
                    "S-1-1-0",
                    true,
                    false),
                new(
                    "unsecured-secret-read",
                    @"C:\ProgramData\WAR-R00M\Windows Sensor\C2\unsecured-secret.fixture",
                    "0x00000001",
                    "S-1-1-0",
                    true,
                    false),
                new(
                    "hidden-attribute-write",
                    @"C:\ProgramData\WAR-R00M\Windows Sensor\C2\hidden-attribute.fixture",
                    "0x00000100",
                    "S-1-1-0",
                    true,
                    false)
            ]);

    public static Security4663MachineReadinessPlan BuildPlan() =>
        new(
            SchemaVersion: 1,
            Checkpoint: "gate-c2d-security-4663-machine-readiness",
            ServiceName: "WARRoomWindowsSensor",
            StartIdentity: @"NT AUTHORITY\LocalService",
            LocalServiceSid: "S-1-5-19",
            LogName: "Security",
            ProviderName: "Microsoft-Windows-Security-Auditing",
            EventId: 4663,
            Level: 0,
            RequiredChannelReadAce: "(A;;0x1;;;LS)",
            AuditSubcategory: "File System",
            RequiresElevation: true,
            RequiresSecurityLogReadAccess: true,
            SecurityLogWriteAllowed: false,
            SecurityLogClearAllowed: false,
            EventLogReadersMembershipAllowed: false,
            SeSecurityPrivilegeAssignmentAllowed: false,
            AuditSuccessRequired: true,
            AuditFailureRequired: false,
            RealCredentialLocationsAllowed: false,
            ReparsePointsAllowed: false,
            ChangesChannelAccess: false,
            ChangesAuditPolicy: false,
            ChangesTargetSacl: false,
            ReadsEvents: false,
            EventsRead: 0,
            RuntimeCollectionEnabled: false,
            TransportEnabled: false,
            InboundListenerEnabled: false,
            CommandChannelEnabled: false,
            Targets: TargetDefinitions);

    public static void ValidatePlan(Security4663MachineReadinessPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var expected = BuildPlan();
        if (
            plan with { Targets = expected.Targets } != expected ||
            plan.Targets.Count != expected.Targets.Count ||
            !plan.Targets.SequenceEqual(expected.Targets))
        {
            throw new InvalidDataException(
                "SENSOR_C2D_SECURITY_4663_READINESS_PLAN_INVALID");
        }
    }
}
