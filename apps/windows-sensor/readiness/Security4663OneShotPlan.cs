namespace WARRoom.WindowsSensor.Readiness;

public sealed record Security4663OneShotPlan(
    int SchemaVersion,
    string Checkpoint,
    string PrerequisiteCheckpoint,
    string ServiceName,
    string ServiceIdentity,
    string ProviderName,
    string ChannelName,
    int EventId,
    int Level,
    string ProfileId,
    string InertTargetPath,
    string RequiredAccessMask,
    bool RequiresFreshOperatorApproval,
    bool RequiresC2dReadiness,
    bool RequiresBaselineRecordId,
    int MaximumTriggerWindowSeconds,
    int MaximumQuerySeconds,
    int MaximumEventsRead,
    int MaximumNormalizedOutputBytes,
    bool RequiresRecordIdAfterBaseline,
    bool RequiresEventTimeWithinTriggerWindow,
    bool RequiresExactTargetHmacBinding,
    bool RetainsRawAccount,
    bool RetainsRawObjectPath,
    bool RetainsRawProcessPath,
    bool ChangesChannelAccess,
    bool ChangesAuditPolicy,
    bool ChangesTargetSacl,
    bool PlanReadsEvents,
    long PlanEventsRead,
    bool RetryEnabled,
    bool PollingEnabled,
    bool RuntimeCollectionEnabled,
    bool TransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    bool ResponseActionEnabled);

public static class Security4663OneShotMachinePlan
{
    public const string Checkpoint =
        "gate-c2e-security-4663-one-shot-plan";

    public static Security4663OneShotPlan BuildPlan()
    {
        var readiness = Security4663MachineReadiness.BuildPlan();
        Security4663MachineReadiness.ValidatePlan(readiness);
        var target = readiness.Targets.Single(item =>
            item.ProfileId == "credential-store-read");
        return new Security4663OneShotPlan(
            1,
            Checkpoint,
            readiness.Checkpoint,
            readiness.ServiceName,
            readiness.StartIdentity,
            readiness.ProviderName,
            readiness.LogName,
            readiness.EventId,
            readiness.Level,
            target.ProfileId,
            target.InertTargetPath,
            target.RequiredAccessMask,
            true,
            true,
            true,
            10,
            2,
            1,
            4096,
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
            0,
            false,
            false,
            false,
            false,
            false,
            false,
            false);
    }

    public static void ValidatePlan(Security4663OneShotPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (plan != BuildPlan())
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_ONE_SHOT_PLAN_INVALID");
        }
    }
}
