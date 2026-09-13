namespace WARRoom.WindowsSensor;

public sealed record Security4663OneShotOperatorPlan(
    int SchemaVersion,
    string Checkpoint,
    string PrerequisiteCheckpoint,
    string ServiceName,
    string ServiceIdentity,
    string ServiceStartupArgument,
    string ApprovalPath,
    string ResultPath,
    string FixedTargetPath,
    string ProfileId,
    bool RequiresElevation,
    bool RequiresOperatorPresence,
    bool RequiresCleanCommit,
    bool RequiresInstalledCommitMatch,
    bool RequiresServiceStopped,
    bool RequiresManualStart,
    bool RequiresFreshMachineSignedApproval,
    int MaximumApprovalLifetimeSeconds,
    bool ConsumesApprovalOnce,
    bool CapturesBaselineFromMetadataOnly,
    bool GeneratesClassificationKeyInServiceMemory,
    bool PersistsClassificationKey,
    bool TriggersOnlyFixedInertRead,
    bool RequiresExternalCheckBeforeRollback,
    bool RollbackAlwaysRequired,
    int MaximumServiceStarts,
    int MaximumTargets,
    int MaximumEventsRead,
    bool RawEventRetentionAllowed,
    bool RetryEnabled,
    bool PollingEnabled,
    bool RuntimeCollectionEnabled,
    bool TransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    bool ResponseActionEnabled,
    IReadOnlyList<string> Steps);

// Design-only Gate C2e operator ceremony. It freezes the lifecycle before the
// elevated approval writer, startup mode, trigger or external checker exists.
public static class Security4663OneShotOperatorCeremony
{
    public const bool RuntimeWired = false;

    private static readonly IReadOnlyList<string> FrozenSteps =
        Array.AsReadOnly([
            "validate-clean-installed-state",
            "apply-gate-c2d-readiness",
            "write-protected-expiring-approval",
            "capture-security-baseline-metadata",
            "start-localservice-once",
            "consume-approval-once",
            "trigger-fixed-inert-read",
            "read-at-most-one-post-baseline-event",
            "write-protected-normalized-result",
            "run-external-result-checker",
            "rollback-gate-c2d-always"
        ]);

    public static Security4663OneShotOperatorPlan BuildPlan()
    {
        var oneShot = Readiness.Security4663OneShotMachinePlan.BuildPlan();
        Readiness.Security4663OneShotMachinePlan.ValidatePlan(oneShot);
        return new Security4663OneShotOperatorPlan(
            1,
            oneShot.Checkpoint,
            oneShot.PrerequisiteCheckpoint,
            oneShot.ServiceName,
            oneShot.ServiceIdentity,
            "--security-4663-one-shot",
            @"C:\ProgramData\WAR-R00M\Windows Sensor\C2\security-4663-one-shot-approval.json",
            @"C:\ProgramData\WAR-R00M\Windows Sensor\C2\security-4663-one-shot-result.json",
            oneShot.InertTargetPath,
            oneShot.ProfileId,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            300,
            true,
            true,
            true,
            false,
            true,
            true,
            true,
            1,
            1,
            1,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            FrozenSteps);
    }

    public static void ValidatePlan(Security4663OneShotOperatorPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (
            plan != BuildPlan() ||
            !plan.Steps.SequenceEqual(FrozenSteps, StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_OPERATOR_PLAN_INVALID");
        }
    }
}
