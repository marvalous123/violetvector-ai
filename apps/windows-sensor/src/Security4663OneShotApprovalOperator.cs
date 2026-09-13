namespace WARRoom.WindowsSensor;

public enum Security4663OneShotApprovalOperatorCommand
{
    Plan,
    ConsumeProofPlan,
    Write,
    Check,
    AbsentCheck,
    ConsumeExercise,
    Cleanup
}

public static class Security4663OneShotApprovalOperatorCommandParser
{
    public static Security4663OneShotApprovalOperatorCommand Parse(
        string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Length != 1)
        {
            throw Invalid();
        }
        return args[0] switch
        {
            "plan" => Security4663OneShotApprovalOperatorCommand.Plan,
            "consume-proof-plan" =>
                Security4663OneShotApprovalOperatorCommand.ConsumeProofPlan,
            "write" => Security4663OneShotApprovalOperatorCommand.Write,
            "check" => Security4663OneShotApprovalOperatorCommand.Check,
            "absent-check" =>
                Security4663OneShotApprovalOperatorCommand.AbsentCheck,
            "consume-exercise" =>
                Security4663OneShotApprovalOperatorCommand.ConsumeExercise,
            "cleanup" => Security4663OneShotApprovalOperatorCommand.Cleanup,
            _ => throw Invalid()
        };
    }

    private static InvalidDataException Invalid() => new(
        "SENSOR_C2E_SECURITY_4663_APPROVAL_OPERATOR_COMMAND_INVALID");
}

public sealed record Security4663OneShotApprovalOperatorPlan(
    int SchemaVersion,
    string Checkpoint,
    IReadOnlyList<string> Commands,
    bool RequiresAdministratorForMutation,
    bool RequiresAdministratorForProtectedRead,
    bool DerivesInstalledCommitFromProtectedManifest,
    bool DerivesIdentityFromMachineKey,
    bool CapturesBaselineFromMetadataOnly,
    bool AcceptsCallerInput,
    bool ReadsEvents,
    int MaximumEventsRead,
    bool StartsService,
    bool MutatesService,
    bool ExternalCheckerMutatesApproval,
    bool CleanupUsesOnlyFixedApprovalPath,
    bool RetryEnabled,
    bool PollingEnabled,
    bool TransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    bool ResponseActionEnabled,
    bool RuntimeWired);

public sealed record Security4663OneShotApprovalOperatorResult(
    int SchemaVersion,
    string Checkpoint,
    string Operation,
    string State,
    long BaselineRecordId,
    string InstalledCommit,
    string IdentityFingerprintSha256,
    DateTimeOffset? ApprovedAtUtc,
    DateTimeOffset? ExpiresAtUtc,
    bool ApprovalPresent,
    bool ApprovalConsumed,
    bool OperatorConsumeOnly,
    bool LocalServiceAuthorityProven,
    bool EventContentRead,
    int EventsRead,
    bool ServiceStarted,
    bool ServiceMutated,
    bool RetryEnabled,
    bool PollingEnabled,
    bool TransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    bool ResponseActionEnabled,
    bool RuntimeWired);

// Fixed, local-only Gate C2e operator boundary. It writes/checks/consumes only
// the signed approval document and never starts the service or reads an event.
public static class Security4663OneShotApprovalOperator
{
    public const bool RuntimeWired = false;

    private static readonly IReadOnlyList<string> Commands =
        Array.AsReadOnly([
            "plan",
            "consume-proof-plan",
            "write",
            "check",
            "absent-check",
            "consume-exercise",
            "cleanup"
        ]);

    public static Security4663OneShotApprovalOperatorPlan BuildPlan() => new(
        1,
        Readiness.Security4663OneShotMachinePlan.Checkpoint,
        Commands,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        0,
        false,
        false,
        false,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        false);

    public static void ValidatePlan(
        Security4663OneShotApprovalOperatorPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var expected = BuildPlan();
        if (
            plan with { Commands = expected.Commands } != expected ||
            !plan.Commands.SequenceEqual(expected.Commands, StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_APPROVAL_OPERATOR_PLAN_INVALID");
        }
    }

    public static Security4663OneShotApprovalOperatorResult Write(
        ISecurity4663OneShotApprovalStore store,
        ISensorIdentitySigner identity,
        InstallManifestBinding manifest,
        ISecurity4663LogMetadataSource baselineSource,
        DateTime utcNow,
        ReadOnlySpan<byte> nonce)
    {
        ValidateContext(identity.Descriptor, manifest, utcNow);
        var baseline = Security4663OneShotBaseline.Capture(baselineSource);
        if (baseline.EventContentRead || baseline.EventsRead != 0)
        {
            throw Invalid(
                "SENSOR_C2E_SECURITY_4663_APPROVAL_OPERATOR_BASELINE_INVALID");
        }
        var approval = Security4663OneShotApprovalLifecycle.CreateAndWrite(
            store,
            identity,
            manifest.Commit,
            baseline.BaselineRecordId,
            utcNow,
            nonce);
        return Result(
            "write",
            "approved",
            approval.BaselineRecordId,
            manifest,
            identity.Descriptor,
            DateTimeOffset.ParseExact(
                approval.ApprovedAt,
                "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal |
                    System.Globalization.DateTimeStyles.AdjustToUniversal),
            DateTimeOffset.ParseExact(
                approval.ExpiresAt,
                "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal |
                    System.Globalization.DateTimeStyles.AdjustToUniversal),
            present: true,
            consumed: false,
            operatorConsumeOnly: false);
    }

    public static Security4663OneShotApprovalOperatorResult Check(
        ISecurity4663OneShotApprovalStore store,
        SensorIdentityDescriptor identity,
        InstallManifestBinding manifest,
        DateTime utcNow)
    {
        ValidateContext(identity, manifest, utcNow);
        var json = store.ReadExisting() ?? throw Invalid(
            "SENSOR_C2E_SECURITY_4663_APPROVAL_MISSING");
        var approval = Security4663OneShotApprovalLifecycle.ValidateApproval(
            json,
            identity,
            manifest.Commit,
            utcNow);
        return Result(
            "check",
            "valid",
            approval.BaselineRecordId,
            manifest,
            identity,
            Parse(approval.ApprovedAt),
            Parse(approval.ExpiresAt),
            present: true,
            consumed: false,
            operatorConsumeOnly: false);
    }

    public static Security4663OneShotApprovalOperatorResult ConsumeExercise(
        ISecurity4663OneShotApprovalStore store,
        SensorIdentityDescriptor identity,
        InstallManifestBinding manifest,
        DateTime utcNow)
    {
        ValidateContext(identity, manifest, utcNow);
        var approval = Security4663OneShotApprovalLifecycle.Consume(
            store,
            identity,
            manifest.Commit,
            utcNow);
        return Result(
            "consume-exercise",
            "consumed",
            approval.BaselineRecordId,
            manifest,
            identity,
            approval.ApprovedAtUtc,
            approval.ExpiresAtUtc,
            present: false,
            consumed: true,
            operatorConsumeOnly: true);
    }

    public static Security4663OneShotApprovalOperatorResult CheckAbsent(
        ISecurity4663OneShotApprovalAbsenceVerifier store,
        SensorIdentityDescriptor identity,
        InstallManifestBinding manifest,
        DateTime utcNow)
    {
        ArgumentNullException.ThrowIfNull(store);
        ValidateContext(identity, manifest, utcNow);
        if (!store.VerifyAbsent())
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_APPROVAL_STILL_PRESENT");
        }
        return Result(
            "absent-check",
            "absent",
            0,
            manifest,
            identity,
            null,
            null,
            present: false,
            consumed: false,
            operatorConsumeOnly: false);
    }

    public static Security4663OneShotApprovalOperatorResult Cleanup(
        NativeSecurity4663OneShotApprovalFileStore store,
        SensorIdentityDescriptor identity,
        InstallManifestBinding manifest,
        DateTime utcNow)
    {
        ArgumentNullException.ThrowIfNull(store);
        ValidateContext(identity, manifest, utcNow);
        var removed = store.RemoveForRecovery();
        return Result(
            "cleanup",
            removed ? "removed" : "absent",
            0,
            manifest,
            identity,
            null,
            null,
            present: false,
            consumed: removed,
            operatorConsumeOnly: true);
    }

    private static void ValidateContext(
        SensorIdentityDescriptor identity,
        InstallManifestBinding manifest,
        DateTime utcNow)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(manifest);
        if (
            utcNow.Kind != DateTimeKind.Utc ||
            manifest.Fingerprint != identity.CertificateFingerprintSha256)
        {
            throw Invalid(
                "SENSOR_C2E_SECURITY_4663_APPROVAL_OPERATOR_CONTEXT_INVALID");
        }
    }

    private static Security4663OneShotApprovalOperatorResult Result(
        string operation,
        string state,
        long baseline,
        InstallManifestBinding manifest,
        SensorIdentityDescriptor identity,
        DateTimeOffset? approvedAt,
        DateTimeOffset? expiresAt,
        bool present,
        bool consumed,
        bool operatorConsumeOnly) => new(
            1,
            Readiness.Security4663OneShotMachinePlan.Checkpoint,
            operation,
            state,
            baseline,
            manifest.Commit,
            identity.CertificateFingerprintSha256,
            approvedAt,
            expiresAt,
            present,
            consumed,
            operatorConsumeOnly,
            false,
            false,
            0,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false);

    private static DateTimeOffset Parse(string value) =>
        DateTimeOffset.ParseExact(
            value,
            "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal |
                System.Globalization.DateTimeStyles.AdjustToUniversal);

    private static InvalidDataException Invalid(string code) => new(code);
}
