using WARRoom.WindowsSensor.Readiness;

namespace WARRoom.WindowsSensor;

public enum Security4663LiveOneShotApprovalOperatorCommand
{
    Plan,
    Write,
    Check,
    AbsentCheck,
    Cleanup
}

public static class Security4663LiveOneShotApprovalOperatorCommandParser
{
    public static Security4663LiveOneShotApprovalOperatorCommand Parse(
        string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Length != 1)
        {
            throw Invalid();
        }
        return args[0] switch
        {
            "plan" => Security4663LiveOneShotApprovalOperatorCommand.Plan,
            "write" => Security4663LiveOneShotApprovalOperatorCommand.Write,
            "check" => Security4663LiveOneShotApprovalOperatorCommand.Check,
            "absent-check" =>
                Security4663LiveOneShotApprovalOperatorCommand.AbsentCheck,
            "cleanup" =>
                Security4663LiveOneShotApprovalOperatorCommand.Cleanup,
            _ => throw Invalid()
        };
    }

    private static InvalidDataException Invalid() => new(
        "SENSOR_C2F_SECURITY_4663_APPROVAL_OPERATOR_COMMAND_INVALID");
}

public sealed record Security4663LiveOneShotApprovalOperatorPlan(
    int SchemaVersion,
    string Checkpoint,
    IReadOnlyList<string> Commands,
    string ApprovalPath,
    bool RequiresAdministratorForMutation,
    bool RequiresAdministratorForProtectedRead,
    bool DerivesInstalledCommitFromProtectedManifest,
    bool DerivesIdentityFromMachineKey,
    bool ExternalCheckerHasSigningAuthority,
    bool VerifiesExactC2dReadiness,
    bool CapturesBaselineFromMetadataOnly,
    bool AcceptsCallerInput,
    bool ReadsEvents,
    int MaximumEventsRead,
    bool StartsService,
    bool MutatesService,
    bool CleanupRequiresIdentityOrManifest,
    bool CleanupUsesOnlyFixedApprovalPath,
    bool RetryEnabled,
    bool PollingEnabled,
    bool TransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    bool ResponseActionEnabled,
    bool RuntimeWired);

public sealed record Security4663LiveOneShotApprovalOperatorResult(
    int SchemaVersion,
    string Checkpoint,
    string Operation,
    string State,
    long BaselineRecordId,
    string? InstalledCommit,
    string? IdentityFingerprintSha256,
    DateTimeOffset? ApprovedAtUtc,
    DateTimeOffset? ExpiresAtUtc,
    bool ApprovalPresent,
    bool RecoveryRemoved,
    bool ReadinessVerified,
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

// Elevated, fixed-path Gate C2f approval operator. It can create and verify
// the distinct live-read approval but cannot consume it, start the service,
// read an event record, or activate the sensor runtime.
public static class Security4663LiveOneShotApprovalOperator
{
    public const bool RuntimeWired = false;

    private static readonly IReadOnlyList<string> Commands =
        Array.AsReadOnly(["plan", "write", "check", "absent-check", "cleanup"]);

    public static Security4663LiveOneShotApprovalOperatorPlan BuildPlan() =>
        new(
            1,
            Security4663LiveOneShotApprovalLifecycle.Checkpoint,
            Commands,
            NativeSecurity4663LiveOneShotApprovalFileStore.ApprovalPath,
            true,
            true,
            true,
            true,
            false,
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
        Security4663LiveOneShotApprovalOperatorPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var expected = BuildPlan();
        if (
            plan with { Commands = expected.Commands } != expected ||
            !plan.Commands.SequenceEqual(expected.Commands, StringComparer.Ordinal))
        {
            throw Invalid(
                "SENSOR_C2F_SECURITY_4663_APPROVAL_OPERATOR_PLAN_INVALID");
        }
        Security4663LiveOneShotApprovalFilePolicy.ValidatePlan(
            Security4663LiveOneShotApprovalFilePolicy.BuildPlan());
    }

    public static Security4663LiveOneShotApprovalOperatorResult Write(
        ISecurity4663LiveOneShotApprovalStore store,
        ISensorIdentitySigner identity,
        InstallManifestBinding manifest,
        ISecurity4663ReadinessProbe readinessProbe,
        ISecurity4663LogMetadataSource baselineSource,
        DateTime utcNow,
        ReadOnlySpan<byte> nonce)
    {
        ValidateContext(identity.Descriptor, manifest, utcNow);
        var readiness = Security4663ReadinessCheck.Check(readinessProbe);
        if (
            !readiness.Ready ||
            readiness.ReadsEvents ||
            readiness.EventsRead != 0)
        {
            throw Invalid(
                "SENSOR_C2F_SECURITY_4663_APPROVAL_OPERATOR_SOURCE_INVALID");
        }
        var baseline = Security4663OneShotBaseline.Capture(baselineSource);
        if (
            baseline.EventContentRead ||
            baseline.EventsRead != 0)
        {
            throw Invalid(
                "SENSOR_C2F_SECURITY_4663_APPROVAL_OPERATOR_SOURCE_INVALID");
        }
        var approval = Security4663LiveOneShotApprovalLifecycle.CreateAndWrite(
            store,
            identity,
            manifest.Commit,
            readiness,
            baseline.BaselineRecordId,
            utcNow,
            nonce);
        return Result(
            "write", "approved", approval.BaselineRecordId, manifest.Commit,
            identity.Descriptor.CertificateFingerprintSha256,
            Security4663LiveOneShotApprovalLifecycle.ParseUtcOffset(
                approval.ApprovedAt),
            Security4663LiveOneShotApprovalLifecycle.ParseUtcOffset(
                approval.ExpiresAt),
            present: true,
            recoveryRemoved: false,
            readinessVerified: true);
    }

    public static Security4663LiveOneShotApprovalOperatorResult Check(
        ISecurity4663LiveOneShotApprovalStore store,
        SensorIdentityDescriptor identity,
        InstallManifestBinding manifest,
        DateTime utcNow)
    {
        ValidateContext(identity, manifest, utcNow);
        var json = store.ReadExisting() ?? throw Invalid(
            "SENSOR_C2F_SECURITY_4663_APPROVAL_MISSING");
        var approval = Security4663LiveOneShotApprovalLifecycle.ValidateApproval(
            json, identity, manifest.Commit, utcNow);
        return Result(
            "check", "valid", approval.BaselineRecordId, manifest.Commit,
            identity.CertificateFingerprintSha256,
            Security4663LiveOneShotApprovalLifecycle.ParseUtcOffset(
                approval.ApprovedAt),
            Security4663LiveOneShotApprovalLifecycle.ParseUtcOffset(
                approval.ExpiresAt),
            present: true,
            recoveryRemoved: false,
            readinessVerified: approval.ReadinessVerified);
    }

    public static Security4663LiveOneShotApprovalOperatorResult CheckAbsent(
        ISecurity4663LiveOneShotApprovalAbsenceVerifier store)
    {
        ArgumentNullException.ThrowIfNull(store);
        if (!store.VerifyAbsent())
        {
            throw Invalid(
                "SENSOR_C2F_SECURITY_4663_APPROVAL_STILL_PRESENT");
        }
        return Result(
            "absent-check", "absent", 0, null, null, null, null,
            present: false,
            recoveryRemoved: false,
            readinessVerified: false);
    }

    public static Security4663LiveOneShotApprovalOperatorResult Cleanup(
        ISecurity4663LiveOneShotApprovalOperatorStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        var removed = store.RemoveForRecovery();
        return Result(
            "cleanup", removed ? "removed" : "absent", 0, null, null, null,
            null,
            present: false,
            recoveryRemoved: removed,
            readinessVerified: false);
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
                "SENSOR_C2F_SECURITY_4663_APPROVAL_OPERATOR_CONTEXT_INVALID");
        }
    }

    private static Security4663LiveOneShotApprovalOperatorResult Result(
        string operation,
        string state,
        long baseline,
        string? commit,
        string? fingerprint,
        DateTimeOffset? approvedAt,
        DateTimeOffset? expiresAt,
        bool present,
        bool recoveryRemoved,
        bool readinessVerified) => new(
            1,
            Security4663LiveOneShotApprovalLifecycle.Checkpoint,
            operation,
            state,
            baseline,
            commit,
            fingerprint,
            approvedAt,
            expiresAt,
            present,
            recoveryRemoved,
            readinessVerified,
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

    private static InvalidDataException Invalid(string code) => new(code);
}
