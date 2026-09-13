using System.Text.Json;
using WARRoom.WindowsSensor.Readiness;

namespace WARRoom.WindowsSensor;

public enum Security4663OneShotReadState
{
    Match = 1,
    NoMatch = 2,
    AccessDenied = 3,
    SourceUnavailable = 4,
    QueryFailed = 5
}

public sealed record Security4663OneShotApproval(
    bool Approved,
    string Checkpoint,
    InertWindowsSecurityEvent4663Profile Profile,
    long BaselineRecordId,
    DateTimeOffset ApprovedAtUtc,
    DateTimeOffset ExpiresAtUtc);

public sealed record Security4663OneShotReadRequest(
    int SchemaVersion,
    string Checkpoint,
    string ProviderName,
    string ChannelName,
    int EventId,
    int Level,
    InertWindowsSecurityEvent4663Profile Profile,
    long BaselineRecordId,
    DateTimeOffset TriggerStartedUtc,
    DateTimeOffset TriggerCompletedUtc,
    int MaximumQueryMilliseconds,
    int MaximumEventsRead);

public sealed record Security4663OneShotReadResult(
    Security4663OneShotReadState State,
    InertWindowsSecurityEventRecord? Record);

public sealed record Security4663OneShotResult(
    int SchemaVersion,
    string Checkpoint,
    Security4663OneShotReadState State,
    int EventsRead,
    bool RawEventContentRetained,
    bool RuntimeWired,
    bool NativeEventAccessEnabled,
    bool RetryEnabled,
    bool PollingEnabled,
    bool TransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    bool ResponseActionEnabled,
    InertWindowsSecurity4663LocalClassification? Classification);

public interface ISecurity4663OneShotReader
{
    Security4663OneShotReadResult ReadOne(
        Security4663OneShotReadRequest request,
        CancellationToken cancellationToken);
}

// Gate C2e pure coordinator only. It accepts a typed bounded reader, but no
// native reader, trigger, hosted-service registration or transport exists.
public sealed class Security4663OneShotCoordinator(
    ISecurity4663OneShotReader reader)
{
    public const bool RuntimeWired = false;
    public const bool NativeEventAccessEnabled = false;
    public const int MaximumApprovalLifetimeSeconds = 300;
    public const long MaximumJsonInteger = 9_007_199_254_740_991;

    private readonly ISecurity4663OneShotReader _reader =
        reader ?? throw new ArgumentNullException(nameof(reader));

    public Security4663OneShotResult CollectOnce(
        Security4663ReadinessCheckResult readiness,
        bool serviceIdentityValidated,
        Security4663OneShotApproval approval,
        long baselineRecordId,
        DateTimeOffset triggerStartedUtc,
        DateTimeOffset triggerCompletedUtc,
        DateTimeOffset nowUtc,
        InertWindowsSecurity4663TargetBinding targetBinding,
        InertWindowsSecurity4663ProcessBinding processBinding,
        int? priorObservationCount,
        ReadOnlySpan<byte> classificationKey,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var plan = Security4663OneShotMachinePlan.BuildPlan();
        Security4663OneShotMachinePlan.ValidatePlan(plan);
        ValidatePrerequisites(
            readiness,
            serviceIdentityValidated,
            approval,
            baselineRecordId,
            triggerStartedUtc,
            triggerCompletedUtc,
            nowUtc,
            plan);
        ValidateTargetBinding(targetBinding, classificationKey, plan);

        var request = new Security4663OneShotReadRequest(
            1,
            plan.Checkpoint,
            plan.ProviderName,
            plan.ChannelName,
            plan.EventId,
            plan.Level,
            InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
            baselineRecordId,
            triggerStartedUtc,
            triggerCompletedUtc,
            plan.MaximumQuerySeconds * 1_000,
            plan.MaximumEventsRead);
        var read = _reader.ReadOne(request, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        ValidateReadResult(read, baselineRecordId, triggerStartedUtc,
            triggerCompletedUtc);

        if (read.State != Security4663OneShotReadState.Match)
        {
            return BuildResult(read.State, 0, null);
        }

        var record = read.Record!;
        var classification =
            InertWindowsSecurity4663LocalClassifier.Classify(
                record,
                InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
                targetBinding,
                processBinding,
                priorObservationCount,
                null,
                classificationKey);
        if (
            classification.GenuineLiveEligible ||
            classification.RawEventContentRetained ||
            JsonSerializer.SerializeToUtf8Bytes(classification).Length >
                plan.MaximumNormalizedOutputBytes)
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_OUTPUT_INVALID");
        }

        return BuildResult(read.State, 1, classification);
    }

    private static void ValidatePrerequisites(
        Security4663ReadinessCheckResult readiness,
        bool serviceIdentityValidated,
        Security4663OneShotApproval approval,
        long baselineRecordId,
        DateTimeOffset triggerStartedUtc,
        DateTimeOffset triggerCompletedUtc,
        DateTimeOffset nowUtc,
        Security4663OneShotPlan plan)
    {
        ArgumentNullException.ThrowIfNull(readiness);
        ArgumentNullException.ThrowIfNull(approval);
        var matchingTargets = readiness.Targets.Where(item =>
            item.ProfileId == plan.ProfileId).ToArray();
        var target = matchingTargets.Length == 1 ? matchingTargets[0] : null;
        if (
            readiness.SchemaVersion != 1 ||
            readiness.Checkpoint != plan.PrerequisiteCheckpoint ||
            !readiness.Ready ||
            !serviceIdentityValidated ||
            readiness.ChangesChannelAccess ||
            readiness.ChangesAuditPolicy ||
            readiness.ChangesTargetSacl ||
            readiness.ReadsEvents ||
            readiness.EventsRead != 0 ||
            readiness.RuntimeCollectionEnabled ||
            readiness.TransportEnabled ||
            readiness.InboundListenerEnabled ||
            readiness.CommandChannelEnabled ||
            !readiness.Channel.Accessible ||
            !readiness.Channel.LocalServiceReadOnly ||
            !readiness.AuditPolicy.Accessible ||
            !readiness.AuditPolicy.SuccessEnabled ||
            readiness.AuditPolicy.FailureEnabled ||
            target is null ||
            !target.Exists ||
            !target.ZeroLength ||
            target.ReparsePoint ||
            !target.SaclAccessible ||
            !target.ExactSuccessAudit ||
            target.ErrorCode is not null)
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_READINESS_INVALID");
        }

        if (
            !approval.Approved ||
            approval.Checkpoint != plan.Checkpoint ||
            approval.Profile !=
                InertWindowsSecurityEvent4663Profile.CredentialStoreRead ||
            approval.BaselineRecordId != baselineRecordId ||
            !IsUtc(approval.ApprovedAtUtc) ||
            !IsUtc(approval.ExpiresAtUtc) ||
            approval.ExpiresAtUtc <= approval.ApprovedAtUtc ||
            approval.ExpiresAtUtc - approval.ApprovedAtUtc >
                TimeSpan.FromSeconds(MaximumApprovalLifetimeSeconds) ||
            !IsUtc(nowUtc) ||
            nowUtc < approval.ApprovedAtUtc ||
            nowUtc > approval.ExpiresAtUtc ||
            approval.ApprovedAtUtc > triggerStartedUtc ||
            approval.ExpiresAtUtc < triggerCompletedUtc)
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_APPROVAL_INVALID");
        }

        if (
            baselineRecordId is < 1 or > MaximumJsonInteger ||
            !IsUtc(triggerStartedUtc) ||
            !IsUtc(triggerCompletedUtc) ||
            triggerCompletedUtc < triggerStartedUtc ||
            triggerCompletedUtc - triggerStartedUtc >
                TimeSpan.FromSeconds(plan.MaximumTriggerWindowSeconds) ||
            triggerCompletedUtc > nowUtc)
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_WINDOW_INVALID");
        }
    }

    private static void ValidateTargetBinding(
        InertWindowsSecurity4663TargetBinding targetBinding,
        ReadOnlySpan<byte> classificationKey,
        Security4663OneShotPlan plan)
    {
        ArgumentNullException.ThrowIfNull(targetBinding);
        var expected =
            InertWindowsSecurity4663LocalClassifier
                .CreateObjectPathTagHmacSha256(
                    plan.InertTargetPath,
                    classificationKey);
        if (
            targetBinding.Profile !=
                InertWindowsSecurityEvent4663Profile.CredentialStoreRead ||
            !targetBinding.TargetSaclConfigured ||
            targetBinding.ObjectPathTagHmacSha256.Length != 64 ||
            !System.Security.Cryptography.CryptographicOperations
                .FixedTimeEquals(
                    System.Text.Encoding.ASCII.GetBytes(
                        targetBinding.ObjectPathTagHmacSha256),
                    System.Text.Encoding.ASCII.GetBytes(expected)))
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_TARGET_BINDING_INVALID");
        }
    }

    private static void ValidateReadResult(
        Security4663OneShotReadResult read,
        long baselineRecordId,
        DateTimeOffset triggerStartedUtc,
        DateTimeOffset triggerCompletedUtc)
    {
        ArgumentNullException.ThrowIfNull(read);
        if (!Enum.IsDefined(read.State))
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_READ_STATE_INVALID");
        }
        if (read.State != Security4663OneShotReadState.Match)
        {
            if (read.Record is not null)
            {
                throw new InvalidDataException(
                    "SENSOR_C2E_SECURITY_4663_NONMATCH_RECORD_INVALID");
            }
            return;
        }

        var record = read.Record ?? throw new InvalidDataException(
            "SENSOR_C2E_SECURITY_4663_MATCH_RECORD_MISSING");
        if (
            record.RecordId <= baselineRecordId ||
            record.RecordId > MaximumJsonInteger ||
            record.TimeCreatedUtc < triggerStartedUtc ||
            record.TimeCreatedUtc > triggerCompletedUtc)
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_EVENT_BINDING_INVALID");
        }
    }

    private static Security4663OneShotResult BuildResult(
        Security4663OneShotReadState state,
        int eventsRead,
        InertWindowsSecurity4663LocalClassification? classification) =>
        new(
            1,
            Security4663OneShotMachinePlan.Checkpoint,
            state,
            eventsRead,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            classification);

    private static bool IsUtc(DateTimeOffset value) =>
        value.Offset == TimeSpan.Zero;
}
