using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace WARRoom.WindowsSensor;

public sealed record Security4663LiveOneShotExecutionPlan(
    int SchemaVersion,
    string Checkpoint,
    string StartupArgument,
    string ServiceIdentity,
    string ApprovalPath,
    string ResultPath,
    string FixedTargetPath,
    string ProfileId,
    bool RequiresLocalServiceBeforeProtectedAccess,
    bool RequiresPreStartOperatorTrigger,
    bool WorkerTriggersTarget,
    bool ConsumesApprovalExactlyOnce,
    bool WritesResultExactlyOnce,
    int MaximumEventsRead,
    int MaximumQueryMilliseconds,
    int MaximumTriggerWindowSeconds,
    bool NativeEventAccessEnabled,
    bool RawEventContentRetained,
    bool PersistsClassificationKey,
    bool ContinuousCollectionEnabled,
    bool RetryEnabled,
    bool PollingEnabled,
    bool TransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    bool ResponseActionEnabled,
    bool RuntimeWired);

public sealed record Security4663LiveOneShotExecutionResult(
    int SchemaVersion,
    string Checkpoint,
    string State,
    string ReadState,
    int EventsRead,
    bool LocalServiceIdentityValidated,
    bool ApprovalConsumed,
    bool ResultWritten,
    bool RawEventContentRetained,
    bool ContinuousCollectionEnabled,
    bool RetryEnabled,
    bool PollingEnabled,
    bool TransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    bool ResponseActionEnabled);

public sealed record Security4663GenuineMatchValidationPlan(
    int SchemaVersion,
    string Checkpoint,
    string ServiceIdentity,
    bool RequiresLocalServiceBeforeProtectedAccess,
    bool RequiresPreStartOperatorTrigger,
    bool RequiresFixedPostTriggerSettlement,
    int TriggerSettlementMilliseconds,
    int MaximumEventsRead,
    int MaximumQueries,
    int MaximumQueryMilliseconds,
    int MaximumTriggerWindowSeconds,
    bool RequiresGenuineMatch,
    int RequiredEventsRead,
    bool RequiresStrictRollback,
    bool RawEventContentRetained,
    bool ContinuousCollectionEnabled,
    bool RetryEnabled,
    bool PollingEnabled,
    bool TelemetryEnabled,
    bool TransportEnabled,
    bool IpcEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    bool ResponseActionEnabled,
    bool RuntimeWired);

// Gate C2g freezes a pure operator-ceremony contract. It grants no runtime
// authority and does not perform the settlement, service start or event read.
public static class Security4663GenuineMatchValidation
{
    public const string Checkpoint =
        "gate-c2g-security-4663-genuine-match";
    public const int TriggerSettlementMilliseconds = 2_000;
    public const int MaximumQueries = 1;

    public static Security4663GenuineMatchValidationPlan BuildPlan() => new(
        1,
        Checkpoint,
        SensorBoundary.ExpectedServiceIdentity,
        true,
        true,
        true,
        TriggerSettlementMilliseconds,
        Security4663LiveOneShotApprovalLifecycle.MaximumEventsRead,
        MaximumQueries,
        Security4663LiveOneShotApprovalLifecycle.MaximumQueryMilliseconds,
        Security4663LiveOneShotApprovalLifecycle.MaximumTriggerWindowSeconds,
        true,
        1,
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
        false);

    public static void ValidatePlan(Security4663GenuineMatchValidationPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (plan != BuildPlan())
        {
            throw new InvalidDataException(
                "SENSOR_C2G_SECURITY_4663_PLAN_INVALID");
        }
    }
}

// Gate C2f is a single bounded read, not a collector loop. The operator must
// create the audited inert read after approval and before the service starts.
public static class Security4663LiveOneShotExecution
{
    public const bool RuntimeWired = true;

    internal static string PublicFailureCode(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        var message = exception.Message;
        return message.StartsWith("SENSOR_", StringComparison.Ordinal) &&
            message.All(character => character is >= 'A' and <= 'Z' or
                >= '0' and <= '9' or '_')
            ? message
            : "SENSOR_C2F_SECURITY_4663_EXECUTION_FAILED";
    }

    public static Security4663LiveOneShotExecutionPlan BuildPlan()
    {
        var oneShot = Readiness.Security4663OneShotMachinePlan.BuildPlan();
        Readiness.Security4663OneShotMachinePlan.ValidatePlan(oneShot);
        return new(
            1,
            Security4663LiveOneShotApprovalLifecycle.Checkpoint,
            Security4663LiveOneShotApprovalLifecycle.StartupArgument,
            SensorBoundary.ExpectedServiceIdentity,
            NativeSecurity4663LiveOneShotApprovalFileStore.ApprovalPath,
            NativeSecurity4663LiveOneShotResultFileSlot.ResultPath,
            oneShot.InertTargetPath,
            Security4663LiveOneShotApprovalLifecycle.TargetProfileId,
            true,
            true,
            false,
            true,
            true,
            Security4663LiveOneShotApprovalLifecycle.MaximumEventsRead,
            Security4663LiveOneShotApprovalLifecycle.MaximumQueryMilliseconds,
            Security4663LiveOneShotApprovalLifecycle.MaximumTriggerWindowSeconds,
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
            true);
    }

    public static void ValidatePlan(Security4663LiveOneShotExecutionPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (plan != BuildPlan())
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_EXECUTION_PLAN_INVALID");
        }
    }

    public static Security4663LiveOneShotExecutionResult Execute(
        ISensorServiceIdentity serviceIdentity,
        IInstallManifestBindingReader manifestReader,
        ISecurity4663LiveOneShotApprovalStore approvalStore,
        ISecurity4663OneShotReader reader,
        ISecurity4663LiveOneShotResultStore resultStore,
        ISensorIdentitySigner identity,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(serviceIdentity);
        ArgumentNullException.ThrowIfNull(manifestReader);
        ArgumentNullException.ThrowIfNull(approvalStore);
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(resultStore);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(timeProvider);

        var plan = BuildPlan();
        ValidatePlan(plan);
        if (!string.Equals(serviceIdentity.CurrentSid,
            NativeKeyAccessPolicy.LocalServiceSid, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "SENSOR_LOCALSERVICE_IDENTITY_REQUIRED");
        }

        cancellationToken.ThrowIfCancellationRequested();
        var manifest = manifestReader.Read();
        if (!string.Equals(manifest.Fingerprint,
            identity.Descriptor.CertificateFingerprintSha256,
            StringComparison.Ordinal))
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_EXECUTION_CONTEXT_INVALID");
        }

        var consumed = Security4663LiveOneShotApprovalLifecycle.ConsumeEnvelope(
            approvalStore,
            identity.Descriptor,
            manifest.Commit,
            timeProvider.GetUtcNow().UtcDateTime);
        var triggerStarted =
            Security4663LiveOneShotApprovalLifecycle.ParseUtcOffset(
                consumed.Approval.ApprovedAt);
        var triggerCompleted = timeProvider.GetUtcNow();
        if (triggerCompleted.Offset != TimeSpan.Zero ||
            triggerCompleted < triggerStarted ||
            triggerCompleted - triggerStarted > TimeSpan.FromSeconds(
                plan.MaximumTriggerWindowSeconds))
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_EXECUTION_WINDOW_INVALID");
        }

        var request = new Security4663OneShotReadRequest(
            1,
            plan.Checkpoint,
            "Microsoft-Windows-Security-Auditing",
            "Security",
            4663,
            0,
            InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
            consumed.Approval.BaselineRecordId,
            triggerStarted,
            triggerCompleted,
            plan.MaximumQueryMilliseconds,
            plan.MaximumEventsRead);
        var read = reader.ReadOne(request, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        ValidateRead(read, consumed.Approval.BaselineRecordId,
            triggerStarted, triggerCompleted);

        var classification = read.State == Security4663OneShotReadState.Match
            ? Classify(read.Record!, plan.FixedTargetPath)
            : null;
        var sourceResult = new Security4663LiveOneShotNormalizedSourceResult(
            1,
            plan.Checkpoint,
            read.State,
            read.State == Security4663OneShotReadState.Match ? 1 : 0,
            false,
            true,
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            classification);
        var createdAt = timeProvider.GetUtcNow();
        var result = Security4663LiveOneShotResultLifecycle.CreateAndWrite(
            resultStore,
            identity,
            manifest.Commit,
            consumed,
            triggerStarted,
            triggerCompleted,
            sourceResult,
            createdAt);
        return new(
            1,
            plan.Checkpoint,
            "completed",
            result.ReadState,
            result.EventsRead,
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
            false);
    }

    private static InertWindowsSecurity4663LocalClassification Classify(
        InertWindowsSecurityEventRecord record,
        string fixedTargetPath)
    {
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            return InertWindowsSecurity4663LocalClassifier.Classify(
                record,
                InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
                new(
                    InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
                    InertWindowsSecurity4663LocalClassifier
                        .CreateObjectPathTagHmacSha256(fixedTargetPath, key),
                    true),
                new(
                    InertWindowsSecurity4663LocalClassifier
                        .CreateProcessPathTagHmacSha256(
                            record.EventData["ProcessName"], key),
                    InertWindowsSecuritySubjectClass.Other,
                    InertWindowsSecurityActorTrust.Unknown,
                    InertWindowsSecurityTrustEvidence.Unresolved),
                null,
                null,
                key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static void ValidateRead(
        Security4663OneShotReadResult read,
        long baseline,
        DateTimeOffset started,
        DateTimeOffset completed)
    {
        ArgumentNullException.ThrowIfNull(read);
        if (!Enum.IsDefined(read.State))
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_EXECUTION_READ_INVALID");
        }
        if (read.State != Security4663OneShotReadState.Match)
        {
            if (read.Record is not null)
            {
                throw Invalid("SENSOR_C2F_SECURITY_4663_EXECUTION_READ_INVALID");
            }
            return;
        }
        var record = read.Record ?? throw Invalid(
            "SENSOR_C2F_SECURITY_4663_EXECUTION_READ_INVALID");
        if (record.RecordId <= baseline ||
            record.RecordId > Security4663OneShotCoordinator.MaximumJsonInteger ||
            record.TimeCreatedUtc.Offset != TimeSpan.Zero ||
            record.TimeCreatedUtc < started || record.TimeCreatedUtc > completed)
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_EXECUTION_READ_INVALID");
        }
    }

    private static InvalidDataException Invalid(string code) => new(code);
}

// A failure receipt is diagnostic-only. It can never be accepted as a sensor
// result or evidence. It uses the already-prepared, LocalService-write-only
// result slot solely to surface a bounded stable code when execution fails
// before the signed result can be written.
public sealed record Security4663LiveOneShotFailureReceipt(
    int SchemaVersion,
    string Purpose,
    string Checkpoint,
    string FailureCode);

public static partial class Security4663LiveOneShotFailureReceiptLifecycle
{
    public const string Purpose =
        "war-room.windows-security-4663.failure-diagnostic.v1";
    public const int MaximumDocumentBytes = 512;

    private static readonly IReadOnlySet<string> Fields = new HashSet<string>(
        ["schemaVersion", "purpose", "checkpoint", "failureCode"],
        StringComparer.Ordinal);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static string Create(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return JsonSerializer.Serialize(new Security4663LiveOneShotFailureReceipt(
            1,
            Purpose,
            Security4663LiveOneShotApprovalLifecycle.Checkpoint,
            Security4663LiveOneShotExecution.PublicFailureCode(exception)),
            JsonOptions);
    }

    public static bool TryWrite(
        ISecurity4663LiveOneShotResultStore store,
        Exception exception)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(exception);
        try
        {
            store.WriteNew(Create(exception));
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static bool TryRead(string json, out string failureCode)
    {
        failureCode = string.Empty;
        if (string.IsNullOrEmpty(json) ||
            Encoding.UTF8.GetByteCount(json) > MaximumDocumentBytes)
        {
            return false;
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException)
        {
            return false;
        }
        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("purpose", out var purpose) ||
                purpose.ValueKind != JsonValueKind.String ||
                purpose.GetString() != Purpose)
            {
                return false;
            }
            var properties = root.EnumerateObject().ToArray();
            if (properties.Length != Fields.Count ||
                properties.Select(item => item.Name).ToHashSet(
                    StringComparer.Ordinal).SetEquals(Fields) is false)
            {
                throw Invalid();
            }
            Security4663LiveOneShotFailureReceipt receipt;
            try
            {
                receipt = JsonSerializer.Deserialize<
                    Security4663LiveOneShotFailureReceipt>(json, JsonOptions) ??
                    throw new JsonException();
            }
            catch (JsonException)
            {
                throw Invalid();
            }
            if (receipt.SchemaVersion != 1 ||
                receipt.Purpose != Purpose ||
                receipt.Checkpoint !=
                    Security4663LiveOneShotApprovalLifecycle.Checkpoint ||
                !FailureCodePattern().IsMatch(receipt.FailureCode))
            {
                throw Invalid();
            }
            failureCode = receipt.FailureCode;
            return true;
        }
    }

    private static InvalidDataException Invalid() => new(
        "SENSOR_C2F_SECURITY_4663_FAILURE_RECEIPT_INVALID");

    [GeneratedRegex("^SENSOR_[A-Z0-9_]{1,120}$", RegexOptions.CultureInvariant)]
    private static partial Regex FailureCodePattern();
}

// Distinct C2f reader domain. It validates the live checkpoint before adapting
// only the already-frozen query/parser contract; no C2e approval is accepted.
public sealed class Security4663LiveOneShotBoundedReader(
    ISecurity4663OneShotEventSource source) : ISecurity4663OneShotReader
{
    public const bool RuntimeWired = true;
    public const bool NativeEventAccessEnabled = true;

    private readonly Security4663OneShotBoundedReader _inner = new(
        source ?? throw new ArgumentNullException(nameof(source)));

    public Security4663OneShotReadResult ReadOne(
        Security4663OneShotReadRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Checkpoint !=
            Security4663LiveOneShotApprovalLifecycle.Checkpoint)
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_READ_REQUEST_INVALID");
        }
        return _inner.ReadOne(
            request with
            {
                Checkpoint = Readiness.Security4663OneShotMachinePlan.Checkpoint
            },
            cancellationToken);
    }

    private static InvalidDataException Invalid(string code) => new(code);
}

public sealed class NativeSecurity4663LiveOneShotEventSource :
    ISecurity4663OneShotEventSource
{
    public const bool RuntimeWired = true;
    public const bool ServiceRegistered = true;

    private readonly NativeSecurity4663OneShotEventSource _inner = new();

    public Security4663OneShotSourceResult ReadOne(
        Security4663OneShotSourceQuery query,
        CancellationToken cancellationToken) =>
        _inner.ReadOne(query, cancellationToken);
}

public sealed class Security4663LiveOneShotExecutionWorker(
    ISensorServiceIdentity serviceIdentity,
    IInstallManifestBindingReader manifestReader,
    ISecurity4663LiveOneShotApprovalStore approvalStore,
    ISecurity4663OneShotReader reader,
    ISecurity4663LiveOneShotResultStore resultStore,
    ISensorIdentitySigner identity,
    TimeProvider timeProvider,
    IHostApplicationLifetime applicationLifetime,
    ILogger<Security4663LiveOneShotExecutionWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await WaitForServiceStartedAsync(stoppingToken);
        try
        {
            var result = Security4663LiveOneShotExecution.Execute(
                serviceIdentity,
                manifestReader,
                approvalStore,
                reader,
                resultStore,
                identity,
                timeProvider,
                stoppingToken);
            logger.LogInformation(
                "WAR-R00M Gate C2f completed one bounded local Security read. State={State}; events read={EventsRead}; continuous collection, transport and commands disabled.",
                result.ReadState,
                result.EventsRead);
        }
        catch (Exception exception)
        {
            _ = Security4663LiveOneShotFailureReceiptLifecycle.TryWrite(
                resultStore, exception);
            logger.LogCritical(
                "WAR-R00M Gate C2f failed closed. Code={FailureCode}; no raw event content retained and transport and commands remain disabled.",
                Security4663LiveOneShotExecution.PublicFailureCode(exception));
            Environment.ExitCode = 2;
            throw;
        }
        finally
        {
            applicationLifetime.StopApplication();
        }
    }

    private async Task WaitForServiceStartedAsync(CancellationToken token)
    {
        if (applicationLifetime.ApplicationStarted.IsCancellationRequested)
        {
            return;
        }
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            applicationLifetime.ApplicationStarted, token);
        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, linked.Token);
        }
        catch (OperationCanceledException) when (
            applicationLifetime.ApplicationStarted.IsCancellationRequested)
        {
            // SCM has observed startup before the one-shot authority is used.
        }
        token.ThrowIfCancellationRequested();
    }
}
