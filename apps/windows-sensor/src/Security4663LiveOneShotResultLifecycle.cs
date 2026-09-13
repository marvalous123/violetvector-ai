using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace WARRoom.WindowsSensor;

public sealed record Security4663LiveOneShotNormalizedSourceResult(
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

public sealed record SignedSecurity4663LiveOneShotResult(
    int SchemaVersion,
    string Profile,
    string Checkpoint,
    string TargetProfileId,
    string ReadState,
    int EventsRead,
    string? Provider,
    string? Channel,
    string? EventFamily,
    string? OccurredAt,
    string? SourceRecordTagHmacSha256,
    string? ActorTrust,
    string? Action,
    string? SubjectClass,
    string? ObjectClass,
    string? Outcome,
    string? BaselineState,
    string? VisibilityState,
    bool? TargetSaclVerified,
    bool? LocalClassificationComplete,
    bool GenuineLiveEligible,
    bool RawEventContentRetained,
    bool RuntimeCollectionEnabled,
    bool RetryEnabled,
    bool PollingEnabled,
    bool TransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    bool ResponseActionEnabled,
    string TriggerStartedAt,
    string TriggerCompletedAt,
    string InstalledCommit,
    string CertificateFingerprintSha256,
    string ApprovalEnvelopeSha256,
    string CreatedAt,
    string SignatureBase64);

public interface ISecurity4663LiveOneShotResultStore
{
    string? ReadExisting();
    void WriteNew(string json);
}

// Gate C2f normalized-result contract. The exact one-shot service branch uses
// it only after consuming and revalidating the distinct C2f approval. It is
// absent from the normal sensor and every transport or command pipeline.
public static partial class Security4663LiveOneShotResultLifecycle
{
    public const string Profile =
        "gate-c2f-security-4663-live-one-shot-result-v1";
    public const string Checkpoint =
        Security4663LiveOneShotApprovalLifecycle.Checkpoint;
    public const int MaximumDocumentBytes = 4_096;
    public const int MaximumResultAgeSeconds = 300;
    public const int MaximumCompletionDelaySeconds = 5;
    public const bool RuntimeWired = true;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private static readonly IReadOnlySet<string> Fields = new HashSet<string>(
        [
            "schemaVersion", "profile", "checkpoint", "targetProfileId",
            "readState", "eventsRead", "provider", "channel", "eventFamily",
            "occurredAt", "sourceRecordTagHmacSha256", "actorTrust", "action",
            "subjectClass", "objectClass", "outcome", "baselineState",
            "visibilityState", "targetSaclVerified",
            "localClassificationComplete", "genuineLiveEligible",
            "rawEventContentRetained", "runtimeCollectionEnabled",
            "retryEnabled", "pollingEnabled", "transportEnabled",
            "inboundListenerEnabled", "commandChannelEnabled",
            "responseActionEnabled", "triggerStartedAt",
            "triggerCompletedAt", "installedCommit",
            "certificateFingerprintSha256", "approvalEnvelopeSha256",
            "createdAt", "signatureBase64"
        ],
        StringComparer.Ordinal);

    public static SignedSecurity4663LiveOneShotResult CreateAndWrite(
        ISecurity4663LiveOneShotResultStore store,
        ISensorIdentitySigner identity,
        string installedCommit,
        ConsumedSecurity4663LiveOneShotApproval consumedApproval,
        DateTimeOffset triggerStartedAt,
        DateTimeOffset triggerCompletedAt,
        Security4663LiveOneShotNormalizedSourceResult sourceResult,
        DateTimeOffset createdAt)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(consumedApproval);
        ArgumentNullException.ThrowIfNull(sourceResult);
        if (createdAt.Offset != TimeSpan.Zero)
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_CONTEXT_INVALID");
        }

        var approval = Security4663LiveOneShotApprovalLifecycle.ValidateApproval(
            consumedApproval.ExactJson,
            identity.Descriptor,
            installedCommit,
            createdAt.UtcDateTime);
        var approvalHash =
            Security4663LiveOneShotApprovalLifecycle.HashEnvelope(
                consumedApproval.ExactJson);
        if (
            approval != consumedApproval.Approval ||
            !FixedTimeHexEquals(
                approvalHash,
                consumedApproval.EnvelopeSha256))
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_APPROVAL_INVALID");
        }
        ValidateContext(
            approval,
            installedCommit,
            identity.Descriptor,
            triggerStartedAt,
            triggerCompletedAt,
            sourceResult,
            createdAt);
        if (store.ReadExisting() is not null)
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_ALREADY_EXISTS");
        }

        var classification = sourceResult.Classification;
        var matched = sourceResult.State == Security4663OneShotReadState.Match;
        var tag = matched
            ? CreateSourceRecordTag(
                approvalHash,
                classification!.SourceRecordId)
            : null;
        var core = new SignedSecurity4663LiveOneShotResult(
            1,
            Profile,
            Checkpoint,
            Security4663LiveOneShotApprovalLifecycle.TargetProfileId,
            FormatReadState(sourceResult.State),
            sourceResult.EventsRead,
            matched ? classification!.Provider : null,
            matched ? classification!.Channel : null,
            matched ? classification!.EventFamily : null,
            matched ? FormatUtc(classification!.OccurredAtUtc) : null,
            tag,
            matched ? classification!.Mapping.ActorTrust : null,
            matched ? classification!.Mapping.Action : null,
            matched ? classification!.Mapping.SubjectClass : null,
            matched ? classification!.Mapping.ObjectClass : null,
            matched ? classification!.Mapping.Outcome : null,
            matched ? classification!.BaselineState : null,
            matched ? classification!.VisibilityState : null,
            matched ? classification!.TargetSaclVerified : null,
            matched ? classification!.LocalClassificationComplete : null,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            FormatUtc(triggerStartedAt),
            FormatUtc(triggerCompletedAt),
            installedCommit,
            identity.Descriptor.CertificateFingerprintSha256,
            approvalHash,
            FormatUtc(createdAt),
            string.Empty);
        var result = core with
        {
            SignatureBase64 = identity.SignUtf8Payload(CanonicalCore(core))
        };
        var json = JsonSerializer.Serialize(result, JsonOptions);
        _ = Validate(json, identity.Descriptor, installedCommit, createdAt);
        if (Encoding.UTF8.GetByteCount(json) > MaximumDocumentBytes)
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_SIZE_INVALID");
        }
        store.WriteNew(json);
        return result;
    }

    public static SignedSecurity4663LiveOneShotResult ReadAndValidate(
        ISecurity4663LiveOneShotResultStore store,
        SensorIdentityDescriptor identity,
        string installedCommit,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(store);
        return Validate(
            store.ReadExisting() ?? throw Invalid(
                "SENSOR_C2F_SECURITY_4663_RESULT_MISSING"),
            identity,
            installedCommit,
            now);
    }

    public static SignedSecurity4663LiveOneShotResult Validate(
        string json,
        SensorIdentityDescriptor identity,
        string installedCommit,
        DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        ArgumentNullException.ThrowIfNull(identity);
        if (
            Encoding.UTF8.GetByteCount(json) > MaximumDocumentBytes ||
            now.Offset != TimeSpan.Zero ||
            !CommitPattern().IsMatch(installedCommit))
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_CONTEXT_INVALID");
        }
        ValidateIdentity(identity);

        SignedSecurity4663LiveOneShotResult result;
        try
        {
            using var document = JsonDocument.Parse(json);
            var properties = document.RootElement.ValueKind == JsonValueKind.Object
                ? document.RootElement.EnumerateObject().ToArray()
                : [];
            if (
                properties.Length != Fields.Count ||
                properties.Select(item => item.Name).Distinct(
                    StringComparer.Ordinal).Count() != Fields.Count ||
                !properties.Select(item => item.Name).ToHashSet(
                    StringComparer.Ordinal).SetEquals(Fields))
            {
                throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_FIELDS_INVALID");
            }
            result = JsonSerializer.Deserialize<
                SignedSecurity4663LiveOneShotResult>(json, JsonOptions) ??
                throw new JsonException();
        }
        catch (JsonException)
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_INPUT_INVALID");
        }

        if (
            !TryReadState(result.ReadState, out var readState) ||
            !TryUtc(result.TriggerStartedAt, out var triggerStartedAt) ||
            !TryUtc(result.TriggerCompletedAt, out var triggerCompletedAt) ||
            !TryUtc(result.CreatedAt, out var createdAt) ||
            result.SchemaVersion != 1 ||
            result.Profile != Profile ||
            result.Checkpoint != Checkpoint ||
            result.TargetProfileId !=
                Security4663LiveOneShotApprovalLifecycle.TargetProfileId ||
            result.EventsRead != ExpectedEventsRead(readState) ||
            !ValidateNormalizedFields(
                result, readState, triggerStartedAt, triggerCompletedAt) ||
            result.GenuineLiveEligible ||
            result.RawEventContentRetained ||
            result.RuntimeCollectionEnabled ||
            result.RetryEnabled ||
            result.PollingEnabled ||
            result.TransportEnabled ||
            result.InboundListenerEnabled ||
            result.CommandChannelEnabled ||
            result.ResponseActionEnabled ||
            triggerCompletedAt < triggerStartedAt ||
            triggerCompletedAt - triggerStartedAt > TimeSpan.FromSeconds(
                Security4663LiveOneShotApprovalLifecycle
                    .MaximumTriggerWindowSeconds) ||
            createdAt < triggerCompletedAt ||
            createdAt - triggerCompletedAt > TimeSpan.FromSeconds(
                MaximumCompletionDelaySeconds) ||
            createdAt > now ||
            now - createdAt > TimeSpan.FromSeconds(MaximumResultAgeSeconds) ||
            result.InstalledCommit != installedCommit ||
            result.CertificateFingerprintSha256 !=
                identity.CertificateFingerprintSha256 ||
            !Sha256Pattern().IsMatch(result.ApprovalEnvelopeSha256) ||
            !Verify(CanonicalCore(result), result.SignatureBase64, identity))
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_INVALID");
        }
        return result;
    }

    private static void ValidateContext(
        SignedSecurity4663LiveOneShotApproval approval,
        string installedCommit,
        SensorIdentityDescriptor identity,
        DateTimeOffset triggerStartedAt,
        DateTimeOffset triggerCompletedAt,
        Security4663LiveOneShotNormalizedSourceResult sourceResult,
        DateTimeOffset createdAt)
    {
        var approvedAt =
            Security4663LiveOneShotApprovalLifecycle.ParseUtcOffset(
                approval.ApprovedAt);
        var expiresAt =
            Security4663LiveOneShotApprovalLifecycle.ParseUtcOffset(
                approval.ExpiresAt);
        var classification = sourceResult.Classification;
        if (
            approval.Profile !=
                Security4663LiveOneShotApprovalLifecycle.Profile ||
            approval.Checkpoint != Checkpoint ||
            approval.InstalledCommit != installedCommit ||
            approval.CertificateFingerprintSha256 !=
                identity.CertificateFingerprintSha256 ||
            triggerStartedAt.Offset != TimeSpan.Zero ||
            triggerCompletedAt.Offset != TimeSpan.Zero ||
            createdAt.Offset != TimeSpan.Zero ||
            triggerStartedAt < approvedAt ||
            triggerCompletedAt > expiresAt ||
            triggerCompletedAt < triggerStartedAt ||
            triggerCompletedAt - triggerStartedAt > TimeSpan.FromSeconds(
                approval.MaximumTriggerWindowSeconds) ||
            createdAt < triggerCompletedAt ||
            createdAt - triggerCompletedAt > TimeSpan.FromSeconds(
                MaximumCompletionDelaySeconds) ||
            createdAt >= expiresAt ||
            sourceResult.SchemaVersion != 1 ||
            sourceResult.Checkpoint != Checkpoint ||
            !Enum.IsDefined(sourceResult.State) ||
            sourceResult.EventsRead != ExpectedEventsRead(sourceResult.State) ||
            sourceResult.RawEventContentRetained ||
            !sourceResult.RuntimeWired ||
            !sourceResult.NativeEventAccessEnabled ||
            sourceResult.RetryEnabled ||
            sourceResult.PollingEnabled ||
            sourceResult.TransportEnabled ||
            sourceResult.InboundListenerEnabled ||
            sourceResult.CommandChannelEnabled ||
            sourceResult.ResponseActionEnabled ||
            !ValidateSourceClassification(
                sourceResult.State,
                classification,
                approval.BaselineRecordId,
                triggerStartedAt,
                triggerCompletedAt))
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_CONTEXT_INVALID");
        }
    }

    private static bool ValidateSourceClassification(
        Security4663OneShotReadState state,
        InertWindowsSecurity4663LocalClassification? classification,
        long baselineRecordId,
        DateTimeOffset triggerStartedAt,
        DateTimeOffset triggerCompletedAt)
    {
        if (state != Security4663OneShotReadState.Match)
        {
            return classification is null;
        }
        return classification is not null &&
            classification.Provider == "windows-security" &&
            classification.Channel == "security" &&
            classification.EventFamily == "file-access" &&
            classification.OccurredAtUtc.Offset == TimeSpan.Zero &&
            classification.OccurredAtUtc >= triggerStartedAt &&
            classification.OccurredAtUtc <= triggerCompletedAt &&
            classification.SourceRecordId > baselineRecordId &&
            classification.SourceRecordId <=
                Security4663OneShotCoordinator.MaximumJsonInteger &&
            classification.Profile ==
                InertWindowsSecurityEvent4663Profile.CredentialStoreRead &&
            ValidMapping(classification.Mapping) &&
            ValidBaselineState(classification.BaselineState) &&
            classification.VisibilityState == "unknown" &&
            classification.TargetSaclVerified &&
            classification.LocalClassificationComplete ==
                (classification.Mapping.ActorTrust != "unknown" &&
                    classification.BaselineState != "unknown") &&
            !classification.GenuineLiveEligible &&
            !classification.RawEventContentRetained;
    }

    private static bool ValidateNormalizedFields(
        SignedSecurity4663LiveOneShotResult result,
        Security4663OneShotReadState state,
        DateTimeOffset triggerStartedAt,
        DateTimeOffset triggerCompletedAt)
    {
        if (state != Security4663OneShotReadState.Match)
        {
            return result.Provider is null && result.Channel is null &&
                result.EventFamily is null && result.OccurredAt is null &&
                result.SourceRecordTagHmacSha256 is null &&
                result.ActorTrust is null && result.Action is null &&
                result.SubjectClass is null && result.ObjectClass is null &&
                result.Outcome is null && result.BaselineState is null &&
                result.VisibilityState is null &&
                result.TargetSaclVerified is null &&
                result.LocalClassificationComplete is null;
        }
        return result.Provider == "windows-security" &&
            result.Channel == "security" &&
            result.EventFamily == "file-access" &&
            result.OccurredAt is not null &&
            TryUtc(result.OccurredAt, out var occurredAt) &&
            occurredAt >= triggerStartedAt &&
            occurredAt <= triggerCompletedAt &&
            result.SourceRecordTagHmacSha256 is not null &&
            Sha256Pattern().IsMatch(result.SourceRecordTagHmacSha256) &&
            result.ActorTrust is "managed" or "untrusted" or "unknown" &&
            result.Action == "read" &&
            result.SubjectClass is "browser" or "password-manager" or "other" &&
            result.ObjectClass == "credential-store" &&
            result.Outcome == "success" &&
            ValidBaselineState(result.BaselineState ?? string.Empty) &&
            result.VisibilityState == "unknown" &&
            result.TargetSaclVerified == true &&
            result.LocalClassificationComplete ==
                (result.ActorTrust != "unknown" &&
                    result.BaselineState != "unknown");
    }

    private static string CreateSourceRecordTag(
        string approvalHash,
        long sourceRecordId)
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var input = Encoding.UTF8.GetBytes(
            "WAR-R00M.C2F.SECURITY4663.RECORD.v1\0" + approvalHash + "\0" +
            sourceRecordId.ToString(CultureInfo.InvariantCulture));
        try
        {
            return Convert.ToHexString(HMACSHA256.HashData(key, input))
                .ToLowerInvariant();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(input);
        }
    }

    private static bool ValidMapping(BoundedFactMapping? mapping) =>
        mapping is not null &&
        mapping.ActorTrust is "managed" or "untrusted" or "unknown" &&
        mapping.Action == "read" &&
        mapping.SubjectClass is "browser" or "password-manager" or "other" &&
        mapping.ObjectClass == "credential-store" &&
        mapping.Outcome == "success";

    private static bool ValidBaselineState(string value) =>
        value is "new" or "rare" or "expected" or "unknown";

    private static void ValidateIdentity(SensorIdentityDescriptor identity)
    {
        byte[] spki;
        try
        {
            spki = Convert.FromBase64String(identity.PublicKeySpkiBase64);
        }
        catch (FormatException)
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_IDENTITY_INVALID");
        }
        try
        {
            if (
                identity.Algorithm != SensorBoundary.SignatureAlgorithm ||
                identity.PublicKeyFormat != "spki-der" ||
                identity.KeyProvider != SensorBoundary.SoftwareProviderName ||
                identity.KeyPersistence !=
                    "non-exportable-machine-cng-software-ksp" ||
                !Sha256Pattern().IsMatch(
                    identity.CertificateFingerprintSha256) ||
                Convert.ToHexString(SHA256.HashData(spki)).ToLowerInvariant() !=
                    identity.CertificateFingerprintSha256)
            {
                throw Invalid(
                    "SENSOR_C2F_SECURITY_4663_RESULT_IDENTITY_INVALID");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(spki);
        }
    }

    private static string CanonicalCore(
        SignedSecurity4663LiveOneShotResult value) =>
        JsonSerializer.Serialize(
            value with { SignatureBase64 = string.Empty },
            JsonOptions);

    private static bool Verify(
        string payload,
        string signatureBase64,
        SensorIdentityDescriptor identity)
    {
        byte[]? spki = null;
        byte[]? signature = null;
        byte[]? bytes = null;
        try
        {
            spki = Convert.FromBase64String(identity.PublicKeySpkiBase64);
            signature = Convert.FromBase64String(signatureBase64);
            bytes = Encoding.UTF8.GetBytes(payload);
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(spki, out var read);
            return read == spki.Length && signature.Length == 64 &&
                verifier.VerifyData(
                    bytes,
                    signature,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (FormatException)
        {
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
        finally
        {
            if (spki is not null) CryptographicOperations.ZeroMemory(spki);
            if (signature is not null)
            {
                CryptographicOperations.ZeroMemory(signature);
            }
            if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static bool FixedTimeHexEquals(string left, string right)
    {
        if (!Sha256Pattern().IsMatch(left) || !Sha256Pattern().IsMatch(right))
        {
            return false;
        }
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(left),
            Encoding.ASCII.GetBytes(right));
    }

    private static int ExpectedEventsRead(Security4663OneShotReadState state) =>
        state == Security4663OneShotReadState.Match ? 1 : 0;

    private static string FormatReadState(Security4663OneShotReadState state) =>
        state switch
        {
            Security4663OneShotReadState.Match => "match",
            Security4663OneShotReadState.NoMatch => "no-match",
            Security4663OneShotReadState.AccessDenied => "access-denied",
            Security4663OneShotReadState.SourceUnavailable =>
                "source-unavailable",
            Security4663OneShotReadState.QueryFailed => "query-failed",
            _ => throw Invalid("SENSOR_C2F_SECURITY_4663_RESULT_CONTEXT_INVALID")
        };

    private static bool TryReadState(
        string value,
        out Security4663OneShotReadState state)
    {
        state = value switch
        {
            "match" => Security4663OneShotReadState.Match,
            "no-match" => Security4663OneShotReadState.NoMatch,
            "access-denied" => Security4663OneShotReadState.AccessDenied,
            "source-unavailable" =>
                Security4663OneShotReadState.SourceUnavailable,
            "query-failed" => Security4663OneShotReadState.QueryFailed,
            _ => 0
        };
        return Enum.IsDefined(state);
    }

    private static string FormatUtc(DateTimeOffset value) =>
        value.ToUniversalTime().ToString(
            "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
            CultureInfo.InvariantCulture);

    private static bool TryUtc(string value, out DateTimeOffset parsed) =>
        DateTimeOffset.TryParseExact(
            value,
            "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out parsed) && parsed.Offset == TimeSpan.Zero;

    private static InvalidDataException Invalid(string code) => new(code);

    [GeneratedRegex("^[0-9a-f]{40}$", RegexOptions.CultureInvariant)]
    private static partial Regex CommitPattern();

    [GeneratedRegex("^[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256Pattern();
}
