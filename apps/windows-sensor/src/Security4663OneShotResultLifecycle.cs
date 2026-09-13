using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace WARRoom.WindowsSensor;

public sealed record SignedSecurity4663OneShotResult(
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

public interface ISecurity4663OneShotResultStore
{
    string? ReadExisting();
    void WriteNew(string json);
    void ConsumeExact(string expectedJson);
}

// Pure, source-only result contract for the future Gate C2e live-read
// ceremony. It does not open the Security log, persist raw event content or
// register any runtime, transport or control-plane capability.
public static partial class Security4663OneShotResultLifecycle
{
    public const string Profile =
        "gate-c2e-security-4663-one-shot-result-v1";
    public const int MaximumDocumentBytes = 4_096;
    public const int MaximumResultAgeSeconds = 300;
    public const bool RuntimeWired = false;

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
            "readState", "eventsRead", "genuineLiveEligible",
            "provider", "channel", "eventFamily", "occurredAt",
            "sourceRecordTagHmacSha256", "actorTrust", "action",
            "subjectClass", "objectClass", "outcome", "baselineState",
            "visibilityState", "targetSaclVerified",
            "localClassificationComplete",
            "rawEventContentRetained", "runtimeCollectionEnabled",
            "retryEnabled", "pollingEnabled", "transportEnabled",
            "inboundListenerEnabled", "commandChannelEnabled",
            "responseActionEnabled", "triggerStartedAt",
            "triggerCompletedAt", "installedCommit",
            "certificateFingerprintSha256", "approvalEnvelopeSha256",
            "createdAt", "signatureBase64"
        ],
        StringComparer.Ordinal);

    public static string HashApprovalEnvelope(string approvalJson)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(approvalJson);
        var bytes = Encoding.UTF8.GetBytes(approvalJson);
        try
        {
            if (bytes.Length > Security4663OneShotApprovalLifecycle.MaximumDocumentBytes)
            {
                throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_APPROVAL_INVALID");
            }
            return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static string CreateSourceRecordTagHmacSha256(
        ReadOnlySpan<byte> sourceRecordTagKey,
        long sourceRecordId)
    {
        if (
            sourceRecordTagKey.Length != 32 ||
            sourceRecordId is < 1 or >
                Security4663OneShotCoordinator.MaximumJsonInteger)
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_RECORD_INVALID");
        }
        var input = Encoding.UTF8.GetBytes(
            "WAR-R00M.C2E.SECURITY4663.RECORD.v1\0" +
            sourceRecordId.ToString(
                System.Globalization.CultureInfo.InvariantCulture));
        try
        {
            return Convert.ToHexString(
                HMACSHA256.HashData(sourceRecordTagKey, input))
                .ToLowerInvariant();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    public static SignedSecurity4663OneShotResult CreateAndWrite(
        ISecurity4663OneShotResultStore store,
        ISensorIdentitySigner identity,
        string installedCommit,
        string approvalJson,
        DateTimeOffset triggerStartedAt,
        DateTimeOffset triggerCompletedAt,
        Security4663OneShotResult sourceResult,
        DateTimeOffset createdAt)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(identity);
        if (store.ReadExisting() is not null)
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_ALREADY_EXISTS");
        }
        if (createdAt.Offset != TimeSpan.Zero)
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_CONTEXT_INVALID");
        }
        var approval = Security4663OneShotApprovalLifecycle.ValidateApproval(
            approvalJson,
            identity.Descriptor,
            installedCommit,
            createdAt.UtcDateTime);
        var approvalEnvelopeSha256 = HashApprovalEnvelope(approvalJson);
        ValidateContext(
            identity.Descriptor,
            installedCommit,
            approval,
            triggerStartedAt,
            triggerCompletedAt,
            sourceResult,
            createdAt);

        var classification = sourceResult.Classification;
        var matched = sourceResult.State == Security4663OneShotReadState.Match;

        var sourceRecordTagKey = RandomNumberGenerator.GetBytes(32);
        SignedSecurity4663OneShotResult core;
        try
        {
            core = new SignedSecurity4663OneShotResult(
                1,
                Profile,
                Readiness.Security4663OneShotMachinePlan.Checkpoint,
                "credential-store-read",
                FormatReadState(sourceResult.State),
                sourceResult.EventsRead,
                matched ? classification!.Provider : null,
                matched ? classification!.Channel : null,
                matched ? classification!.EventFamily : null,
                matched ? FormatUtc(classification!.OccurredAtUtc) : null,
                matched ? CreateSourceRecordTagHmacSha256(
                    sourceRecordTagKey,
                    classification!.SourceRecordId) : null,
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
                approvalEnvelopeSha256,
                FormatUtc(createdAt),
                string.Empty);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sourceRecordTagKey);
        }
        var result = core with
        {
            SignatureBase64 = identity.SignUtf8Payload(CanonicalCore(core))
        };
        var json = JsonSerializer.Serialize(result, JsonOptions);
        _ = Validate(
            json,
            identity.Descriptor,
            installedCommit,
            createdAt);
        if (Encoding.UTF8.GetByteCount(json) > MaximumDocumentBytes)
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_SIZE_INVALID");
        }
        store.WriteNew(json);
        return result;
    }

    public static SignedSecurity4663OneShotResult ReadAndValidate(
        ISecurity4663OneShotResultStore store,
        SensorIdentityDescriptor identity,
        string installedCommit,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(store);
        return Validate(
            store.ReadExisting() ?? throw Invalid(
                "SENSOR_C2E_SECURITY_4663_RESULT_MISSING"),
            identity,
            installedCommit,
            now);
    }

    public static SignedSecurity4663OneShotResult Consume(
        ISecurity4663OneShotResultStore store,
        SensorIdentityDescriptor identity,
        string installedCommit,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(store);
        var json = store.ReadExisting() ?? throw Invalid(
            "SENSOR_C2E_SECURITY_4663_RESULT_MISSING");
        var result = Validate(
            json,
            identity,
            installedCommit,
            now);
        store.ConsumeExact(json);
        return result;
    }

    public static SignedSecurity4663OneShotResult Validate(
        string json,
        SensorIdentityDescriptor identity,
        string installedCommit,
        DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        ArgumentNullException.ThrowIfNull(identity);
        if (
            Encoding.UTF8.GetByteCount(json) > MaximumDocumentBytes ||
            !CommitPattern().IsMatch(installedCommit) ||
            now.Offset != TimeSpan.Zero)
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_CONTEXT_INVALID");
        }
        ValidateIdentity(identity);

        JsonElement root;
        try
        {
            using var document = JsonDocument.Parse(json);
            root = document.RootElement.Clone();
        }
        catch (JsonException)
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_INPUT_INVALID");
        }
        var properties = root.ValueKind == JsonValueKind.Object
            ? root.EnumerateObject().ToArray()
            : [];
        if (
            properties.Length != Fields.Count ||
            properties.Select(item => item.Name).Distinct(
                StringComparer.Ordinal).Count() != Fields.Count ||
            !properties.Select(item => item.Name).ToHashSet(
                StringComparer.Ordinal).SetEquals(Fields))
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_FIELDS_INVALID");
        }

        SignedSecurity4663OneShotResult result;
        try
        {
            result = JsonSerializer.Deserialize<SignedSecurity4663OneShotResult>(
                json,
                JsonOptions) ?? throw new JsonException();
        }
        catch (JsonException)
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_INPUT_INVALID");
        }

        if (
            !TryReadState(result.ReadState, out var readState) ||
            !TryUtc(result.TriggerStartedAt, out var triggerStartedAt) ||
            !TryUtc(result.TriggerCompletedAt, out var triggerCompletedAt) ||
            !TryUtc(result.CreatedAt, out var createdAt) ||
            result.SchemaVersion != 1 ||
            result.Profile != Profile ||
            result.Checkpoint !=
                Readiness.Security4663OneShotMachinePlan.Checkpoint ||
            result.TargetProfileId != "credential-store-read" ||
            result.EventsRead != ExpectedEventsRead(readState) ||
            !ValidateNormalizedFields(
                result,
                readState,
                triggerStartedAt,
                triggerCompletedAt) ||
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
            triggerCompletedAt - triggerStartedAt > TimeSpan.FromSeconds(10) ||
            createdAt < triggerCompletedAt ||
            createdAt > now ||
            now - createdAt > TimeSpan.FromSeconds(MaximumResultAgeSeconds) ||
            result.InstalledCommit != installedCommit ||
            result.CertificateFingerprintSha256 !=
                identity.CertificateFingerprintSha256 ||
            !Sha256Pattern().IsMatch(result.ApprovalEnvelopeSha256) ||
            !Verify(CanonicalCore(result), result.SignatureBase64, identity))
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_INVALID");
        }
        return result;
    }

    private static void ValidateContext(
        SensorIdentityDescriptor identity,
        string installedCommit,
        SignedSecurity4663OneShotApproval approval,
        DateTimeOffset triggerStartedAt,
        DateTimeOffset triggerCompletedAt,
        Security4663OneShotResult sourceResult,
        DateTimeOffset createdAt)
    {
        ArgumentNullException.ThrowIfNull(sourceResult);
        ValidateIdentity(identity);
        if (
            !CommitPattern().IsMatch(installedCommit) ||
            approval.InstalledCommit != installedCommit ||
            approval.CertificateFingerprintSha256 !=
                identity.CertificateFingerprintSha256 ||
            !TryUtc(approval.ApprovedAt, out var approvedAt) ||
            !TryUtc(approval.ExpiresAt, out var expiresAt) ||
            triggerStartedAt.Offset != TimeSpan.Zero ||
            triggerCompletedAt.Offset != TimeSpan.Zero ||
            createdAt.Offset != TimeSpan.Zero ||
            triggerCompletedAt < triggerStartedAt ||
            triggerCompletedAt - triggerStartedAt > TimeSpan.FromSeconds(10) ||
            triggerStartedAt < approvedAt ||
            triggerCompletedAt > expiresAt ||
            createdAt >= expiresAt ||
            createdAt < triggerCompletedAt ||
            sourceResult.SchemaVersion != 1 ||
            sourceResult.Checkpoint !=
                Readiness.Security4663OneShotMachinePlan.Checkpoint ||
            !Enum.IsDefined(sourceResult.State) ||
            sourceResult.EventsRead != ExpectedEventsRead(sourceResult.State) ||
            sourceResult.RawEventContentRetained ||
            sourceResult.RuntimeWired ||
            sourceResult.NativeEventAccessEnabled ||
            sourceResult.RetryEnabled ||
            sourceResult.PollingEnabled ||
            sourceResult.TransportEnabled ||
            sourceResult.InboundListenerEnabled ||
            sourceResult.CommandChannelEnabled ||
            sourceResult.ResponseActionEnabled ||
            !ValidateSourceClassification(
                sourceResult,
                approval.BaselineRecordId,
                triggerStartedAt,
                triggerCompletedAt))
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_CONTEXT_INVALID");
        }
    }

    private static void ValidateIdentity(SensorIdentityDescriptor identity)
    {
        byte[] spki;
        try
        {
            spki = Convert.FromBase64String(identity.PublicKeySpkiBase64);
        }
        catch (FormatException)
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_IDENTITY_INVALID");
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
                throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_IDENTITY_INVALID");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(spki);
        }
    }

    private static bool ValidateSourceClassification(
        Security4663OneShotResult sourceResult,
        long baselineRecordId,
        DateTimeOffset triggerStartedAt,
        DateTimeOffset triggerCompletedAt)
    {
        var classification = sourceResult.Classification;
        if (sourceResult.State != Security4663OneShotReadState.Match)
        {
            return classification is null;
        }
        if (classification is null)
        {
            return false;
        }
        return
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
        SignedSecurity4663OneShotResult result,
        Security4663OneShotReadState readState,
        DateTimeOffset triggerStartedAt,
        DateTimeOffset triggerCompletedAt)
    {
        if (readState != Security4663OneShotReadState.Match)
        {
            return
                result.Provider is null &&
                result.Channel is null &&
                result.EventFamily is null &&
                result.OccurredAt is null &&
                result.SourceRecordTagHmacSha256 is null &&
                result.ActorTrust is null &&
                result.Action is null &&
                result.SubjectClass is null &&
                result.ObjectClass is null &&
                result.Outcome is null &&
                result.BaselineState is null &&
                result.VisibilityState is null &&
                result.TargetSaclVerified is null &&
                result.LocalClassificationComplete is null;
        }

        return
            result.Provider == "windows-security" &&
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
            result.BaselineState is "new" or "rare" or "expected" or "unknown" &&
            result.VisibilityState == "unknown" &&
            result.TargetSaclVerified == true &&
            result.LocalClassificationComplete ==
                (result.ActorTrust != "unknown" &&
                    result.BaselineState != "unknown");
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

    private static string CanonicalCore(SignedSecurity4663OneShotResult value)
    {
        using var output = new MemoryStream();
        using (var writer = new Utf8JsonWriter(
            output,
            new JsonWriterOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            }))
        {
            writer.WriteStartObject();
            writer.WriteString("approvalEnvelopeSha256", value.ApprovalEnvelopeSha256);
            writer.WriteString("action", value.Action);
            writer.WriteString("actorTrust", value.ActorTrust);
            writer.WriteString("baselineState", value.BaselineState);
            writer.WriteString("certificateFingerprintSha256", value.CertificateFingerprintSha256);
            writer.WriteString("channel", value.Channel);
            writer.WriteString("checkpoint", value.Checkpoint);
            writer.WriteBoolean("commandChannelEnabled", value.CommandChannelEnabled);
            writer.WriteString("createdAt", value.CreatedAt);
            writer.WriteString("eventFamily", value.EventFamily);
            writer.WriteNumber("eventsRead", value.EventsRead);
            writer.WriteBoolean("genuineLiveEligible", value.GenuineLiveEligible);
            writer.WriteBoolean("inboundListenerEnabled", value.InboundListenerEnabled);
            writer.WriteString("installedCommit", value.InstalledCommit);
            WriteNullableBoolean(
                writer,
                "localClassificationComplete",
                value.LocalClassificationComplete);
            writer.WriteString("objectClass", value.ObjectClass);
            writer.WriteString("occurredAt", value.OccurredAt);
            writer.WriteString("outcome", value.Outcome);
            writer.WriteBoolean("pollingEnabled", value.PollingEnabled);
            writer.WriteString("profile", value.Profile);
            writer.WriteString("provider", value.Provider);
            writer.WriteBoolean("rawEventContentRetained", value.RawEventContentRetained);
            writer.WriteString("readState", value.ReadState);
            writer.WriteBoolean("responseActionEnabled", value.ResponseActionEnabled);
            writer.WriteBoolean("retryEnabled", value.RetryEnabled);
            writer.WriteBoolean("runtimeCollectionEnabled", value.RuntimeCollectionEnabled);
            writer.WriteNumber("schemaVersion", value.SchemaVersion);
            writer.WriteString(
                "sourceRecordTagHmacSha256",
                value.SourceRecordTagHmacSha256);
            writer.WriteString("subjectClass", value.SubjectClass);
            writer.WriteString("targetProfileId", value.TargetProfileId);
            WriteNullableBoolean(
                writer,
                "targetSaclVerified",
                value.TargetSaclVerified);
            writer.WriteBoolean("transportEnabled", value.TransportEnabled);
            writer.WriteString("triggerCompletedAt", value.TriggerCompletedAt);
            writer.WriteString("triggerStartedAt", value.TriggerStartedAt);
            writer.WriteString("visibilityState", value.VisibilityState);
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(output.ToArray());
    }

    private static void WriteNullableBoolean(
        Utf8JsonWriter writer,
        string propertyName,
        bool? value)
    {
        if (value.HasValue)
        {
            writer.WriteBoolean(propertyName, value.Value);
        }
        else
        {
            writer.WriteNull(propertyName);
        }
    }

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
            if (signature is not null) CryptographicOperations.ZeroMemory(signature);
            if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static int ExpectedEventsRead(Security4663OneShotReadState state) =>
        state == Security4663OneShotReadState.Match ? 1 : 0;

    private static string FormatReadState(Security4663OneShotReadState state) =>
        state switch
        {
            Security4663OneShotReadState.Match => "match",
            Security4663OneShotReadState.NoMatch => "no-match",
            Security4663OneShotReadState.AccessDenied => "access-denied",
            Security4663OneShotReadState.SourceUnavailable => "source-unavailable",
            Security4663OneShotReadState.QueryFailed => "query-failed",
            _ => throw Invalid("SENSOR_C2E_SECURITY_4663_RESULT_CONTEXT_INVALID")
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
            "source-unavailable" => Security4663OneShotReadState.SourceUnavailable,
            "query-failed" => Security4663OneShotReadState.QueryFailed,
            _ => 0
        };
        return Enum.IsDefined(state);
    }

    private static string FormatUtc(DateTimeOffset value) =>
        value.ToUniversalTime().ToString(
            "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
            System.Globalization.CultureInfo.InvariantCulture);

    private static bool TryUtc(string value, out DateTimeOffset parsed) =>
        DateTimeOffset.TryParseExact(
            value,
            "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal |
                System.Globalization.DateTimeStyles.AdjustToUniversal,
            out parsed) && parsed.Offset == TimeSpan.Zero;

    private static InvalidDataException Invalid(string code) => new(code);

    [GeneratedRegex("^[0-9a-f]{40}$", RegexOptions.CultureInvariant)]
    private static partial Regex CommitPattern();

    [GeneratedRegex("^[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256Pattern();
}
