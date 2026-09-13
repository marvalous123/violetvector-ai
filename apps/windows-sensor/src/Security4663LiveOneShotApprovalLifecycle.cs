using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using WARRoom.WindowsSensor.Readiness;

namespace WARRoom.WindowsSensor;

public sealed record SignedSecurity4663LiveOneShotApproval(
    int SchemaVersion,
    string Profile,
    string State,
    string Checkpoint,
    string CapabilityPurpose,
    string ReadinessCheckpoint,
    string ServiceName,
    string ServiceIdentity,
    string ServiceStartupArgument,
    string TargetProfileId,
    long BaselineRecordId,
    bool ReadinessVerified,
    bool ChannelLocalServiceReadOnly,
    bool AuditSuccessOnly,
    bool TargetExists,
    bool TargetZeroLength,
    bool TargetReparsePoint,
    bool TargetSaclVerified,
    int MaximumQueryMilliseconds,
    int MaximumEventsRead,
    int MaximumTriggerWindowSeconds,
    bool NormalizedResultRequired,
    bool RawEventContentRetentionAllowed,
    bool RetryEnabled,
    bool PollingEnabled,
    bool RuntimeCollectionEnabled,
    bool TransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    bool ResponseActionEnabled,
    string InstalledCommit,
    string CertificateFingerprintSha256,
    string NonceBase64,
    string ApprovedAt,
    string ExpiresAt,
    string SignatureBase64);

public sealed record ConsumedSecurity4663LiveOneShotApproval(
    SignedSecurity4663LiveOneShotApproval Approval,
    string ExactJson,
    string EnvelopeSha256);

public interface ISecurity4663LiveOneShotApprovalStore
{
    string? ReadExisting();
    void WriteNew(string json);
    void ConsumeExact(string expectedJson);
}

// A distinct approval domain for the first live bounded read. It cannot be
// consumed by the older zero-event authority proof and carries the exact C2d
// readiness facts that LocalService cannot safely rediscover from protected
// SACL state.
public static partial class Security4663LiveOneShotApprovalLifecycle
{
    public const string Profile =
        "gate-c2f-security-4663-live-one-shot-approval-v1";
    public const string Checkpoint =
        "gate-c2f-security-4663-live-one-shot";
    public const string CapabilityPurpose =
        "fixed-inert-security-4663-read-and-normalize";
    public const string StartupArgument =
        "--security-4663-live-one-shot";
    public const string TargetProfileId = "credential-store-read";
    public const int MaximumDocumentBytes = 4_096;
    public const int NonceBytes = 32;
    public const int LifetimeSeconds = 300;
    public const int MaximumQueryMilliseconds = 2_000;
    public const int MaximumEventsRead = 1;
    public const int MaximumTriggerWindowSeconds = 10;
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
            "schemaVersion", "profile", "state", "checkpoint",
            "capabilityPurpose", "readinessCheckpoint", "serviceName",
            "serviceIdentity", "serviceStartupArgument", "targetProfileId",
            "baselineRecordId", "readinessVerified",
            "channelLocalServiceReadOnly", "auditSuccessOnly", "targetExists",
            "targetZeroLength", "targetReparsePoint", "targetSaclVerified",
            "maximumQueryMilliseconds", "maximumEventsRead",
            "maximumTriggerWindowSeconds", "normalizedResultRequired",
            "rawEventContentRetentionAllowed", "retryEnabled",
            "pollingEnabled", "runtimeCollectionEnabled", "transportEnabled",
            "inboundListenerEnabled", "commandChannelEnabled",
            "responseActionEnabled",
            "installedCommit", "certificateFingerprintSha256", "nonceBase64",
            "approvedAt", "expiresAt", "signatureBase64"
        ],
        StringComparer.Ordinal);

    public static SignedSecurity4663LiveOneShotApproval CreateAndWrite(
        ISecurity4663LiveOneShotApprovalStore store,
        ISensorIdentitySigner identity,
        string installedCommit,
        Security4663ReadinessCheckResult readiness,
        long baselineRecordId,
        DateTime utcNow,
        ReadOnlySpan<byte> nonce)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(identity);
        ValidateContext(
            identity.Descriptor, installedCommit, readiness, baselineRecordId,
            utcNow, nonce);
        if (store.ReadExisting() is not null)
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_APPROVAL_ALREADY_EXISTS");
        }

        var core = new SignedSecurity4663LiveOneShotApproval(
            1,
            Profile,
            "approved",
            Checkpoint,
            CapabilityPurpose,
            Security4663ReadinessCeremony.Checkpoint,
            SensorBoundary.ServiceName,
            SensorBoundary.ExpectedServiceIdentity,
            StartupArgument,
            TargetProfileId,
            baselineRecordId,
            true,
            true,
            true,
            true,
            true,
            false,
            true,
            MaximumQueryMilliseconds,
            MaximumEventsRead,
            MaximumTriggerWindowSeconds,
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            installedCommit,
            identity.Descriptor.CertificateFingerprintSha256,
            Convert.ToBase64String(nonce),
            FormatUtc(utcNow),
            FormatUtc(utcNow.AddSeconds(LifetimeSeconds)),
            string.Empty);
        var approval = core with
        {
            SignatureBase64 = identity.SignUtf8Payload(CanonicalCore(core))
        };
        var json = JsonSerializer.Serialize(approval, JsonOptions);
        _ = ValidateApproval(json, identity.Descriptor, installedCommit, utcNow);
        if (Encoding.UTF8.GetByteCount(json) > MaximumDocumentBytes)
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_APPROVAL_SIZE_INVALID");
        }
        store.WriteNew(json);
        return approval;
    }

    public static ConsumedSecurity4663LiveOneShotApproval ConsumeEnvelope(
        ISecurity4663LiveOneShotApprovalStore store,
        SensorIdentityDescriptor identity,
        string installedCommit,
        DateTime utcNow)
    {
        ArgumentNullException.ThrowIfNull(store);
        var json = store.ReadExisting() ?? throw Invalid(
            "SENSOR_C2F_SECURITY_4663_APPROVAL_MISSING");
        var approval = ValidateApproval(json, identity, installedCommit, utcNow);
        store.ConsumeExact(json);
        return new ConsumedSecurity4663LiveOneShotApproval(
            approval,
            json,
            HashEnvelope(json));
    }

    public static SignedSecurity4663LiveOneShotApproval ValidateApproval(
        string json,
        SensorIdentityDescriptor identity,
        string installedCommit,
        DateTime utcNow)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        ArgumentNullException.ThrowIfNull(identity);
        if (
            Encoding.UTF8.GetByteCount(json) > MaximumDocumentBytes ||
            utcNow.Kind != DateTimeKind.Utc ||
            !CommitPattern().IsMatch(installedCommit))
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_APPROVAL_CONTEXT_INVALID");
        }

        JsonElement root;
        try
        {
            using var document = JsonDocument.Parse(json);
            root = document.RootElement.Clone();
        }
        catch (JsonException)
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_APPROVAL_INPUT_INVALID");
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
            throw Invalid("SENSOR_C2F_SECURITY_4663_APPROVAL_FIELDS_INVALID");
        }

        SignedSecurity4663LiveOneShotApproval approval;
        try
        {
            approval = JsonSerializer.Deserialize<
                SignedSecurity4663LiveOneShotApproval>(json, JsonOptions) ??
                throw Invalid("SENSOR_C2F_SECURITY_4663_APPROVAL_INPUT_INVALID");
        }
        catch (JsonException)
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_APPROVAL_INPUT_INVALID");
        }

        ValidateIdentity(identity);
        byte[] nonce;
        try
        {
            nonce = Convert.FromBase64String(approval.NonceBase64);
        }
        catch (FormatException)
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_APPROVAL_INVALID");
        }
        try
        {
            if (
                nonce.Length != NonceBytes ||
                approval.SchemaVersion != 1 ||
                approval.Profile != Profile ||
                approval.State != "approved" ||
                approval.Checkpoint != Checkpoint ||
                approval.CapabilityPurpose != CapabilityPurpose ||
                approval.ReadinessCheckpoint !=
                    Security4663ReadinessCeremony.Checkpoint ||
                approval.ServiceName != SensorBoundary.ServiceName ||
                approval.ServiceIdentity !=
                    SensorBoundary.ExpectedServiceIdentity ||
                approval.ServiceStartupArgument != StartupArgument ||
                approval.TargetProfileId != TargetProfileId ||
                approval.BaselineRecordId is < 1 or >
                    Security4663OneShotCoordinator.MaximumJsonInteger ||
                !approval.ReadinessVerified ||
                !approval.ChannelLocalServiceReadOnly ||
                !approval.AuditSuccessOnly ||
                !approval.TargetExists ||
                !approval.TargetZeroLength ||
                approval.TargetReparsePoint ||
                !approval.TargetSaclVerified ||
                approval.MaximumQueryMilliseconds !=
                    MaximumQueryMilliseconds ||
                approval.MaximumEventsRead != MaximumEventsRead ||
                approval.MaximumTriggerWindowSeconds !=
                    MaximumTriggerWindowSeconds ||
                !approval.NormalizedResultRequired ||
                approval.RawEventContentRetentionAllowed ||
                approval.RetryEnabled ||
                approval.PollingEnabled ||
                approval.RuntimeCollectionEnabled ||
                approval.TransportEnabled ||
                approval.InboundListenerEnabled ||
                approval.CommandChannelEnabled ||
                approval.ResponseActionEnabled ||
                approval.InstalledCommit != installedCommit ||
                approval.CertificateFingerprintSha256 !=
                    identity.CertificateFingerprintSha256 ||
                !TryUtc(approval.ApprovedAt, out var approvedAt) ||
                !TryUtc(approval.ExpiresAt, out var expiresAt) ||
                expiresAt != approvedAt.AddSeconds(LifetimeSeconds) ||
                utcNow < approvedAt ||
                utcNow >= expiresAt ||
                !Verify(CanonicalCore(approval), approval.SignatureBase64, identity))
            {
                throw Invalid("SENSOR_C2F_SECURITY_4663_APPROVAL_INVALID");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
        }
        return approval;
    }

    public static string HashEnvelope(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        var bytes = Encoding.UTF8.GetBytes(json);
        try
        {
            return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static void ValidateContext(
        SensorIdentityDescriptor identity,
        string installedCommit,
        Security4663ReadinessCheckResult readiness,
        long baselineRecordId,
        DateTime utcNow,
        ReadOnlySpan<byte> nonce)
    {
        ArgumentNullException.ThrowIfNull(readiness);
        ValidateIdentity(identity);
        var plan = Security4663OneShotMachinePlan.BuildPlan();
        Security4663OneShotMachinePlan.ValidatePlan(plan);
        var target = readiness.Targets.Where(item =>
            item.ProfileId == plan.ProfileId).ToArray();
        if (
            utcNow.Kind != DateTimeKind.Utc ||
            !CommitPattern().IsMatch(installedCommit) ||
            baselineRecordId is < 1 or >
                Security4663OneShotCoordinator.MaximumJsonInteger ||
            nonce.Length != NonceBytes ||
            plan.MaximumQuerySeconds * 1_000 != MaximumQueryMilliseconds ||
            plan.MaximumEventsRead != MaximumEventsRead ||
            plan.MaximumTriggerWindowSeconds != MaximumTriggerWindowSeconds ||
            readiness.SchemaVersion != 1 ||
            readiness.Checkpoint != Security4663ReadinessCeremony.Checkpoint ||
            !readiness.Ready ||
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
            target.Length != 1 ||
            !target[0].Exists ||
            !target[0].ZeroLength ||
            target[0].ReparsePoint ||
            !target[0].SaclAccessible ||
            !target[0].ExactSuccessAudit ||
            target[0].ErrorCode is not null)
        {
            throw Invalid("SENSOR_C2F_SECURITY_4663_APPROVAL_CONTEXT_INVALID");
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
            throw Invalid("SENSOR_C2F_SECURITY_4663_APPROVAL_IDENTITY_INVALID");
        }
        try
        {
            if (
                identity.Algorithm != SensorBoundary.SignatureAlgorithm ||
                identity.PublicKeyFormat != "spki-der" ||
                identity.KeyProvider != SensorBoundary.SoftwareProviderName ||
                identity.KeyPersistence !=
                    "non-exportable-machine-cng-software-ksp" ||
                !Sha256Pattern().IsMatch(identity.CertificateFingerprintSha256) ||
                Convert.ToHexString(SHA256.HashData(spki)).ToLowerInvariant() !=
                    identity.CertificateFingerprintSha256)
            {
                throw Invalid(
                    "SENSOR_C2F_SECURITY_4663_APPROVAL_IDENTITY_INVALID");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(spki);
        }
    }

    private static string CanonicalCore(
        SignedSecurity4663LiveOneShotApproval value)
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
            writer.WriteString("approvedAt", value.ApprovedAt);
            writer.WriteBoolean("auditSuccessOnly", value.AuditSuccessOnly);
            writer.WriteNumber("baselineRecordId", value.BaselineRecordId);
            writer.WriteString("capabilityPurpose", value.CapabilityPurpose);
            writer.WriteString(
                "certificateFingerprintSha256",
                value.CertificateFingerprintSha256);
            writer.WriteBoolean(
                "channelLocalServiceReadOnly",
                value.ChannelLocalServiceReadOnly);
            writer.WriteString("checkpoint", value.Checkpoint);
            writer.WriteBoolean(
                "commandChannelEnabled",
                value.CommandChannelEnabled);
            writer.WriteString("expiresAt", value.ExpiresAt);
            writer.WriteString("installedCommit", value.InstalledCommit);
            writer.WriteBoolean(
                "inboundListenerEnabled",
                value.InboundListenerEnabled);
            writer.WriteNumber(
                "maximumEventsRead",
                value.MaximumEventsRead);
            writer.WriteNumber(
                "maximumQueryMilliseconds",
                value.MaximumQueryMilliseconds);
            writer.WriteNumber(
                "maximumTriggerWindowSeconds",
                value.MaximumTriggerWindowSeconds);
            writer.WriteString("nonceBase64", value.NonceBase64);
            writer.WriteBoolean(
                "normalizedResultRequired",
                value.NormalizedResultRequired);
            writer.WriteBoolean("pollingEnabled", value.PollingEnabled);
            writer.WriteString("profile", value.Profile);
            writer.WriteBoolean(
                "rawEventContentRetentionAllowed",
                value.RawEventContentRetentionAllowed);
            writer.WriteString("readinessCheckpoint", value.ReadinessCheckpoint);
            writer.WriteBoolean("readinessVerified", value.ReadinessVerified);
            writer.WriteBoolean("responseActionEnabled", value.ResponseActionEnabled);
            writer.WriteBoolean("retryEnabled", value.RetryEnabled);
            writer.WriteBoolean(
                "runtimeCollectionEnabled",
                value.RuntimeCollectionEnabled);
            writer.WriteNumber("schemaVersion", value.SchemaVersion);
            writer.WriteString("serviceIdentity", value.ServiceIdentity);
            writer.WriteString("serviceName", value.ServiceName);
            writer.WriteString(
                "serviceStartupArgument",
                value.ServiceStartupArgument);
            writer.WriteString("state", value.State);
            writer.WriteBoolean("targetExists", value.TargetExists);
            writer.WriteString("targetProfileId", value.TargetProfileId);
            writer.WriteBoolean("targetReparsePoint", value.TargetReparsePoint);
            writer.WriteBoolean("targetSaclVerified", value.TargetSaclVerified);
            writer.WriteBoolean("targetZeroLength", value.TargetZeroLength);
            writer.WriteBoolean("transportEnabled", value.TransportEnabled);
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(output.ToArray());
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
            return read == spki.Length &&
                signature.Length == 64 &&
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

    private static string FormatUtc(DateTime value) => value.ToString(
        "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
        CultureInfo.InvariantCulture);

    internal static DateTimeOffset ParseUtcOffset(string value) =>
        new(DateTime.ParseExact(
            value,
            "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal));

    private static bool TryUtc(string value, out DateTime parsed)
    {
        parsed = DateTime.MinValue;
        return TimestampPattern().IsMatch(value) && DateTime.TryParseExact(
            value,
            "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out parsed) && parsed.Kind == DateTimeKind.Utc;
    }

    private static InvalidDataException Invalid(string code) => new(code);

    [GeneratedRegex("^[a-f0-9]{40}$", RegexOptions.CultureInvariant)]
    private static partial Regex CommitPattern();

    [GeneratedRegex("^[a-f0-9]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256Pattern();

    [GeneratedRegex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$", RegexOptions.CultureInvariant)]
    private static partial Regex TimestampPattern();
}
