using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WARRoom.WindowsSensor;

public sealed record PendingEndpointBinding(
    int SchemaVersion,
    string Profile,
    string State,
    string MissionId,
    string ConnectorId,
    string EndpointId,
    string EnrollmentChallengeId,
    string CertificateFingerprintSha256,
    string IdentityIssuedAt,
    string IdentityExpiresAt,
    string Provider,
    string Channel,
    string EventFamily,
    IReadOnlyList<string> Fields,
    string FilterHash,
    string CollectorVersion,
    string ServiceSourceCommit,
    bool CollectorEnabled,
    bool TelemetryEnabled,
    bool CommandChannelEnabled);

public sealed record SignedEndpointCapabilityProof(
    int SchemaVersion,
    string MissionId,
    string ConnectorId,
    string EndpointId,
    string CertificateFingerprintSha256,
    string Provider,
    string Channel,
    string EventFamily,
    IReadOnlyList<string> Fields,
    string FilterHash,
    string CollectorVersion,
    CapabilityLoss Loss,
    string Continuity,
    string ContinuousSince,
    string LastSuccessfulReadAt,
    string ObservedAt,
    int FreshnessSeconds,
    string ReportHash,
    string SignatureBase64);

public sealed record CapabilityLoss(string State, int? LostRecordCount);

public sealed record FinalEndpointBinding(
    int SchemaVersion,
    string Profile,
    string State,
    string MissionId,
    string ConnectorId,
    string EndpointId,
    string EnrollmentChallengeId,
    string CertificateFingerprintSha256,
    string IdentityIssuedAt,
    string IdentityExpiresAt,
    string Provider,
    string Channel,
    string EventFamily,
    IReadOnlyList<string> Fields,
    string FilterHash,
    string CollectorVersion,
    string CapabilitySnapshotId,
    string CapabilityReportHash,
    string CapabilityFreshUntil,
    string ServiceSourceCommit,
    bool CollectorEnabled,
    bool TelemetryEnabled,
    bool CommandChannelEnabled);

public static partial class EndpointBindingLifecycle
{
    public const int MaximumDocumentBytes = 32_768;
    public const string PendingProfile = "gate-c0b-pending-binding-v1";
    public const string CandidateProfile = "gate-c0b-identity-binding-candidate-v1";
    public const string FinalInputProfile = "gate-c0b-final-binding-input-v1";
    public const string FinalProfile = "gate-c0b-final-binding-v1";
    public const string Provider = "windows-scm";
    public const string Channel = "system";
    public const string EventFamily = "service-change";
    public const string CollectorVersion = "windows-sensor-0.1.0";
    public const string FilterHash =
        "89d3e1f9a63f38a94c640fb5555e59cd23d74bc5bef77059473c67c3516f3063";
    public const int FreshnessSeconds = 300;

    public static IReadOnlyList<string> Fields { get; } =
        ["action", "actorTrust", "objectClass", "outcome", "subjectClass"];

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private static readonly IReadOnlySet<string> CandidateFields = ExactSet(
        "schemaVersion", "profile", "state", "missionId", "connectorId",
        "endpointId", "enrollmentChallengeId", "certificateFingerprintSha256",
        "identityIssuedAt", "identityExpiresAt", "provider", "channel",
        "eventFamily", "fields", "filterHash", "collectorVersion");
    private static readonly IReadOnlySet<string> PendingFields = CandidateFields
        .Concat(["serviceSourceCommit", "collectorEnabled", "telemetryEnabled",
            "commandChannelEnabled"])
        .ToHashSet(StringComparer.Ordinal);
    private static readonly IReadOnlySet<string> CapabilityFields = ExactSet(
        "schemaVersion", "missionId", "connectorId", "endpointId",
        "certificateFingerprintSha256", "provider", "channel", "eventFamily",
        "fields", "filterHash", "collectorVersion", "loss", "continuity",
        "continuousSince", "lastSuccessfulReadAt", "observedAt",
        "freshnessSeconds", "reportHash", "signatureBase64");
    private static readonly IReadOnlySet<string> FinalInputFields = CandidateFields
        .Where(field => field != "state")
        .Concat(["state", "capabilitySnapshotId", "capabilityReportHash",
            "capabilityFreshUntil"])
        .ToHashSet(StringComparer.Ordinal);
    private static readonly IReadOnlySet<string> FinalFields = FinalInputFields
        .Concat(["serviceSourceCommit", "collectorEnabled", "telemetryEnabled",
            "commandChannelEnabled"])
        .ToHashSet(StringComparer.Ordinal);

    [GeneratedRegex("^[a-f0-9]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256Pattern();
    [GeneratedRegex("^[a-f0-9]{40}$", RegexOptions.CultureInvariant)]
    private static partial Regex CommitPattern();
    [GeneratedRegex("^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$", RegexOptions.CultureInvariant)]
    private static partial Regex MissionPattern();
    [GeneratedRegex("^connector-[a-f0-9-]{36}$", RegexOptions.CultureInvariant)]
    private static partial Regex ConnectorPattern();
    [GeneratedRegex("^endpoint-[a-f0-9-]{36}$", RegexOptions.CultureInvariant)]
    private static partial Regex EndpointPattern();
    [GeneratedRegex("^enrollment-[a-f0-9-]{36}$", RegexOptions.CultureInvariant)]
    private static partial Regex EnrollmentPattern();
    [GeneratedRegex("^capability-[a-f0-9-]{36}$", RegexOptions.CultureInvariant)]
    private static partial Regex CapabilityPattern();
    [GeneratedRegex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$", RegexOptions.CultureInvariant)]
    private static partial Regex TimestampPattern();

    public static PendingEndpointBinding CreatePending(
        string candidateJson,
        SensorIdentityDescriptor identity,
        string serviceSourceCommit,
        DateTime utcNow)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var root = ParseRoot(candidateJson);
        RequireExact(root, CandidateFields, "SENSOR_BINDING_CANDIDATE_FIELDS_INVALID");
        var binding = ReadBinding(root, CandidateProfile, "capability-pending", identity,
            serviceSourceCommit, utcNow);
        return binding;
    }

    public static PendingEndpointBinding ValidatePending(
        string json,
        SensorIdentityDescriptor identity,
        string serviceSourceCommit,
        DateTime utcNow)
    {
        var root = ParseRoot(json);
        RequireExact(root, PendingFields, "SENSOR_BINDING_FIELDS_INVALID");
        if (
            root.GetProperty("collectorEnabled").ValueKind != JsonValueKind.False ||
            root.GetProperty("telemetryEnabled").ValueKind != JsonValueKind.False ||
            root.GetProperty("commandChannelEnabled").ValueKind != JsonValueKind.False)
        {
            throw Invalid("SENSOR_BINDING_AUTHORITY_INVALID");
        }
        return ReadBinding(root, PendingProfile, "coverage-blocked", identity,
            serviceSourceCommit, utcNow);
    }

    public static string SerializePending(PendingEndpointBinding binding) =>
        JsonSerializer.Serialize(binding, JsonOptions);

    public static string SerializeCapabilityProof(SignedEndpointCapabilityProof proof) =>
        JsonSerializer.Serialize(proof, JsonOptions);

    public static FinalEndpointBinding FinalizeBinding(
        string finalInputJson,
        PendingEndpointBinding pending,
        SignedEndpointCapabilityProof proof,
        SensorIdentityDescriptor identity,
        string serviceSourceCommit,
        DateTime utcNow)
    {
        var root = ParseRoot(finalInputJson);
        RequireExact(root, FinalInputFields, "SENSOR_FINAL_BINDING_INPUT_FIELDS_INVALID");
        var suppliedBase = ReadBinding(root, FinalInputProfile, "coverage-blocked",
            identity, serviceSourceCommit, utcNow);
        RequireSameBinding(suppliedBase, pending);
        var capabilityId = Required(root, "capabilitySnapshotId");
        var reportHash = Required(root, "capabilityReportHash");
        var freshUntil = Required(root, "capabilityFreshUntil");
        if (!CapabilityPattern().IsMatch(capabilityId) || reportHash != proof.ReportHash ||
            !TryUtc(freshUntil, out var fresh) ||
            fresh != DateTime.ParseExact(proof.LastSuccessfulReadAt,
                "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal)
                .AddSeconds(FreshnessSeconds) || utcNow >= fresh)
            throw Invalid("SENSOR_FINAL_BINDING_CAPABILITY_INVALID");
        return new FinalEndpointBinding(
            1, FinalProfile, "coverage-blocked", pending.MissionId,
            pending.ConnectorId, pending.EndpointId, pending.EnrollmentChallengeId,
            pending.CertificateFingerprintSha256, pending.IdentityIssuedAt,
            pending.IdentityExpiresAt, Provider, Channel, EventFamily, Fields,
            FilterHash, CollectorVersion, capabilityId, reportHash, freshUntil,
            serviceSourceCommit, false, false, false);
    }

    public static string SerializeFinal(FinalEndpointBinding binding) =>
        JsonSerializer.Serialize(binding, JsonOptions);

    public static FinalEndpointBinding ValidateFinal(
        string finalJson,
        string capabilityProofJson,
        SensorIdentityDescriptor identity,
        string serviceSourceCommit,
        DateTime utcNow)
    {
        var root = ParseRoot(finalJson);
        RequireExact(root, FinalFields, "SENSOR_FINAL_BINDING_FIELDS_INVALID");
        if (root.GetProperty("collectorEnabled").ValueKind != JsonValueKind.False ||
            root.GetProperty("telemetryEnabled").ValueKind != JsonValueKind.False ||
            root.GetProperty("commandChannelEnabled").ValueKind != JsonValueKind.False)
            throw Invalid("SENSOR_BINDING_AUTHORITY_INVALID");
        var baseBinding = ReadBinding(root, FinalProfile, "coverage-blocked",
            identity, serviceSourceCommit, utcNow);
        var proof = ValidateCapabilityProof(
            capabilityProofJson, baseBinding, identity, utcNow,
            requireFreshness: false);
        var capabilityId = Required(root, "capabilitySnapshotId");
        var reportHash = Required(root, "capabilityReportHash");
        var freshUntil = Required(root, "capabilityFreshUntil");
        if (!CapabilityPattern().IsMatch(capabilityId) || reportHash != proof.ReportHash ||
            !TryUtc(freshUntil, out var fresh) ||
            fresh != DateTime.ParseExact(proof.LastSuccessfulReadAt,
                "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal)
                .AddSeconds(FreshnessSeconds))
            throw Invalid("SENSOR_FINAL_BINDING_CAPABILITY_INVALID");
        return JsonSerializer.Deserialize<FinalEndpointBinding>(finalJson, JsonOptions) ??
            throw Invalid("SENSOR_FINAL_BINDING_INPUT_INVALID");
    }

    public static SignedEndpointCapabilityProof CreateCapabilityProof(
        PendingEndpointBinding binding,
        ISensorIdentitySigner identity,
        ISensorServiceIdentity serviceIdentity,
        IGenuineScmEventReader reader,
        DateTime utcNow,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(serviceIdentity);
        ArgumentNullException.ThrowIfNull(reader);
        if (
            utcNow.Kind != DateTimeKind.Utc ||
            serviceIdentity.CurrentSid != NativeKeyAccessPolicy.LocalServiceSid ||
            binding.CertificateFingerprintSha256 != identity.Descriptor.CertificateFingerprintSha256)
        {
            throw Invalid("SENSOR_CAPABILITY_PROOF_BOUNDARY_INVALID");
        }
        cancellationToken.ThrowIfCancellationRequested();
        var metadata = reader.ReadOne(cancellationToken) ??
            throw Invalid("SENSOR_CAPABILITY_READ_NOT_PROVED");
        if (
            metadata.ProviderName != NativeGenuineScmEventReader.ProviderName ||
            metadata.EventId != NativeGenuineScmEventReader.EventId ||
            metadata.Level != NativeGenuineScmEventReader.Level ||
            metadata.RecordId < 1)
        {
            throw Invalid("SENSOR_CAPABILITY_EVENT_METADATA_INVALID");
        }

        var observedAt = utcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
        var core = CapabilityCore(binding, observedAt);
        var canonical = CanonicalCapabilityCore(core);
        var reportHash = Sha256(canonical);
        var signature = identity.SignUtf8Payload(canonical);
        if (!Verify(canonical, signature, identity.Descriptor))
        {
            throw Invalid("SENSOR_CAPABILITY_SIGNATURE_INVALID");
        }
        return new SignedEndpointCapabilityProof(
            core.SchemaVersion, core.MissionId, core.ConnectorId, core.EndpointId,
            core.CertificateFingerprintSha256, core.Provider, core.Channel,
            core.EventFamily, core.Fields, core.FilterHash, core.CollectorVersion,
            core.Loss, core.Continuity, core.ContinuousSince,
            core.LastSuccessfulReadAt, core.ObservedAt, core.FreshnessSeconds,
            reportHash, signature);
    }

    public static SignedEndpointCapabilityProof ValidateCapabilityProof(
        string json,
        PendingEndpointBinding binding,
        SensorIdentityDescriptor identity,
        DateTime utcNow,
        bool requireFreshness = true)
    {
        var root = ParseRoot(json);
        RequireExact(root, CapabilityFields, "SENSOR_CAPABILITY_FIELDS_INVALID");
        var proof = JsonSerializer.Deserialize<SignedEndpointCapabilityProof>(json, JsonOptions) ??
            throw Invalid("SENSOR_CAPABILITY_INPUT_INVALID");
        var core = CapabilityCore(binding, proof.ObservedAt);
        if (
            proof.SchemaVersion != core.SchemaVersion || proof.MissionId != core.MissionId ||
            proof.ConnectorId != core.ConnectorId || proof.EndpointId != core.EndpointId ||
            proof.CertificateFingerprintSha256 != core.CertificateFingerprintSha256 ||
            proof.Provider != core.Provider || proof.Channel != core.Channel ||
            proof.EventFamily != core.EventFamily || !proof.Fields.SequenceEqual(core.Fields) ||
            proof.FilterHash != core.FilterHash || proof.CollectorVersion != core.CollectorVersion ||
            proof.Loss != core.Loss || proof.Continuity != core.Continuity ||
            proof.ContinuousSince != proof.ObservedAt ||
            proof.LastSuccessfulReadAt != proof.ObservedAt ||
            proof.FreshnessSeconds != FreshnessSeconds ||
            !Sha256Pattern().IsMatch(proof.ReportHash) ||
            Sha256(CanonicalCapabilityCore(core)) != proof.ReportHash ||
            !Verify(CanonicalCapabilityCore(core), proof.SignatureBase64, identity) ||
            !TryUtc(proof.ObservedAt, out var observed) ||
            observed > utcNow.AddSeconds(30) ||
            (requireFreshness && utcNow >= observed.AddSeconds(FreshnessSeconds)))
        {
            throw Invalid("SENSOR_CAPABILITY_PROOF_INVALID");
        }
        return proof;
    }

    public static bool HasFinalProfile(string json)
    {
        var root = ParseRoot(json);
        return Required(root, "profile") == FinalProfile;
    }

    private static PendingEndpointBinding ReadBinding(
        JsonElement root, string profile, string state,
        SensorIdentityDescriptor identity, string commit, DateTime utcNow)
    {
        if (utcNow.Kind != DateTimeKind.Utc || !CommitPattern().IsMatch(commit))
            throw Invalid("SENSOR_BINDING_CONTEXT_INVALID");
        if (!root.TryGetProperty("schemaVersion", out var schemaVersion) ||
            schemaVersion.ValueKind != JsonValueKind.Number ||
            !schemaVersion.TryGetInt32(out var schema) || schema != 1 ||
            !root.TryGetProperty("fields", out var fieldValues) ||
            fieldValues.ValueKind != JsonValueKind.Array)
            throw Invalid("SENSOR_BINDING_VALUE_INVALID");
        var fields = fieldValues.EnumerateArray()
            .Select(item => item.ValueKind == JsonValueKind.String
                ? item.GetString() ?? ""
                : "").ToArray();
        var issued = Required(root, "identityIssuedAt");
        var expires = Required(root, "identityExpiresAt");
        if (
            Required(root, "profile") != profile || Required(root, "state") != state ||
            !MissionPattern().IsMatch(Required(root, "missionId")) ||
            !ConnectorPattern().IsMatch(Required(root, "connectorId")) ||
            !EndpointPattern().IsMatch(Required(root, "endpointId")) ||
            !EnrollmentPattern().IsMatch(Required(root, "enrollmentChallengeId")) ||
            Required(root, "certificateFingerprintSha256") != identity.CertificateFingerprintSha256 ||
            Required(root, "provider") != Provider || Required(root, "channel") != Channel ||
            Required(root, "eventFamily") != EventFamily || !fields.SequenceEqual(Fields) ||
            Required(root, "filterHash") != FilterHash ||
            Required(root, "collectorVersion") != CollectorVersion ||
            !TryUtc(issued, out var issuedAt) || !TryUtc(expires, out var expiresAt) ||
            issuedAt > utcNow.AddSeconds(30) || expiresAt <= utcNow || expiresAt <= issuedAt ||
            (profile is PendingProfile or FinalProfile &&
                Required(root, "serviceSourceCommit") != commit))
        {
            throw Invalid("SENSOR_BINDING_VALUE_INVALID");
        }
        return new PendingEndpointBinding(
            1, PendingProfile, "coverage-blocked", Required(root, "missionId"),
            Required(root, "connectorId"), Required(root, "endpointId"),
            Required(root, "enrollmentChallengeId"), identity.CertificateFingerprintSha256,
            issued, expires, Provider, Channel, EventFamily, Fields, FilterHash,
            CollectorVersion, commit, false, false, false);
    }

    private static void RequireSameBinding(
        PendingEndpointBinding left, PendingEndpointBinding right)
    {
        if (
            left.SchemaVersion != right.SchemaVersion ||
            left.MissionId != right.MissionId ||
            left.ConnectorId != right.ConnectorId ||
            left.EndpointId != right.EndpointId ||
            left.EnrollmentChallengeId != right.EnrollmentChallengeId ||
            left.CertificateFingerprintSha256 != right.CertificateFingerprintSha256 ||
            left.IdentityIssuedAt != right.IdentityIssuedAt ||
            left.IdentityExpiresAt != right.IdentityExpiresAt ||
            left.Provider != right.Provider || left.Channel != right.Channel ||
            left.EventFamily != right.EventFamily ||
            !left.Fields.SequenceEqual(right.Fields) ||
            left.FilterHash != right.FilterHash ||
            left.CollectorVersion != right.CollectorVersion ||
            left.ServiceSourceCommit != right.ServiceSourceCommit ||
            left.CollectorEnabled != right.CollectorEnabled ||
            left.TelemetryEnabled != right.TelemetryEnabled ||
            left.CommandChannelEnabled != right.CommandChannelEnabled)
            throw Invalid("SENSOR_FINAL_BINDING_IDENTITY_MISMATCH");
    }

    private static SignedEndpointCapabilityProof CapabilityCore(
        PendingEndpointBinding binding, string observedAt) =>
        new(1, binding.MissionId, binding.ConnectorId, binding.EndpointId,
            binding.CertificateFingerprintSha256, Provider, Channel, EventFamily,
            Fields, FilterHash, CollectorVersion, new("unknown", null), "unknown",
            observedAt, observedAt, observedAt, FreshnessSeconds, "", "");

    private static string CanonicalCapabilityCore(SignedEndpointCapabilityProof core)
    {
        using var output = new MemoryStream();
        using (var writer = new Utf8JsonWriter(output, new JsonWriterOptions
        { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
        {
            writer.WriteStartObject();
            writer.WriteString("certificateFingerprintSha256", core.CertificateFingerprintSha256);
            writer.WriteString("channel", core.Channel);
            writer.WriteString("collectorVersion", core.CollectorVersion);
            writer.WriteString("connectorId", core.ConnectorId);
            writer.WriteString("continuity", core.Continuity);
            writer.WriteString("continuousSince", core.ContinuousSince);
            writer.WriteString("endpointId", core.EndpointId);
            writer.WriteString("eventFamily", core.EventFamily);
            writer.WritePropertyName("fields"); writer.WriteStartArray();
            foreach (var field in core.Fields) writer.WriteStringValue(field);
            writer.WriteEndArray();
            writer.WriteString("filterHash", core.FilterHash);
            writer.WriteNumber("freshnessSeconds", core.FreshnessSeconds);
            writer.WriteString("lastSuccessfulReadAt", core.LastSuccessfulReadAt);
            writer.WritePropertyName("loss"); writer.WriteStartObject();
            writer.WriteNull("lostRecordCount"); writer.WriteString("state", "unknown"); writer.WriteEndObject();
            writer.WriteString("missionId", core.MissionId);
            writer.WriteString("observedAt", core.ObservedAt);
            writer.WriteString("provider", core.Provider);
            writer.WriteNumber("schemaVersion", 1);
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(output.ToArray());
    }

    private static bool Verify(string payload, string signatureBase64, SensorIdentityDescriptor identity)
    {
        try
        {
            var spki = Convert.FromBase64String(identity.PublicKeySpkiBase64);
            var signature = Convert.FromBase64String(signatureBase64);
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(spki, out var read);
            return read == spki.Length && signature.Length == 64 &&
                verifier.VerifyData(Encoding.UTF8.GetBytes(payload), signature,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception error) when (error is FormatException or CryptographicException)
        {
            return false;
        }
    }

    private static JsonElement ParseRoot(string json)
    {
        if (string.IsNullOrWhiteSpace(json) || Encoding.UTF8.GetByteCount(json) > MaximumDocumentBytes)
            throw Invalid("SENSOR_BINDING_INPUT_INVALID");
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions
            { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 6 });
            return document.RootElement.Clone();
        }
        catch (JsonException error)
        {
            throw new InvalidDataException("SENSOR_BINDING_INPUT_INVALID", error);
        }
    }

    private static void RequireExact(JsonElement value, IReadOnlySet<string> expected, string code)
    {
        if (value.ValueKind != JsonValueKind.Object) throw Invalid(code);
        var actual = value.EnumerateObject().Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);
        if (actual.Count != value.EnumerateObject().Count() || !actual.SetEquals(expected))
            throw Invalid(code);
    }

    private static string Required(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String)
            throw Invalid("SENSOR_BINDING_VALUE_INVALID");
        return value.GetString() ?? throw Invalid("SENSOR_BINDING_VALUE_INVALID");
    }

    private static bool TryUtc(string value, out DateTime parsed)
    {
        parsed = DateTime.MinValue;
        return TimestampPattern().IsMatch(value) && DateTime.TryParseExact(
            value, "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out parsed) &&
            parsed.Kind == DateTimeKind.Utc;
    }

    private static string Sha256(string value) => Convert.ToHexString(
        SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    private static InvalidDataException Invalid(string code) => new(code);
    private static IReadOnlySet<string> ExactSet(params string[] values) =>
        values.ToHashSet(StringComparer.Ordinal);
}

public interface IEndpointBindingStore
{
    string? ReadBinding();
    string? ReadCapabilityProof();
    void WriteCapabilityProof(string json);
}

public sealed class FixedEndpointBindingStore : IEndpointBindingStore
{
    public string? ReadBinding() => ReadOptional(
        SensorBoundary.EndpointBindingPath,
        EndpointBindingLifecycle.MaximumDocumentBytes);

    public string? ReadCapabilityProof() => ReadOptional(
        SensorBoundary.LocalCapabilityProofPath,
        EndpointBindingLifecycle.MaximumDocumentBytes);

    public void WriteCapabilityProof(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        ValidateRegularFile(SensorBoundary.LocalCapabilityProofPath);
        var bytes = Encoding.UTF8.GetBytes(json);
        if (bytes.Length > EndpointBindingLifecycle.MaximumDocumentBytes)
            throw new InvalidDataException("SENSOR_CAPABILITY_FILE_SIZE_INVALID");
        try
        {
            using var output = LocalProofNativeFileAccess.OpenExistingForOverwrite(
                SensorBoundary.LocalCapabilityProofPath);
            output.SetLength(0);
            output.Write(bytes);
            output.Flush(flushToDisk: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static string? ReadOptional(string path, int maximumBytes)
    {
        if (!File.Exists(path)) return null;
        ValidateRegularFile(path);
        var length = new FileInfo(path).Length;
        if (length == 0) return null;
        if (length > maximumBytes)
            throw new InvalidDataException("SENSOR_BINDING_FILE_SIZE_INVALID");
        return File.ReadAllText(path, Encoding.UTF8);
    }

    private static void ValidateRegularFile(string path)
    {
        if (!File.Exists(path) ||
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("SENSOR_BINDING_STATE_FILE_INVALID");
    }
}

public interface IInstallManifestBindingReader
{
    InstallManifestBinding Read();
}

public sealed record InstallManifestBinding(
    string Commit,
    string Fingerprint,
    string BindingDescriptorSha256);

public sealed class FixedInstallManifestBindingReader : IInstallManifestBindingReader
{
    public InstallManifestBinding Read()
    {
        var path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "WAR-R00M", "Windows Sensor", "install-manifest.json");
        if (!File.Exists(path) ||
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0 ||
            new FileInfo(path).Length is < 1 or > 1_048_576)
            throw new IOException("SENSOR_INSTALL_MANIFEST_INVALID");
        using var document = JsonDocument.Parse(File.ReadAllText(path, Encoding.UTF8),
            new JsonDocumentOptions
            { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 8 });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("SENSOR_INSTALL_MANIFEST_BINDING_INVALID");
        var commit = UniqueString(root, "commit");
        var fingerprint = UniqueString(root, "identityFingerprintSha256");
        var bindingHash = UniqueString(root, "bindingDescriptorSha256");
        if (!Regex.IsMatch(commit, "^[a-f0-9]{40}$", RegexOptions.CultureInvariant) ||
            !Regex.IsMatch(fingerprint, "^[a-f0-9]{64}$", RegexOptions.CultureInvariant) ||
            !Regex.IsMatch(bindingHash, "^[a-f0-9]{64}$", RegexOptions.CultureInvariant))
            throw new InvalidDataException("SENSOR_INSTALL_MANIFEST_BINDING_INVALID");
        var bindingPath = SensorBoundary.EndpointBindingPath;
        if (!File.Exists(bindingPath) ||
            (File.GetAttributes(bindingPath) & FileAttributes.ReparsePoint) != 0 ||
            new FileInfo(bindingPath).Length > EndpointBindingLifecycle.MaximumDocumentBytes)
            throw new IOException("SENSOR_BINDING_STATE_FILE_INVALID");
        var actualHash = Convert.ToHexString(
            SHA256.HashData(File.ReadAllBytes(bindingPath))).ToLowerInvariant();
        if (actualHash != bindingHash)
            throw new InvalidDataException("SENSOR_BINDING_MANIFEST_HASH_INVALID");
        return new(commit, fingerprint, bindingHash);
    }

    private static string UniqueString(JsonElement root, string name)
    {
        var values = root.EnumerateObject().Where(property => property.NameEquals(name)).ToArray();
        if (values.Length != 1 || values[0].Value.ValueKind != JsonValueKind.String)
            throw new InvalidDataException("SENSOR_INSTALL_MANIFEST_BINDING_INVALID");
        return values[0].Value.GetString() ??
            throw new InvalidDataException("SENSOR_INSTALL_MANIFEST_BINDING_INVALID");
    }
}

public sealed class EndpointCapabilityProofWorker(
    ISensorIdentitySigner identity,
    ISensorServiceIdentity serviceIdentity,
    IGenuineScmEventReader reader,
    IEndpointBindingStore store,
    IInstallManifestBindingReader manifestReader,
    TimeProvider timeProvider,
    ILogger<EndpointCapabilityProofWorker> logger) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var bindingJson = store.ReadBinding();
        if (bindingJson is null)
        {
            logger.LogInformation(
                "WAR-R00M Gate C0b binding absent; capability writer stayed disabled.");
            return Task.CompletedTask;
        }
        var manifest = manifestReader.Read();
        if (manifest.Fingerprint != identity.Descriptor.CertificateFingerprintSha256)
            throw new InvalidDataException("SENSOR_BINDING_MANIFEST_IDENTITY_MISMATCH");
        var now = timeProvider.GetUtcNow().UtcDateTime;
        var existing = store.ReadCapabilityProof();
        if (EndpointBindingLifecycle.HasFinalProfile(bindingJson))
        {
            if (existing is null)
                throw new InvalidDataException("SENSOR_FINAL_BINDING_PROOF_MISSING");
            _ = EndpointBindingLifecycle.ValidateFinal(
                bindingJson, existing, identity.Descriptor, manifest.Commit, now);
            logger.LogInformation(
                "WAR-R00M Gate C0b final blocked binding verified; no event read, telemetry or transport performed.");
            return Task.CompletedTask;
        }
        var binding = EndpointBindingLifecycle.ValidatePending(
            bindingJson, identity.Descriptor, manifest.Commit, now);
        if (existing is not null)
        {
            _ = EndpointBindingLifecycle.ValidateCapabilityProof(
                existing, binding, identity.Descriptor, now,
                requireFreshness: false);
            logger.LogInformation(
                "WAR-R00M Gate C0b capability proof already verified; no event read or rewrite performed.");
            return Task.CompletedTask;
        }
        var proof = EndpointBindingLifecycle.CreateCapabilityProof(
            binding, identity, serviceIdentity, reader, now, cancellationToken);
        store.WriteCapabilityProof(
            EndpointBindingLifecycle.SerializeCapabilityProof(proof));
        logger.LogInformation(
            "WAR-R00M Gate C0b wrote one signed read-access proof with unknown loss and continuity; telemetry and transport remain disabled.");
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
