using System.Buffers.Binary;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WARRoom.WindowsSensor;

public sealed record GenuineScmEventMetadata(
    string ProviderName,
    int EventId,
    int Level,
    DateTimeOffset TimeCreated,
    long RecordId);

public interface IGenuineScmEventReader
{
    GenuineScmEventMetadata? ReadOne(CancellationToken cancellationToken);
}

public sealed class NativeGenuineScmEventReader : IGenuineScmEventReader
{
    public const string LogName = "System";
    public const string ProviderName = "Service Control Manager";
    public const int EventId = 7045;
    public const int Level = 4;
    public const int MaximumRecords = 1;
    public const int MaximumReadMilliseconds = 2_000;
    public const string FixedQuery =
        "*[System[Provider[@Name='Service Control Manager'] and EventID=7045 and Level=4]]";

    public GenuineScmEventMetadata? ReadOne(CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var query = new EventLogQuery(LogName, PathType.LogName, FixedQuery)
            {
                ReverseDirection = true,
                TolerateQueryErrors = false
            };
            using var reader = new EventLogReader(query);
            reader.BatchSize = MaximumRecords;
            using var record = reader.ReadEvent(
                TimeSpan.FromMilliseconds(MaximumReadMilliseconds));
            cancellationToken.ThrowIfCancellationRequested();
            if (record is null)
            {
                return null;
            }

            var providerName = record.ProviderName;
            var level = record.Level;
            var timeCreated = record.TimeCreated;
            var recordId = record.RecordId;
            if (
                providerName is null ||
                level is null ||
                timeCreated is null ||
                recordId is null)
            {
                throw new InvalidDataException("SENSOR_GENUINE_EVENT_METADATA_MISSING");
            }
            return new GenuineScmEventMetadata(
                providerName,
                record.Id,
                level.Value,
                new DateTimeOffset(timeCreated.Value),
                recordId.Value);
        }
        catch (EventLogNotFoundException)
        {
            throw new InvalidOperationException("SENSOR_GENUINE_EVENT_LOG_NOT_FOUND");
        }
        catch (UnauthorizedAccessException)
        {
            throw new InvalidOperationException("SENSOR_GENUINE_EVENT_ACCESS_DENIED");
        }
        catch (SecurityException)
        {
            throw new InvalidOperationException("SENSOR_GENUINE_EVENT_ACCESS_DENIED");
        }
        catch (EventLogException)
        {
            throw new InvalidOperationException("SENSOR_GENUINE_EVENT_QUERY_FAILED");
        }
    }
}

public sealed record GenuineScmProofDocument(
    int SchemaVersion,
    string ProofMode,
    string GeneratedAtUtc,
    string ManifestGeneratedAtUtc,
    string ServiceSid,
    string CertificateFingerprintSha256,
    bool GenuineEventRead,
    bool RawEventContentRead,
    bool EventReaderEnabled,
    int EventsRead,
    bool NetworkTransportEnabled,
    bool InboundListenerEnabled,
    bool PollingEnabled,
    bool CommandChannelEnabled,
    LocalSyntheticSignedBatch Batch);

public sealed record GenuineScmProofValidation(
    string CertificateFingerprintSha256,
    string GeneratedAtUtc,
    string ManifestGeneratedAtUtc,
    string OccurredAtUtc,
    string SourceRecordIdHash,
    string BatchHash,
    int BatchCount,
    int FactCount,
    int EventsRead,
    bool GenuineEventRead,
    bool RawEventContentRead,
    bool EventReaderEnabled,
    bool NetworkTransportEnabled,
    bool InboundListenerEnabled,
    bool PollingEnabled,
    bool CommandChannelEnabled);

public static class GenuineScmBatchProof
{
    public const string ProofMode = "local-genuine-gate-b1";
    public const int MaximumProofBytes = 32_768;
    public const int SaltBytes = 32;
    public const long MaximumJsonInteger = 9_007_199_254_740_991;

    private const string MissionId = "local-gate-b1-genuine";
    private const string ConnectorId =
        "connector-11111111-1111-4111-8111-111111111111";
    private const string EndpointId =
        "endpoint-22222222-2222-4222-8222-222222222222";
    private const string CapabilityId =
        "capability-44444444-4444-4444-8444-444444444444";
    private const string BootId = "boot-local-gate-b1-one-shot";
    private const string Provider = "windows-scm";
    private const string Channel = "system";
    private const string EventFamily = "service-change";
    private const string HashDomain = "WAR-R00M.GateB1.SourceRecordHash.v1";
    private const string FilterDomain = "WAR-R00M.GateB1.SCM.7045.Level4.v1";

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    private static readonly IReadOnlySet<string> ProofFields = ExactSet(
        "schemaVersion", "proofMode", "generatedAtUtc",
        "manifestGeneratedAtUtc", "serviceSid",
        "certificateFingerprintSha256", "genuineEventRead",
        "rawEventContentRead", "eventReaderEnabled", "eventsRead",
        "networkTransportEnabled", "inboundListenerEnabled", "pollingEnabled",
        "commandChannelEnabled", "batch");

    private static readonly IReadOnlySet<string> BatchFields = ExactSet(
        "batchSequence", "previousBatchHash", "canonicalPayload", "batchHash",
        "signatureBase64");

    public static GenuineScmProofDocument? Create(
        ISensorIdentitySigner identity,
        ISensorServiceIdentity serviceIdentity,
        IGenuineScmEventReader reader,
        byte[] sourceSalt,
        DateTime manifestGeneratedAtUtc,
        DateTime startupCapturedAtUtc,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(serviceIdentity);
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(sourceSalt);
        if (
            sourceSalt.Length != SaltBytes ||
            manifestGeneratedAtUtc.Kind != DateTimeKind.Utc ||
            startupCapturedAtUtc.Kind != DateTimeKind.Utc ||
            manifestGeneratedAtUtc > startupCapturedAtUtc ||
            !StringComparer.Ordinal.Equals(
                serviceIdentity.CurrentSid,
                NativeKeyAccessPolicy.LocalServiceSid))
        {
            throw new InvalidOperationException("SENSOR_GENUINE_PROOF_BOUNDARY_INVALID");
        }

        cancellationToken.ThrowIfCancellationRequested();
        var metadata = reader.ReadOne(cancellationToken);
        if (metadata is null)
        {
            return null;
        }
        if (
            metadata.TimeCreated.ToUniversalTime() <
            new DateTimeOffset(manifestGeneratedAtUtc))
        {
            return null;
        }
        var occurredAtUtc = ValidateMetadata(
            metadata,
            manifestGeneratedAtUtc,
            startupCapturedAtUtc);
        var sourceHash = SourceRecordIdHash(metadata, occurredAtUtc, sourceSalt);
        var coreJson = BuildCore(
            identity.Descriptor.CertificateFingerprintSha256,
            occurredAtUtc,
            sourceHash);
        var core = NativeTelemetryFactBatch.ParseCore(coreJson);
        core.ValidateContinuity(null);
        var signing = core.Sign(identity);
        var batch = new LocalSyntheticSignedBatch(
            0,
            null,
            signing.CanonicalPayload,
            signing.BatchHash,
            signing.SignatureBase64);
        var proof = new GenuineScmProofDocument(
            1,
            ProofMode,
            startupCapturedAtUtc.ToString("O"),
            manifestGeneratedAtUtc.ToString("O"),
            NativeKeyAccessPolicy.LocalServiceSid,
            identity.Descriptor.CertificateFingerprintSha256,
            true,
            false,
            true,
            1,
            false,
            false,
            false,
            false,
            batch);
        _ = Validate(Serialize(proof), identity);
        return proof;
    }

    public static string Serialize(GenuineScmProofDocument proof)
    {
        ArgumentNullException.ThrowIfNull(proof);
        var json = JsonSerializer.Serialize(proof, SerializerOptions);
        if (Encoding.UTF8.GetByteCount(json) > MaximumProofBytes)
        {
            throw new InvalidDataException("SENSOR_GENUINE_PROOF_SIZE_INVALID");
        }
        return json;
    }

    public static GenuineScmProofValidation Validate(
        string json,
        ISensorIdentitySigner identity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        ArgumentNullException.ThrowIfNull(identity);
        if (Encoding.UTF8.GetByteCount(json) > MaximumProofBytes)
        {
            throw new InvalidDataException("SENSOR_GENUINE_PROOF_SIZE_INVALID");
        }
        using var parsed = JsonDocument.Parse(
            json,
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 20
            });
        RequireExactProperties(
            parsed.RootElement,
            ProofFields,
            "SENSOR_GENUINE_PROOF_FIELDS_INVALID");
        RequireExactProperties(
            parsed.RootElement.GetProperty("batch"),
            BatchFields,
            "SENSOR_GENUINE_PROOF_BATCH_FIELDS_INVALID");
        var proof = JsonSerializer.Deserialize<GenuineScmProofDocument>(
            json,
            SerializerOptions) ??
            throw new InvalidDataException("SENSOR_GENUINE_PROOF_INVALID");
        if (
            proof.SchemaVersion != 1 ||
            !StringComparer.Ordinal.Equals(proof.ProofMode, ProofMode) ||
            !StringComparer.Ordinal.Equals(
                proof.ServiceSid,
                NativeKeyAccessPolicy.LocalServiceSid) ||
            !StringComparer.Ordinal.Equals(
                proof.CertificateFingerprintSha256,
                identity.Descriptor.CertificateFingerprintSha256) ||
            !proof.GenuineEventRead ||
            proof.RawEventContentRead ||
            !proof.EventReaderEnabled ||
            proof.EventsRead != 1 ||
            proof.NetworkTransportEnabled ||
            proof.InboundListenerEnabled ||
            proof.PollingEnabled ||
            proof.CommandChannelEnabled ||
            !TryParseUtc(proof.GeneratedAtUtc, out var generatedAt) ||
            !TryParseUtc(
                proof.ManifestGeneratedAtUtc,
                out var manifestGeneratedAt) ||
            generatedAt < manifestGeneratedAt)
        {
            throw new InvalidDataException("SENSOR_GENUINE_PROOF_INVALID");
        }

        var batch = proof.Batch;
        if (batch.BatchSequence != 0 || batch.PreviousBatchHash is not null)
        {
            throw new InvalidDataException("SENSOR_GENUINE_PROOF_BATCH_INVALID");
        }
        var core = NativeTelemetryFactBatch.ParseCore(batch.CanonicalPayload);
        core.ValidateContinuity(null);
        if (
            !StringComparer.Ordinal.Equals(
                batch.CanonicalPayload,
                core.CanonicalPayload()) ||
            !StringComparer.Ordinal.Equals(
                batch.BatchHash,
                core.BatchHash()) ||
            !VerifySignature(
                batch.CanonicalPayload,
                batch.SignatureBase64,
                identity))
        {
            throw new InvalidDataException("SENSOR_GENUINE_PROOF_BATCH_INVALID");
        }

        using var payload = JsonDocument.Parse(batch.CanonicalPayload);
        var root = payload.RootElement;
        if (
            root.GetProperty("schemaVersion").GetInt32() != 1 ||
            root.GetProperty("missionId").GetString() != MissionId ||
            root.GetProperty("connectorId").GetString() != ConnectorId ||
            root.GetProperty("endpointId").GetString() != EndpointId ||
            root.GetProperty("certificateFingerprintSha256").GetString() !=
                proof.CertificateFingerprintSha256 ||
            root.GetProperty("capabilitySnapshotId").GetString() != CapabilityId ||
            root.GetProperty("bootId").GetString() != BootId ||
            root.GetProperty("batchSequence").GetInt64() != 0 ||
            root.GetProperty("previousBatchHash").ValueKind != JsonValueKind.Null ||
            root.GetProperty("provider").GetString() != Provider ||
            root.GetProperty("channel").GetString() != Channel ||
            root.GetProperty("eventFamily").GetString() != EventFamily ||
            root.GetProperty("filterHash").GetString() != Sha256(FilterDomain))
        {
            throw new InvalidDataException("SENSOR_GENUINE_PROOF_CORE_INVALID");
        }
        var facts = root.GetProperty("facts");
        if (facts.GetArrayLength() != 1)
        {
            throw new InvalidDataException("SENSOR_GENUINE_PROOF_FACT_INVALID");
        }
        var fact = facts[0];
        var occurredAtText = fact.GetProperty("occurredAt").GetString() ?? "";
        var sourceHash = fact.GetProperty("sourceRecordIdHash").GetString() ?? "";
        if (
            !TryParseUtc(occurredAtText, out var occurredAt) ||
            occurredAt < manifestGeneratedAt ||
            occurredAt > generatedAt.AddSeconds(5) ||
            sourceHash.Length != 64 ||
            !sourceHash.All(IsLowerHex) ||
            fact.GetProperty("factId").GetString() !=
                $"fact-local-gate-b1-{sourceHash[..32]}")
        {
            throw new InvalidDataException("SENSOR_GENUINE_PROOF_FACT_INVALID");
        }
        var fields = fact.GetProperty("fields");
        RequireExactProperties(
            fields,
            ExactSet("actorTrust", "action", "subjectClass", "objectClass", "outcome"),
            "SENSOR_GENUINE_PROOF_FACT_FIELDS_INVALID");
        if (
            fields.GetProperty("actorTrust").GetString() != "unknown" ||
            fields.GetProperty("action").GetString() != "create" ||
            fields.GetProperty("subjectClass").GetString() != "other" ||
            fields.GetProperty("objectClass").GetString() != "service" ||
            fields.GetProperty("outcome").GetString() != "unknown")
        {
            throw new InvalidDataException("SENSOR_GENUINE_PROOF_FACT_FIELDS_INVALID");
        }
        return new GenuineScmProofValidation(
            proof.CertificateFingerprintSha256,
            proof.GeneratedAtUtc,
            proof.ManifestGeneratedAtUtc,
            occurredAtText,
            sourceHash,
            batch.BatchHash,
            1,
            1,
            proof.EventsRead,
            proof.GenuineEventRead,
            proof.RawEventContentRead,
            proof.EventReaderEnabled,
            proof.NetworkTransportEnabled,
            proof.InboundListenerEnabled,
            proof.PollingEnabled,
            proof.CommandChannelEnabled);
    }

    public static GenuineScmProofValidation ValidateForManifest(
        string json,
        ISensorIdentitySigner identity,
        DateTime currentManifestGeneratedAtUtc)
    {
        if (currentManifestGeneratedAtUtc.Kind != DateTimeKind.Utc)
        {
            throw new InvalidDataException(
                "SENSOR_GENUINE_PROOF_MANIFEST_MISMATCH");
        }
        var validation = Validate(json, identity);
        if (
            validation.ManifestGeneratedAtUtc !=
            currentManifestGeneratedAtUtc.ToString("O"))
        {
            throw new InvalidDataException(
                "SENSOR_GENUINE_PROOF_MANIFEST_MISMATCH");
        }
        return validation;
    }

    public static string SourceRecordIdHash(
        GenuineScmEventMetadata metadata,
        string normalizedOccurredAtUtc,
        byte[] sourceSalt)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentException.ThrowIfNullOrWhiteSpace(normalizedOccurredAtUtc);
        ArgumentNullException.ThrowIfNull(sourceSalt);
        if (sourceSalt.Length != SaltBytes)
        {
            throw new InvalidDataException("SENSOR_GENUINE_SOURCE_SALT_INVALID");
        }
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        AppendField(hash, Encoding.UTF8.GetBytes(HashDomain));
        AppendField(hash, sourceSalt);
        foreach (var value in new[]
        {
            NativeGenuineScmEventReader.LogName,
            metadata.ProviderName,
            metadata.EventId.ToString(CultureInfo.InvariantCulture),
            metadata.Level.ToString(CultureInfo.InvariantCulture),
            metadata.RecordId.ToString(CultureInfo.InvariantCulture),
            normalizedOccurredAtUtc
        })
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            try
            {
                AppendField(hash, bytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private static string ValidateMetadata(
        GenuineScmEventMetadata metadata,
        DateTime manifestGeneratedAtUtc,
        DateTime startupCapturedAtUtc)
    {
        var occurredAt = metadata.TimeCreated.ToUniversalTime();
        if (
            metadata.ProviderName != NativeGenuineScmEventReader.ProviderName ||
            metadata.EventId != NativeGenuineScmEventReader.EventId ||
            metadata.Level != NativeGenuineScmEventReader.Level ||
            metadata.RecordId is < 1 or > MaximumJsonInteger ||
            occurredAt < new DateTimeOffset(manifestGeneratedAtUtc) ||
            occurredAt > new DateTimeOffset(startupCapturedAtUtc.AddSeconds(5)))
        {
            throw new InvalidDataException("SENSOR_GENUINE_EVENT_METADATA_INVALID");
        }
        return occurredAt.UtcDateTime.ToString("O");
    }

    private static string BuildCore(
        string fingerprint,
        string occurredAtUtc,
        string sourceRecordIdHash)
    {
        var core = new
        {
            schemaVersion = 1,
            missionId = MissionId,
            connectorId = ConnectorId,
            endpointId = EndpointId,
            certificateFingerprintSha256 = fingerprint,
            capabilitySnapshotId = CapabilityId,
            bootId = BootId,
            batchSequence = 0,
            previousBatchHash = (string?)null,
            provider = Provider,
            channel = Channel,
            eventFamily = EventFamily,
            filterHash = Sha256(FilterDomain),
            facts = new[]
            {
                new
                {
                    factId = $"fact-local-gate-b1-{sourceRecordIdHash[..32]}",
                    occurredAt = occurredAtUtc,
                    sourceRecordIdHash,
                    fields = new
                    {
                        actorTrust = "unknown",
                        action = "create",
                        subjectClass = "other",
                        objectClass = "service",
                        outcome = "unknown"
                    }
                }
            }
        };
        return JsonSerializer.Serialize(core, SerializerOptions);
    }

    private static void AppendField(IncrementalHash hash, byte[] value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, value.Length);
        hash.AppendData(length);
        hash.AppendData(value);
    }

    private static bool VerifySignature(
        string payload,
        string signatureBase64,
        ISensorIdentitySigner identity)
    {
        try
        {
            var spki = Convert.FromBase64String(
                identity.Descriptor.PublicKeySpkiBase64);
            var signature = Convert.FromBase64String(signatureBase64);
            var bytes = Encoding.UTF8.GetBytes(payload);
            try
            {
                var fingerprint = Convert.ToHexString(SHA256.HashData(spki))
                    .ToLowerInvariant();
                using var verifier = ECDsa.Create();
                verifier.ImportSubjectPublicKeyInfo(spki, out var read);
                return
                    read == spki.Length &&
                    signature.Length == 64 &&
                    fingerprint == identity.Descriptor.CertificateFingerprintSha256 &&
                    verifier.VerifyData(
                        bytes,
                        signature,
                        HashAlgorithmName.SHA256,
                        DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(spki);
                CryptographicOperations.ZeroMemory(signature);
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
        catch (FormatException)
        {
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool TryParseUtc(string value, out DateTime parsed)
    {
        parsed = DateTime.MinValue;
        return
            value.EndsWith("Z", StringComparison.Ordinal) &&
            DateTime.TryParseExact(
                value,
                "O",
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind,
                out parsed) &&
            parsed.Kind == DateTimeKind.Utc;
    }

    private static void RequireExactProperties(
        JsonElement value,
        IReadOnlySet<string> expected,
        string errorCode)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(errorCode);
        }
        var supplied = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            if (!supplied.Add(property.Name))
            {
                throw new InvalidDataException(errorCode);
            }
        }
        if (!supplied.SetEquals(expected))
        {
            throw new InvalidDataException(errorCode);
        }
    }

    private static string Sha256(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)))
            .ToLowerInvariant();

    private static bool IsLowerHex(char value) =>
        value is >= '0' and <= '9' or >= 'a' and <= 'f';

    private static IReadOnlySet<string> ExactSet(params string[] values) =>
        values.ToHashSet(StringComparer.Ordinal);
}

public interface IGenuineScmProofStore
{
    string? ReadExisting();
    byte[] ReadSourceSalt();
    void Write(string json);
}

public sealed class FixedGenuineScmProofStore : IGenuineScmProofStore
{
    public string? ReadExisting()
    {
        ValidateFile(SensorBoundary.LocalGenuineBatchProofPath);
        var length = new FileInfo(SensorBoundary.LocalGenuineBatchProofPath).Length;
        if (length == 0)
        {
            return null;
        }
        if (length > GenuineScmBatchProof.MaximumProofBytes)
        {
            throw new InvalidDataException("SENSOR_GENUINE_PROOF_SIZE_INVALID");
        }
        return File.ReadAllText(
            SensorBoundary.LocalGenuineBatchProofPath,
            Encoding.UTF8);
    }

    public byte[] ReadSourceSalt()
    {
        ValidateFile(SensorBoundary.LocalGenuineSourceSaltPath);
        var bytes = File.ReadAllBytes(SensorBoundary.LocalGenuineSourceSaltPath);
        if (bytes.Length != GenuineScmBatchProof.SaltBytes)
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw new InvalidDataException("SENSOR_GENUINE_SOURCE_SALT_INVALID");
        }
        return bytes;
    }

    public void Write(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        ValidateFile(SensorBoundary.LocalGenuineBatchProofPath);
        var bytes = Encoding.UTF8.GetBytes(json);
        if (bytes.Length is < 1 or > GenuineScmBatchProof.MaximumProofBytes)
        {
            throw new InvalidDataException("SENSOR_GENUINE_PROOF_SIZE_INVALID");
        }
        try
        {
            using var output = LocalProofNativeFileAccess.OpenExistingForOverwrite(
                SensorBoundary.LocalGenuineBatchProofPath);
            output.SetLength(0);
            output.Write(bytes);
            output.Flush(flushToDisk: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static void ValidateFile(string path)
    {
        if (
            !File.Exists(path) ||
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException("SENSOR_GENUINE_STATE_FILE_INVALID");
        }
    }
}

public static class FixedInstallManifestTimestamp
{
    public static DateTime ReadUtc()
    {
        var path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "WAR-R00M",
            "Windows Sensor",
            "install-manifest.json");
        if (
            !File.Exists(path) ||
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException("SENSOR_INSTALL_MANIFEST_INVALID");
        }
        using var document = JsonDocument.Parse(
            File.ReadAllText(path, Encoding.UTF8),
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 8
            });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("SENSOR_INSTALL_MANIFEST_TIMESTAMP_INVALID");
        }
        var generatedAtProperties = root.EnumerateObject()
            .Count(property => property.NameEquals("generatedAt"));
        if (
            generatedAtProperties != 1 ||
            !root.TryGetProperty("generatedAt", out var generatedAt) ||
            generatedAt.ValueKind != JsonValueKind.String ||
            !TryParseUtc(generatedAt.GetString() ?? "", out var parsed))
        {
            throw new InvalidDataException("SENSOR_INSTALL_MANIFEST_TIMESTAMP_INVALID");
        }
        return parsed;
    }

    private static bool TryParseUtc(string value, out DateTime parsed)
    {
        parsed = DateTime.MinValue;
        return
            value.EndsWith("Z", StringComparison.Ordinal) &&
            DateTime.TryParseExact(
                value,
                "O",
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind,
                out parsed) &&
            parsed.Kind == DateTimeKind.Utc;
    }
}

public sealed class GenuineScmBatchProofWorker(
    ISensorIdentitySigner identity,
    ISensorServiceIdentity serviceIdentity,
    IGenuineScmEventReader reader,
    IGenuineScmProofStore store,
    TimeProvider timeProvider,
    ILogger<GenuineScmBatchProofWorker> logger) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var currentManifestGeneratedAtUtc = FixedInstallManifestTimestamp.ReadUtc();
        var existing = store.ReadExisting();
        if (existing is not null)
        {
            _ = GenuineScmBatchProof.ValidateForManifest(
                existing,
                identity,
                currentManifestGeneratedAtUtc);
            logger.LogInformation(
                "WAR-R00M genuine Gate B1 proof already verified; no event query or re-signing performed.");
            return Task.CompletedTask;
        }

        var salt = store.ReadSourceSalt();
        try
        {
            var startupCapturedAt = timeProvider.GetUtcNow().UtcDateTime;
            var proof = GenuineScmBatchProof.Create(
                identity,
                serviceIdentity,
                reader,
                salt,
                currentManifestGeneratedAtUtc,
                startupCapturedAt,
                cancellationToken);
            if (proof is null)
            {
                logger.LogInformation(
                    "WAR-R00M genuine Gate B1 returned bounded no-match; no fact was created.");
                return Task.CompletedTask;
            }
            store.Write(GenuineScmBatchProof.Serialize(proof));
            logger.LogInformation(
                "WAR-R00M genuine Gate B1 wrote one signed metadata-only fact; raw content, polling, network and command channels disabled.");
            return Task.CompletedTask;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(salt);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) =>
        Task.CompletedTask;
}
