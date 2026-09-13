using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WARRoom.WindowsSensor;

public sealed record BoundedCollectorProofResult(
    string Family,
    string State,
    string? OccurredAtUtc,
    string? SourceRecordIdHash);

public sealed record BoundedCollectorProofCore(
    int SchemaVersion,
    string ProofMode,
    string GeneratedAtUtc,
    string ManifestGeneratedAtUtc,
    string ServiceSid,
    string CertificateFingerprintSha256,
    string CollectionMode,
    string LossState,
    string ContinuityState,
    int FamiliesQueried,
    int EventsRead,
    bool RawEventContentRead,
    bool RuntimeProofEventReaderEnabled,
    bool NetworkTransportEnabled,
    bool AutomaticRetryEnabled,
    bool PollingEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    bool ResponseActionsEnabled,
    IReadOnlyList<BoundedCollectorProofResult> Results);

public sealed record BoundedCollectorProofEnvelope(
    string CanonicalPayload,
    string ProofHash,
    string SignatureBase64);

public sealed record BoundedCollectorProofValidation(
    string CertificateFingerprintSha256,
    string GeneratedAtUtc,
    string ManifestGeneratedAtUtc,
    string ProofHash,
    int FamiliesQueried,
    int EventsRead,
    int MatchCount,
    int NoMatchCount,
    int FailureCount,
    bool RawEventContentRead,
    bool RuntimeProofEventReaderEnabled,
    bool NetworkTransportEnabled,
    bool AutomaticRetryEnabled,
    bool PollingEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    bool ResponseActionsEnabled);

public static class BoundedCollectorProof
{
    public const int SchemaVersion = 1;
    public const string ProofMode = "local-bounded-gate-c1";
    public const int MaximumProofBytes = 32_768;
    public const int SaltBytes = 32;

    private const string HashDomain =
        "WAR-R00M.GateC1.SourceRecordHash.v1";
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };
    private static readonly IReadOnlySet<string> EnvelopeFields = ExactSet(
        "canonicalPayload", "proofHash", "signatureBase64");
    private static readonly IReadOnlySet<string> CoreFields = ExactSet(
        "schemaVersion", "proofMode", "generatedAtUtc",
        "manifestGeneratedAtUtc", "serviceSid",
        "certificateFingerprintSha256", "collectionMode", "lossState",
        "continuityState", "familiesQueried", "eventsRead",
        "rawEventContentRead", "runtimeProofEventReaderEnabled",
        "networkTransportEnabled", "automaticRetryEnabled", "pollingEnabled",
        "inboundListenerEnabled", "commandChannelEnabled",
        "responseActionsEnabled", "results");
    private static readonly IReadOnlySet<string> ResultFields = ExactSet(
        "family", "state", "occurredAtUtc", "sourceRecordIdHash");

    public static BoundedCollectorProofEnvelope Create(
        ISensorIdentitySigner identity,
        ISensorServiceIdentity serviceIdentity,
        BoundedCollectorSnapshot snapshot,
        byte[] sourceSalt,
        DateTime manifestGeneratedAtUtc,
        DateTime generatedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(serviceIdentity);
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(sourceSalt);
        if (
            serviceIdentity.CurrentSid != NativeKeyAccessPolicy.LocalServiceSid ||
            sourceSalt.Length != SaltBytes ||
            manifestGeneratedAtUtc.Kind != DateTimeKind.Utc ||
            generatedAtUtc.Kind != DateTimeKind.Utc ||
            manifestGeneratedAtUtc > generatedAtUtc)
        {
            throw new InvalidOperationException("SENSOR_C1_PROOF_BOUNDARY_INVALID");
        }
        ValidateSnapshotBoundary(snapshot);

        var results = new List<BoundedCollectorProofResult>(
            BoundedMultiEventCollector.MaximumFamilies);
        for (var index = 0; index < snapshot.Results.Count; index++)
        {
            var source = snapshot.Results[index];
            var contract = BoundedMultiEventCollector.Contracts[index];
            if (source.Family != contract.Family)
            {
                throw new InvalidDataException("SENSOR_C1_PROOF_RESULT_ORDER_INVALID");
            }
            var familyName = FamilyName(source.Family);
            if (source.State == BoundedEventReadState.Match)
            {
                var metadata = source.Metadata ?? throw new InvalidDataException(
                    "SENSOR_C1_PROOF_MATCH_METADATA_MISSING");
                var occurredAt = metadata.TimeCreatedUtc.ToUniversalTime();
                if (
                    metadata.ProviderName != contract.ProviderName ||
                    metadata.EventId != contract.EventId ||
                    metadata.Level != contract.Level ||
                    metadata.TimeCreatedUtc.Offset != TimeSpan.Zero ||
                    metadata.RecordId is < 1 or >
                        BoundedMultiEventCollector.MaximumJsonInteger ||
                    occurredAt < new DateTimeOffset(manifestGeneratedAtUtc) ||
                    occurredAt > new DateTimeOffset(generatedAtUtc.AddSeconds(5)))
                {
                    throw new InvalidDataException(
                        "SENSOR_C1_PROOF_MATCH_METADATA_INVALID");
                }
                var occurredAtUtc = occurredAt.UtcDateTime.ToString("O");
                results.Add(new BoundedCollectorProofResult(
                    familyName,
                    StateName(source.State),
                    occurredAtUtc,
                    SourceRecordIdHash(
                        contract,
                        metadata,
                        occurredAtUtc,
                        sourceSalt)));
                continue;
            }
            if (source.Metadata is not null)
            {
                throw new InvalidDataException(
                    "SENSOR_C1_PROOF_NONMATCH_METADATA_INVALID");
            }
            results.Add(new BoundedCollectorProofResult(
                familyName,
                StateName(source.State),
                null,
                null));
        }

        var core = new BoundedCollectorProofCore(
            SchemaVersion,
            ProofMode,
            generatedAtUtc.ToString("O"),
            manifestGeneratedAtUtc.ToString("O"),
            NativeKeyAccessPolicy.LocalServiceSid,
            identity.Descriptor.CertificateFingerprintSha256,
            snapshot.CollectionMode,
            "unknown",
            "unknown",
            snapshot.FamiliesQueried,
            snapshot.EventsRead,
            false,
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            results.AsReadOnly());
        var canonicalPayload = JsonSerializer.Serialize(core, SerializerOptions);
        var proofHash = Sha256(canonicalPayload);
        var envelope = new BoundedCollectorProofEnvelope(
            canonicalPayload,
            proofHash,
            identity.SignUtf8Payload(canonicalPayload));
        _ = Validate(Serialize(envelope), identity);
        return envelope;
    }

    public static string Serialize(BoundedCollectorProofEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var json = JsonSerializer.Serialize(envelope, SerializerOptions);
        if (Encoding.UTF8.GetByteCount(json) > MaximumProofBytes)
        {
            throw new InvalidDataException("SENSOR_C1_PROOF_SIZE_INVALID");
        }
        return json;
    }

    public static BoundedCollectorProofValidation Validate(
        string json,
        ISensorIdentitySigner identity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        ArgumentNullException.ThrowIfNull(identity);
        if (Encoding.UTF8.GetByteCount(json) > MaximumProofBytes)
        {
            throw new InvalidDataException("SENSOR_C1_PROOF_SIZE_INVALID");
        }
        using var envelopeDocument = Parse(json);
        RequireExactProperties(
            envelopeDocument.RootElement,
            EnvelopeFields,
            "SENSOR_C1_PROOF_ENVELOPE_FIELDS_INVALID");
        var envelope = JsonSerializer.Deserialize<BoundedCollectorProofEnvelope>(
            json,
            SerializerOptions) ?? throw new InvalidDataException(
                "SENSOR_C1_PROOF_ENVELOPE_INVALID");
        if (
            envelope.ProofHash != Sha256(envelope.CanonicalPayload) ||
            !VerifySignature(
                envelope.CanonicalPayload,
                envelope.SignatureBase64,
                identity))
        {
            throw new InvalidDataException("SENSOR_C1_PROOF_SIGNATURE_INVALID");
        }

        using var coreDocument = Parse(envelope.CanonicalPayload);
        RequireExactProperties(
            coreDocument.RootElement,
            CoreFields,
            "SENSOR_C1_PROOF_CORE_FIELDS_INVALID");
        var resultsElement = coreDocument.RootElement.GetProperty("results");
        if (
            resultsElement.ValueKind != JsonValueKind.Array ||
            resultsElement.GetArrayLength() !=
                BoundedMultiEventCollector.MaximumFamilies)
        {
            throw new InvalidDataException("SENSOR_C1_PROOF_RESULTS_INVALID");
        }
        foreach (var result in resultsElement.EnumerateArray())
        {
            RequireExactProperties(
                result,
                ResultFields,
                "SENSOR_C1_PROOF_RESULT_FIELDS_INVALID");
        }
        var core = JsonSerializer.Deserialize<BoundedCollectorProofCore>(
            envelope.CanonicalPayload,
            SerializerOptions) ?? throw new InvalidDataException(
                "SENSOR_C1_PROOF_CORE_INVALID");
        if (
            envelope.CanonicalPayload !=
                JsonSerializer.Serialize(core, SerializerOptions) ||
            core.SchemaVersion != SchemaVersion ||
            core.ProofMode != ProofMode ||
            core.ServiceSid != NativeKeyAccessPolicy.LocalServiceSid ||
            core.CertificateFingerprintSha256 !=
                identity.Descriptor.CertificateFingerprintSha256 ||
            core.CollectionMode != "explicit-one-shot-contract" ||
            core.LossState != "unknown" ||
            core.ContinuityState != "unknown" ||
            core.FamiliesQueried !=
                BoundedMultiEventCollector.MaximumFamilies ||
            core.EventsRead is < 0 or >
                BoundedMultiEventCollector.MaximumEvents ||
            core.RawEventContentRead ||
            !core.RuntimeProofEventReaderEnabled ||
            core.NetworkTransportEnabled ||
            core.AutomaticRetryEnabled ||
            core.PollingEnabled ||
            core.InboundListenerEnabled ||
            core.CommandChannelEnabled ||
            core.ResponseActionsEnabled ||
            !TryParseUtc(core.GeneratedAtUtc, out var generatedAtUtc) ||
            !TryParseUtc(
                core.ManifestGeneratedAtUtc,
                out var manifestGeneratedAtUtc) ||
            generatedAtUtc < manifestGeneratedAtUtc ||
            core.Results.Count != BoundedMultiEventCollector.MaximumFamilies)
        {
            throw new InvalidDataException("SENSOR_C1_PROOF_CORE_INVALID");
        }

        var matchCount = 0;
        var noMatchCount = 0;
        var failureCount = 0;
        var sourceHashes = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < core.Results.Count; index++)
        {
            var result = core.Results[index];
            if (result.Family != FamilyName(
                BoundedMultiEventCollector.Contracts[index].Family))
            {
                throw new InvalidDataException(
                    "SENSOR_C1_PROOF_RESULT_ORDER_INVALID");
            }
            if (result.State == "match")
            {
                if (
                    !TryParseUtc(result.OccurredAtUtc ?? "", out var occurredAt) ||
                    occurredAt < manifestGeneratedAtUtc ||
                    occurredAt > generatedAtUtc.AddSeconds(5) ||
                    result.SourceRecordIdHash is null ||
                    result.SourceRecordIdHash.Length != 64 ||
                    !result.SourceRecordIdHash.All(IsLowerHex) ||
                    !sourceHashes.Add(result.SourceRecordIdHash))
                {
                    throw new InvalidDataException(
                        "SENSOR_C1_PROOF_MATCH_RESULT_INVALID");
                }
                matchCount++;
            }
            else
            {
                if (
                    result.State is not (
                        "no-match" or "access-denied" or
                        "source-unavailable" or "query-failed") ||
                    result.OccurredAtUtc is not null ||
                    result.SourceRecordIdHash is not null)
                {
                    throw new InvalidDataException(
                        "SENSOR_C1_PROOF_NONMATCH_RESULT_INVALID");
                }
                if (result.State == "no-match") noMatchCount++;
                else failureCount++;
            }
        }
        if (core.EventsRead != matchCount)
        {
            throw new InvalidDataException("SENSOR_C1_PROOF_EVENT_COUNT_INVALID");
        }
        return new BoundedCollectorProofValidation(
            core.CertificateFingerprintSha256,
            core.GeneratedAtUtc,
            core.ManifestGeneratedAtUtc,
            envelope.ProofHash,
            core.FamiliesQueried,
            core.EventsRead,
            matchCount,
            noMatchCount,
            failureCount,
            core.RawEventContentRead,
            core.RuntimeProofEventReaderEnabled,
            core.NetworkTransportEnabled,
            core.AutomaticRetryEnabled,
            core.PollingEnabled,
            core.InboundListenerEnabled,
            core.CommandChannelEnabled,
            core.ResponseActionsEnabled);
    }

    public static BoundedCollectorProofValidation ValidateForManifest(
        string json,
        ISensorIdentitySigner identity,
        DateTime manifestGeneratedAtUtc)
    {
        if (manifestGeneratedAtUtc.Kind != DateTimeKind.Utc)
        {
            throw new InvalidDataException("SENSOR_C1_PROOF_MANIFEST_INVALID");
        }
        var validation = Validate(json, identity);
        if (
            validation.ManifestGeneratedAtUtc !=
                manifestGeneratedAtUtc.ToString("O"))
        {
            throw new InvalidDataException("SENSOR_C1_PROOF_MANIFEST_MISMATCH");
        }
        return validation;
    }

    private static void ValidateSnapshotBoundary(BoundedCollectorSnapshot snapshot)
    {
        if (
            snapshot.CollectionMode != "explicit-one-shot-contract" ||
            snapshot.LossState != "unknown" ||
            snapshot.ContinuityState != "unknown" ||
            snapshot.FamiliesQueried !=
                BoundedMultiEventCollector.MaximumFamilies ||
            snapshot.EventsRead is < 0 or >
                BoundedMultiEventCollector.MaximumEvents ||
            snapshot.RawEventContentRead ||
            snapshot.RuntimeWired ||
            snapshot.NetworkTransportEnabled ||
            snapshot.AutomaticRetryEnabled ||
            snapshot.PollingEnabled ||
            snapshot.InboundListenerEnabled ||
            snapshot.CommandChannelEnabled ||
            snapshot.ResponseActionsEnabled ||
            snapshot.Results.Count !=
                BoundedMultiEventCollector.MaximumFamilies ||
            snapshot.Results.Count(result =>
                result.State == BoundedEventReadState.Match) !=
                snapshot.EventsRead)
        {
            throw new InvalidDataException("SENSOR_C1_PROOF_SNAPSHOT_INVALID");
        }
    }

    private static string SourceRecordIdHash(
        BoundedEventFamilyContract contract,
        BoundedEventMetadata metadata,
        string occurredAtUtc,
        byte[] sourceSalt)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        AppendField(hash, Encoding.UTF8.GetBytes(HashDomain));
        AppendField(hash, sourceSalt);
        foreach (var value in new[]
        {
            FamilyName(contract.Family),
            contract.LogName,
            contract.ProviderName,
            contract.EventId.ToString(CultureInfo.InvariantCulture),
            contract.Level.ToString(CultureInfo.InvariantCulture),
            metadata.RecordId.ToString(CultureInfo.InvariantCulture),
            occurredAtUtc
        })
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            try { AppendField(hash, bytes); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
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
            var signature = Convert.FromBase64String(signatureBase64);
            var spki = Convert.FromBase64String(
                identity.Descriptor.PublicKeySpkiBase64);
            try
            {
                if (signature.Length != 64) return false;
                using var verifier = ECDsa.Create();
                verifier.ImportSubjectPublicKeyInfo(spki, out var bytesRead);
                return
                    bytesRead == spki.Length &&
                    Sha256(spki) ==
                        identity.Descriptor.CertificateFingerprintSha256 &&
                    verifier.VerifyData(
                        Encoding.UTF8.GetBytes(payload),
                        signature,
                        HashAlgorithmName.SHA256,
                        DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(signature);
                CryptographicOperations.ZeroMemory(spki);
            }
        }
        catch (FormatException) { return false; }
        catch (CryptographicException) { return false; }
    }

    private static JsonDocument Parse(string json) => JsonDocument.Parse(
        json,
        new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 20
        });

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

    private static string FamilyName(BoundedEventFamily family) => family switch
    {
        BoundedEventFamily.ScmServiceInstalled => "scm-service-installed",
        BoundedEventFamily.ScmServiceStateChanged => "scm-service-state-changed",
        _ => throw new InvalidDataException("SENSOR_C1_PROOF_FAMILY_INVALID")
    };

    private static string StateName(BoundedEventReadState state) => state switch
    {
        BoundedEventReadState.Match => "match",
        BoundedEventReadState.NoMatch => "no-match",
        BoundedEventReadState.AccessDenied => "access-denied",
        BoundedEventReadState.SourceUnavailable => "source-unavailable",
        BoundedEventReadState.QueryFailed => "query-failed",
        _ => throw new InvalidDataException("SENSOR_C1_PROOF_STATE_INVALID")
    };

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

    private static string Sha256(string value) =>
        Sha256(Encoding.UTF8.GetBytes(value));

    private static string Sha256(byte[] value) =>
        Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();

    private static bool IsLowerHex(char value) =>
        value is >= '0' and <= '9' or >= 'a' and <= 'f';

    private static IReadOnlySet<string> ExactSet(params string[] values) =>
        values.ToHashSet(StringComparer.Ordinal);
}

public interface IBoundedCollectorProofStore
{
    string? ReadExisting();
    byte[] ReadSourceSalt();
    void Write(string json);
}

public sealed class FixedBoundedCollectorProofStore :
    IBoundedCollectorProofStore
{
    public string? ReadExisting()
    {
        ValidateFile(SensorBoundary.LocalBoundedCollectorProofPath);
        var file = new FileInfo(SensorBoundary.LocalBoundedCollectorProofPath);
        if (file.Length == 0) return null;
        if (file.Length > BoundedCollectorProof.MaximumProofBytes)
        {
            throw new InvalidDataException("SENSOR_C1_PROOF_SIZE_INVALID");
        }
        return File.ReadAllText(
            SensorBoundary.LocalBoundedCollectorProofPath,
            Encoding.UTF8);
    }

    public byte[] ReadSourceSalt()
    {
        ValidateFile(SensorBoundary.LocalGenuineSourceSaltPath);
        var bytes = File.ReadAllBytes(SensorBoundary.LocalGenuineSourceSaltPath);
        if (bytes.Length != BoundedCollectorProof.SaltBytes)
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw new InvalidDataException("SENSOR_C1_SOURCE_SALT_INVALID");
        }
        return bytes;
    }

    public void Write(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        ValidateFile(SensorBoundary.LocalBoundedCollectorProofPath);
        var bytes = Encoding.UTF8.GetBytes(json);
        if (bytes.Length is < 1 or > BoundedCollectorProof.MaximumProofBytes)
        {
            throw new InvalidDataException("SENSOR_C1_PROOF_SIZE_INVALID");
        }
        try
        {
            using var output = LocalProofNativeFileAccess.OpenExistingForOverwrite(
                SensorBoundary.LocalBoundedCollectorProofPath);
            output.SetLength(0);
            output.Write(bytes);
            output.Flush(flushToDisk: true);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static void ValidateFile(string path)
    {
        if (
            !File.Exists(path) ||
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException("SENSOR_C1_STATE_FILE_INVALID");
        }
    }
}

public sealed class BoundedCollectorProofWorker(
    ISensorIdentitySigner identity,
    ISensorServiceIdentity serviceIdentity,
    IMultiEventCollector collector,
    IBoundedCollectorProofStore store,
    IInstallManifestTimestampReader manifestReader,
    TimeProvider timeProvider,
    ILogger<BoundedCollectorProofWorker> logger) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var manifestGeneratedAtUtc = manifestReader.ReadUtc();
        var existing = store.ReadExisting();
        if (existing is not null)
        {
            _ = BoundedCollectorProof.ValidateForManifest(
                existing,
                identity,
                manifestGeneratedAtUtc);
            logger.LogInformation(
                "WAR-R00M Gate C1 proof already verified; no event query or re-signing performed.");
            return Task.CompletedTask;
        }

        var salt = store.ReadSourceSalt();
        try
        {
            var snapshot = collector.CollectOnce(
                manifestGeneratedAtUtc,
                cancellationToken);
            var generatedAtUtc = timeProvider.GetUtcNow().UtcDateTime;
            var proof = BoundedCollectorProof.Create(
                identity,
                serviceIdentity,
                snapshot,
                salt,
                manifestGeneratedAtUtc,
                generatedAtUtc);
            store.Write(BoundedCollectorProof.Serialize(proof));
            logger.LogInformation(
                "WAR-R00M Gate C1 wrote one signed bounded metadata snapshot; raw content, retry, network and commands disabled.");
            return Task.CompletedTask;
        }
        finally { CryptographicOperations.ZeroMemory(salt); }
    }

    public Task StopAsync(CancellationToken cancellationToken) =>
        Task.CompletedTask;
}
