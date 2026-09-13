using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WARRoom.WindowsSensor;

public sealed record LocalSyntheticSignedBatch(
    long BatchSequence,
    string? PreviousBatchHash,
    string CanonicalPayload,
    string BatchHash,
    string SignatureBase64);

public sealed record LocalSyntheticBatchProofDocument(
    int SchemaVersion,
    string ProofMode,
    string GeneratedAtUtc,
    string ServiceSid,
    string CertificateFingerprintSha256,
    bool SyntheticOnly,
    bool EventReaderEnabled,
    bool NetworkTransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    IReadOnlyList<LocalSyntheticSignedBatch> Batches);

public sealed record LocalSyntheticBatchProofValidation(
    string CertificateFingerprintSha256,
    string GeneratedAtUtc,
    int BatchCount,
    string FirstBatchHash,
    string LastBatchHash,
    bool SyntheticOnly,
    bool EventReaderEnabled,
    bool NetworkTransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled);

public static class LocalSyntheticBatchProof
{
    public const string ProofMode = "local-synthetic-gate-b0";
    public const int MaximumProofBytes = 32_768;
    public const int ExactBatchCount = 2;

    private const string MissionId = "local-gate-b0-synthetic";
    private const string ConnectorId =
        "connector-11111111-1111-4111-8111-111111111111";
    private const string EndpointId =
        "endpoint-22222222-2222-4222-8222-222222222222";
    private const string CapabilityId =
        "capability-33333333-3333-4333-8333-333333333333";
    private const string BootId = "boot-local-gate-b0-00000001";
    private const string Provider = "windows-eventlog";
    private const string Channel = "eventlog-admin";
    private const string EventFamily = "event-log-clear";

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    private static readonly IReadOnlySet<string> ProofFields = ExactSet(
        "schemaVersion",
        "proofMode",
        "generatedAtUtc",
        "serviceSid",
        "certificateFingerprintSha256",
        "syntheticOnly",
        "eventReaderEnabled",
        "networkTransportEnabled",
        "inboundListenerEnabled",
        "commandChannelEnabled",
        "batches");

    private static readonly IReadOnlySet<string> BatchFields = ExactSet(
        "batchSequence",
        "previousBatchHash",
        "canonicalPayload",
        "batchHash",
        "signatureBase64");

    public static LocalSyntheticBatchProofDocument Create(
        ISensorIdentitySigner identity,
        ISensorServiceIdentity serviceIdentity,
        DateTime utcNow)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(serviceIdentity);
        if (
            utcNow.Kind != DateTimeKind.Utc ||
            !StringComparer.Ordinal.Equals(
                serviceIdentity.CurrentSid,
                NativeKeyAccessPolicy.LocalServiceSid))
        {
            throw new InvalidOperationException(
                "SENSOR_LOCAL_PROOF_LOCALSERVICE_REQUIRED");
        }

        var generatedAtUtc = utcNow.ToString("O");
        var fingerprint =
            identity.Descriptor.CertificateFingerprintSha256;
        var first = SignCore(
            identity,
            BuildCore(0, null, generatedAtUtc, fingerprint));
        var firstHead = new NativeFactStreamHead(
            BootId,
            first.BatchSequence,
            first.BatchHash);
        var secondCore = NativeTelemetryFactBatch.ParseCore(
            BuildCore(1, first.BatchHash, generatedAtUtc, fingerprint));
        secondCore.ValidateContinuity(firstHead);
        var secondSigning = secondCore.Sign(identity);
        var second = new LocalSyntheticSignedBatch(
            secondCore.BatchSequence,
            secondCore.PreviousBatchHash,
            secondSigning.CanonicalPayload,
            secondSigning.BatchHash,
            secondSigning.SignatureBase64);

        var document = new LocalSyntheticBatchProofDocument(
            1,
            ProofMode,
            generatedAtUtc,
            NativeKeyAccessPolicy.LocalServiceSid,
            fingerprint,
            true,
            false,
            false,
            false,
            false,
            [first, second]);
        _ = Validate(Serialize(document), identity);
        return document;
    }

    public static string Serialize(LocalSyntheticBatchProofDocument proof)
    {
        ArgumentNullException.ThrowIfNull(proof);
        var json = JsonSerializer.Serialize(proof, SerializerOptions);
        if (Encoding.UTF8.GetByteCount(json) > MaximumProofBytes)
        {
            throw new InvalidDataException("SENSOR_LOCAL_PROOF_SIZE_INVALID");
        }
        return json;
    }

    public static LocalSyntheticBatchProofValidation Validate(
        string json,
        ISensorIdentitySigner identity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        ArgumentNullException.ThrowIfNull(identity);
        if (Encoding.UTF8.GetByteCount(json) > MaximumProofBytes)
        {
            throw new InvalidDataException("SENSOR_LOCAL_PROOF_SIZE_INVALID");
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
            "SENSOR_LOCAL_PROOF_FIELDS_INVALID");
        var batchElements = parsed.RootElement.GetProperty("batches");
        if (
            batchElements.ValueKind != JsonValueKind.Array ||
            batchElements.GetArrayLength() != ExactBatchCount)
        {
            throw new InvalidDataException(
                "SENSOR_LOCAL_PROOF_BATCH_COUNT_INVALID");
        }
        foreach (var batch in batchElements.EnumerateArray())
        {
            RequireExactProperties(
                batch,
                BatchFields,
                "SENSOR_LOCAL_PROOF_BATCH_FIELDS_INVALID");
        }

        var proof = JsonSerializer.Deserialize<LocalSyntheticBatchProofDocument>(
            json,
            SerializerOptions) ??
            throw new InvalidDataException("SENSOR_LOCAL_PROOF_INVALID");
        if (
            proof.SchemaVersion != 1 ||
            !StringComparer.Ordinal.Equals(proof.ProofMode, ProofMode) ||
            !StringComparer.Ordinal.Equals(
                proof.ServiceSid,
                NativeKeyAccessPolicy.LocalServiceSid) ||
            !StringComparer.Ordinal.Equals(
                proof.CertificateFingerprintSha256,
                identity.Descriptor.CertificateFingerprintSha256) ||
            !proof.SyntheticOnly ||
            proof.EventReaderEnabled ||
            proof.NetworkTransportEnabled ||
            proof.InboundListenerEnabled ||
            proof.CommandChannelEnabled ||
            proof.Batches.Count != ExactBatchCount ||
            !TryParseUtc(proof.GeneratedAtUtc, out _))
        {
            throw new InvalidDataException("SENSOR_LOCAL_PROOF_INVALID");
        }

        NativeFactStreamHead? head = null;
        for (var index = 0; index < ExactBatchCount; index++)
        {
            var supplied = proof.Batches[index];
            var expectedCore = NativeTelemetryFactBatch.ParseCore(
                BuildCore(
                    index,
                    index == 0 ? null : proof.Batches[0].BatchHash,
                    proof.GeneratedAtUtc,
                    proof.CertificateFingerprintSha256));
            var expectedPayload = expectedCore.CanonicalPayload();
            expectedCore.ValidateContinuity(head);
            if (
                supplied.BatchSequence != index ||
                !StringComparer.Ordinal.Equals(
                    supplied.PreviousBatchHash,
                    expectedCore.PreviousBatchHash) ||
                !StringComparer.Ordinal.Equals(
                    supplied.CanonicalPayload,
                    expectedPayload) ||
                !StringComparer.Ordinal.Equals(
                    supplied.BatchHash,
                    expectedCore.BatchHash()) ||
                !VerifySignature(
                    supplied.CanonicalPayload,
                    supplied.SignatureBase64,
                    identity))
            {
                throw new InvalidDataException(
                    "SENSOR_LOCAL_PROOF_BATCH_INVALID");
            }
            head = new NativeFactStreamHead(
                expectedCore.BootId,
                expectedCore.BatchSequence,
                supplied.BatchHash);
        }

        return new LocalSyntheticBatchProofValidation(
            proof.CertificateFingerprintSha256,
            proof.GeneratedAtUtc,
            proof.Batches.Count,
            proof.Batches[0].BatchHash,
            proof.Batches[1].BatchHash,
            proof.SyntheticOnly,
            proof.EventReaderEnabled,
            proof.NetworkTransportEnabled,
            proof.InboundListenerEnabled,
            proof.CommandChannelEnabled);
    }

    private static LocalSyntheticSignedBatch SignCore(
        ISensorIdentitySigner identity,
        string json)
    {
        var core = NativeTelemetryFactBatch.ParseCore(json);
        core.ValidateContinuity(null);
        var signing = core.Sign(identity);
        return new LocalSyntheticSignedBatch(
            core.BatchSequence,
            core.PreviousBatchHash,
            signing.CanonicalPayload,
            signing.BatchHash,
            signing.SignatureBase64);
    }

    private static string BuildCore(
        long sequence,
        string? previousBatchHash,
        string occurredAt,
        string fingerprint)
    {
        var factSuffix = sequence == 0 ? "00000001" : "00000002";
        var sourceLabel = sequence == 0
            ? "WAR-R00M.LocalSyntheticGateB0.SourceRecord.1"
            : "WAR-R00M.LocalSyntheticGateB0.SourceRecord.2";
        var core = new
        {
            schemaVersion = 1,
            missionId = MissionId,
            connectorId = ConnectorId,
            endpointId = EndpointId,
            certificateFingerprintSha256 = fingerprint,
            capabilitySnapshotId = CapabilityId,
            bootId = BootId,
            batchSequence = sequence,
            previousBatchHash,
            provider = Provider,
            channel = Channel,
            eventFamily = EventFamily,
            filterHash = Sha256(
                "WAR-R00M.LocalSyntheticGateB0.Filter.v1"),
            facts = new[]
            {
                new
                {
                    factId = $"fact-local-gate-b0-{factSuffix}",
                    occurredAt,
                    sourceRecordIdHash = Sha256(sourceLabel),
                    fields = new
                    {
                        actorTrust = "managed",
                        action = "clear",
                        subjectClass = "admin-tool",
                        objectClass = "event-log",
                        outcome = "success"
                    }
                }
            }
        };
        return JsonSerializer.Serialize(core, SerializerOptions);
    }

    private static bool VerifySignature(
        string payload,
        string signatureBase64,
        ISensorIdentitySigner identity)
    {
        byte[]? spki = null;
        byte[]? signature = null;
        byte[]? payloadBytes = null;
        try
        {
            spki = Convert.FromBase64String(
                identity.Descriptor.PublicKeySpkiBase64);
            signature = Convert.FromBase64String(signatureBase64);
            payloadBytes = Encoding.UTF8.GetBytes(payload);
            var fingerprint =
                Convert.ToHexString(SHA256.HashData(spki)).ToLowerInvariant();
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(spki, out var bytesRead);
            return
                bytesRead == spki.Length &&
                signature.Length == 64 &&
                StringComparer.Ordinal.Equals(
                    fingerprint,
                    identity.Descriptor.CertificateFingerprintSha256) &&
                verifier.VerifyData(
                    payloadBytes,
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
            if (spki is not null)
            {
                CryptographicOperations.ZeroMemory(spki);
            }
            if (signature is not null)
            {
                CryptographicOperations.ZeroMemory(signature);
            }
            if (payloadBytes is not null)
            {
                CryptographicOperations.ZeroMemory(payloadBytes);
            }
        }
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

    private static bool TryParseUtc(string value, out DateTime parsed)
    {
        parsed = DateTime.MinValue;
        return
            value.EndsWith("Z", StringComparison.Ordinal) &&
            DateTime.TryParseExact(
                value,
                "O",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.RoundtripKind,
                out parsed) &&
            parsed.Kind == DateTimeKind.Utc;
    }

    private static string Sha256(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)))
            .ToLowerInvariant();

    private static IReadOnlySet<string> ExactSet(params string[] values) =>
        values.ToHashSet(StringComparer.Ordinal);
}

public interface ILocalSyntheticBatchProofStore
{
    void Write(string json);
}

public static class LocalProofNativeFileAccess
{
    public const uint DesiredAccess = 0x00000002; // FILE_WRITE_DATA only.
    public const uint ShareMode = 0x00000001; // FILE_SHARE_READ.
    public const uint CreationDisposition = 3; // OPEN_EXISTING.
    public const uint FlagsAndAttributes = 0x80000080; // WRITE_THROUGH | NORMAL.

    public static FileStream OpenExistingForOverwrite(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("SENSOR_WINDOWS_REQUIRED");
        }

        var handle = CreateFile(
            path,
            DesiredAccess,
            ShareMode,
            IntPtr.Zero,
            CreationDisposition,
            FlagsAndAttributes,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw new IOException("SENSOR_LOCAL_PROOF_FILE_OPEN_FAILED");
        }
        try
        {
            var stream = new FileStream(
                handle,
                FileAccess.Write,
                bufferSize: 4096,
                isAsync: false);
            handle = null!;
            return stream;
        }
        finally
        {
            handle?.Dispose();
        }
    }

    [DllImport(
        "kernel32.dll",
        EntryPoint = "CreateFileW",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);
}

public sealed class FixedLocalSyntheticBatchProofStore :
    ILocalSyntheticBatchProofStore
{
    public void Write(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        var path = SensorBoundary.LocalSyntheticBatchProofPath;
        if (
            !File.Exists(path) ||
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException("SENSOR_LOCAL_PROOF_FILE_INVALID");
        }
        var bytes = Encoding.UTF8.GetBytes(json);
        if (bytes.Length is < 1 or > LocalSyntheticBatchProof.MaximumProofBytes)
        {
            throw new InvalidDataException("SENSOR_LOCAL_PROOF_SIZE_INVALID");
        }
        try
        {
            using var output =
                LocalProofNativeFileAccess.OpenExistingForOverwrite(path);
            output.SetLength(0);
            output.Write(bytes);
            output.Flush(flushToDisk: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }
}

public sealed class LocalSyntheticBatchProofWorker(
    ISensorIdentitySigner identity,
    ISensorServiceIdentity serviceIdentity,
    ILocalSyntheticBatchProofStore store,
    TimeProvider timeProvider,
    ILogger<LocalSyntheticBatchProofWorker> logger) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var proof = LocalSyntheticBatchProof.Create(
            identity,
            serviceIdentity,
            timeProvider.GetUtcNow().UtcDateTime);
        store.Write(LocalSyntheticBatchProof.Serialize(proof));
        logger.LogInformation(
            "WAR-R00M local synthetic Gate B0 proof written. Batches={BatchCount}; event reader and network transport disabled.",
            proof.Batches.Count);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) =>
        Task.CompletedTask;
}
