using System.Globalization;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WARRoom.WindowsSensor;

public sealed record EndpointDeliveryDocument(
    int SchemaVersion,
    string Profile,
    string State,
    string AttemptedAt,
    string ServiceSourceCommit,
    string BindingDescriptorSha256,
    string CapabilitySnapshotId,
    string CapabilityReportHash,
    string BatchHash,
    long BatchSequence,
    int FactCount,
    string ReasonCode,
    bool NetworkAttempted,
    bool AutomaticRetryEnabled,
    bool RemoteTransportEnabled,
    bool InboundListenerEnabled,
    bool PollingEnabled,
    bool CommandChannelEnabled);

public interface IEndpointDeliveryStore
{
    string? ReadExisting();
    void Write(string json);
}

public interface IInstallManifestTimestampReader
{
    DateTime ReadUtc();
}

public sealed class FixedInstallManifestTimestampReader :
    IInstallManifestTimestampReader
{
    public DateTime ReadUtc() => FixedInstallManifestTimestamp.ReadUtc();
}

public sealed class FixedEndpointDeliveryStore : IEndpointDeliveryStore
{
    public string? ReadExisting()
    {
        ValidateFile();
        var length = new FileInfo(SensorBoundary.LocalLoopbackDeliveryPath).Length;
        if (length == 0) return null;
        if (length > EndpointOneShotDelivery.MaximumDocumentBytes)
            throw new InvalidDataException("SENSOR_DELIVERY_FILE_SIZE_INVALID");
        return File.ReadAllText(
            SensorBoundary.LocalLoopbackDeliveryPath,
            Encoding.UTF8);
    }

    public void Write(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        ValidateFile();
        var bytes = Encoding.UTF8.GetBytes(json);
        if (bytes.Length is < 1 or > EndpointOneShotDelivery.MaximumDocumentBytes)
            throw new InvalidDataException("SENSOR_DELIVERY_FILE_SIZE_INVALID");
        try
        {
            using var output = LocalProofNativeFileAccess.OpenExistingForOverwrite(
                SensorBoundary.LocalLoopbackDeliveryPath);
            output.SetLength(0);
            output.Write(bytes);
            output.Flush(flushToDisk: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static void ValidateFile()
    {
        var path = SensorBoundary.LocalLoopbackDeliveryPath;
        if (!File.Exists(path) ||
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("SENSOR_DELIVERY_STATE_FILE_INVALID");
    }
}

public static class EndpointOneShotDelivery
{
    public const string Profile = "gate-c0c-loopback-delivery-v1";
    public const int MaximumDocumentBytes = 8_192;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never
    };

    private static readonly IReadOnlySet<string> DocumentFields = ExactSet(
        "schemaVersion", "profile", "state", "attemptedAt",
        "serviceSourceCommit", "bindingDescriptorSha256",
        "capabilitySnapshotId", "capabilityReportHash", "batchHash",
        "batchSequence", "factCount", "reasonCode", "networkAttempted",
        "automaticRetryEnabled", "remoteTransportEnabled",
        "inboundListenerEnabled", "pollingEnabled", "commandChannelEnabled");

    public static LocalSyntheticSignedBatch CreateBatch(
        string finalBindingJson,
        string capabilityProofJson,
        string genuineProofJson,
        ISensorIdentitySigner identity,
        InstallManifestBinding manifest,
        DateTime manifestGeneratedAtUtc,
        DateTime utcNow,
        bool requireFreshCapability = true)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(manifest);
        if (utcNow.Kind != DateTimeKind.Utc ||
            manifestGeneratedAtUtc.Kind != DateTimeKind.Utc ||
            manifest.Fingerprint != identity.Descriptor.CertificateFingerprintSha256)
            throw Invalid("SENSOR_DELIVERY_CONTEXT_INVALID");

        var binding = EndpointBindingLifecycle.ValidateFinal(
            finalBindingJson,
            capabilityProofJson,
            identity.Descriptor,
            manifest.Commit,
            utcNow);
        if (!TryUtc(binding.CapabilityFreshUntil, out var freshUntil) ||
            (requireFreshCapability && utcNow >= freshUntil))
            throw Invalid("SENSOR_DELIVERY_CAPABILITY_STALE");

        var genuine = GenuineScmBatchProof.ValidateForManifest(
            genuineProofJson,
            identity,
            manifestGeneratedAtUtc);
        using var proofDocument = JsonDocument.Parse(
            genuineProofJson,
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 20
            });
        var genuinePayload = proofDocument.RootElement
            .GetProperty("batch")
            .GetProperty("canonicalPayload")
            .GetString() ?? throw Invalid("SENSOR_DELIVERY_GENUINE_PROOF_INVALID");
        using var genuineCore = JsonDocument.Parse(genuinePayload);
        var sourceFact = genuineCore.RootElement.GetProperty("facts")[0];
        var sourceHash = sourceFact.GetProperty("sourceRecordIdHash").GetString() ?? "";
        var occurredAt = sourceFact.GetProperty("occurredAt").GetString() ?? "";
        if (sourceHash != genuine.SourceRecordIdHash ||
            occurredAt != genuine.OccurredAtUtc)
            throw Invalid("SENSOR_DELIVERY_GENUINE_PROOF_INVALID");

        var bootHash = Sha256($"{manifest.Commit}:{manifest.BindingDescriptorSha256}");
        var coreJson = JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            missionId = binding.MissionId,
            connectorId = binding.ConnectorId,
            endpointId = binding.EndpointId,
            certificateFingerprintSha256 = binding.CertificateFingerprintSha256,
            capabilitySnapshotId = binding.CapabilitySnapshotId,
            bootId = $"boot-c0c-{bootHash[..32]}",
            batchSequence = 0,
            previousBatchHash = (string?)null,
            provider = binding.Provider,
            channel = binding.Channel,
            eventFamily = binding.EventFamily,
            filterHash = binding.FilterHash,
            facts = new[]
            {
                new
                {
                    factId = $"fact-c0c-scm-{sourceHash[..32]}",
                    occurredAt,
                    sourceRecordIdHash = sourceHash,
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
        }, JsonOptions);
        var core = NativeTelemetryFactBatch.ParseCore(coreJson);
        core.ValidateContinuity(null);
        var signed = core.Sign(identity);
        return new LocalSyntheticSignedBatch(
            0,
            null,
            signed.CanonicalPayload,
            signed.BatchHash,
            signed.SignatureBase64);
    }

    public static string Accepted(
        LocalSyntheticSignedBatch batch,
        LoopbackFactReceipt receipt,
        FinalEndpointBinding binding,
        InstallManifestBinding manifest,
        DateTime attemptedAtUtc)
    {
        if (attemptedAtUtc.Kind != DateTimeKind.Utc ||
            receipt.Status != "accepted" ||
            receipt.BatchHash != batch.BatchHash ||
            receipt.BatchSequence != 0 ||
            receipt.FactCount != 1)
            throw Invalid("SENSOR_DELIVERY_RECEIPT_INVALID");
        return Serialize(new EndpointDeliveryDocument(
            1, Profile, "accepted", Timestamp(attemptedAtUtc), manifest.Commit,
            manifest.BindingDescriptorSha256, binding.CapabilitySnapshotId,
            binding.CapabilityReportHash, batch.BatchHash, 0, 1, "accepted",
            true, false, false, false, false, false));
    }

    public static string Claimed(
        LocalSyntheticSignedBatch batch,
        FinalEndpointBinding binding,
        InstallManifestBinding manifest,
        DateTime attemptedAtUtc)
    {
        if (attemptedAtUtc.Kind != DateTimeKind.Utc)
            throw Invalid("SENSOR_DELIVERY_CLAIM_INVALID");
        return Serialize(new EndpointDeliveryDocument(
            1, Profile, "claimed", Timestamp(attemptedAtUtc), manifest.Commit,
            manifest.BindingDescriptorSha256, binding.CapabilitySnapshotId,
            binding.CapabilityReportHash, batch.BatchHash, 0, 1, "pending",
            false, false, false, false, false, false));
    }

    public static string Failed(
        LocalSyntheticSignedBatch batch,
        FinalEndpointBinding binding,
        InstallManifestBinding manifest,
        DateTime attemptedAtUtc,
        string reasonCode)
    {
        if (attemptedAtUtc.Kind != DateTimeKind.Utc ||
            reasonCode is not ("timeout" or "connection-failed" or "response-invalid"))
            throw Invalid("SENSOR_DELIVERY_FAILURE_INVALID");
        return Serialize(new EndpointDeliveryDocument(
            1, Profile, "failed", Timestamp(attemptedAtUtc), manifest.Commit,
            manifest.BindingDescriptorSha256, binding.CapabilitySnapshotId,
            binding.CapabilityReportHash, batch.BatchHash, 0, 1, reasonCode,
            true, false, false, false, false, false));
    }

    public static EndpointDeliveryDocument Validate(
        string json,
        LocalSyntheticSignedBatch expectedBatch,
        FinalEndpointBinding binding,
        InstallManifestBinding manifest,
        bool requireAccepted)
    {
        if (Encoding.UTF8.GetByteCount(json) is < 1 or > MaximumDocumentBytes)
            throw Invalid("SENSOR_DELIVERY_DOCUMENT_SIZE_INVALID");
        using var parsed = JsonDocument.Parse(json, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 8
        });
        RequireExact(parsed.RootElement, DocumentFields);
        var document = JsonSerializer.Deserialize<EndpointDeliveryDocument>(
            json, JsonOptions) ?? throw Invalid("SENSOR_DELIVERY_DOCUMENT_INVALID");
        if (document.SchemaVersion != 1 || document.Profile != Profile ||
            document.State is not ("accepted" or "failed" or "claimed") ||
            (requireAccepted && document.State != "accepted") ||
            !TryUtc(document.AttemptedAt, out _) ||
            document.ServiceSourceCommit != manifest.Commit ||
            document.BindingDescriptorSha256 != manifest.BindingDescriptorSha256 ||
            document.CapabilitySnapshotId != binding.CapabilitySnapshotId ||
            document.CapabilityReportHash != binding.CapabilityReportHash ||
            document.BatchHash != expectedBatch.BatchHash ||
            document.BatchSequence != 0 || document.FactCount != 1 ||
            document.AutomaticRetryEnabled ||
            document.RemoteTransportEnabled || document.InboundListenerEnabled ||
            document.PollingEnabled || document.CommandChannelEnabled ||
            (document.State == "accepted" &&
                (!document.NetworkAttempted || document.ReasonCode != "accepted")) ||
            (document.State == "failed" && document.ReasonCode is not
                ("timeout" or "connection-failed" or "response-invalid")) ||
            (document.State == "failed" && !document.NetworkAttempted) ||
            (document.State == "claimed" &&
                (document.NetworkAttempted || document.ReasonCode != "pending")))
            throw Invalid("SENSOR_DELIVERY_DOCUMENT_INVALID");
        return document;
    }

    private static string Serialize(EndpointDeliveryDocument document)
    {
        var json = JsonSerializer.Serialize(document, JsonOptions);
        if (Encoding.UTF8.GetByteCount(json) > MaximumDocumentBytes)
            throw Invalid("SENSOR_DELIVERY_DOCUMENT_SIZE_INVALID");
        return json;
    }

    private static void RequireExact(JsonElement root, IReadOnlySet<string> expected)
    {
        if (root.ValueKind != JsonValueKind.Object)
            throw Invalid("SENSOR_DELIVERY_DOCUMENT_FIELDS_INVALID");
        var fields = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
            if (!fields.Add(property.Name))
                throw Invalid("SENSOR_DELIVERY_DOCUMENT_FIELDS_INVALID");
        if (!fields.SetEquals(expected))
            throw Invalid("SENSOR_DELIVERY_DOCUMENT_FIELDS_INVALID");
    }

    private static string Timestamp(DateTime value) =>
        value.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    private static bool TryUtc(string value, out DateTime parsed) =>
        DateTime.TryParseExact(
            value,
            "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out parsed);

    private static string Sha256(string value) => Convert.ToHexString(
        SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static IReadOnlySet<string> ExactSet(params string[] values) =>
        values.ToHashSet(StringComparer.Ordinal);

    private static InvalidDataException Invalid(string code) => new(code);
}

public sealed class EndpointOneShotDeliveryWorker(
    ISensorIdentitySigner identity,
    IEndpointBindingStore bindingStore,
    IGenuineScmProofStore genuineStore,
    IEndpointDeliveryStore deliveryStore,
    IInstallManifestBindingReader manifestReader,
    IInstallManifestTimestampReader manifestTimestampReader,
    ILoopbackFactTransport transport,
    TimeProvider timeProvider,
    ILogger<EndpointOneShotDeliveryWorker> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var bindingJson = bindingStore.ReadBinding();
        if (bindingJson is null || !EndpointBindingLifecycle.HasFinalProfile(bindingJson))
        {
            logger.LogInformation(
                "WAR-R00M Gate C0c final binding absent; loopback delivery stayed disabled.");
            return;
        }
        var capabilityProof = bindingStore.ReadCapabilityProof() ??
            throw new InvalidDataException("SENSOR_DELIVERY_CAPABILITY_PROOF_MISSING");
        var genuineProof = genuineStore.ReadExisting() ??
            throw new InvalidDataException("SENSOR_DELIVERY_GENUINE_PROOF_MISSING");
        var manifest = manifestReader.Read();
        var now = timeProvider.GetUtcNow().UtcDateTime;
        var final = EndpointBindingLifecycle.ValidateFinal(
            bindingJson, capabilityProof, identity.Descriptor, manifest.Commit, now);
        var manifestGeneratedAt = manifestTimestampReader.ReadUtc();
        var existing = deliveryStore.ReadExisting();
        var batch = EndpointOneShotDelivery.CreateBatch(
            bindingJson, capabilityProof, genuineProof, identity, manifest,
            manifestGeneratedAt, now, requireFreshCapability: existing is null);
        if (existing is not null)
        {
            var prior = EndpointOneShotDelivery.Validate(
                existing, batch, final, manifest, requireAccepted: false);
            if (prior.State != "accepted")
                throw new InvalidDataException(
                    prior.State == "failed"
                        ? "SENSOR_DELIVERY_PREVIOUS_FAILURE"
                        : "SENSOR_DELIVERY_PREVIOUS_INCOMPLETE");
            logger.LogInformation(
                "WAR-R00M Gate C0c delivery receipt already verified; no retry performed.");
            return;
        }

        deliveryStore.Write(EndpointOneShotDelivery.Claimed(
            batch, final, manifest, now));
        try
        {
            var receipt = await transport.SendOnceAsync(batch, cancellationToken)
                .ConfigureAwait(false);
            deliveryStore.Write(EndpointOneShotDelivery.Accepted(
                batch, receipt, final, manifest, now));
            logger.LogInformation(
                "WAR-R00M Gate C0c completed one loopback fact delivery; retry, remote transport, listeners and commands remain disabled.");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            deliveryStore.Write(EndpointOneShotDelivery.Failed(
                batch, final, manifest, now, "timeout"));
            throw;
        }
        catch (HttpRequestException)
        {
            deliveryStore.Write(EndpointOneShotDelivery.Failed(
                batch, final, manifest, now, "connection-failed"));
            throw;
        }
        catch (InvalidDataException error) when (
            error.Message.StartsWith("SENSOR_LOOPBACK_RESPONSE_", StringComparison.Ordinal) ||
            error.Message.StartsWith("SENSOR_LOOPBACK_RECEIPT_", StringComparison.Ordinal))
        {
            deliveryStore.Write(EndpointOneShotDelivery.Failed(
                batch, final, manifest, now, "response-invalid"));
            throw;
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
