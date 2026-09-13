using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using WARRoom.WindowsSensor;

try
{
    RequireWindowsAdministrator();
    if (args.Length != 1 || args[0] is not
        ("create-pending" or "finalize" or "check-pending" or "check-final" or
         "check-delivery"))
        throw new InvalidDataException("SENSOR_BINDING_TOOL_COMMAND_INVALID");

    using var identity = CngMachineKeySigner.OpenProvisioned();
    var manifest = new FixedInstallManifestBindingReader().Read();
    if (manifest.Fingerprint != identity.Descriptor.CertificateFingerprintSha256)
        throw new InvalidDataException("SENSOR_BINDING_MANIFEST_IDENTITY_MISMATCH");
    var store = new FixedEndpointBindingStore();
    var now = DateTime.UtcNow;
    object result = args[0] switch
    {
        "create-pending" => CreatePending(ReadBoundedInput(), identity, manifest, now),
        "finalize" => Finalize(ReadBoundedInput(), identity, manifest, store, now),
        "check-pending" => CheckPending(identity, manifest, store, now),
        "check-final" => CheckFinal(identity, manifest, store, now),
        "check-delivery" => CheckDelivery(identity, manifest, store, now),
        _ => throw new InvalidDataException("SENSOR_BINDING_TOOL_COMMAND_INVALID")
    };
    Console.WriteLine(JsonSerializer.Serialize(result, CreateJsonOptions()));
    return 0;
}
catch (Exception error) when (error is CryptographicException or InvalidDataException or
    IOException or JsonException or PlatformNotSupportedException or UnauthorizedAccessException)
{
    Console.Error.WriteLine(JsonSerializer.Serialize(new
    {
        ok = false,
        error = error.Message.StartsWith("SENSOR_", StringComparison.Ordinal)
            ? error.Message
            : "SENSOR_BINDING_TOOL_FAILED"
    }, CreateJsonOptions()));
    return 1;
}

static object CreatePending(
    string candidate,
    ISensorIdentitySigner identity,
    InstallManifestBinding manifest,
    DateTime now)
{
    var descriptor = EndpointBindingLifecycle.SerializePending(
        EndpointBindingLifecycle.CreatePending(
            candidate, identity.Descriptor, manifest.Commit, now));
    return DescriptorResult("create-pending", descriptor, "capability-pending");
}

static object Finalize(
    string input,
    ISensorIdentitySigner identity,
    InstallManifestBinding manifest,
    IEndpointBindingStore store,
    DateTime now)
{
    var pendingJson = store.ReadBinding() ??
        throw new InvalidDataException("SENSOR_PENDING_BINDING_MISSING");
    var proofJson = store.ReadCapabilityProof() ??
        throw new InvalidDataException("SENSOR_CAPABILITY_PROOF_MISSING");
    var pending = EndpointBindingLifecycle.ValidatePending(
        pendingJson, identity.Descriptor, manifest.Commit, now);
    var proof = EndpointBindingLifecycle.ValidateCapabilityProof(
        proofJson, pending, identity.Descriptor, now);
    var descriptor = EndpointBindingLifecycle.SerializeFinal(
        EndpointBindingLifecycle.FinalizeBinding(
            input, pending, proof, identity.Descriptor, manifest.Commit, now));
    return DescriptorResult("finalize", descriptor, "coverage-blocked");
}

static object CheckPending(
    ISensorIdentitySigner identity,
    InstallManifestBinding manifest,
    IEndpointBindingStore store,
    DateTime now)
{
    var bindingJson = store.ReadBinding() ??
        throw new InvalidDataException("SENSOR_PENDING_BINDING_MISSING");
    var proofJson = store.ReadCapabilityProof() ??
        throw new InvalidDataException("SENSOR_CAPABILITY_PROOF_MISSING");
    var binding = EndpointBindingLifecycle.ValidatePending(
        bindingJson, identity.Descriptor, manifest.Commit, now);
    var proof = EndpointBindingLifecycle.ValidateCapabilityProof(
        proofJson, binding, identity.Descriptor, now);
    return CheckResult("check-pending", binding.State, proof, manifest);
}

static object CheckFinal(
    ISensorIdentitySigner identity,
    InstallManifestBinding manifest,
    IEndpointBindingStore store,
    DateTime now)
{
    var bindingJson = store.ReadBinding() ??
        throw new InvalidDataException("SENSOR_FINAL_BINDING_MISSING");
    var proofJson = store.ReadCapabilityProof() ??
        throw new InvalidDataException("SENSOR_CAPABILITY_PROOF_MISSING");
    var binding = EndpointBindingLifecycle.ValidateFinal(
        bindingJson, proofJson, identity.Descriptor, manifest.Commit, now);
    if (!DateTime.TryParseExact(binding.CapabilityFreshUntil,
        "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", null,
        System.Globalization.DateTimeStyles.AssumeUniversal |
        System.Globalization.DateTimeStyles.AdjustToUniversal,
        out var freshUntil) || now >= freshUntil)
        throw new InvalidDataException("SENSOR_FINAL_BINDING_CAPABILITY_STALE");
    var pending = new PendingEndpointBinding(
        binding.SchemaVersion, EndpointBindingLifecycle.PendingProfile,
        binding.State, binding.MissionId, binding.ConnectorId, binding.EndpointId,
        binding.EnrollmentChallengeId, binding.CertificateFingerprintSha256,
        binding.IdentityIssuedAt, binding.IdentityExpiresAt, binding.Provider,
        binding.Channel, binding.EventFamily, binding.Fields, binding.FilterHash,
        binding.CollectorVersion, binding.ServiceSourceCommit, false, false, false);
    var proof = EndpointBindingLifecycle.ValidateCapabilityProof(
        proofJson, pending, identity.Descriptor, now);
    return CheckResult("check-final", binding.State, proof, manifest);
}

static object CheckDelivery(
    ISensorIdentitySigner identity,
    InstallManifestBinding manifest,
    IEndpointBindingStore store,
    DateTime now)
{
    var bindingJson = store.ReadBinding() ??
        throw new InvalidDataException("SENSOR_FINAL_BINDING_MISSING");
    var proofJson = store.ReadCapabilityProof() ??
        throw new InvalidDataException("SENSOR_CAPABILITY_PROOF_MISSING");
    var genuineJson = new FixedGenuineScmProofStore().ReadExisting() ??
        throw new InvalidDataException("SENSOR_DELIVERY_GENUINE_PROOF_MISSING");
    var deliveryJson = new FixedEndpointDeliveryStore().ReadExisting() ??
        throw new InvalidDataException("SENSOR_DELIVERY_RECEIPT_MISSING");
    var final = EndpointBindingLifecycle.ValidateFinal(
        bindingJson, proofJson, identity.Descriptor, manifest.Commit, now);
    var batch = EndpointOneShotDelivery.CreateBatch(
        bindingJson, proofJson, genuineJson, identity, manifest,
        FixedInstallManifestTimestamp.ReadUtc(), now,
        requireFreshCapability: false);
    var delivery = EndpointOneShotDelivery.Validate(
        deliveryJson, batch, final, manifest, requireAccepted: true);
    return new
    {
        ok = true,
        command = "check-delivery",
        state = delivery.State,
        manifestBound = true,
        bindingDescriptorSha256 = manifest.BindingDescriptorSha256,
        capabilityReportHash = delivery.CapabilityReportHash,
        batchHash = delivery.BatchHash,
        batchSequence = delivery.BatchSequence,
        factCount = delivery.FactCount,
        networkAttempts = 1,
        eventsRead = 0,
        serviceMutated = false,
        automaticRetryEnabled = false,
        remoteTransportEnabled = false,
        inboundListenerEnabled = false,
        pollingEnabled = false,
        commandChannelEnabled = false
    };
}

static object DescriptorResult(string command, string descriptor, string state)
{
    var bytes = Encoding.UTF8.GetBytes(descriptor);
    return new
    {
        ok = true,
        command,
        descriptorBase64 = Convert.ToBase64String(bytes),
        descriptorSha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),
        state,
        collectorEnabled = false,
        telemetryEnabled = false,
        commandChannelEnabled = false
    };
}

static object CheckResult(
    string command,
    string state,
    SignedEndpointCapabilityProof proof,
    InstallManifestBinding manifest) => new
{
    ok = true,
    command,
    state,
    manifestBound = true,
    bindingDescriptorSha256 = manifest.BindingDescriptorSha256,
    capabilityReportHash = proof.ReportHash,
    lossState = proof.Loss.State,
    continuity = proof.Continuity,
    capabilityFresh = true,
    eventsRead = 0,
    serviceMutated = false,
    networkTransportEnabled = false,
    collectorEnabled = false,
    telemetryEnabled = false,
    commandChannelEnabled = false
};

static string ReadBoundedInput()
{
    var buffer = new char[EndpointBindingLifecycle.MaximumDocumentBytes + 1];
    var total = 0;
    while (total < buffer.Length)
    {
        var read = Console.In.Read(buffer, total, buffer.Length - total);
        if (read == 0) break;
        total += read;
    }
    if (total > EndpointBindingLifecycle.MaximumDocumentBytes || Console.In.Peek() != -1)
        throw new InvalidDataException("SENSOR_BINDING_INPUT_INVALID");
    var input = new string(buffer, 0, total);
    if (Encoding.UTF8.GetByteCount(input) > EndpointBindingLifecycle.MaximumDocumentBytes)
        throw new InvalidDataException("SENSOR_BINDING_INPUT_INVALID");
    return input;
}

static void RequireWindowsAdministrator()
{
    if (!OperatingSystem.IsWindows())
        throw new PlatformNotSupportedException("SENSOR_WINDOWS_REQUIRED");
    using var identity = WindowsIdentity.GetCurrent();
    if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        throw new UnauthorizedAccessException("SENSOR_ADMINISTRATOR_REQUIRED");
}

static JsonSerializerOptions CreateJsonOptions() => new()
{
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    WriteIndented = true
};
