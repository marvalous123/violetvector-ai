using System.Text;
using System.Text.Json;
using WARRoom.WindowsSensor;

try
{
    if (args.Length != 0)
    {
        throw new InvalidDataException("SENSOR_C1_PROOF_ARGUMENTS_DENIED");
    }
    var path = SensorBoundary.LocalBoundedCollectorProofPath;
    if (
        !File.Exists(path) ||
        (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
    {
        throw new InvalidDataException("SENSOR_C1_PROOF_FILE_INVALID");
    }
    var file = new FileInfo(path);
    if (file.Length > BoundedCollectorProof.MaximumProofBytes)
    {
        throw new InvalidDataException("SENSOR_C1_PROOF_SIZE_INVALID");
    }
    using var identity = CngMachineKeySigner.OpenProvisioned();
    if (file.Length == 0)
    {
        WriteResult(new
        {
            ok = true,
            command = "bounded-collector-check",
            result = new
            {
                proofMode = BoundedCollectorProof.ProofMode,
                status = "pending",
                machineProofComplete = false,
                certificateFingerprintSha256 =
                    identity.Descriptor.CertificateFingerprintSha256,
                familiesQueried = 0,
                eventsRead = 0,
                matchCount = 0,
                noMatchCount = 0,
                failureCount = 0,
                rawEventContentRead = false,
                runtimeProofEventReaderEnabled = true,
                checkerEventReaderEnabled = false,
                networkTransportEnabled = false,
                automaticRetryEnabled = false,
                pollingEnabled = false,
                inboundListenerEnabled = false,
                commandChannelEnabled = false,
                responseActionsEnabled = false,
                serviceMutated = false
            }
        });
        return 0;
    }

    string json;
    using (var input = new FileStream(
        path,
        FileMode.Open,
        FileAccess.Read,
        FileShare.ReadWrite,
        bufferSize: 4096,
        FileOptions.SequentialScan))
    using (var reader = new StreamReader(
        input,
        new UTF8Encoding(false, true),
        detectEncodingFromByteOrderMarks: false))
    {
        json = reader.ReadToEnd();
    }
    var validation = BoundedCollectorProof.ValidateForManifest(
        json,
        identity,
        FixedInstallManifestTimestamp.ReadUtc());
    WriteResult(new
    {
        ok = true,
        command = "bounded-collector-check",
        result = new
        {
            proofMode = BoundedCollectorProof.ProofMode,
            status = "verified",
            machineProofComplete = true,
            validation.CertificateFingerprintSha256,
            validation.GeneratedAtUtc,
            validation.ManifestGeneratedAtUtc,
            validation.ProofHash,
            validation.FamiliesQueried,
            validation.EventsRead,
            validation.MatchCount,
            validation.NoMatchCount,
            validation.FailureCount,
            validation.RawEventContentRead,
            validation.RuntimeProofEventReaderEnabled,
            checkerEventReaderEnabled = false,
            validation.NetworkTransportEnabled,
            validation.AutomaticRetryEnabled,
            validation.PollingEnabled,
            validation.InboundListenerEnabled,
            validation.CommandChannelEnabled,
            validation.ResponseActionsEnabled,
            serviceMutated = false
        }
    });
    return 0;
}
catch (DecoderFallbackException)
{
    Console.Error.WriteLine("SENSOR_C1_PROOF_UTF8_INVALID");
    return 2;
}
catch (InvalidDataException error)
{
    Console.Error.WriteLine(error.Message);
    return 2;
}
catch (Exception)
{
    Console.Error.WriteLine("SENSOR_C1_PROOF_CHECK_FAILED");
    return 3;
}

static void WriteResult(object value) =>
    Console.WriteLine(JsonSerializer.Serialize(
        value,
        new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true
        }));
