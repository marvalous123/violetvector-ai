using System.Text;
using System.Text.Json;
using WARRoom.WindowsSensor;

try
{
    if (args.Length != 0)
    {
        throw new InvalidDataException(
            "SENSOR_GENUINE_PROOF_ARGUMENTS_DENIED");
    }

    var path = SensorBoundary.LocalGenuineBatchProofPath;
    if (
        !File.Exists(path) ||
        (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
    {
        throw new InvalidDataException("SENSOR_GENUINE_PROOF_FILE_INVALID");
    }
    var file = new FileInfo(path);
    if (file.Length > GenuineScmBatchProof.MaximumProofBytes)
    {
        throw new InvalidDataException("SENSOR_GENUINE_PROOF_SIZE_INVALID");
    }

    using var identity = CngMachineKeySigner.OpenProvisioned();
    if (file.Length == 0)
    {
        WriteResult(new
        {
            ok = true,
            command = "local-genuine-batch-check",
            result = new
            {
                proofMode = GenuineScmBatchProof.ProofMode,
                status = "no-match",
                machineProofComplete = false,
                certificateFingerprintSha256 =
                    identity.Descriptor.CertificateFingerprintSha256,
                batchCount = 0,
                factCount = 0,
                eventsRead = 0,
                genuineEventRead = false,
                rawEventContentRead = false,
                runtimeProofEventReaderEnabled = true,
                checkerEventReaderEnabled = false,
                networkTransportEnabled = false,
                inboundListenerEnabled = false,
                pollingEnabled = false,
                commandChannelEnabled = false
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
        new UTF8Encoding(
            encoderShouldEmitUTF8Identifier: false,
            throwOnInvalidBytes: true),
        detectEncodingFromByteOrderMarks: false))
    {
        json = reader.ReadToEnd();
    }

    var validation = GenuineScmBatchProof.Validate(json, identity);
    WriteResult(new
    {
        ok = true,
        command = "local-genuine-batch-check",
        result = new
        {
            proofMode = GenuineScmBatchProof.ProofMode,
            status = "verified",
            machineProofComplete = true,
            validation.CertificateFingerprintSha256,
            validation.GeneratedAtUtc,
            validation.ManifestGeneratedAtUtc,
            validation.OccurredAtUtc,
            validation.SourceRecordIdHash,
            validation.BatchHash,
            validation.BatchCount,
            validation.FactCount,
            validation.EventsRead,
            validation.GenuineEventRead,
            validation.RawEventContentRead,
            runtimeProofEventReaderEnabled = validation.EventReaderEnabled,
            checkerEventReaderEnabled = false,
            validation.NetworkTransportEnabled,
            validation.InboundListenerEnabled,
            validation.PollingEnabled,
            validation.CommandChannelEnabled
        }
    });
    return 0;
}
catch (DecoderFallbackException)
{
    Console.Error.WriteLine("SENSOR_GENUINE_PROOF_UTF8_INVALID");
    return 2;
}
catch (InvalidDataException error)
{
    Console.Error.WriteLine(error.Message);
    return 2;
}
catch (Exception)
{
    Console.Error.WriteLine("SENSOR_GENUINE_PROOF_CHECK_FAILED");
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
