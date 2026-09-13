using System.Text;
using System.Text.Json;
using WARRoom.WindowsSensor;

try
{
    if (args.Length != 0)
    {
        throw new InvalidDataException(
            "SENSOR_LOCAL_PROOF_ARGUMENTS_DENIED");
    }

    var path = SensorBoundary.LocalSyntheticBatchProofPath;
    if (
        !File.Exists(path) ||
        (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
    {
        throw new InvalidDataException("SENSOR_LOCAL_PROOF_FILE_INVALID");
    }

    var file = new FileInfo(path);
    if (
        file.Length is < 1 or > LocalSyntheticBatchProof.MaximumProofBytes)
    {
        throw new InvalidDataException("SENSOR_LOCAL_PROOF_SIZE_INVALID");
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

    using var identity = CngMachineKeySigner.OpenProvisioned();
    var validation = LocalSyntheticBatchProof.Validate(json, identity);
    Console.WriteLine(JsonSerializer.Serialize(
        new
        {
            ok = true,
            command = "local-synthetic-batch-check",
            result = new
            {
                proofMode = LocalSyntheticBatchProof.ProofMode,
                validation.CertificateFingerprintSha256,
                validation.GeneratedAtUtc,
                validation.BatchCount,
                validation.FirstBatchHash,
                validation.LastBatchHash,
                validation.SyntheticOnly,
                validation.EventReaderEnabled,
                validation.NetworkTransportEnabled,
                validation.InboundListenerEnabled,
                validation.CommandChannelEnabled,
                eventsRead = 0
            }
        },
        new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true
        }));
    return 0;
}
catch (DecoderFallbackException)
{
    Console.Error.WriteLine("SENSOR_LOCAL_PROOF_UTF8_INVALID");
    return 2;
}
catch (InvalidDataException error)
{
    Console.Error.WriteLine(error.Message);
    return 2;
}
catch (Exception)
{
    Console.Error.WriteLine("SENSOR_LOCAL_PROOF_CHECK_FAILED");
    return 3;
}
