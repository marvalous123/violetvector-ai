using System.Collections.Frozen;
using System.Security.Cryptography;

namespace WARRoom.WindowsSensor;

public static class SensorBoundary
{
    public const string ServiceName = "WARRoomWindowsSensor";
    public const string ServiceDisplayName = "WAR-R00M Windows Sensor";
    public const string ExpectedServiceIdentity = @"NT AUTHORITY\LocalService";
    public const string IdentityKeyName = "WAR-R00M.WindowsSensor.Identity.v1";
    public const string NativeIdentityProfile = "software-ksp-machine-v1";
    public const string SoftwareProviderName = "Microsoft Software Key Storage Provider";
    public const string ExperimentalPlatformProviderName = "Microsoft Platform Crypto Provider";
    public const string SignatureAlgorithm = "ecdsa-p256-sha256";
    public const int MaximumSigningPayloadBytes = 1_048_576;
    public static string LocalSyntheticBatchProofPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "WAR-R00M",
        "Windows Sensor",
        "local-synthetic-batch-proof.json");
    public static string LocalGenuineBatchProofPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "WAR-R00M",
        "Windows Sensor",
        "local-genuine-batch-proof.json");
    public static string LocalGenuineSourceSaltPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "WAR-R00M",
        "Windows Sensor",
        "local-genuine-source-salt.bin");
    public static string LocalBoundedCollectorProofPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "WAR-R00M",
        "Windows Sensor",
        "local-bounded-collector-proof.json");
    public static string EndpointBindingPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "WAR-R00M", "Windows Sensor", "endpoint-binding.json");
    public static string LocalCapabilityProofPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "WAR-R00M", "Windows Sensor", "local-capability-proof.json");
    public static string LocalLoopbackDeliveryPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "WAR-R00M", "Windows Sensor", "local-loopback-delivery.json");

    public static bool PermitsInboundListener => false;
    public static bool PermitsCommandChannel => false;
    public static bool PermitsJobPolling => false;
    public static bool PermitsResponseActions => false;

    public static IReadOnlySet<string> ReceiptFields { get; } =
        new[]
        {
            "acceptedSequence",
            "batchId",
            "receiptHash"
        }.ToFrozenSet(StringComparer.Ordinal);

    public static void ValidateReceiptFields(IEnumerable<string> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        var supplied = fields.ToHashSet(StringComparer.Ordinal);
        if (!supplied.SetEquals(ReceiptFields))
        {
            throw new InvalidDataException("SENSOR_RECEIPT_FIELDS_INVALID");
        }
    }
}

public sealed record NativeKeyMetadata(
    string KeyName,
    string ProviderName,
    string Algorithm,
    string AlgorithmGroup,
    int KeySize,
    bool IsMachineKey,
    bool IsEphemeral,
    CngExportPolicies ExportPolicy,
    CngKeyUsages KeyUsage);

public static class SensorIdentityPolicy
{
    public static void Validate(NativeKeyMetadata key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (
            !StringComparer.Ordinal.Equals(key.KeyName, SensorBoundary.IdentityKeyName) ||
            !StringComparer.Ordinal.Equals(key.ProviderName, SensorBoundary.SoftwareProviderName) ||
            !StringComparer.Ordinal.Equals(key.Algorithm, CngAlgorithm.ECDsaP256.Algorithm) ||
            !StringComparer.Ordinal.Equals(key.AlgorithmGroup, CngAlgorithmGroup.ECDsa.AlgorithmGroup) ||
            key.KeySize != 256 ||
            !key.IsMachineKey ||
            key.IsEphemeral ||
            key.ExportPolicy != CngExportPolicies.None ||
            key.KeyUsage != CngKeyUsages.Signing)
        {
            throw new CryptographicException("SENSOR_NATIVE_KEY_POLICY_INVALID");
        }
    }
}
