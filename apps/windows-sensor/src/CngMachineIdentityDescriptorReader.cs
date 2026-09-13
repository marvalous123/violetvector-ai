using System.Buffers.Binary;
using System.Security.Cryptography;

namespace WARRoom.WindowsSensor;

// Read-only public-identity boundary for external verification tools. This
// type exposes no signing method and implements no signing interface.
public sealed class CngMachineIdentityDescriptorReader
{
    public SensorIdentityDescriptor ReadProvisioned()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("SENSOR_WINDOWS_REQUIRED");
        }

        var provider = new CngProvider(SensorBoundary.SoftwareProviderName);
        using var key = CngKey.Open(
            SensorBoundary.IdentityKeyName,
            provider,
            CngKeyOpenOptions.MachineKey);
        SensorIdentityPolicy.Validate(new NativeKeyMetadata(
            key.KeyName ?? string.Empty,
            key.Provider?.Provider ?? string.Empty,
            key.Algorithm.Algorithm,
            key.AlgorithmGroup?.AlgorithmGroup ?? string.Empty,
            key.KeySize,
            key.IsMachineKey,
            key.IsEphemeral,
            key.ExportPolicy,
            key.KeyUsage));
        NativeKeyAccessPolicy.Validate(
            key.GetProperty(
                NativeKeyAccessPolicy.SecurityDescriptorPropertyName,
                NativeKeyAccessPolicy.ReadOptions)
            .GetValue() ?? throw new CryptographicException(
                "SENSOR_NATIVE_KEY_ACL_INVALID"));

        var publicBlob = key.Export(CngKeyBlobFormat.EccPublicBlob);
        ECParameters publicParameters = default;
        byte[]? spki = null;
        try
        {
            publicParameters = ParseP256PublicBlob(publicBlob);
            using var publicReader = ECDsa.Create(publicParameters);
            spki = publicReader.ExportSubjectPublicKeyInfo();
            return new SensorIdentityDescriptor(
                SensorBoundary.SignatureAlgorithm,
                "spki-der",
                Convert.ToBase64String(spki),
                Convert.ToHexString(SHA256.HashData(spki)).ToLowerInvariant(),
                SensorBoundary.SoftwareProviderName,
                "non-exportable-machine-cng-software-ksp");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicBlob);
            if (publicParameters.Q.X is not null)
            {
                CryptographicOperations.ZeroMemory(publicParameters.Q.X);
            }
            if (publicParameters.Q.Y is not null)
            {
                CryptographicOperations.ZeroMemory(publicParameters.Q.Y);
            }
            if (spki is not null)
            {
                CryptographicOperations.ZeroMemory(spki);
            }
        }
    }

    internal static ECParameters ParseP256PublicBlob(ReadOnlySpan<byte> blob)
    {
        const uint ecdsaPublicP256Magic = 0x31534345;
        const int coordinateBytes = 32;
        const int headerBytes = 8;
        if (
            blob.Length != headerBytes + (coordinateBytes * 2) ||
            BinaryPrimitives.ReadUInt32LittleEndian(blob) !=
                ecdsaPublicP256Magic ||
            BinaryPrimitives.ReadUInt32LittleEndian(blob[4..]) !=
                coordinateBytes)
        {
            throw new CryptographicException(
                "SENSOR_NATIVE_PUBLIC_KEY_BLOB_INVALID");
        }
        return new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = blob.Slice(headerBytes, coordinateBytes).ToArray(),
                Y = blob.Slice(
                    headerBytes + coordinateBytes,
                    coordinateBytes).ToArray()
            }
        };
    }
}
