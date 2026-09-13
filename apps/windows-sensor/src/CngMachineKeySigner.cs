using System.Security.Cryptography;
using System.Text;

namespace WARRoom.WindowsSensor;

public sealed record SensorIdentityDescriptor(
    string Algorithm,
    string PublicKeyFormat,
    string PublicKeySpkiBase64,
    string CertificateFingerprintSha256,
    string KeyProvider,
    string KeyPersistence);

public interface ISensorIdentitySigner : IDisposable
{
    SensorIdentityDescriptor Descriptor { get; }
    string SignUtf8Payload(string payload);
}

public static class NativeSignatureProfile
{
    public static byte[] Sign(ECDsa signer, ReadOnlySpan<byte> payload)
    {
        ArgumentNullException.ThrowIfNull(signer);
        if (payload.Length is < 1 or > SensorBoundary.MaximumSigningPayloadBytes)
        {
            throw new CryptographicException("SENSOR_SIGNING_PAYLOAD_SIZE_INVALID");
        }
        return signer.SignData(
            payload,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }
}

public sealed class CngMachineKeySigner : ISensorIdentitySigner
{
    private readonly ECDsaCng signer;

    private CngMachineKeySigner(ECDsaCng signer, SensorIdentityDescriptor descriptor)
    {
        this.signer = signer;
        Descriptor = descriptor;
    }

    public SensorIdentityDescriptor Descriptor { get; }

    public static CngMachineKeySigner OpenProvisioned()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("SENSOR_WINDOWS_REQUIRED");
        }

        var provider = new CngProvider(SensorBoundary.SoftwareProviderName);
        CngKey? key = null;
        ECDsaCng? signer = null;
        try
        {
            key = CngKey.Open(
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
                .GetValue() ??
                throw new CryptographicException("SENSOR_NATIVE_KEY_ACL_INVALID"));

            signer = new ECDsaCng(key);
            key.Dispose();
            key = null;
            var spki = signer.ExportSubjectPublicKeyInfo();
            var fingerprint = Convert.ToHexString(SHA256.HashData(spki)).ToLowerInvariant();
            var result = new CngMachineKeySigner(
                signer,
                new SensorIdentityDescriptor(
                    SensorBoundary.SignatureAlgorithm,
                    "spki-der",
                    Convert.ToBase64String(spki),
                    fingerprint,
                    SensorBoundary.SoftwareProviderName,
                    "non-exportable-machine-cng-software-ksp"));
            signer = null;
            return result;
        }
        catch
        {
            signer?.Dispose();
            key?.Dispose();
            throw;
        }
    }

    public string SignUtf8Payload(string payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        var byteCount = Encoding.UTF8.GetByteCount(payload);
        if (byteCount is < 1 or > SensorBoundary.MaximumSigningPayloadBytes)
        {
            throw new CryptographicException("SENSOR_SIGNING_PAYLOAD_SIZE_INVALID");
        }
        var encoded = Encoding.UTF8.GetBytes(payload);
        try
        {
            return Convert.ToBase64String(NativeSignatureProfile.Sign(signer, encoded));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    public void Dispose()
    {
        signer.Dispose();
    }
}

public sealed record NativeStartupProofResult(
    string PayloadSha256,
    string SignatureSha256);

public static class NativeStartupProof
{
    private const string Payload =
        "WAR-R00M.WindowsSensor.LocalServiceStartupProof.v1";

    public static NativeStartupProofResult Create(ISensorIdentitySigner identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        byte[]? payload = null;
        byte[]? signature = null;
        byte[]? spki = null;
        try
        {
            payload = Encoding.UTF8.GetBytes(Payload);
            signature = Convert.FromBase64String(identity.SignUtf8Payload(Payload));
            spki = Convert.FromBase64String(identity.Descriptor.PublicKeySpkiBase64);
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(spki, out var bytesRead);
            if (
                bytesRead != spki.Length ||
                signature.Length != 64 ||
                !verifier.VerifyData(
                    payload,
                    signature,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                throw new CryptographicException("SENSOR_STARTUP_PROOF_INVALID");
            }

            return new NativeStartupProofResult(
                Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant(),
                Convert.ToHexString(SHA256.HashData(signature)).ToLowerInvariant());
        }
        catch (FormatException error)
        {
            throw new CryptographicException("SENSOR_STARTUP_PROOF_INVALID", error);
        }
        catch (CryptographicException error) when (
            error.Message != "SENSOR_STARTUP_PROOF_INVALID")
        {
            throw new CryptographicException("SENSOR_STARTUP_PROOF_INVALID", error);
        }
        finally
        {
            if (payload is not null)
            {
                CryptographicOperations.ZeroMemory(payload);
            }
            if (signature is not null)
            {
                CryptographicOperations.ZeroMemory(signature);
            }
            if (spki is not null)
            {
                CryptographicOperations.ZeroMemory(spki);
            }
        }
    }
}
