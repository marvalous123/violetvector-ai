using System.Collections.Frozen;
using System.Security.Cryptography;
using System.Text;

namespace WARRoom.WindowsSensor;

public enum NativeIdentityProvisionerCommand
{
    Plan,
    Status,
    Provision,
    EnrollmentIdentity,
    SignEnrollmentChallenge,
    ProbePlan,
    ProbeStatus,
    ProbeCleanup
}

public static class NativeIdentityProvisionerCommandParser
{
    public static IReadOnlySet<string> SupportedCommands { get; } =
        new[]
        {
            "plan",
            "status",
            "provision",
            "enrollment-identity",
            "sign-enrollment-challenge",
            "probe-plan",
            "probe-status",
            "probe-cleanup"
        }
            .ToFrozenSet(StringComparer.Ordinal);

    public static NativeIdentityProvisionerCommand Parse(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Length != 1 || !SupportedCommands.Contains(args[0]))
        {
            throw new InvalidDataException("SENSOR_PROVISIONER_COMMAND_INVALID");
        }

        return args[0] switch
        {
            "plan" => NativeIdentityProvisionerCommand.Plan,
            "status" => NativeIdentityProvisionerCommand.Status,
            "provision" => NativeIdentityProvisionerCommand.Provision,
            "enrollment-identity" => NativeIdentityProvisionerCommand.EnrollmentIdentity,
            "sign-enrollment-challenge" =>
                NativeIdentityProvisionerCommand.SignEnrollmentChallenge,
            "probe-plan" => NativeIdentityProvisionerCommand.ProbePlan,
            "probe-status" => NativeIdentityProvisionerCommand.ProbeStatus,
            "probe-cleanup" => NativeIdentityProvisionerCommand.ProbeCleanup,
            _ => throw new InvalidDataException("SENSOR_PROVISIONER_COMMAND_INVALID")
        };
    }
}

public sealed record NativeIdentityProvisioningPlan(
    string Profile,
    string KeyName,
    string Provider,
    string Algorithm,
    string Scope,
    string Usage,
    string ExportPolicy,
    string ServiceIdentity,
    string ServiceAccess,
    bool RequiresElevation,
    bool ReplacesExistingIdentity,
    bool PermitsCommandChannel);

public sealed record NativeIdentityStatus(
    bool Exists,
    bool PolicyValid,
    string? ErrorCode,
    string Profile,
    string KeyName,
    string Provider,
    string? PublicKeyFingerprintSha256,
    bool? AclVerified);

public sealed record NativeIdentityProvisioningProof(
    string PayloadBase64,
    string SignatureBase64);

public sealed record NativeIdentityProvisioningResult(
    string Profile,
    string KeyName,
    string Provider,
    string Algorithm,
    string PublicKeyFormat,
    string PublicKeySpkiBase64,
    string PublicKeyFingerprintSha256,
    bool AclVerified,
    bool PrivateExportBlocked,
    NativeIdentityProvisioningProof Proof);

public interface IProvisionedNativeIdentity : IDisposable
{
    NativeKeyMetadata Metadata { get; }
    byte[] ReadSecurityDescriptor();
    byte[] ExportPublicKeySpki();
    byte[] Sign(ReadOnlySpan<byte> payload);
    bool IsPrivateExportBlocked();
    void Delete();
}

public interface INativeIdentityKeyStore
{
    bool Exists();
    IProvisionedNativeIdentity Open();
    IProvisionedNativeIdentity Create();
}

public static class NativeIdentityProvisioner
{
    private const string ProofPayload =
        "WAR-R00M.WindowsSensor.Identity.ProvisioningProof.v1";

    public static NativeIdentityProvisioningPlan BuildPlan() =>
        new(
            SensorBoundary.NativeIdentityProfile,
            SensorBoundary.IdentityKeyName,
            SensorBoundary.SoftwareProviderName,
            SensorBoundary.SignatureAlgorithm,
            "machine",
            "signing-only",
            "non-exportable",
            SensorBoundary.ExpectedServiceIdentity,
            "generic-read-only",
            RequiresElevation: true,
            ReplacesExistingIdentity: false,
            PermitsCommandChannel: false);

    public static NativeIdentityStatus ReadStatus(INativeIdentityKeyStore keyStore)
    {
        ArgumentNullException.ThrowIfNull(keyStore);
        if (!keyStore.Exists())
        {
            return new NativeIdentityStatus(
                Exists: false,
                PolicyValid: false,
                ErrorCode: null,
                SensorBoundary.NativeIdentityProfile,
                SensorBoundary.IdentityKeyName,
                SensorBoundary.SoftwareProviderName,
                PublicKeyFingerprintSha256: null,
                AclVerified: null);
        }

        try
        {
            using var identity = keyStore.Open();
            SensorIdentityPolicy.Validate(identity.Metadata);
            NativeKeyAccessPolicy.Validate(identity.ReadSecurityDescriptor());
            if (!identity.IsPrivateExportBlocked())
            {
                throw new CryptographicException("SENSOR_NATIVE_KEY_EXPORTABLE");
            }
            var spki = identity.ExportPublicKeySpki();
            return new NativeIdentityStatus(
                Exists: true,
                PolicyValid: true,
                ErrorCode: null,
                SensorBoundary.NativeIdentityProfile,
                SensorBoundary.IdentityKeyName,
                SensorBoundary.SoftwareProviderName,
                Convert.ToHexString(SHA256.HashData(spki)).ToLowerInvariant(),
                AclVerified: true);
        }
        catch (CryptographicException error)
        {
            return new NativeIdentityStatus(
                Exists: true,
                PolicyValid: false,
                ErrorCode: ToPublicErrorCode(error),
                SensorBoundary.NativeIdentityProfile,
                SensorBoundary.IdentityKeyName,
                SensorBoundary.SoftwareProviderName,
                PublicKeyFingerprintSha256: null,
                AclVerified: false);
        }
    }

    public static NativeIdentityProvisioningResult Provision(INativeIdentityKeyStore keyStore)
    {
        ArgumentNullException.ThrowIfNull(keyStore);
        if (keyStore.Exists())
        {
            throw new CryptographicException("SENSOR_NATIVE_KEY_ALREADY_EXISTS");
        }

        IProvisionedNativeIdentity? created = null;
        var completed = false;
        try
        {
            created = keyStore.Create();
            SensorIdentityPolicy.Validate(created.Metadata);
            NativeKeyAccessPolicy.Validate(created.ReadSecurityDescriptor());
            if (!created.IsPrivateExportBlocked())
            {
                throw new CryptographicException("SENSOR_NATIVE_KEY_EXPORTABLE");
            }

            var payload = Encoding.UTF8.GetBytes(ProofPayload);
            try
            {
                var signature = created.Sign(payload);
                var spki = created.ExportPublicKeySpki();
                VerifyProof(spki, payload, signature);
                var result = new NativeIdentityProvisioningResult(
                    SensorBoundary.NativeIdentityProfile,
                    SensorBoundary.IdentityKeyName,
                    SensorBoundary.SoftwareProviderName,
                    SensorBoundary.SignatureAlgorithm,
                    "spki-der",
                    Convert.ToBase64String(spki),
                    Convert.ToHexString(SHA256.HashData(spki)).ToLowerInvariant(),
                    AclVerified: true,
                    PrivateExportBlocked: true,
                    new NativeIdentityProvisioningProof(
                        Convert.ToBase64String(payload),
                        Convert.ToBase64String(signature)));
                completed = true;
                return result;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload);
            }
        }
        finally
        {
            if (created is not null)
            {
                try
                {
                    if (!completed)
                    {
                        created.Delete();
                    }
                }
                finally
                {
                    created.Dispose();
                }
            }
        }
    }

    private static void VerifyProof(byte[] spki, byte[] payload, byte[] signature)
    {
        try
        {
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
                throw new CryptographicException("SENSOR_NATIVE_KEY_PROOF_INVALID");
            }
        }
        catch (CryptographicException error) when (
            error.Message != "SENSOR_NATIVE_KEY_PROOF_INVALID")
        {
            throw new CryptographicException("SENSOR_NATIVE_KEY_PROOF_INVALID", error);
        }
    }

    private static string ToPublicErrorCode(CryptographicException error) =>
        error.Message is
            "SENSOR_NATIVE_KEY_POLICY_INVALID" or
            "SENSOR_NATIVE_KEY_ACL_INVALID" or
            "SENSOR_NATIVE_KEY_EXPORTABLE"
                ? error.Message
                : "SENSOR_NATIVE_KEY_STATUS_INVALID";
}

public sealed class CngNativeIdentityKeyStore : INativeIdentityKeyStore
{
    private static readonly CngProvider Provider =
        new(SensorBoundary.SoftwareProviderName);

    public bool Exists()
    {
        RequireWindows();
        return CngKey.Exists(
            SensorBoundary.IdentityKeyName,
            Provider,
            CngKeyOpenOptions.MachineKey);
    }

    public IProvisionedNativeIdentity Open()
    {
        RequireWindows();
        return new CngProvisionedNativeIdentity(CngKey.Open(
            SensorBoundary.IdentityKeyName,
            Provider,
            CngKeyOpenOptions.MachineKey));
    }

    public IProvisionedNativeIdentity Create()
    {
        RequireWindows();
        var parameters = new CngKeyCreationParameters
        {
            Provider = Provider,
            ExportPolicy = CngExportPolicies.None,
            KeyCreationOptions = CngKeyCreationOptions.MachineKey,
            KeyUsage = CngKeyUsages.Signing
        };
        parameters.Parameters.Add(new CngProperty(
            NativeKeyAccessPolicy.SecurityDescriptorPropertyName,
            NativeKeyAccessPolicy.CreateProtectedDescriptor(),
            NativeKeyAccessPolicy.CreateOptions));

        return new CngProvisionedNativeIdentity(CngKey.Create(
            CngAlgorithm.ECDsaP256,
            SensorBoundary.IdentityKeyName,
            parameters));
    }

    private static void RequireWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("SENSOR_WINDOWS_REQUIRED");
        }
    }
}

internal sealed class CngProvisionedNativeIdentity(CngKey key)
    : IProvisionedNativeIdentity
{
    private CngKey? key = key ?? throw new ArgumentNullException(nameof(key));

    public NativeKeyMetadata Metadata
    {
        get
        {
            var current = GetKey();
            return new NativeKeyMetadata(
                current.KeyName ?? string.Empty,
                current.Provider?.Provider ?? string.Empty,
                current.Algorithm.Algorithm,
                current.AlgorithmGroup?.AlgorithmGroup ?? string.Empty,
                current.KeySize,
                current.IsMachineKey,
                current.IsEphemeral,
                current.ExportPolicy,
                current.KeyUsage);
        }
    }

    public byte[] ReadSecurityDescriptor() =>
        GetKey()
            .GetProperty(
                NativeKeyAccessPolicy.SecurityDescriptorPropertyName,
                NativeKeyAccessPolicy.ReadOptions)
            .GetValue() ??
        throw new CryptographicException("SENSOR_NATIVE_KEY_ACL_INVALID");

    public byte[] ExportPublicKeySpki()
    {
        using var signer = new ECDsaCng(GetKey());
        return signer.ExportSubjectPublicKeyInfo();
    }

    public byte[] Sign(ReadOnlySpan<byte> payload)
    {
        using var signer = new ECDsaCng(GetKey());
        return NativeSignatureProfile.Sign(signer, payload);
    }

    public bool IsPrivateExportBlocked()
    {
        byte[]? exported = null;
        try
        {
            exported = GetKey().Export(CngKeyBlobFormat.EccPrivateBlob);
            return false;
        }
        catch (CryptographicException)
        {
            return true;
        }
        finally
        {
            if (exported is not null)
            {
                CryptographicOperations.ZeroMemory(exported);
            }
        }
    }

    public void Delete()
    {
        var current = GetKey();
        current.Delete();
        current.Dispose();
        key = null;
    }

    public void Dispose()
    {
        key?.Dispose();
        key = null;
    }

    private CngKey GetKey() =>
        key ?? throw new ObjectDisposedException(nameof(CngProvisionedNativeIdentity));
}
