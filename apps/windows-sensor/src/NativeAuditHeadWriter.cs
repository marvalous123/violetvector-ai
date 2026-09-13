using System.Collections.Frozen;
using System.Globalization;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace WARRoom.WindowsSensor;

public enum NativeAuditHeadWriterCommand
{
    Plan,
    Status,
    Provision
}

public static class NativeAuditHeadWriterCommandParser
{
    private static readonly IReadOnlySet<string> Commands = new[]
    {
        "plan", "status", "provision"
    }.ToFrozenSet(StringComparer.Ordinal);

    public static NativeAuditHeadWriterCommand Parse(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Length != 1 || !Commands.Contains(args[0]))
        {
            throw new InvalidDataException(
                "SENSOR_AUDIT_HEAD_COMMAND_INVALID");
        }
        return args[0] switch
        {
            "plan" => NativeAuditHeadWriterCommand.Plan,
            "status" => NativeAuditHeadWriterCommand.Status,
            "provision" => NativeAuditHeadWriterCommand.Provision,
            _ => throw new InvalidDataException(
                "SENSOR_AUDIT_HEAD_COMMAND_INVALID")
        };
    }
}

public sealed record NativeAuditHeadWriterPlan(
    int SchemaVersion,
    string KeyName,
    string KeyProvider,
    string KeyAlgorithm,
    string PendingPath,
    string StatePath,
    IReadOnlyList<string> Commands,
    bool AcceptsCallerPath,
    bool AcceptsCallerKey,
    bool AcceptsCallerSid,
    bool AcceptsCallerService,
    bool AcceptsCallerAlgorithm,
    bool AcceptsCallerPayload,
    bool RequiresElevationForMutation,
    bool CheckpointEnabled,
    bool StateOrdinaryUserReadable,
    bool StateOrdinaryUserWritable,
    bool UsesSensorIdentity,
    bool ServiceWired,
    bool IpcEnabled,
    bool NetworkEnabled,
    bool DatabaseAccessEnabled);

public sealed record NativeAuditHeadWriterStatus(
    bool KeyExists,
    bool StateExists,
    AuditHeadProtectedState? State);

public sealed record NativeAuditHeadProvisioningResult(
    AuditHeadSignerDescriptor Descriptor,
    bool AclVerified,
    bool PrivateExportBlocked,
    string ProofSignatureBase64);

public interface IAuditHeadWriterIdentity :
    IAuditHeadCheckpointSigner,
    IDisposable
{
    NativeKeyMetadata Metadata { get; }
    byte[] ReadSecurityDescriptor();
    bool IsPrivateExportBlocked();
    void Delete();
}

public interface IAuditHeadWriterKeyStore
{
    bool Exists();
    IAuditHeadWriterIdentity Open();
    IAuditHeadWriterIdentity Create();
}

public interface IAuditHeadPendingProofStore
{
    string ReadFixed();
}

public static class NativeAuditHeadWriter
{
    public const string KeyName = "Project15.AuditHeadSigner.v1";
    public const string PendingPath =
        @"C:\ProgramData\Project15 Audit Head\Pending\audit-head-pending-v1.json";
    public const string StatePath =
        @"C:\ProgramData\Project15 Audit Head\Protected\audit-head-state-v1.json";
    public const int MaximumPendingBytes = 131_072;
    private const string ProofPayload =
        "project15.audit-head-signer.provisioning-proof.v1";

    public static NativeAuditHeadWriterPlan BuildPlan() => new(
        1,
        KeyName,
        SensorBoundary.SoftwareProviderName,
        AuditHeadCheckpoint.Algorithm,
        PendingPath,
        StatePath,
        Array.AsReadOnly(["plan", "status", "provision"]),
        false, false, false, false, false, false,
        RequiresElevationForMutation: true,
        CheckpointEnabled: false,
        StateOrdinaryUserReadable: true,
        StateOrdinaryUserWritable: false,
        UsesSensorIdentity: false,
        ServiceWired: false,
        IpcEnabled: false,
        NetworkEnabled: false,
        DatabaseAccessEnabled: false);

    public static NativeAuditHeadWriterStatus ReadStatus(
        IAuditHeadWriterKeyStore keyStore,
        IAuditHeadCheckpointStateStore stateStore)
    {
        ArgumentNullException.ThrowIfNull(keyStore);
        ArgumentNullException.ThrowIfNull(stateStore);
        var state = stateStore.Read();
        return new(keyStore.Exists(), state is not null, state);
    }

    public static NativeAuditHeadProvisioningResult Provision(
        IAuditHeadWriterKeyStore keyStore)
    {
        ArgumentNullException.ThrowIfNull(keyStore);
        if (keyStore.Exists())
        {
            throw new CryptographicException(
                "SENSOR_AUDIT_HEAD_KEY_ALREADY_EXISTS");
        }

        IAuditHeadWriterIdentity? identity = null;
        var completed = false;
        try
        {
            identity = keyStore.Create();
            ValidateIdentity(identity);
            var proof = identity.Sign(Encoding.UTF8.GetBytes(ProofPayload));
            try
            {
                if (!Verify(identity.Descriptor, ProofPayload, proof))
                {
                    throw new CryptographicException(
                        "SENSOR_AUDIT_HEAD_KEY_PROOF_INVALID");
                }
                completed = true;
                return new(
                    identity.Descriptor,
                    AclVerified: true,
                    PrivateExportBlocked: true,
                    Convert.ToBase64String(proof));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(proof);
            }
        }
        finally
        {
            if (identity is not null)
            {
                try
                {
                    if (!completed)
                    {
                        identity.Delete();
                    }
                }
                finally
                {
                    identity.Dispose();
                }
            }
        }
    }

    public static SignedAuditHeadCheckpoint Checkpoint(
        IAuditHeadWriterKeyStore keyStore,
        IAuditHeadPendingProofStore pendingStore,
        IAuditHeadCheckpointStateStore stateStore)
    {
        ArgumentNullException.ThrowIfNull(keyStore);
        ArgumentNullException.ThrowIfNull(pendingStore);
        ArgumentNullException.ThrowIfNull(stateStore);
        if (!keyStore.Exists())
        {
            throw new CryptographicException(
                "SENSOR_AUDIT_HEAD_KEY_MISSING");
        }
        using var identity = keyStore.Open();
        ValidateIdentity(identity);
        var request = ParsePending(pendingStore.ReadFixed());
        return AuditHeadCheckpoint.Create(stateStore, identity, request);
    }

    public static AuditHeadCheckpointRequest ParsePending(string json)
    {
        if (string.IsNullOrWhiteSpace(json) ||
            Encoding.UTF8.GetByteCount(json) > MaximumPendingBytes)
        {
            throw Invalid("SENSOR_AUDIT_HEAD_PENDING_INVALID");
        }
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 8
            });
            var root = document.RootElement;
            RequireFields(root,
            [
                "schemaVersion", "priorSequence", "priorEventHash",
                "priorCheckpointHash", "rows"
            ]);
            if (root.GetProperty("schemaVersion").GetInt32() != 1)
            {
                throw Invalid("SENSOR_AUDIT_HEAD_PENDING_INVALID");
            }
            var rowsElement = root.GetProperty("rows");
            if (rowsElement.ValueKind != JsonValueKind.Array)
            {
                throw Invalid("SENSOR_AUDIT_HEAD_PENDING_INVALID");
            }
            var links = new List<AuditHeadCheckpointLink>();
            foreach (var item in rowsElement.EnumerateArray())
            {
                RequireFields(item,
                [
                    "sequence", "occurredAt", "eventType", "payloadJson",
                    "previousHash", "eventHash"
                ]);
                var sequence = item.GetProperty("sequence").GetInt64();
                var occurredAt = item.GetProperty("occurredAt").GetString() ??
                    string.Empty;
                var eventType = item.GetProperty("eventType").GetString() ??
                    string.Empty;
                var payloadJson = item.GetProperty("payloadJson").GetString() ??
                    string.Empty;
                var previousHash =
                    item.GetProperty("previousHash").GetString() ?? string.Empty;
                var eventHash = item.GetProperty("eventHash").GetString() ??
                    string.Empty;
                ValidatePendingRow(
                    occurredAt,
                    eventType,
                    payloadJson,
                    previousHash,
                    eventHash);
                links.Add(new(sequence, previousHash, eventHash));
                if (links.Count > AuditHeadCheckpoint.MaximumLinks)
                {
                    throw Invalid("SENSOR_AUDIT_HEAD_PENDING_INVALID");
                }
            }
            return new(
                root.GetProperty("priorSequence").GetInt64(),
                root.GetProperty("priorEventHash").GetString() ?? string.Empty,
                root.GetProperty("priorCheckpointHash").GetString() ?? string.Empty,
                links);
        }
        catch (Exception error) when (
            error is JsonException or InvalidOperationException or
            FormatException or OverflowException or KeyNotFoundException)
        {
            throw Invalid("SENSOR_AUDIT_HEAD_PENDING_INVALID", error);
        }
    }

    private static void ValidatePendingRow(
        string occurredAt,
        string eventType,
        string payloadJson,
        string previousHash,
        string eventHash)
    {
        if (
            !DateTimeOffset.TryParseExact(
                occurredAt,
                "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var timestamp) ||
            timestamp.ToString(
                "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
                CultureInfo.InvariantCulture) != occurredAt ||
            eventType.Length is < 1 or > 128 ||
            payloadJson.Length is < 2 or > 65_536)
        {
            throw Invalid("SENSOR_AUDIT_HEAD_PENDING_INVALID");
        }

        try
        {
            using var payload = JsonDocument.Parse(payloadJson, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 64
            });
        }
        catch (JsonException error)
        {
            throw Invalid("SENSOR_AUDIT_HEAD_PENDING_INVALID", error);
        }

        var canonicalRow =
            $"{previousHash}\n{occurredAt}\n{eventType}\n{payloadJson}";
        var computedHash = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(canonicalRow)))
            .ToLowerInvariant();
        if (!CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(computedHash),
            Encoding.ASCII.GetBytes(eventHash)))
        {
            throw Invalid("SENSOR_AUDIT_HEAD_PENDING_HASH_INVALID");
        }
    }

    internal static void ValidateIdentity(IAuditHeadWriterIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        AuditHeadWriterKeyPolicy.ValidateMetadata(identity.Metadata);
        AuditHeadWriterKeyPolicy.ValidateAcl(identity.ReadSecurityDescriptor());
        if (!identity.IsPrivateExportBlocked())
        {
            throw new CryptographicException(
                "SENSOR_AUDIT_HEAD_KEY_EXPORTABLE");
        }
        if (identity.Descriptor.Profile != AuditHeadCheckpoint.SignerProfile ||
            identity.Descriptor.Algorithm != AuditHeadCheckpoint.Algorithm ||
            identity.Descriptor.KeyPersistence != AuditHeadCheckpoint.KeyPersistence)
        {
            throw new CryptographicException(
                "SENSOR_AUDIT_HEAD_KEY_DESCRIPTOR_INVALID");
        }
    }

    private static void RequireFields(
        JsonElement element,
        IReadOnlyList<string> expected)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw Invalid("SENSOR_AUDIT_HEAD_PENDING_INVALID");
        }
        var fields = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (!fields.Add(property.Name))
            {
                throw Invalid("SENSOR_AUDIT_HEAD_PENDING_INVALID");
            }
        }
        if (!fields.SetEquals(expected))
        {
            throw Invalid("SENSOR_AUDIT_HEAD_PENDING_INVALID");
        }
    }

    private static bool Verify(
        AuditHeadSignerDescriptor descriptor,
        string payload,
        byte[] signature)
    {
        try
        {
            var spki = Convert.FromBase64String(descriptor.PublicKeySpkiBase64);
            try
            {
                using var verifier = ECDsa.Create();
                verifier.ImportSubjectPublicKeyInfo(spki, out var read);
                return read == spki.Length && signature.Length == 64 &&
                    verifier.VerifyData(
                        Encoding.UTF8.GetBytes(payload),
                        signature,
                        HashAlgorithmName.SHA256,
                        DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(spki);
            }
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static InvalidDataException Invalid(
        string code,
        Exception? error = null) => new(code, error);
}

public static class AuditHeadWriterKeyPolicy
{
    public const string ProtectedDescriptorSddl =
        "O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)";

    public static byte[] CreateDescriptor()
    {
        var descriptor = new RawSecurityDescriptor(ProtectedDescriptorSddl);
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        ValidateAcl(bytes);
        return bytes;
    }

    public static void ValidateMetadata(NativeKeyMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        if (metadata.KeyName != NativeAuditHeadWriter.KeyName ||
            metadata.ProviderName != SensorBoundary.SoftwareProviderName ||
            metadata.Algorithm != CngAlgorithm.ECDsaP256.Algorithm ||
            metadata.AlgorithmGroup != CngAlgorithmGroup.ECDsa.AlgorithmGroup ||
            metadata.KeySize != 256 || !metadata.IsMachineKey ||
            metadata.IsEphemeral || metadata.ExportPolicy != CngExportPolicies.None ||
            metadata.KeyUsage != CngKeyUsages.Signing)
        {
            throw new CryptographicException(
                "SENSOR_AUDIT_HEAD_KEY_POLICY_INVALID");
        }
    }

    public static void ValidateAcl(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        RawSecurityDescriptor descriptor;
        try
        {
            descriptor = new(bytes, 0);
        }
        catch (ArgumentException error)
        {
            throw new CryptographicException(
                "SENSOR_AUDIT_HEAD_KEY_ACL_INVALID", error);
        }
        var rules = descriptor.DiscretionaryAcl?.Cast<CommonAce>().ToArray();
        if (descriptor.Owner?.Value != NativeKeyAccessPolicy.BuiltinAdministratorsSid ||
            descriptor.Group?.Value != NativeKeyAccessPolicy.BuiltinAdministratorsSid ||
            !descriptor.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected) ||
            rules is null || rules.Length != 2 ||
            rules.Any(rule => rule.IsInherited ||
                rule.AceQualifier != AceQualifier.AccessAllowed) ||
            !HasFull(rules, NativeKeyAccessPolicy.LocalSystemSid) ||
            !HasFull(rules, NativeKeyAccessPolicy.BuiltinAdministratorsSid))
        {
            throw new CryptographicException(
                "SENSOR_AUDIT_HEAD_KEY_ACL_INVALID");
        }
    }

    private static bool HasFull(IEnumerable<CommonAce> rules, string sid) =>
        rules.Count(rule => rule.SecurityIdentifier.Value == sid &&
            rule.AccessMask is 0x10000000 or unchecked((int)0xd01f01ff)) == 1;
}

public sealed class CngAuditHeadWriterKeyStore : IAuditHeadWriterKeyStore
{
    private static readonly CngProvider Provider =
        new(SensorBoundary.SoftwareProviderName);

    public bool Exists() => CngKey.Exists(
        NativeAuditHeadWriter.KeyName,
        Provider,
        CngKeyOpenOptions.MachineKey);

    public IAuditHeadWriterIdentity Open() => new CngAuditHeadWriterIdentity(
        CngKey.Open(
            NativeAuditHeadWriter.KeyName,
            Provider,
            CngKeyOpenOptions.MachineKey));

    public IAuditHeadWriterIdentity Create()
    {
        var parameters = new CngKeyCreationParameters
        {
            Provider = Provider,
            ExportPolicy = CngExportPolicies.None,
            KeyCreationOptions = CngKeyCreationOptions.MachineKey,
            KeyUsage = CngKeyUsages.Signing
        };
        parameters.Parameters.Add(new CngProperty(
            NativeKeyAccessPolicy.SecurityDescriptorPropertyName,
            AuditHeadWriterKeyPolicy.CreateDescriptor(),
            NativeKeyAccessPolicy.CreateOptions));
        return new CngAuditHeadWriterIdentity(CngKey.Create(
            CngAlgorithm.ECDsaP256,
            NativeAuditHeadWriter.KeyName,
            parameters));
    }
}

internal sealed class CngAuditHeadWriterIdentity(CngKey key) :
    IAuditHeadWriterIdentity
{
    private CngKey? key = key;

    public NativeKeyMetadata Metadata
    {
        get
        {
            var value = GetKey();
            return new(
                value.KeyName ?? string.Empty,
                value.Provider?.Provider ?? string.Empty,
                value.Algorithm.Algorithm,
                value.AlgorithmGroup?.AlgorithmGroup ?? string.Empty,
                value.KeySize,
                value.IsMachineKey,
                value.IsEphemeral,
                value.ExportPolicy,
                value.KeyUsage);
        }
    }

    public AuditHeadSignerDescriptor Descriptor
    {
        get
        {
            using var signer = new ECDsaCng(GetKey());
            var spki = signer.ExportSubjectPublicKeyInfo();
            try
            {
                var fingerprint = Convert.ToHexString(
                    SHA256.HashData(spki)).ToLowerInvariant();
                var chainId = AuditHeadCheckpoint.DeriveChainId(fingerprint);
                return new(
                    AuditHeadCheckpoint.SignerProfile,
                    chainId,
                    AuditHeadCheckpoint.Algorithm,
                    AuditHeadCheckpoint.PublicKeyFormat,
                    Convert.ToBase64String(spki),
                    fingerprint,
                    AuditHeadCheckpoint.KeyPersistence);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(spki);
            }
        }
    }

    public byte[] ReadSecurityDescriptor() => GetKey().GetProperty(
        NativeKeyAccessPolicy.SecurityDescriptorPropertyName,
        NativeKeyAccessPolicy.ReadOptions).GetValue() ??
        throw new CryptographicException(
            "SENSOR_AUDIT_HEAD_KEY_ACL_INVALID");

    public bool IsPrivateExportBlocked()
    {
        try
        {
            _ = GetKey().Export(CngKeyBlobFormat.EccPrivateBlob);
            return false;
        }
        catch (CryptographicException)
        {
            return true;
        }
    }

    public byte[] Sign(ReadOnlySpan<byte> payload)
    {
        using var signer = new ECDsaCng(GetKey());
        return NativeSignatureProfile.Sign(signer, payload);
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

    private CngKey GetKey() => key ??
        throw new ObjectDisposedException(nameof(CngAuditHeadWriterIdentity));
}
