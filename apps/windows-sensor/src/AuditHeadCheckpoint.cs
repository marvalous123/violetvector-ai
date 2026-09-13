using System.Security.Cryptography;
using System.Text.Json;

namespace WARRoom.WindowsSensor;

public sealed record AuditHeadSignerDescriptor(
    string Profile,
    string ChainId,
    string Algorithm,
    string PublicKeyFormat,
    string PublicKeySpkiBase64,
    string PublicKeyFingerprintSha256,
    string KeyPersistence);

public sealed record AuditHeadCheckpointLink(
    long Sequence,
    string PreviousHash,
    string EventHash);

public sealed record AuditHeadCheckpointRequest(
    long PriorSequence,
    string PriorEventHash,
    string PriorCheckpointHash,
    IReadOnlyList<AuditHeadCheckpointLink> Links);

public sealed record AuditHeadProtectedState(
    string ChainId,
    long Sequence,
    string EventHash,
    string CheckpointHash);

public sealed record AuditHeadProtectedDocument(
    AuditHeadSignerDescriptor Signer,
    SignedAuditHeadCheckpoint Checkpoint);

public sealed record SignedAuditHeadCheckpoint(
    int SchemaVersion,
    string Purpose,
    string ChainId,
    long PriorSequence,
    string PriorEventHash,
    string PriorCheckpointHash,
    long Sequence,
    string EventHash,
    string SignerProfile,
    string SignerAlgorithm,
    string SignerPublicKeyFingerprintSha256,
    string CheckpointHash,
    string SignatureBase64);

public interface IAuditHeadCheckpointSigner
{
    AuditHeadSignerDescriptor Descriptor { get; }
    byte[] Sign(ReadOnlySpan<byte> payload);
}

public interface IAuditHeadCheckpointStateStore
{
    AuditHeadProtectedState? Read();
    bool TryCommit(
        AuditHeadProtectedState? expected,
        AuditHeadProtectedDocument next);
}

public static class AuditHeadCheckpoint
{
    public const int SchemaVersion = 1;
    public const string Purpose = "project15.audit-head-checkpoint.v1";
    public const string ChainPurpose = "project15.audit-head-chain.v1";
    public const string SignerProfile = "project15-audit-head-signer-v1";
    public const string Algorithm = "ecdsa-p256-sha256";
    public const string PublicKeyFormat = "spki-der";
    public const string KeyPersistence =
        "non-exportable-machine-cng-audit-v1";
    public const int MaximumLinks = 256;
    public const long MaximumSequence = 9_007_199_254_740_991;
    public static string GenesisHash { get; } = new('0', 64);

    public static SignedAuditHeadCheckpoint Create(
        IAuditHeadCheckpointStateStore store,
        IAuditHeadCheckpointSigner signer,
        AuditHeadCheckpointRequest request)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(request);
        var descriptor = signer.Descriptor;
        ValidateDescriptor(descriptor);

        var state = store.Read();
        ValidatePriorState(state, descriptor, request);
        var head = ValidateLinks(request);
        var unsigned = new SignedAuditHeadCheckpoint(
            SchemaVersion,
            Purpose,
            descriptor.ChainId,
            request.PriorSequence,
            request.PriorEventHash,
            request.PriorCheckpointHash,
            head.Sequence,
            head.EventHash,
            descriptor.Profile,
            descriptor.Algorithm,
            descriptor.PublicKeyFingerprintSha256,
            string.Empty,
            string.Empty);

        byte[]? payload = null;
        byte[]? signature = null;
        try
        {
            payload = CanonicalPayload(unsigned);
            var checkpointHash = Hex(SHA256.HashData(payload));
            signature = signer.Sign(payload);
            if (!VerifySignature(payload, signature, descriptor))
            {
                throw Invalid("SENSOR_AUDIT_HEAD_SIGNATURE_INVALID");
            }

            var checkpoint = unsigned with
            {
                CheckpointHash = checkpointHash,
                SignatureBase64 = Convert.ToBase64String(signature)
            };
            var next = new AuditHeadProtectedState(
                checkpoint.ChainId,
                checkpoint.Sequence,
                checkpoint.EventHash,
                checkpoint.CheckpointHash);
            var document = new AuditHeadProtectedDocument(
                descriptor,
                checkpoint);
            if (!store.TryCommit(state, document))
            {
                throw new InvalidOperationException(
                    "SENSOR_AUDIT_HEAD_STATE_CONFLICT");
            }
            return checkpoint;
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
        }
    }

    public static void Validate(
        SignedAuditHeadCheckpoint checkpoint,
        AuditHeadSignerDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        ValidateDescriptor(descriptor);
        if (
            checkpoint.SchemaVersion != SchemaVersion ||
            checkpoint.Purpose != Purpose ||
            checkpoint.ChainId != descriptor.ChainId ||
            checkpoint.SignerProfile != descriptor.Profile ||
            checkpoint.SignerAlgorithm != descriptor.Algorithm ||
            checkpoint.SignerPublicKeyFingerprintSha256 !=
                descriptor.PublicKeyFingerprintSha256 ||
            checkpoint.PriorSequence < 0 ||
            checkpoint.PriorSequence >= checkpoint.Sequence ||
            checkpoint.Sequence > MaximumSequence ||
            !IsHash(checkpoint.PriorEventHash) ||
            !IsHash(checkpoint.PriorCheckpointHash) ||
            !IsHash(checkpoint.EventHash) ||
            checkpoint.EventHash == GenesisHash ||
            !IsHash(checkpoint.CheckpointHash) ||
            checkpoint.CheckpointHash == GenesisHash ||
            (
                checkpoint.PriorSequence == 0 &&
                (
                    checkpoint.PriorEventHash != GenesisHash ||
                    checkpoint.PriorCheckpointHash != GenesisHash
                )
            ) ||
            (
                checkpoint.PriorSequence > 0 &&
                (
                    checkpoint.PriorEventHash == GenesisHash ||
                    checkpoint.PriorCheckpointHash == GenesisHash
                )
            ))
        {
            throw Invalid("SENSOR_AUDIT_HEAD_CHECKPOINT_INVALID");
        }

        byte[]? payload = null;
        byte[]? signature = null;
        try
        {
            payload = CanonicalPayload(checkpoint);
            if (Hex(SHA256.HashData(payload)) != checkpoint.CheckpointHash)
            {
                throw Invalid("SENSOR_AUDIT_HEAD_CHECKPOINT_INVALID");
            }
            try
            {
                signature = Convert.FromBase64String(checkpoint.SignatureBase64);
            }
            catch (FormatException error)
            {
                throw Invalid("SENSOR_AUDIT_HEAD_SIGNATURE_INVALID", error);
            }
            if (
                Convert.ToBase64String(signature) !=
                    checkpoint.SignatureBase64 ||
                !VerifySignature(payload, signature, descriptor))
            {
                throw Invalid("SENSOR_AUDIT_HEAD_SIGNATURE_INVALID");
            }
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
        }
    }

    public static void ValidateAnchoredPrefix(
        SignedAuditHeadCheckpoint checkpoint,
        AuditHeadSignerDescriptor descriptor,
        long databaseHeadSequence,
        string checkpointEventHashAtSequence)
    {
        Validate(checkpoint, descriptor);
        if (
            databaseHeadSequence < checkpoint.Sequence ||
            checkpointEventHashAtSequence != checkpoint.EventHash)
        {
            throw Invalid("SENSOR_AUDIT_HEAD_PREFIX_INVALID");
        }
    }

    public static AuditHeadProtectedState ValidateProtectedDocument(
        AuditHeadProtectedDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        Validate(document.Checkpoint, document.Signer);
        return new(
            document.Checkpoint.ChainId,
            document.Checkpoint.Sequence,
            document.Checkpoint.EventHash,
            document.Checkpoint.CheckpointHash);
    }

    public static string DeriveChainId(string signerFingerprint)
    {
        if (!IsHash(signerFingerprint) || signerFingerprint == GenesisHash)
        {
            throw Invalid("SENSOR_AUDIT_HEAD_SIGNER_INVALID");
        }
        return Hex(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(
            $"{ChainPurpose}\n{signerFingerprint}")));
    }

    internal static byte[] CanonicalPayload(
        SignedAuditHeadCheckpoint checkpoint)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions
        {
            Indented = false,
            SkipValidation = false
        }))
        {
            writer.WriteStartObject();
            writer.WriteString("chainId", checkpoint.ChainId);
            writer.WriteString("eventHash", checkpoint.EventHash);
            writer.WriteString(
                "priorCheckpointHash",
                checkpoint.PriorCheckpointHash);
            writer.WriteString("priorEventHash", checkpoint.PriorEventHash);
            writer.WriteNumber("priorSequence", checkpoint.PriorSequence);
            writer.WriteString("purpose", checkpoint.Purpose);
            writer.WriteNumber("schemaVersion", checkpoint.SchemaVersion);
            writer.WriteNumber("sequence", checkpoint.Sequence);
            writer.WriteString("signerAlgorithm", checkpoint.SignerAlgorithm);
            writer.WriteString("signerProfile", checkpoint.SignerProfile);
            writer.WriteString(
                "signerPublicKeyFingerprintSha256",
                checkpoint.SignerPublicKeyFingerprintSha256);
            writer.WriteEndObject();
        }
        return buffer.ToArray();
    }

    private static AuditHeadCheckpointLink ValidateLinks(
        AuditHeadCheckpointRequest request)
    {
        ArgumentNullException.ThrowIfNull(request.Links);
        if (
            request.Links.Count is < 1 or > MaximumLinks ||
            request.PriorSequence < 0 ||
            request.PriorSequence >= MaximumSequence ||
            !IsHash(request.PriorEventHash) ||
            !IsHash(request.PriorCheckpointHash))
        {
            throw Invalid("SENSOR_AUDIT_HEAD_REQUEST_INVALID");
        }

        var expectedSequence = request.PriorSequence + 1;
        var expectedPreviousHash = request.PriorEventHash;
        AuditHeadCheckpointLink? head = null;
        foreach (var link in request.Links)
        {
            if (
                link is null ||
                link.Sequence != expectedSequence ||
                link.Sequence > MaximumSequence ||
                link.PreviousHash != expectedPreviousHash ||
                !IsHash(link.PreviousHash) ||
                !IsHash(link.EventHash) ||
                link.EventHash == GenesisHash)
            {
                throw Invalid("SENSOR_AUDIT_HEAD_CONTINUITY_INVALID");
            }
            head = link;
            expectedPreviousHash = link.EventHash;
            expectedSequence++;
        }
        return head ?? throw Invalid("SENSOR_AUDIT_HEAD_REQUEST_INVALID");
    }

    private static void ValidatePriorState(
        AuditHeadProtectedState? state,
        AuditHeadSignerDescriptor descriptor,
        AuditHeadCheckpointRequest request)
    {
        if (state is null)
        {
            if (
                request.PriorSequence != 0 ||
                request.PriorEventHash != GenesisHash ||
                request.PriorCheckpointHash != GenesisHash)
            {
                throw Invalid("SENSOR_AUDIT_HEAD_GENESIS_INVALID");
            }
            return;
        }

        if (
            state.ChainId != descriptor.ChainId ||
            state.Sequence is < 1 or > MaximumSequence ||
            !IsHash(state.EventHash) ||
            state.EventHash == GenesisHash ||
            !IsHash(state.CheckpointHash) ||
            state.CheckpointHash == GenesisHash)
        {
            throw Invalid("SENSOR_AUDIT_HEAD_PROTECTED_STATE_INVALID");
        }
        if (
            request.PriorSequence != state.Sequence ||
            request.PriorEventHash != state.EventHash ||
            request.PriorCheckpointHash != state.CheckpointHash)
        {
            throw Invalid("SENSOR_AUDIT_HEAD_PREDECESSOR_INVALID");
        }
    }

    private static void ValidateDescriptor(AuditHeadSignerDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        if (
            descriptor.Profile != SignerProfile ||
            !IsHash(descriptor.ChainId) ||
            descriptor.ChainId == GenesisHash ||
            descriptor.Algorithm != Algorithm ||
            descriptor.PublicKeyFormat != PublicKeyFormat ||
            !IsHash(descriptor.PublicKeyFingerprintSha256) ||
            descriptor.ChainId != DeriveChainId(
                descriptor.PublicKeyFingerprintSha256) ||
            descriptor.KeyPersistence != KeyPersistence)
        {
            throw Invalid("SENSOR_AUDIT_HEAD_SIGNER_INVALID");
        }

        byte[]? spki = null;
        try
        {
            spki = Convert.FromBase64String(descriptor.PublicKeySpkiBase64);
            if (
                Convert.ToBase64String(spki) !=
                    descriptor.PublicKeySpkiBase64 ||
                Hex(SHA256.HashData(spki)) !=
                    descriptor.PublicKeyFingerprintSha256)
            {
                throw Invalid("SENSOR_AUDIT_HEAD_SIGNER_INVALID");
            }
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(spki, out var read);
            if (read != spki.Length || verifier.KeySize != 256)
            {
                throw Invalid("SENSOR_AUDIT_HEAD_SIGNER_INVALID");
            }
        }
        catch (FormatException error)
        {
            throw Invalid("SENSOR_AUDIT_HEAD_SIGNER_INVALID", error);
        }
        catch (CryptographicException error)
        {
            throw Invalid("SENSOR_AUDIT_HEAD_SIGNER_INVALID", error);
        }
        finally
        {
            if (spki is not null)
            {
                CryptographicOperations.ZeroMemory(spki);
            }
        }
    }

    private static bool VerifySignature(
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> signature,
        AuditHeadSignerDescriptor descriptor)
    {
        byte[]? spki = null;
        try
        {
            spki = Convert.FromBase64String(descriptor.PublicKeySpkiBase64);
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(spki, out var read);
            return read == spki.Length &&
                verifier.KeySize == 256 &&
                signature.Length == 64 &&
                verifier.VerifyData(
                    payload,
                    signature,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
        finally
        {
            if (spki is not null)
            {
                CryptographicOperations.ZeroMemory(spki);
            }
        }
    }

    private static bool IsHash(string? value) =>
        value is { Length: 64 } &&
        value.All(character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static string Hex(ReadOnlySpan<byte> value) =>
        Convert.ToHexString(value).ToLowerInvariant();

    private static InvalidDataException Invalid(
        string code,
        Exception? inner = null) =>
        new(code, inner);
}
