using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace WARRoom.WindowsSensor;

public sealed record SignedSecurity4663OneShotApproval(
    int SchemaVersion,
    string Profile,
    string State,
    string Checkpoint,
    string ServiceName,
    string ServiceIdentity,
    string ServiceStartupArgument,
    string TargetProfileId,
    long BaselineRecordId,
    string InstalledCommit,
    string CertificateFingerprintSha256,
    string NonceBase64,
    string ApprovedAt,
    string ExpiresAt,
    string SignatureBase64);

public interface ISecurity4663OneShotApprovalStore
{
    string? ReadExisting();
    void WriteNew(string json);
    void ConsumeExact(string expectedJson);
}

// Gate C2e one-time approval contract. Only the disabled consume-proof startup
// mode uses it; event access and the full one-shot ceremony remain unwired.
public static partial class Security4663OneShotApprovalLifecycle
{
    public const string Profile =
        "gate-c2e-security-4663-one-shot-approval-v1";
    public const int MaximumDocumentBytes = 4_096;
    public const int NonceBytes = 32;
    public const int LifetimeSeconds = 300;
    public const bool RuntimeWired = true;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private static readonly IReadOnlySet<string> Fields = new HashSet<string>(
        [
            "schemaVersion", "profile", "state", "checkpoint", "serviceName",
            "serviceIdentity", "serviceStartupArgument", "targetProfileId",
            "baselineRecordId", "installedCommit",
            "certificateFingerprintSha256", "nonceBase64", "approvedAt",
            "expiresAt", "signatureBase64"
        ],
        StringComparer.Ordinal);

    public static SignedSecurity4663OneShotApproval CreateAndWrite(
        ISecurity4663OneShotApprovalStore store,
        ISensorIdentitySigner identity,
        string installedCommit,
        long baselineRecordId,
        DateTime utcNow,
        ReadOnlySpan<byte> nonce)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(identity);
        if (store.ReadExisting() is not null)
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_APPROVAL_ALREADY_EXISTS");
        }
        ValidateContext(
            identity.Descriptor,
            installedCommit,
            baselineRecordId,
            utcNow,
            nonce);
        var core = new SignedSecurity4663OneShotApproval(
            1,
            Profile,
            "approved",
            Readiness.Security4663OneShotMachinePlan.Checkpoint,
            "WARRoomWindowsSensor",
            @"NT AUTHORITY\LocalService",
            "--security-4663-one-shot",
            "credential-store-read",
            baselineRecordId,
            installedCommit,
            identity.Descriptor.CertificateFingerprintSha256,
            Convert.ToBase64String(nonce),
            FormatUtc(utcNow),
            FormatUtc(utcNow.AddSeconds(LifetimeSeconds)),
            string.Empty);
        var canonical = CanonicalCore(core);
        var approval = core with
        {
            SignatureBase64 = identity.SignUtf8Payload(canonical)
        };
        ValidateApproval(
            JsonSerializer.Serialize(approval, JsonOptions),
            identity.Descriptor,
            installedCommit,
            utcNow);
        var json = JsonSerializer.Serialize(approval, JsonOptions);
        if (Encoding.UTF8.GetByteCount(json) > MaximumDocumentBytes)
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_APPROVAL_SIZE_INVALID");
        }
        store.WriteNew(json);
        return approval;
    }

    public static Security4663OneShotApproval Consume(
        ISecurity4663OneShotApprovalStore store,
        SensorIdentityDescriptor identity,
        string installedCommit,
        DateTime utcNow)
    {
        ArgumentNullException.ThrowIfNull(store);
        var json = store.ReadExisting() ?? throw Invalid(
            "SENSOR_C2E_SECURITY_4663_APPROVAL_MISSING");
        var approval = ValidateApproval(
            json,
            identity,
            installedCommit,
            utcNow);
        store.ConsumeExact(json);
        return new Security4663OneShotApproval(
            true,
            approval.Checkpoint,
            InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
            approval.BaselineRecordId,
            ParseUtcOffset(approval.ApprovedAt),
            ParseUtcOffset(approval.ExpiresAt));
    }

    public static SignedSecurity4663OneShotApproval ValidateApproval(
        string json,
        SensorIdentityDescriptor identity,
        string installedCommit,
        DateTime utcNow)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        ArgumentNullException.ThrowIfNull(identity);
        if (
            Encoding.UTF8.GetByteCount(json) > MaximumDocumentBytes ||
            utcNow.Kind != DateTimeKind.Utc ||
            !CommitPattern().IsMatch(installedCommit))
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_APPROVAL_CONTEXT_INVALID");
        }

        JsonElement root;
        try
        {
            using var document = JsonDocument.Parse(json);
            root = document.RootElement.Clone();
        }
        catch (JsonException)
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_APPROVAL_INPUT_INVALID");
        }
        var properties = root.ValueKind == JsonValueKind.Object
            ? root.EnumerateObject().ToArray()
            : [];
        if (
            properties.Length != Fields.Count ||
            properties.Select(item => item.Name).Distinct(
                StringComparer.Ordinal).Count() != Fields.Count ||
            !properties.Select(item => item.Name).ToHashSet(
                StringComparer.Ordinal).SetEquals(Fields))
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_APPROVAL_FIELDS_INVALID");
        }

        SignedSecurity4663OneShotApproval approval;
        try
        {
            approval = JsonSerializer.Deserialize<SignedSecurity4663OneShotApproval>(
                json,
                JsonOptions) ?? throw Invalid(
                    "SENSOR_C2E_SECURITY_4663_APPROVAL_INPUT_INVALID");
        }
        catch (JsonException)
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_APPROVAL_INPUT_INVALID");
        }

        ValidateIdentity(identity);
        byte[] nonce;
        try
        {
            nonce = Convert.FromBase64String(approval.NonceBase64);
        }
        catch (FormatException)
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_APPROVAL_INVALID");
        }
        try
        {
            if (
                nonce.Length != NonceBytes ||
                approval.SchemaVersion != 1 ||
                approval.Profile != Profile ||
                approval.State != "approved" ||
                approval.Checkpoint !=
                    Readiness.Security4663OneShotMachinePlan.Checkpoint ||
                approval.ServiceName != "WARRoomWindowsSensor" ||
                approval.ServiceIdentity != @"NT AUTHORITY\LocalService" ||
                approval.ServiceStartupArgument != "--security-4663-one-shot" ||
                approval.TargetProfileId != "credential-store-read" ||
                approval.BaselineRecordId is < 1 or >
                    Security4663OneShotCoordinator.MaximumJsonInteger ||
                approval.InstalledCommit != installedCommit ||
                approval.CertificateFingerprintSha256 !=
                    identity.CertificateFingerprintSha256 ||
                !TryUtc(approval.ApprovedAt, out var approvedAt) ||
                !TryUtc(approval.ExpiresAt, out var expiresAt) ||
                expiresAt != approvedAt.AddSeconds(LifetimeSeconds) ||
                utcNow < approvedAt ||
                utcNow >= expiresAt ||
                !Verify(
                    CanonicalCore(approval),
                    approval.SignatureBase64,
                    identity))
            {
                throw Invalid("SENSOR_C2E_SECURITY_4663_APPROVAL_INVALID");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
        }
        return approval;
    }

    private static void ValidateContext(
        SensorIdentityDescriptor identity,
        string installedCommit,
        long baselineRecordId,
        DateTime utcNow,
        ReadOnlySpan<byte> nonce)
    {
        ValidateIdentity(identity);
        if (
            utcNow.Kind != DateTimeKind.Utc ||
            !CommitPattern().IsMatch(installedCommit) ||
            baselineRecordId is < 1 or >
                Security4663OneShotCoordinator.MaximumJsonInteger ||
            nonce.Length != NonceBytes)
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_APPROVAL_CONTEXT_INVALID");
        }
    }

    private static void ValidateIdentity(SensorIdentityDescriptor identity)
    {
        byte[] spki;
        try
        {
            spki = Convert.FromBase64String(identity.PublicKeySpkiBase64);
        }
        catch (FormatException)
        {
            throw Invalid("SENSOR_C2E_SECURITY_4663_APPROVAL_IDENTITY_INVALID");
        }
        try
        {
            if (
                identity.Algorithm != SensorBoundary.SignatureAlgorithm ||
                identity.PublicKeyFormat != "spki-der" ||
                identity.KeyProvider != SensorBoundary.SoftwareProviderName ||
                identity.KeyPersistence !=
                    "non-exportable-machine-cng-software-ksp" ||
                !Sha256Pattern().IsMatch(
                    identity.CertificateFingerprintSha256) ||
                Convert.ToHexString(SHA256.HashData(spki)).ToLowerInvariant() !=
                    identity.CertificateFingerprintSha256)
            {
                throw Invalid(
                    "SENSOR_C2E_SECURITY_4663_APPROVAL_IDENTITY_INVALID");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(spki);
        }
    }

    private static string CanonicalCore(
        SignedSecurity4663OneShotApproval value)
    {
        using var output = new MemoryStream();
        using (var writer = new Utf8JsonWriter(
            output,
            new JsonWriterOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            }))
        {
            writer.WriteStartObject();
            writer.WriteString("approvedAt", value.ApprovedAt);
            writer.WriteNumber("baselineRecordId", value.BaselineRecordId);
            writer.WriteString(
                "certificateFingerprintSha256",
                value.CertificateFingerprintSha256);
            writer.WriteString("checkpoint", value.Checkpoint);
            writer.WriteString("expiresAt", value.ExpiresAt);
            writer.WriteString("installedCommit", value.InstalledCommit);
            writer.WriteString("nonceBase64", value.NonceBase64);
            writer.WriteString("profile", value.Profile);
            writer.WriteNumber("schemaVersion", value.SchemaVersion);
            writer.WriteString("serviceIdentity", value.ServiceIdentity);
            writer.WriteString("serviceName", value.ServiceName);
            writer.WriteString(
                "serviceStartupArgument",
                value.ServiceStartupArgument);
            writer.WriteString("state", value.State);
            writer.WriteString("targetProfileId", value.TargetProfileId);
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(output.ToArray());
    }

    private static bool Verify(
        string payload,
        string signatureBase64,
        SensorIdentityDescriptor identity)
    {
        byte[]? spki = null;
        byte[]? signature = null;
        byte[]? bytes = null;
        try
        {
            spki = Convert.FromBase64String(identity.PublicKeySpkiBase64);
            signature = Convert.FromBase64String(signatureBase64);
            bytes = Encoding.UTF8.GetBytes(payload);
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(spki, out var read);
            return read == spki.Length &&
                signature.Length == 64 &&
                verifier.VerifyData(
                    bytes,
                    signature,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (FormatException)
        {
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
        finally
        {
            if (spki is not null) CryptographicOperations.ZeroMemory(spki);
            if (signature is not null)
            {
                CryptographicOperations.ZeroMemory(signature);
            }
            if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static string FormatUtc(DateTime value) => value.ToString(
        "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
        CultureInfo.InvariantCulture);

    private static DateTimeOffset ParseUtcOffset(string value) =>
        new(DateTime.ParseExact(
            value,
            "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal |
                DateTimeStyles.AdjustToUniversal));

    private static bool TryUtc(string value, out DateTime parsed)
    {
        parsed = DateTime.MinValue;
        return TimestampPattern().IsMatch(value) && DateTime.TryParseExact(
            value,
            "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out parsed) && parsed.Kind == DateTimeKind.Utc;
    }

    private static InvalidDataException Invalid(string code) => new(code);

    [GeneratedRegex("^[a-f0-9]{40}$", RegexOptions.CultureInvariant)]
    private static partial Regex CommitPattern();

    [GeneratedRegex("^[a-f0-9]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256Pattern();

    [GeneratedRegex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$", RegexOptions.CultureInvariant)]
    private static partial Regex TimestampPattern();
}
