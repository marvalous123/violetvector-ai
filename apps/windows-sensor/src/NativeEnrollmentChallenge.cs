using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace WARRoom.WindowsSensor;

public sealed record NativeEnrollmentChallengeProof(
    int SchemaVersion,
    string ChallengeId,
    string ChallengeHash,
    string CertificateFingerprintSha256,
    string PublicKeySpkiBase64,
    string CanonicalPayload,
    string ProofSignatureBase64,
    string ChallengeExpiresAt,
    string IdentityExpiresAt);

public static partial class NativeEnrollmentChallenge
{
    public const int MaximumInputBytes = 8_192;
    public const int MaximumChallengeSeconds = 900;
    public const int MaximumIdentitySeconds = 604_800;

    private static readonly IReadOnlySet<string> WrapperFields = ExactSet("challenge");
    private static readonly IReadOnlySet<string> ChallengeFields = ExactSet(
        "id", "status", "payload", "challengeHash");
    private static readonly IReadOnlySet<string> PayloadFields = ExactSet(
        "schemaVersion",
        "challengeId",
        "missionId",
        "connectorId",
        "endpointId",
        "certificateFingerprintSha256",
        "nonceBase64Url",
        "requestedAt",
        "challengeExpiresAt",
        "identityExpiresAt");

    [GeneratedRegex("^enrollment-[a-f0-9-]{36}$", RegexOptions.CultureInvariant)]
    private static partial Regex ChallengeIdPattern();

    [GeneratedRegex("^connector-[a-f0-9-]{36}$", RegexOptions.CultureInvariant)]
    private static partial Regex ConnectorIdPattern();

    [GeneratedRegex("^endpoint-[a-f0-9-]{36}$", RegexOptions.CultureInvariant)]
    private static partial Regex EndpointIdPattern();

    [GeneratedRegex("^[a-f0-9]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256Pattern();

    [GeneratedRegex("^[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant)]
    private static partial Regex NoncePattern();

    [GeneratedRegex(
        "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$",
        RegexOptions.CultureInvariant)]
    private static partial Regex TimestampPattern();

    public static NativeEnrollmentChallengeProof Sign(
        string json,
        ISensorIdentitySigner identity,
        DateTime utcNow)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        ArgumentNullException.ThrowIfNull(identity);
        if (
            utcNow.Kind != DateTimeKind.Utc ||
            Encoding.UTF8.GetByteCount(json) > MaximumInputBytes)
        {
            throw Invalid("SENSOR_ENROLLMENT_CHALLENGE_INPUT_INVALID");
        }

        using var document = Parse(json);
        RequireExactProperties(
            document.RootElement,
            WrapperFields,
            "SENSOR_ENROLLMENT_CHALLENGE_FIELDS_INVALID");
        var challenge = document.RootElement.GetProperty("challenge");
        RequireExactProperties(
            challenge,
            ChallengeFields,
            "SENSOR_ENROLLMENT_CHALLENGE_FIELDS_INVALID");
        var payload = challenge.GetProperty("payload");
        RequireExactProperties(
            payload,
            PayloadFields,
            "SENSOR_ENROLLMENT_CHALLENGE_FIELDS_INVALID");

        var challengeId = RequiredString(payload, "challengeId");
        var missionId = RequiredString(payload, "missionId");
        var connectorId = RequiredString(payload, "connectorId");
        var endpointId = RequiredString(payload, "endpointId");
        var fingerprint = RequiredString(payload, "certificateFingerprintSha256");
        var nonce = RequiredString(payload, "nonceBase64Url");
        var requestedAtText = RequiredString(payload, "requestedAt");
        var challengeExpiresAtText = RequiredString(payload, "challengeExpiresAt");
        var identityExpiresAtText = RequiredString(payload, "identityExpiresAt");
        var challengeHash = RequiredString(challenge, "challengeHash");
        if (
            payload.GetProperty("schemaVersion").ValueKind != JsonValueKind.Number ||
            !payload.GetProperty("schemaVersion").TryGetInt32(out var schemaVersion) ||
            schemaVersion != 1 ||
            RequiredString(challenge, "id") != challengeId ||
            RequiredString(challenge, "status") != "pending" ||
            !ChallengeIdPattern().IsMatch(challengeId) ||
            !GuidText(challengeId["enrollment-".Length..]) ||
            !GuidText(missionId) ||
            !ConnectorIdPattern().IsMatch(connectorId) ||
            !GuidText(connectorId["connector-".Length..]) ||
            !EndpointIdPattern().IsMatch(endpointId) ||
            !GuidText(endpointId["endpoint-".Length..]) ||
            !Sha256Pattern().IsMatch(fingerprint) ||
            !Sha256Pattern().IsMatch(challengeHash) ||
            !NoncePattern().IsMatch(nonce) ||
            !StringComparer.Ordinal.Equals(
                fingerprint,
                identity.Descriptor.CertificateFingerprintSha256) ||
            identity.Descriptor.Algorithm != SensorBoundary.SignatureAlgorithm ||
            identity.Descriptor.PublicKeyFormat != "spki-der" ||
            identity.Descriptor.KeyProvider != SensorBoundary.SoftwareProviderName ||
            identity.Descriptor.KeyPersistence !=
                "non-exportable-machine-cng-software-ksp")
        {
            throw Invalid("SENSOR_ENROLLMENT_CHALLENGE_VALUE_INVALID");
        }
        ValidateNonce(nonce);

        var requestedAt = ParseUtc(requestedAtText);
        var challengeExpiresAt = ParseUtc(challengeExpiresAtText);
        var identityExpiresAt = ParseUtc(identityExpiresAtText);
        if (
            challengeExpiresAt <= requestedAt ||
            (challengeExpiresAt - requestedAt).TotalSeconds is < 30 or > MaximumChallengeSeconds ||
            identityExpiresAt <= challengeExpiresAt ||
            (identityExpiresAt - requestedAt).TotalSeconds > MaximumIdentitySeconds ||
            utcNow < requestedAt.UtcDateTime.AddSeconds(-30) ||
            utcNow >= challengeExpiresAt.UtcDateTime)
        {
            throw Invalid("SENSOR_ENROLLMENT_CHALLENGE_TIME_INVALID");
        }

        var canonicalPayload = CanonicalPayload(
            schemaVersion,
            challengeId,
            missionId,
            connectorId,
            endpointId,
            fingerprint,
            nonce,
            requestedAtText,
            challengeExpiresAtText,
            identityExpiresAtText);
        var expectedHash = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(canonicalPayload)))
            .ToLowerInvariant();
        if (!StringComparer.Ordinal.Equals(expectedHash, challengeHash))
        {
            throw Invalid("SENSOR_ENROLLMENT_CHALLENGE_HASH_INVALID");
        }

        var signatureBase64 = identity.SignUtf8Payload(canonicalPayload);
        VerifyProof(canonicalPayload, signatureBase64, identity.Descriptor);
        return new NativeEnrollmentChallengeProof(
            1,
            challengeId,
            challengeHash,
            fingerprint,
            identity.Descriptor.PublicKeySpkiBase64,
            canonicalPayload,
            signatureBase64,
            challengeExpiresAtText,
            identityExpiresAtText);
    }

    private static JsonDocument Parse(string json)
    {
        try
        {
            return JsonDocument.Parse(
                json,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 5
                });
        }
        catch (JsonException error)
        {
            throw new InvalidDataException(
                "SENSOR_ENROLLMENT_CHALLENGE_INPUT_INVALID",
                error);
        }
    }

    private static string CanonicalPayload(
        int schemaVersion,
        string challengeId,
        string missionId,
        string connectorId,
        string endpointId,
        string fingerprint,
        string nonce,
        string requestedAt,
        string challengeExpiresAt,
        string identityExpiresAt)
    {
        using var output = new MemoryStream();
        using (var writer = new Utf8JsonWriter(
            output,
            new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
        {
            writer.WriteStartObject();
            writer.WriteString("certificateFingerprintSha256", fingerprint);
            writer.WriteString("challengeExpiresAt", challengeExpiresAt);
            writer.WriteString("challengeId", challengeId);
            writer.WriteString("connectorId", connectorId);
            writer.WriteString("endpointId", endpointId);
            writer.WriteString("identityExpiresAt", identityExpiresAt);
            writer.WriteString("missionId", missionId);
            writer.WriteString("nonceBase64Url", nonce);
            writer.WriteString("requestedAt", requestedAt);
            writer.WriteNumber("schemaVersion", schemaVersion);
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(output.ToArray());
    }

    private static void VerifyProof(
        string payload,
        string signatureBase64,
        SensorIdentityDescriptor descriptor)
    {
        byte[]? signature = null;
        byte[]? publicKey = null;
        try
        {
            signature = Convert.FromBase64String(signatureBase64);
            publicKey = Convert.FromBase64String(descriptor.PublicKeySpkiBase64);
            var fingerprint = Convert.ToHexString(SHA256.HashData(publicKey))
                .ToLowerInvariant();
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(publicKey, out var bytesRead);
            if (
                bytesRead != publicKey.Length ||
                signature.Length != 64 ||
                fingerprint != descriptor.CertificateFingerprintSha256 ||
                !verifier.VerifyData(
                    Encoding.UTF8.GetBytes(payload),
                    signature,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                throw Invalid("SENSOR_ENROLLMENT_CHALLENGE_PROOF_INVALID");
            }
        }
        catch (FormatException error)
        {
            throw new InvalidDataException(
                "SENSOR_ENROLLMENT_CHALLENGE_PROOF_INVALID",
                error);
        }
        finally
        {
            if (signature is not null) CryptographicOperations.ZeroMemory(signature);
            if (publicKey is not null) CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    private static DateTimeOffset ParseUtc(string value)
    {
        if (
            !TimestampPattern().IsMatch(value) ||
            !DateTimeOffset.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind,
                out var result) ||
            result.Offset != TimeSpan.Zero)
        {
            throw Invalid("SENSOR_ENROLLMENT_CHALLENGE_TIME_INVALID");
        }
        return result;
    }

    private static void ValidateNonce(string value)
    {
        try
        {
            var bytes = Convert.FromBase64String(
                value.Replace('-', '+').Replace('_', '/') + "=");
            var roundTrip = Convert.ToBase64String(bytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
            if (bytes.Length != 32 || roundTrip != value)
            {
                throw Invalid("SENSOR_ENROLLMENT_CHALLENGE_VALUE_INVALID");
            }
            CryptographicOperations.ZeroMemory(bytes);
        }
        catch (FormatException error)
        {
            throw new InvalidDataException(
                "SENSOR_ENROLLMENT_CHALLENGE_VALUE_INVALID",
                error);
        }
    }

    private static bool GuidText(string value) =>
        value.Length == 36 &&
        value == value.ToLowerInvariant() &&
        Guid.TryParseExact(value, "D", out _);

    private static string RequiredString(JsonElement value, string property)
    {
        var item = value.GetProperty(property);
        if (item.ValueKind != JsonValueKind.String)
        {
            throw Invalid("SENSOR_ENROLLMENT_CHALLENGE_VALUE_INVALID");
        }
        return item.GetString() ??
            throw Invalid("SENSOR_ENROLLMENT_CHALLENGE_VALUE_INVALID");
    }

    private static void RequireExactProperties(
        JsonElement value,
        IReadOnlySet<string> expected,
        string error)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw Invalid(error);
        }
        var supplied = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            if (!supplied.Add(property.Name))
            {
                throw Invalid(error);
            }
        }
        if (!supplied.SetEquals(expected))
        {
            throw Invalid(error);
        }
    }

    private static IReadOnlySet<string> ExactSet(params string[] values) =>
        values.ToHashSet(StringComparer.Ordinal);

    private static InvalidDataException Invalid(string code) => new(code);
}
