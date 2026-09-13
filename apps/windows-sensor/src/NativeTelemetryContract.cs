using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Globalization;

namespace WARRoom.WindowsSensor;

public sealed record NativeFactStreamHead(
    string BootId,
    long LastBatchSequence,
    string LastBatchHash);

public sealed record NativeTelemetrySigningResult(
    string CanonicalPayload,
    string BatchHash,
    string SignatureBase64);

public sealed class NativeTelemetryFactBatch
{
    private const long MaximumJsonInteger = 9_007_199_254_740_991;

    private static readonly Regex ConnectorIdPattern = ExactPattern(
        "^connector-[a-f0-9-]{36}$");
    private static readonly Regex EndpointIdPattern = ExactPattern(
        "^endpoint-[a-f0-9-]{36}$");
    private static readonly Regex CapabilityIdPattern = ExactPattern(
        "^capability-[a-f0-9-]{36}$");
    private static readonly Regex BootIdPattern = ExactPattern(
        "^boot-[a-z0-9-]{8,80}$");
    private static readonly Regex FactIdPattern = ExactPattern(
        "^fact-[a-z0-9-]{8,96}$");
    private static readonly Regex Sha256Pattern = ExactPattern("^[a-f0-9]{64}$");
    private static readonly Regex IsoDateTimePattern = ExactPattern(
        "^(?<year>\\d{4})-(?<month>\\d{2})-(?<day>\\d{2})T(?<hour>\\d{2}):(?<minute>\\d{2}):(?<second>\\d{2})(?:\\.\\d{1,9})?(?:Z|[+-](?<offsetHour>\\d{2}):(?<offsetMinute>\\d{2}))$");

    private static readonly IReadOnlySet<string> CoreFields = ExactSet(
        "schemaVersion",
        "missionId",
        "connectorId",
        "endpointId",
        "certificateFingerprintSha256",
        "capabilitySnapshotId",
        "bootId",
        "batchSequence",
        "previousBatchHash",
        "provider",
        "channel",
        "eventFamily",
        "filterHash",
        "facts");

    private static readonly IReadOnlySet<string> FactFields = ExactSet(
        "factId",
        "occurredAt",
        "sourceRecordIdHash",
        "fields");

    private static readonly IReadOnlySet<string> MinimizedFieldNames = ExactSet(
        "actorTrust",
        "action",
        "subjectClass",
        "objectClass",
        "parentClass",
        "signerState",
        "originZone",
        "elevated",
        "outcome",
        "baselineState",
        "contentState",
        "visibilityState",
        "metadataState",
        "failureCountBucket",
        "recentExecution");

    private static readonly IReadOnlySet<string> ScmSystemFieldProfile = ExactSet(
        "actorTrust", "action", "subjectClass", "objectClass", "outcome");

    private static readonly IReadOnlyDictionary<string, IReadOnlySet<string>>
        StringFieldValues =
            new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal)
            {
                ["actorTrust"] = ExactSet("managed", "untrusted", "unknown"),
                ["action"] = ExactSet(
                    "start", "open-process", "read", "create", "modify", "delete",
                    "clear", "stop", "disable", "add-rule", "remove-rule", "access",
                    "export", "register", "authenticate", "request", "load",
                    "write-memory", "execute", "decode", "hide"),
                ["subjectClass"] = ExactSet(
                    "powershell", "office", "browser", "document-reader",
                    "password-manager", "mshta", "msiexec", "regsvr32", "rundll32",
                    "system-binary", "security-tool", "admin-tool", "other"),
                ["objectClass"] = ExactSet(
                    "auth-memory", "credential-store", "security-control", "event-log",
                    "firewall-policy", "scheduled-task", "service", "unsecured-secret",
                    "input-device", "authentication", "kerberos-ticket", "session-store",
                    "application-token", "authentication-component", "authentication-key",
                    "installer-package", "module", "process-memory", "audit-policy",
                    "encoded-content", "binary-metadata", "hidden-artifact",
                    "executable-artifact", "other"),
                ["parentClass"] = ExactSet(
                    "office", "browser", "shell", "service-manager", "unknown"),
                ["signerState"] = ExactSet(
                    "signed-trusted", "signed-untrusted", "unsigned", "unknown"),
                ["originZone"] = ExactSet(
                    "system", "program-files", "user-writable", "remote", "unknown"),
                ["outcome"] = ExactSet("success", "failure", "unknown"),
                ["baselineState"] = ExactSet("expected", "new", "rare", "unknown"),
                ["contentState"] = ExactSet(
                    "plain", "encoded", "high-entropy", "unknown"),
                ["visibilityState"] = ExactSet(
                    "visible", "hidden", "alternate-stream", "unknown"),
                ["metadataState"] = ExactSet("consistent", "mismatch", "unknown"),
                ["failureCountBucket"] = ExactSet("none", "low", "burst", "unknown")
            };

    private static readonly IReadOnlyDictionary<string, (
        string Channel,
        IReadOnlySet<string> Families)> ProviderStreams =
            new Dictionary<string, (string, IReadOnlySet<string>)>(
                StringComparer.Ordinal)
            {
                ["windows-security"] = (
                    "security",
                    ExactSet(
                        "process-start", "authentication", "ticket-request",
                        "authentication-component-change", "certificate-key-access",
                        "scheduled-task-change", "service-change")),
                ["windows-sysmon"] = (
                    "sysmon-operational",
                    ExactSet(
                        "process-start", "process-access", "file-access", "image-load",
                        "file-attribute-change")),
                ["windows-defender"] = (
                    "defender-operational",
                    ExactSet("security-control-change")),
                ["windows-eventlog"] = (
                    "eventlog-admin",
                    ExactSet("event-log-impairment", "event-log-clear")),
                ["windows-firewall"] = (
                    "firewall-operational",
                    ExactSet("firewall-policy-change")),
                ["windows-scm"] = (
                    "system",
                    ExactSet("service-change"))
            };

    private readonly JsonElement core;

    private NativeTelemetryFactBatch(
        JsonElement core,
        string certificateFingerprintSha256,
        string bootId,
        long batchSequence,
        string? previousBatchHash)
    {
        this.core = core;
        CertificateFingerprintSha256 = certificateFingerprintSha256;
        BootId = bootId;
        BatchSequence = batchSequence;
        PreviousBatchHash = previousBatchHash;
    }

    public string CertificateFingerprintSha256 { get; }

    public string BootId { get; }

    public long BatchSequence { get; }

    public string? PreviousBatchHash { get; }

    public static NativeTelemetryFactBatch ParseCore(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        using var document = JsonDocument.Parse(
            json,
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 16
            });
        var root = document.RootElement;
        RequireExactProperties(root, CoreFields, "SENSOR_FACT_BATCH_FIELDS_INVALID");
        if (RequireInteger(root, "schemaVersion") != 1)
        {
            throw Invalid("SENSOR_FACT_BATCH_SCHEMA_INVALID");
        }
        var missionId = RequireString(root, "missionId");
        if (missionId.Length is < 1 or > 128)
        {
            throw Invalid("SENSOR_FACT_BATCH_MISSION_INVALID");
        }
        RequirePattern(root, "connectorId", ConnectorIdPattern);
        RequirePattern(root, "endpointId", EndpointIdPattern);
        var certificateFingerprintSha256 = RequirePattern(
            root,
            "certificateFingerprintSha256",
            Sha256Pattern);
        RequirePattern(root, "capabilitySnapshotId", CapabilityIdPattern);
        var bootId = RequirePattern(root, "bootId", BootIdPattern);
        var batchSequence = RequireInteger(root, "batchSequence");
        if (batchSequence is < 0 or > MaximumJsonInteger)
        {
            throw Invalid("SENSOR_FACT_BATCH_SEQUENCE_INVALID");
        }
        var previousBatchHash = OptionalHash(root, "previousBatchHash");
        var provider = RequireString(root, "provider");
        var channel = RequireString(root, "channel");
        var eventFamily = RequireString(root, "eventFamily");
        if (
            !ProviderStreams.TryGetValue(provider, out var stream) ||
            !StringComparer.Ordinal.Equals(stream.Channel, channel) ||
            !stream.Families.Contains(eventFamily))
        {
            throw Invalid("SENSOR_FACT_BATCH_STREAM_INVALID");
        }
        RequirePattern(root, "filterHash", Sha256Pattern);
        ValidateFacts(root.GetProperty("facts"), provider, channel, eventFamily);
        return new NativeTelemetryFactBatch(
            root.Clone(),
            certificateFingerprintSha256,
            bootId,
            batchSequence,
            previousBatchHash);
    }

    public string CanonicalPayload() => CanonicalJson(core);

    public string BatchHash() =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalPayload())))
            .ToLowerInvariant();

    public NativeTelemetrySigningResult Sign(ISensorIdentitySigner identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (
            !StringComparer.Ordinal.Equals(
                CertificateFingerprintSha256,
                identity.Descriptor.CertificateFingerprintSha256))
        {
            throw new CryptographicException("SENSOR_FACT_IDENTITY_MISMATCH");
        }

        byte[]? payloadBytes = null;
        byte[]? signature = null;
        byte[]? spki = null;
        try
        {
            var payload = CanonicalPayload();
            payloadBytes = Encoding.UTF8.GetBytes(payload);
            signature = Convert.FromBase64String(identity.SignUtf8Payload(payload));
            spki = Convert.FromBase64String(
                identity.Descriptor.PublicKeySpkiBase64);
            var descriptorFingerprint =
                Convert.ToHexString(SHA256.HashData(spki)).ToLowerInvariant();
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(spki, out var bytesRead);
            if (
                !StringComparer.Ordinal.Equals(
                    descriptorFingerprint,
                    identity.Descriptor.CertificateFingerprintSha256) ||
                bytesRead != spki.Length ||
                signature.Length != 64 ||
                !verifier.VerifyData(
                    payloadBytes,
                    signature,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                throw new CryptographicException("SENSOR_FACT_SIGNING_INVALID");
            }
            return new NativeTelemetrySigningResult(
                payload,
                Convert.ToHexString(SHA256.HashData(payloadBytes))
                    .ToLowerInvariant(),
                Convert.ToBase64String(signature));
        }
        catch (FormatException error)
        {
            throw new CryptographicException(
                "SENSOR_FACT_SIGNING_INVALID",
                error);
        }
        catch (CryptographicException error) when (
            error.Message is not
                "SENSOR_FACT_IDENTITY_MISMATCH" and not
                "SENSOR_FACT_SIGNING_INVALID")
        {
            throw new CryptographicException(
                "SENSOR_FACT_SIGNING_INVALID",
                error);
        }
        finally
        {
            if (payloadBytes is not null)
            {
                CryptographicOperations.ZeroMemory(payloadBytes);
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

    public void ValidateContinuity(NativeFactStreamHead? head)
    {
        if (head is null)
        {
            if (BatchSequence != 0 || PreviousBatchHash is not null)
            {
                throw Invalid("SENSOR_FACT_SEQUENCE_ORIGIN_INVALID");
            }
            return;
        }
        if (
            !BootIdPattern.IsMatch(head.BootId) ||
            head.LastBatchSequence is < 0 or >= MaximumJsonInteger ||
            !Sha256Pattern.IsMatch(head.LastBatchHash))
        {
            throw Invalid("SENSOR_FACT_STREAM_HEAD_INVALID");
        }
        if (!StringComparer.Ordinal.Equals(PreviousBatchHash, head.LastBatchHash))
        {
            throw Invalid("SENSOR_FACT_PREVIOUS_BATCH_MISMATCH");
        }
        if (StringComparer.Ordinal.Equals(BootId, head.BootId))
        {
            if (BatchSequence != head.LastBatchSequence + 1)
            {
                throw Invalid("SENSOR_FACT_SEQUENCE_CONTINUITY_INVALID");
            }
            return;
        }
        if (BatchSequence != 0)
        {
            throw Invalid("SENSOR_FACT_BOOT_TRANSITION_INVALID");
        }
    }

    private static void ValidateFacts(
        JsonElement facts,
        string provider,
        string channel,
        string eventFamily)
    {
        if (
            facts.ValueKind != JsonValueKind.Array ||
            facts.GetArrayLength() is < 1 or > 128)
        {
            throw Invalid("SENSOR_FACT_BATCH_FACTS_INVALID");
        }
        var factIds = new HashSet<string>(StringComparer.Ordinal);
        var sourceHashes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var fact in facts.EnumerateArray())
        {
            RequireExactProperties(
                fact,
                FactFields,
                "SENSOR_MINIMIZED_FACT_FIELDS_INVALID");
            var factId = RequirePattern(fact, "factId", FactIdPattern);
            var sourceHash = RequirePattern(
                fact,
                "sourceRecordIdHash",
                Sha256Pattern);
            if (!factIds.Add(factId) || !sourceHashes.Add(sourceHash))
            {
                throw Invalid("SENSOR_MINIMIZED_FACT_DUPLICATE");
            }
            var occurredAt = RequireString(fact, "occurredAt");
            if (!ValidIsoDateTime(occurredAt))
            {
                throw Invalid("SENSOR_MINIMIZED_FACT_TIME_INVALID");
            }
            var fields = fact.GetProperty("fields");
            ValidateMinimizedFields(fields);
            if (
                provider == "windows-scm" &&
                (
                    channel != "system" ||
                    eventFamily != "service-change" ||
                    !ExactPropertyNames(fields, ScmSystemFieldProfile) ||
                    fields.GetProperty("actorTrust").GetString() != "unknown" ||
                    fields.GetProperty("action").GetString() != "create" ||
                    fields.GetProperty("subjectClass").GetString() != "other" ||
                    fields.GetProperty("objectClass").GetString() != "service" ||
                    fields.GetProperty("outcome").GetString() != "unknown"
                ))
            {
                throw Invalid("SENSOR_SCM_FACT_PROFILE_INVALID");
            }
        }
    }

    private static bool ExactPropertyNames(
        JsonElement value,
        IReadOnlySet<string> expected)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            return false;
        }
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            if (!names.Add(property.Name))
            {
                return false;
            }
        }
        return names.SetEquals(expected);
    }

    private static void ValidateMinimizedFields(JsonElement fields)
    {
        if (fields.ValueKind != JsonValueKind.Object)
        {
            throw Invalid("SENSOR_MINIMIZED_FACT_VALUES_INVALID");
        }
        var supplied = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in fields.EnumerateObject())
        {
            if (!supplied.Add(property.Name) || !MinimizedFieldNames.Contains(property.Name))
            {
                throw Invalid("SENSOR_MINIMIZED_FACT_VALUES_INVALID");
            }
            if (property.Name is "elevated" or "recentExecution")
            {
                if (
                    property.Value.ValueKind is not JsonValueKind.True and
                    not JsonValueKind.False)
                {
                    throw Invalid("SENSOR_MINIMIZED_FACT_VALUES_INVALID");
                }
                continue;
            }
            if (
                property.Value.ValueKind != JsonValueKind.String ||
                !StringFieldValues[property.Name].Contains(
                    property.Value.GetString() ?? ""))
            {
                throw Invalid("SENSOR_MINIMIZED_FACT_VALUES_INVALID");
            }
        }
        foreach (var required in new[]
                 {
                     "actorTrust", "action", "subjectClass", "objectClass"
                 })
        {
            if (!supplied.Contains(required))
            {
                throw Invalid("SENSOR_MINIMIZED_FACT_VALUES_INVALID");
            }
        }
    }

    private static string CanonicalJson(JsonElement value)
    {
        using var output = new MemoryStream();
        using (
            var writer = new Utf8JsonWriter(
                output,
                new JsonWriterOptions
                {
                    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                }))
        {
            WriteCanonical(writer, value);
        }
        return Encoding.UTF8.GetString(output.ToArray());
    }

    private static void WriteCanonical(Utf8JsonWriter writer, JsonElement value)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (
                    var property in value.EnumerateObject()
                        .OrderBy(item => item.Name, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(property.Name);
                    WriteCanonical(writer, property.Value);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in value.EnumerateArray())
                {
                    WriteCanonical(writer, item);
                }
                writer.WriteEndArray();
                break;
            case JsonValueKind.String:
                writer.WriteRawValue(
                    JavaScriptJsonString(value.GetString() ?? ""),
                    skipInputValidation: true);
                break;
            case JsonValueKind.Number:
                if (!value.TryGetInt64(out var integer))
                {
                    throw Invalid("SENSOR_FACT_BATCH_JSON_INVALID");
                }
                writer.WriteNumberValue(integer);
                break;
            case JsonValueKind.True:
                writer.WriteBooleanValue(true);
                break;
            case JsonValueKind.False:
                writer.WriteBooleanValue(false);
                break;
            case JsonValueKind.Null:
                writer.WriteNullValue();
                break;
            default:
                throw Invalid("SENSOR_FACT_BATCH_JSON_INVALID");
        }
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

    private static string RequireString(JsonElement value, string property)
    {
        var item = value.GetProperty(property);
        if (item.ValueKind != JsonValueKind.String)
        {
            throw Invalid("SENSOR_FACT_BATCH_VALUE_INVALID");
        }
        return item.GetString() ?? throw Invalid("SENSOR_FACT_BATCH_VALUE_INVALID");
    }

    private static string RequirePattern(
        JsonElement value,
        string property,
        Regex pattern)
    {
        var item = RequireString(value, property);
        if (!pattern.IsMatch(item))
        {
            throw Invalid("SENSOR_FACT_BATCH_VALUE_INVALID");
        }
        return item;
    }

    private static long RequireInteger(JsonElement value, string property)
    {
        var item = value.GetProperty(property);
        if (item.ValueKind != JsonValueKind.Number || !item.TryGetInt64(out var result))
        {
            throw Invalid("SENSOR_FACT_BATCH_VALUE_INVALID");
        }
        return result;
    }

    private static string? OptionalHash(JsonElement value, string property)
    {
        var item = value.GetProperty(property);
        if (item.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        if (
            item.ValueKind != JsonValueKind.String ||
            !Sha256Pattern.IsMatch(item.GetString() ?? ""))
        {
            throw Invalid("SENSOR_FACT_BATCH_VALUE_INVALID");
        }
        return item.GetString();
    }

    private static Regex ExactPattern(string pattern) =>
        new(
            pattern,
            RegexOptions.CultureInvariant | RegexOptions.NonBacktracking,
            TimeSpan.FromMilliseconds(100));

    private static bool ValidIsoDateTime(string value)
    {
        var match = IsoDateTimePattern.Match(value);
        if (!match.Success)
        {
            return false;
        }
        if (
            !DateOnly.TryParseExact(
                $"{match.Groups["year"].Value}-{match.Groups["month"].Value}-{match.Groups["day"].Value}",
                "yyyy-MM-dd",
                CultureInfo.InvariantCulture,
                DateTimeStyles.None,
                out _) ||
            !int.TryParse(
                match.Groups["hour"].Value,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var hour) ||
            !int.TryParse(
                match.Groups["minute"].Value,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var minute) ||
            !int.TryParse(
                match.Groups["second"].Value,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var second) ||
            hour > 23 ||
            minute > 59 ||
            second > 59)
        {
            return false;
        }
        if (!match.Groups["offsetHour"].Success)
        {
            return true;
        }
        var offsetHour = int.Parse(
            match.Groups["offsetHour"].Value,
            CultureInfo.InvariantCulture);
        var offsetMinute = int.Parse(
            match.Groups["offsetMinute"].Value,
            CultureInfo.InvariantCulture);
        return
            offsetHour <= 14 &&
            offsetMinute <= 59 &&
            (offsetHour != 14 || offsetMinute == 0);
    }

    private static string JavaScriptJsonString(string value)
    {
        var result = new StringBuilder(value.Length + 2);
        result.Append('"');
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            switch (character)
            {
                case '"':
                    result.Append("\\\"");
                    break;
                case '\\':
                    result.Append("\\\\");
                    break;
                case '\b':
                    result.Append("\\b");
                    break;
                case '\f':
                    result.Append("\\f");
                    break;
                case '\n':
                    result.Append("\\n");
                    break;
                case '\r':
                    result.Append("\\r");
                    break;
                case '\t':
                    result.Append("\\t");
                    break;
                default:
                    if (character < 0x20 || char.IsSurrogate(character))
                    {
                        if (
                            char.IsHighSurrogate(character) &&
                            index + 1 < value.Length &&
                            char.IsLowSurrogate(value[index + 1]))
                        {
                            result.Append(character);
                            result.Append(value[++index]);
                        }
                        else
                        {
                            result.Append("\\u");
                            result.Append(((int)character).ToString(
                                "x4",
                                CultureInfo.InvariantCulture));
                        }
                    }
                    else
                    {
                        result.Append(character);
                    }
                    break;
            }
        }
        result.Append('"');
        return result.ToString();
    }

    private static IReadOnlySet<string> ExactSet(params string[] values) =>
        values.ToHashSet(StringComparer.Ordinal);

    private static InvalidDataException Invalid(string code) => new(code);
}
