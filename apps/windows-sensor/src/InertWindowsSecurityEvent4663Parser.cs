using System.Globalization;
using System.Text.RegularExpressions;

namespace WARRoom.WindowsSensor;

public enum InertWindowsSecurityEvent4663Profile
{
    CredentialStoreRead = 1,
    UnsecuredSecretRead = 2,
    HiddenAttributeWrite = 3
}

public sealed record InertWindowsSecurityEvent4663Candidate(
    string Provider,
    string Channel,
    string EventFamily,
    DateTimeOffset OccurredAtUtc,
    long SourceRecordId,
    InertWindowsSecurityEvent4663Profile Profile,
    string ObservedAccessClass,
    string RequiredObjectClass,
    IReadOnlyList<string> RequiredLocalClassifications,
    bool TargetSaclRequired,
    bool GenuineLiveEligible,
    bool RawEventContentRetained);

// Gate C2c candidate parser only. Profile selection is not caller-controlled at
// runtime because this type is deliberately unwired and performs no I/O.
public static partial class InertWindowsSecurityEvent4663Parser
{
    private const uint FileReadData = 0x00000001;
    private const uint FileWriteAttributes = 0x00000100;

    public const bool RuntimeWired = false;

    public static readonly IReadOnlyList<string> AllowedEventDataFields =
        Array.AsReadOnly([
            "AccessList",
            "AccessMask",
            "HandleId",
            "ObjectName",
            "ObjectServer",
            "ObjectType",
            "ProcessId",
            "ProcessName",
            "ResourceAttributes",
            "SubjectDomainName",
            "SubjectLogonId",
            "SubjectUserName",
            "SubjectUserSid"
        ]);

    public static InertWindowsSecurityEvent4663Candidate ParseCandidate(
        InertWindowsSecurityEventRecord record,
        InertWindowsSecurityEvent4663Profile profile)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(record.EventData);
        if (
            record.ProviderName != "Microsoft-Windows-Security-Auditing" ||
            record.ChannelName != "Security" ||
            record.EventId != 4663 ||
            record.Level != 0 ||
            record.TimeCreatedUtc.Offset != TimeSpan.Zero ||
            record.RecordId is < 1 or > InertWindowsSecurityEvent1102Parser.MaximumJsonInteger)
        {
            throw new InvalidDataException("SENSOR_C2C_EVENT_4663_METADATA_INVALID");
        }

        if (
            record.EventData.Count != AllowedEventDataFields.Count ||
            record.EventData.Keys.Order(StringComparer.Ordinal).SequenceEqual(
                AllowedEventDataFields,
                StringComparer.Ordinal) is false)
        {
            throw new InvalidDataException("SENSOR_C2C_EVENT_4663_FIELDS_INVALID");
        }

        ValidateValues(record.EventData);
        var accessMask = ParseAccessMask(record.EventData["AccessMask"]);
        var (eventFamily, accessClass, objectClass, requiredMask, enrichments) =
            profile switch
            {
                InertWindowsSecurityEvent4663Profile.CredentialStoreRead => (
                    "file-access",
                    "read",
                    "credential-store",
                    FileReadData,
                    Array.AsReadOnly([
                        "actor-trust", "subject-class", "target-class", "baseline-state"
                    ])),
                InertWindowsSecurityEvent4663Profile.UnsecuredSecretRead => (
                    "file-access",
                    "read",
                    "unsecured-secret",
                    FileReadData,
                    Array.AsReadOnly([
                        "actor-trust", "subject-class", "target-class", "baseline-state"
                    ])),
                InertWindowsSecurityEvent4663Profile.HiddenAttributeWrite => (
                    "file-attribute-change",
                    "write-attributes",
                    "hidden-artifact",
                    FileWriteAttributes,
                    Array.AsReadOnly([
                        "actor-trust", "subject-class", "target-class", "post-event-visibility"
                    ])),
                _ => throw new InvalidDataException(
                    "SENSOR_C2C_EVENT_4663_PROFILE_INVALID")
            };

        if ((accessMask & requiredMask) != requiredMask)
        {
            throw new InvalidDataException("SENSOR_C2C_EVENT_4663_ACCESS_INVALID");
        }

        return new InertWindowsSecurityEvent4663Candidate(
            "windows-security",
            "security",
            eventFamily,
            record.TimeCreatedUtc,
            record.RecordId,
            profile,
            accessClass,
            objectClass,
            enrichments,
            true,
            false,
            false);
    }

    private static void ValidateValues(
        IReadOnlyDictionary<string, string> eventData)
    {
        if (
            !SidPattern().IsMatch(eventData["SubjectUserSid"]) ||
            !IsBoundedText(eventData["SubjectUserName"], 256) ||
            !IsBoundedText(eventData["SubjectDomainName"], 256) ||
            !HexPointerPattern().IsMatch(eventData["SubjectLogonId"]) ||
            eventData["ObjectServer"] != "Security" ||
            eventData["ObjectType"] != "File" ||
            !IsBoundedText(eventData["ObjectName"], 1024) ||
            !HexPointerPattern().IsMatch(eventData["HandleId"]) ||
            !AccessListPattern().IsMatch(eventData["AccessList"]) ||
            !AccessMaskPattern().IsMatch(eventData["AccessMask"]) ||
            !HexPointerPattern().IsMatch(eventData["ProcessId"]) ||
            !IsBoundedText(eventData["ProcessName"], 1024) ||
            !IsBoundedText(eventData["ResourceAttributes"], 2048))
        {
            throw new InvalidDataException("SENSOR_C2C_EVENT_4663_VALUES_INVALID");
        }
    }

    private static uint ParseAccessMask(string value)
    {
        if (!uint.TryParse(
            value.AsSpan(2),
            NumberStyles.AllowHexSpecifier,
            CultureInfo.InvariantCulture,
            out var accessMask))
        {
            throw new InvalidDataException("SENSOR_C2C_EVENT_4663_VALUES_INVALID");
        }

        return accessMask;
    }

    private static bool IsBoundedText(string value, int maximumLength) =>
        value.Length is >= 1 &&
        value.Length <= maximumLength &&
        value.All(character => !char.IsControl(character));

    [GeneratedRegex(@"^S-[0-9]+(?:-[0-9]+){2,15}$", RegexOptions.CultureInvariant)]
    private static partial Regex SidPattern();

    [GeneratedRegex(@"^0x[0-9A-Fa-f]{1,16}$", RegexOptions.CultureInvariant)]
    private static partial Regex HexPointerPattern();

    // Event XML normalises the native Windows CRLF AccessList delimiter to LF.
    // Accept only the observed four-tab message-template delimiter (including
    // its optional trailing delimiter), or the canonical single-space fixture
    // form. No other control characters or whitespace are accepted.
    [GeneratedRegex(@"^%%[0-9]{4}(?:(?: |\n\t{4})%%[0-9]{4}){0,31}(?:\n\t{4})?$", RegexOptions.CultureInvariant)]
    private static partial Regex AccessListPattern();

    [GeneratedRegex(@"^0x[0-9A-Fa-f]{1,8}$", RegexOptions.CultureInvariant)]
    private static partial Regex AccessMaskPattern();
}
