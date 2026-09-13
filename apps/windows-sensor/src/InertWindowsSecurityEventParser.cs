using System.Text.RegularExpressions;

namespace WARRoom.WindowsSensor;

public sealed record InertWindowsSecurityEventRecord(
    string ProviderName,
    string ChannelName,
    int EventId,
    int Level,
    DateTimeOffset TimeCreatedUtc,
    long RecordId,
    IReadOnlyDictionary<string, string> EventData);

public sealed record InertWindowsSecurityNormalizedFact(
    string Provider,
    string Channel,
    string EventFamily,
    DateTimeOffset OccurredAtUtc,
    long SourceRecordId,
    BoundedFactMapping Mapping,
    bool RawEventContentRetained);

// Gate C2c is an inert parser contract only. It is deliberately absent from
// dependency injection and the hosted service, and it performs no I/O.
public static partial class InertWindowsSecurityEvent1102Parser
{
    public const bool RuntimeWired = false;
    public const long MaximumJsonInteger = 9_007_199_254_740_991;

    public static readonly IReadOnlyList<string> AllowedEventDataFields =
        Array.AsReadOnly([
            "SubjectDomainName",
            "SubjectLogonId",
            "SubjectUserName",
            "SubjectUserSid"
        ]);

    public static InertWindowsSecurityNormalizedFact Parse(
        InertWindowsSecurityEventRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(record.EventData);
        if (
            record.ProviderName != "Microsoft-Windows-Eventlog" ||
            record.ChannelName != "Security" ||
            record.EventId != 1102 ||
            record.Level != 4 ||
            record.TimeCreatedUtc.Offset != TimeSpan.Zero ||
            record.RecordId is < 1 or > MaximumJsonInteger)
        {
            throw new InvalidDataException("SENSOR_C2C_EVENT_1102_METADATA_INVALID");
        }

        if (
            record.EventData.Count != AllowedEventDataFields.Count ||
            record.EventData.Keys.Order(StringComparer.Ordinal).SequenceEqual(
                AllowedEventDataFields,
                StringComparer.Ordinal) is false)
        {
            throw new InvalidDataException("SENSOR_C2C_EVENT_1102_FIELDS_INVALID");
        }

        var sid = record.EventData["SubjectUserSid"];
        var user = record.EventData["SubjectUserName"];
        var domain = record.EventData["SubjectDomainName"];
        var logonId = record.EventData["SubjectLogonId"];
        if (
            !SidPattern().IsMatch(sid) ||
            !LogonIdPattern().IsMatch(logonId) ||
            !IsBoundedText(user) ||
            !IsBoundedText(domain))
        {
            throw new InvalidDataException("SENSOR_C2C_EVENT_1102_VALUES_INVALID");
        }

        return new InertWindowsSecurityNormalizedFact(
            "windows-security",
            "security",
            "event-log-clear",
            record.TimeCreatedUtc,
            record.RecordId,
            new BoundedFactMapping(
                "unknown", "clear", "other", "event-log", "success"),
            false);
    }

    private static bool IsBoundedText(string value) =>
        value.Length is >= 1 and <= 256 &&
        value.All(character => !char.IsControl(character));

    [GeneratedRegex(@"^S-[0-9]+(?:-[0-9]+){2,15}$", RegexOptions.CultureInvariant)]
    private static partial Regex SidPattern();

    [GeneratedRegex(@"^0x[0-9A-Fa-f]{1,16}$", RegexOptions.CultureInvariant)]
    private static partial Regex LogonIdPattern();
}
