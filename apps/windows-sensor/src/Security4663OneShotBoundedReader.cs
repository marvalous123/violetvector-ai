using System.Globalization;
using System.Xml;
using System.Xml.Linq;
using WARRoom.WindowsSensor.Readiness;

namespace WARRoom.WindowsSensor;

public sealed record Security4663OneShotSourceQuery(
    string LogName,
    string XPath,
    bool ReverseDirection,
    bool TolerateQueryErrors,
    int MaximumEventsRead,
    int MaximumQueryMilliseconds,
    int MaximumEventXmlCharacters);

public sealed record Security4663OneShotSourceResult(
    Security4663OneShotReadState State,
    string? EventXml);

public interface ISecurity4663OneShotEventSource
{
    Security4663OneShotSourceResult ReadOne(
        Security4663OneShotSourceQuery query,
        CancellationToken cancellationToken);
}

// Gate C2e bounded reader contract. The low-level source remains a fake-only
// interface: no EventLogReader implementation or runtime registration exists.
public sealed class Security4663OneShotBoundedReader(
    ISecurity4663OneShotEventSource source) : ISecurity4663OneShotReader
{
    public const bool RuntimeWired = false;
    public const bool NativeEventAccessEnabled = false;
    public const int MaximumEventXmlCharacters = 16_384;

    private const string EventNamespace =
        "http://schemas.microsoft.com/win/2004/08/events/event";

    private readonly ISecurity4663OneShotEventSource _source =
        source ?? throw new ArgumentNullException(nameof(source));

    public Security4663OneShotReadResult ReadOne(
        Security4663OneShotReadRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateRequest(request);
        var query = new Security4663OneShotSourceQuery(
            request.ChannelName,
            BuildXPath(request.BaselineRecordId),
            true,
            false,
            1,
            2_000,
            MaximumEventXmlCharacters);
        var sourceResult = _source.ReadOne(query, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(sourceResult);
        if (!Enum.IsDefined(sourceResult.State))
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_SOURCE_STATE_INVALID");
        }
        if (sourceResult.State != Security4663OneShotReadState.Match)
        {
            if (sourceResult.EventXml is not null)
            {
                throw new InvalidDataException(
                    "SENSOR_C2E_SECURITY_4663_SOURCE_NONMATCH_XML_INVALID");
            }
            return new Security4663OneShotReadResult(
                sourceResult.State,
                null);
        }

        if (
            string.IsNullOrEmpty(sourceResult.EventXml) ||
            sourceResult.EventXml.Length > MaximumEventXmlCharacters)
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_SOURCE_XML_INVALID");
        }

        return new Security4663OneShotReadResult(
            Security4663OneShotReadState.Match,
            ParseExactEventXml(sourceResult.EventXml));
    }

    public static string BuildXPath(long baselineRecordId)
    {
        if (baselineRecordId is < 1 or >
            Security4663OneShotCoordinator.MaximumJsonInteger)
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_BASELINE_INVALID");
        }
        return "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] " +
            "and EventID=4663 and Level=0 and EventRecordID>" +
            baselineRecordId.ToString(CultureInfo.InvariantCulture) + "]]";
    }

    private static void ValidateRequest(Security4663OneShotReadRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (
            request.SchemaVersion != 1 ||
            request.Checkpoint != Security4663OneShotMachinePlan.Checkpoint ||
            request.ProviderName !=
                "Microsoft-Windows-Security-Auditing" ||
            request.ChannelName != "Security" ||
            request.EventId != 4663 ||
            request.Level != 0 ||
            request.Profile !=
                InertWindowsSecurityEvent4663Profile.CredentialStoreRead ||
            request.BaselineRecordId is < 1 or >
                Security4663OneShotCoordinator.MaximumJsonInteger ||
            request.TriggerStartedUtc.Offset != TimeSpan.Zero ||
            request.TriggerCompletedUtc.Offset != TimeSpan.Zero ||
            request.TriggerCompletedUtc < request.TriggerStartedUtc ||
            request.TriggerCompletedUtc - request.TriggerStartedUtc >
                TimeSpan.FromSeconds(10) ||
            request.MaximumQueryMilliseconds != 2_000 ||
            request.MaximumEventsRead != 1)
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_READ_REQUEST_INVALID");
        }
    }

    private static InertWindowsSecurityEventRecord ParseExactEventXml(
        string eventXml)
    {
        XDocument document;
        try
        {
            using var stringReader = new StringReader(eventXml);
            using var xmlReader = XmlReader.Create(
                stringReader,
                new XmlReaderSettings
                {
                    DtdProcessing = DtdProcessing.Prohibit,
                    XmlResolver = null,
                    MaxCharactersInDocument = MaximumEventXmlCharacters
                });
            document = XDocument.Load(xmlReader, LoadOptions.None);
        }
        catch (XmlException)
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_SOURCE_XML_INVALID");
        }

        XNamespace ns = EventNamespace;
        var root = document.Root;
        var system = root?.Element(ns + "System");
        var eventData = root?.Element(ns + "EventData");
        var providers = system?.Elements(ns + "Provider").ToArray() ?? [];
        var timeCreatedValues =
            system?.Elements(ns + "TimeCreated").ToArray() ?? [];
        var provider = providers.Length == 1 ? providers[0] : null;
        var timeCreated =
            timeCreatedValues.Length == 1 ? timeCreatedValues[0] : null;
        if (
            root?.Name != ns + "Event" ||
            root.Elements().Count() != 2 ||
            system is null ||
            eventData is null ||
            provider is null ||
            timeCreated is null)
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_SOURCE_XML_INVALID");
        }

        var fields = eventData.Elements(ns + "Data").ToArray();
        if (
            eventData.Elements().Count() != fields.Length ||
            fields.Any(field => field.Elements().Any()))
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_SOURCE_XML_INVALID");
        }

        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var field in fields)
        {
            var name = field.Attribute("Name")?.Value;
            if (
                field.Attributes().Count() != 1 ||
                string.IsNullOrEmpty(name) ||
                !values.TryAdd(name, field.Value))
            {
                throw new InvalidDataException(
                    "SENSOR_C2E_SECURITY_4663_SOURCE_XML_INVALID");
            }
        }

        if (
            !HasExactProviderAttributes(provider) ||
            timeCreated.Attributes().Count() != 1 ||
            system.Elements(ns + "EventID").Count() != 1 ||
            system.Elements(ns + "Level").Count() != 1 ||
            system.Elements(ns + "EventRecordID").Count() != 1 ||
            system.Elements(ns + "Channel").Count() != 1 ||
            !int.TryParse(
                system.Element(ns + "EventID")?.Value,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var eventId) ||
            !int.TryParse(
                system.Element(ns + "Level")?.Value,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var level) ||
            !long.TryParse(
                system.Element(ns + "EventRecordID")?.Value,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var recordId) ||
            !DateTimeOffset.TryParseExact(
                timeCreated.Attribute("SystemTime")?.Value,
                "O",
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind,
                out var occurredAtUtc))
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_SOURCE_XML_INVALID");
        }

        var record = new InertWindowsSecurityEventRecord(
            provider.Attribute("Name")?.Value ?? string.Empty,
            system.Element(ns + "Channel")?.Value ?? string.Empty,
            eventId,
            level,
            occurredAtUtc,
            recordId,
            values);
        _ = InertWindowsSecurityEvent4663Parser.ParseCandidate(
            record,
            InertWindowsSecurityEvent4663Profile.CredentialStoreRead);
        return record;
    }

    private static bool HasExactProviderAttributes(XElement provider)
    {
        var attributes = provider.Attributes().ToArray();
        if (attributes.Length is < 1 or > 2 ||
            provider.Attribute("Name") is null)
        {
            return false;
        }
        if (attributes.Length == 1) return true;
        var guid = provider.Attribute("Guid")?.Value;
        return guid is not null && string.Equals(
            guid,
            "{54849625-5478-4994-A5BA-3E3B0328C30D}",
            StringComparison.OrdinalIgnoreCase);
    }
}
