namespace WARRoom.WindowsSensor;

public enum BoundedEventFamily
{
    ScmServiceInstalled = 1,
    ScmServiceStateChanged = 2
}

public enum BoundedEventReadState
{
    Match = 1,
    NoMatch = 2,
    AccessDenied = 3,
    SourceUnavailable = 4,
    QueryFailed = 5
}

public sealed record BoundedFactMapping(
    string ActorTrust,
    string Action,
    string SubjectClass,
    string ObjectClass,
    string Outcome);

public sealed record BoundedEventFamilyContract(
    BoundedEventFamily Family,
    string LogName,
    string ProviderName,
    int EventId,
    int Level,
    string FixedQuery,
    string NormalizedProvider,
    string NormalizedChannel,
    string NormalizedEventFamily,
    BoundedFactMapping Mapping);

public sealed record BoundedEventMetadata(
    string ProviderName,
    int EventId,
    int Level,
    DateTimeOffset TimeCreatedUtc,
    long RecordId);

public sealed record BoundedEventReadResult(
    BoundedEventReadState State,
    BoundedEventMetadata? Metadata);

public sealed record BoundedEventFamilyResult(
    BoundedEventFamily Family,
    BoundedEventReadState State,
    BoundedEventMetadata? Metadata);

public sealed record BoundedCollectorSnapshot(
    string CollectionMode,
    string LossState,
    string ContinuityState,
    int FamiliesQueried,
    int EventsRead,
    bool RawEventContentRead,
    bool RuntimeWired,
    bool NetworkTransportEnabled,
    bool AutomaticRetryEnabled,
    bool PollingEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    bool ResponseActionsEnabled,
    IReadOnlyList<BoundedEventFamilyResult> Results);

public interface IBoundedEventMetadataReader
{
    BoundedEventReadResult ReadOne(
        BoundedEventFamily family,
        CancellationToken cancellationToken);
}

public interface IMultiEventCollector
{
    BoundedCollectorSnapshot CollectOnce(
        DateTime notBeforeUtc,
        CancellationToken cancellationToken);
}

// Gate C1a keeps the native reader behind a deterministic, bounded coordinator
// that validates metadata before applying the current-install time window.
public sealed class BoundedMultiEventCollector(
    IBoundedEventMetadataReader reader) : IMultiEventCollector
{
    public const int MaximumFamilies = 2;
    public const int MaximumRecordsPerFamily = 1;
    public const int MaximumEvents = 2;
    public const int MaximumReadMillisecondsPerFamily = 2_000;
    public const int MaximumTotalReadMilliseconds = 4_000;
    public const long MaximumJsonInteger = 9_007_199_254_740_991;

    public static readonly IReadOnlyList<string> AllowedRecordAccessors =
        Array.AsReadOnly([
            "Id", "Level", "ProviderName", "RecordId", "TimeCreated"
        ]);

    public static readonly IReadOnlyList<BoundedEventFamilyContract> Contracts =
        Array.AsReadOnly([
            new BoundedEventFamilyContract(
                BoundedEventFamily.ScmServiceInstalled,
                "System",
                "Service Control Manager",
                7045,
                4,
                "*[System[Provider[@Name='Service Control Manager'] and EventID=7045 and Level=4]]",
                "windows-scm",
                "system",
                "service-change",
                new BoundedFactMapping(
                    "unknown", "create", "other", "service", "unknown")),
            new BoundedEventFamilyContract(
                BoundedEventFamily.ScmServiceStateChanged,
                "System",
                "Service Control Manager",
                7036,
                4,
                "*[System[Provider[@Name='Service Control Manager'] and EventID=7036 and Level=4]]",
                "windows-scm",
                "system",
                "service-state-change",
                new BoundedFactMapping(
                    "unknown", "modify", "other", "service", "unknown"))
        ]);

    private readonly IBoundedEventMetadataReader _reader =
        reader ?? throw new ArgumentNullException(nameof(reader));

    public BoundedCollectorSnapshot CollectOnce(
        DateTime notBeforeUtc,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (notBeforeUtc.Kind != DateTimeKind.Utc)
        {
            throw new InvalidOperationException(
                "SENSOR_C1_COLLECTION_WINDOW_INVALID");
        }
        if (Contracts.Count != MaximumFamilies)
        {
            throw new InvalidOperationException("SENSOR_C1_SOURCE_CONTRACT_INVALID");
        }

        var results = new List<BoundedEventFamilyResult>(MaximumFamilies);
        var eventsRead = 0;
        foreach (var contract in Contracts)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = _reader.ReadOne(contract.Family, cancellationToken);
            ValidateResult(contract, result);
            result = ApplyCollectionWindow(result, notBeforeUtc);
            if (result.State == BoundedEventReadState.Match)
            {
                eventsRead++;
            }
            results.Add(new BoundedEventFamilyResult(
                contract.Family,
                result.State,
                result.Metadata));
        }

        if (eventsRead > MaximumEvents)
        {
            throw new InvalidOperationException("SENSOR_C1_EVENT_BUDGET_EXCEEDED");
        }

        return new BoundedCollectorSnapshot(
            "explicit-one-shot-contract",
            "unknown",
            "unknown",
            MaximumFamilies,
            eventsRead,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            results.AsReadOnly());
    }

    internal static BoundedEventReadResult ApplyCollectionWindow(
        BoundedEventReadResult result,
        DateTime notBeforeUtc)
    {
        ArgumentNullException.ThrowIfNull(result);
        if (notBeforeUtc.Kind != DateTimeKind.Utc)
        {
            throw new InvalidOperationException(
                "SENSOR_C1_COLLECTION_WINDOW_INVALID");
        }
        if (
            result.State == BoundedEventReadState.Match &&
            result.Metadata is not null &&
            result.Metadata.TimeCreatedUtc < new DateTimeOffset(notBeforeUtc))
        {
            return new BoundedEventReadResult(
                BoundedEventReadState.NoMatch,
                null);
        }
        return result;
    }

    private static void ValidateResult(
        BoundedEventFamilyContract contract,
        BoundedEventReadResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        if (!Enum.IsDefined(result.State))
        {
            throw new InvalidDataException("SENSOR_C1_READ_STATE_INVALID");
        }
        if (result.State != BoundedEventReadState.Match)
        {
            if (result.Metadata is not null)
            {
                throw new InvalidDataException("SENSOR_C1_NONMATCH_METADATA_INVALID");
            }
            return;
        }

        var metadata = result.Metadata ??
            throw new InvalidDataException("SENSOR_C1_MATCH_METADATA_MISSING");
        if (
            metadata.ProviderName != contract.ProviderName ||
            metadata.EventId != contract.EventId ||
            metadata.Level != contract.Level ||
            metadata.TimeCreatedUtc.Offset != TimeSpan.Zero ||
            metadata.RecordId is < 1 or > MaximumJsonInteger)
        {
            throw new InvalidDataException("SENSOR_C1_EVENT_METADATA_INVALID");
        }
    }
}
