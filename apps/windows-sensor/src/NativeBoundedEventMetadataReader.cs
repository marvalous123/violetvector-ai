using System.Diagnostics.Eventing.Reader;
using System.Security;

namespace WARRoom.WindowsSensor;

// Gate C1b supplies the native metadata-only reader behind the frozen C1a
// coordinator. The coordinator owns validation and current-install filtering.
public sealed class NativeBoundedEventMetadataReader :
    IBoundedEventMetadataReader
{
    public BoundedEventReadResult ReadOne(
        BoundedEventFamily family,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var contract = ContractFor(family);
        try
        {
            var query = new EventLogQuery(
                contract.LogName,
                PathType.LogName,
                contract.FixedQuery)
            {
                ReverseDirection = true,
                TolerateQueryErrors = false
            };
            using var reader = new EventLogReader(query);
            reader.BatchSize =
                BoundedMultiEventCollector.MaximumRecordsPerFamily;
            using var record = reader.ReadEvent(TimeSpan.FromMilliseconds(
                BoundedMultiEventCollector.MaximumReadMillisecondsPerFamily));
            cancellationToken.ThrowIfCancellationRequested();
            if (record is null)
            {
                return new BoundedEventReadResult(
                    BoundedEventReadState.NoMatch,
                    null);
            }

            var providerName = record.ProviderName;
            var level = record.Level;
            var timeCreated = record.TimeCreated;
            var recordId = record.RecordId;
            if (
                providerName is null ||
                level is null ||
                timeCreated is null ||
                recordId is null)
            {
                return new BoundedEventReadResult(
                    BoundedEventReadState.QueryFailed,
                    null);
            }

            var metadata = new BoundedEventMetadata(
                providerName,
                record.Id,
                level.Value,
                new DateTimeOffset(timeCreated.Value).ToUniversalTime(),
                recordId.Value);
            return new BoundedEventReadResult(
                BoundedEventReadState.Match,
                metadata);
        }
        catch (EventLogNotFoundException)
        {
            return new BoundedEventReadResult(
                BoundedEventReadState.SourceUnavailable,
                null);
        }
        catch (UnauthorizedAccessException)
        {
            return new BoundedEventReadResult(
                BoundedEventReadState.AccessDenied,
                null);
        }
        catch (SecurityException)
        {
            return new BoundedEventReadResult(
                BoundedEventReadState.AccessDenied,
                null);
        }
        catch (EventLogException)
        {
            return new BoundedEventReadResult(
                BoundedEventReadState.QueryFailed,
                null);
        }
    }

    internal static BoundedEventFamilyContract ContractFor(
        BoundedEventFamily family) => family switch
    {
        BoundedEventFamily.ScmServiceInstalled =>
            BoundedMultiEventCollector.Contracts[0],
        BoundedEventFamily.ScmServiceStateChanged =>
            BoundedMultiEventCollector.Contracts[1],
        _ => throw new InvalidOperationException(
            "SENSOR_C1_EVENT_FAMILY_INVALID")
    };
}
