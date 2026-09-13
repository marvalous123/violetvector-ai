using System.Diagnostics.Eventing.Reader;
using System.Security;

namespace WARRoom.WindowsSensor;

internal interface ISecurity4663EventLogSession : IDisposable
{
    string? ReadOneXml(TimeSpan timeout);
}

internal interface ISecurity4663EventLogSessionFactory
{
    ISecurity4663EventLogSession Open(Security4663OneShotSourceQuery query);
}

// Gate C2e native source remains disabled for direct service registration. The
// distinct C2f wrapper may delegate exactly one frozen bounded-reader query to
// it only inside the separately approved one-shot startup branch.
public sealed class NativeSecurity4663OneShotEventSource :
    ISecurity4663OneShotEventSource
{
    public const bool RuntimeWired = false;
    public const bool ServiceRegistered = false;

    private readonly ISecurity4663EventLogSessionFactory _factory;

    public NativeSecurity4663OneShotEventSource() :
        this(new NativeSecurity4663EventLogSessionFactory())
    {
    }

    internal NativeSecurity4663OneShotEventSource(
        ISecurity4663EventLogSessionFactory factory)
    {
        _factory = factory ?? throw new ArgumentNullException(nameof(factory));
    }

    public Security4663OneShotSourceResult ReadOne(
        Security4663OneShotSourceQuery query,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateQuery(query);
        try
        {
            using var session = _factory.Open(query);
            var eventXml = session.ReadOneXml(
                TimeSpan.FromMilliseconds(query.MaximumQueryMilliseconds));
            cancellationToken.ThrowIfCancellationRequested();
            return eventXml is null
                ? new Security4663OneShotSourceResult(
                    Security4663OneShotReadState.NoMatch,
                    null)
                : new Security4663OneShotSourceResult(
                    Security4663OneShotReadState.Match,
                    eventXml);
        }
        catch (UnauthorizedAccessException)
        {
            return Failed(Security4663OneShotReadState.AccessDenied);
        }
        catch (SecurityException)
        {
            return Failed(Security4663OneShotReadState.AccessDenied);
        }
        catch (EventLogNotFoundException)
        {
            return Failed(Security4663OneShotReadState.SourceUnavailable);
        }
        catch (EventLogReadingException)
        {
            return Failed(Security4663OneShotReadState.QueryFailed);
        }
    }

    private static void ValidateQuery(Security4663OneShotSourceQuery query)
    {
        ArgumentNullException.ThrowIfNull(query);
        const string prefix =
            "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] " +
            "and EventID=4663 and Level=0 and EventRecordID>";
        if (
            query.LogName != "Security" ||
            !query.XPath.StartsWith(prefix, StringComparison.Ordinal) ||
            !query.XPath.EndsWith("]]", StringComparison.Ordinal) ||
            !long.TryParse(
                query.XPath.AsSpan(prefix.Length, query.XPath.Length -
                    prefix.Length - 2),
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out var baseline) ||
            Security4663OneShotBoundedReader.BuildXPath(baseline) !=
                query.XPath ||
            !query.ReverseDirection ||
            query.TolerateQueryErrors ||
            query.MaximumEventsRead != 1 ||
            query.MaximumQueryMilliseconds != 2_000 ||
            query.MaximumEventXmlCharacters !=
                Security4663OneShotBoundedReader.MaximumEventXmlCharacters)
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_NATIVE_QUERY_INVALID");
        }
    }

    private static Security4663OneShotSourceResult Failed(
        Security4663OneShotReadState state) => new(state, null);
}

internal sealed class NativeSecurity4663EventLogSessionFactory :
    ISecurity4663EventLogSessionFactory
{
    public ISecurity4663EventLogSession Open(
        Security4663OneShotSourceQuery query) =>
        new NativeSecurity4663EventLogSession(query);
}

internal sealed class NativeSecurity4663EventLogSession :
    ISecurity4663EventLogSession
{
    private readonly EventLogReader _reader;

    public NativeSecurity4663EventLogSession(
        Security4663OneShotSourceQuery query)
    {
        var eventQuery = new EventLogQuery(
            query.LogName,
            PathType.LogName,
            query.XPath)
        {
            ReverseDirection = query.ReverseDirection,
            TolerateQueryErrors = query.TolerateQueryErrors
        };
        _reader = new EventLogReader(eventQuery);
    }

    public string? ReadOneXml(TimeSpan timeout)
    {
        using var record = _reader.ReadEvent(timeout);
        return record?.ToXml();
    }

    public void Dispose() => _reader.Dispose();
}
