using System.Diagnostics.Eventing.Reader;

namespace WARRoom.WindowsSensor;

public sealed record Security4663LogMetadata(
    long? OldestRecordNumber,
    long? RecordCount,
    bool? IsLogFull);

public sealed record Security4663OneShotBaselineResult(
    int SchemaVersion,
    string Checkpoint,
    string LogName,
    long OldestRecordNumber,
    long RecordCount,
    long BaselineRecordId,
    bool LogFull,
    bool EventContentRead,
    int EventsRead,
    bool RuntimeWired,
    bool TransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    bool ResponseActionEnabled);

public interface ISecurity4663LogMetadataSource
{
    Security4663LogMetadata ReadSecurityLogMetadata();
}

// Gate C2e baseline proof uses channel metadata only. It never opens or reads
// an event record and remains absent from service startup.
public static class Security4663OneShotBaseline
{
    public const bool RuntimeWired = false;

    public static Security4663OneShotBaselineResult Capture(
        ISecurity4663LogMetadataSource source)
    {
        ArgumentNullException.ThrowIfNull(source);
        var metadata = source.ReadSecurityLogMetadata();
        ArgumentNullException.ThrowIfNull(metadata);
        if (
            metadata.OldestRecordNumber is not long oldest ||
            metadata.RecordCount is not long count ||
            metadata.IsLogFull is not bool logFull ||
            oldest is < 1 or > Security4663OneShotCoordinator.MaximumJsonInteger ||
            count is < 1 or > Security4663OneShotCoordinator.MaximumJsonInteger)
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_BASELINE_METADATA_INVALID");
        }

        long baseline;
        try
        {
            baseline = checked(oldest + count - 1);
        }
        catch (OverflowException)
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_BASELINE_METADATA_INVALID");
        }
        if (baseline > Security4663OneShotCoordinator.MaximumJsonInteger)
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_BASELINE_METADATA_INVALID");
        }

        return new Security4663OneShotBaselineResult(
            1,
            Readiness.Security4663OneShotMachinePlan.Checkpoint,
            "Security",
            oldest,
            count,
            baseline,
            logFull,
            false,
            0,
            false,
            false,
            false,
            false,
            false);
    }
}

internal interface ISecurity4663LogInformationSession
{
    Security4663LogMetadata Read(string logName, PathType pathType);
}

public sealed class NativeSecurity4663LogMetadataSource :
    ISecurity4663LogMetadataSource
{
    public const bool RuntimeWired = false;
    public const bool ServiceRegistered = false;

    private readonly ISecurity4663LogInformationSession _session;

    public NativeSecurity4663LogMetadataSource() :
        this(new NativeSecurity4663LogInformationSession())
    {
    }

    internal NativeSecurity4663LogMetadataSource(
        ISecurity4663LogInformationSession session)
    {
        _session = session ?? throw new ArgumentNullException(nameof(session));
    }

    public Security4663LogMetadata ReadSecurityLogMetadata() =>
        _session.Read("Security", PathType.LogName);
}

internal sealed class NativeSecurity4663LogInformationSession :
    ISecurity4663LogInformationSession
{
    public Security4663LogMetadata Read(string logName, PathType pathType)
    {
        var information = EventLogSession.GlobalSession.GetLogInformation(
            logName,
            pathType);
        return new Security4663LogMetadata(
            information.OldestRecordNumber,
            information.RecordCount,
            information.IsLogFull);
    }
}
