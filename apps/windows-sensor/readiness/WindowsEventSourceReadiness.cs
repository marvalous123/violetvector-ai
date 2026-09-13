using System.Collections.ObjectModel;
using System.Diagnostics.Eventing.Reader;
using System.Security;

namespace WARRoom.WindowsSensor.Readiness;

public enum WindowsEventSourceReadinessCommand
{
    Plan,
    Check,
    Security4663Plan,
    Security4663Check,
    Security4663CeremonyPlan,
    Security4663Apply,
    Security4663Rollback,
    Security4663Exercise,
    Security4663OneShotPlan
}

public static class WindowsEventSourceReadinessCommandParser
{
    public static WindowsEventSourceReadinessCommand Parse(string[] arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        if (arguments.Length != 1)
        {
            throw new InvalidDataException(
                "SENSOR_SOURCE_READINESS_COMMAND_INVALID");
        }
        return arguments[0] switch
        {
            "plan" => WindowsEventSourceReadinessCommand.Plan,
            "check" => WindowsEventSourceReadinessCommand.Check,
            "security-4663-plan" =>
                WindowsEventSourceReadinessCommand.Security4663Plan,
            "security-4663-check" =>
                WindowsEventSourceReadinessCommand.Security4663Check,
            "security-4663-ceremony-plan" =>
                WindowsEventSourceReadinessCommand.Security4663CeremonyPlan,
            "security-4663-apply" =>
                WindowsEventSourceReadinessCommand.Security4663Apply,
            "security-4663-rollback" =>
                WindowsEventSourceReadinessCommand.Security4663Rollback,
            "security-4663-exercise" =>
                WindowsEventSourceReadinessCommand.Security4663Exercise,
            "security-4663-one-shot-plan" =>
                WindowsEventSourceReadinessCommand.Security4663OneShotPlan,
            _ => throw new InvalidDataException(
                "SENSOR_SOURCE_READINESS_COMMAND_INVALID")
        };
    }
}

public sealed record WindowsEventSourceDefinition(
    string SourceId,
    string LogName,
    IReadOnlyList<string> PermittedFutureEventMetadataFields);

public sealed record WindowsEventSourceReadinessPlan(
    int SchemaVersion,
    string ProbeContext,
    bool ServiceIdentityValidated,
    bool RuntimeCollectionEnabled,
    bool TransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    bool ArbitraryChannelsAllowed,
    bool RawEventContentAllowed,
    long EventsRead,
    IReadOnlyList<WindowsEventSourceDefinition> Sources);

public sealed record WindowsEventLogMetadata(
    bool Enabled,
    long? RecordCount);

public sealed record WindowsEventSourceStatus(
    string SourceId,
    string LogName,
    bool Accessible,
    bool Enabled,
    long? RecordCount,
    string? ErrorCode);

public sealed record WindowsEventSourceReadinessResult(
    int SchemaVersion,
    string ProbeContext,
    bool ServiceIdentityValidated,
    bool RuntimeCollectionEnabled,
    bool TransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    bool ArbitraryChannelsAllowed,
    bool RawEventContentRead,
    long EventsRead,
    bool Ready,
    IReadOnlyList<WindowsEventSourceStatus> Sources);

public enum WindowsEventLogSource
{
    System,
    Application
}

public interface IWindowsEventLogMetadataReader
{
    WindowsEventLogMetadata Read(WindowsEventLogSource source);
}

public sealed class NativeWindowsEventLogMetadataReader :
    IWindowsEventLogMetadataReader
{
    public WindowsEventLogMetadata Read(WindowsEventLogSource source)
    {
        var logName = source switch
        {
            WindowsEventLogSource.System => "System",
            WindowsEventLogSource.Application => "Application",
            _ => throw new InvalidDataException(
                "SENSOR_EVENT_SOURCE_INVALID")
        };
        using var configuration = new EventLogConfiguration(logName);
        var information = EventLogSession.GlobalSession.GetLogInformation(
            logName,
            PathType.LogName);
        return new WindowsEventLogMetadata(
            configuration.IsEnabled,
            information.RecordCount);
    }
}

public static class WindowsEventSourceReadiness
{
    private static readonly IReadOnlyList<string> EventMetadataFields =
        Array.AsReadOnly(
        [
            "providerName",
            "eventId",
            "level",
            "timeCreatedUtc",
            "recordId"
        ]);

    private static readonly IReadOnlyList<WindowsEventSourceDefinition>
        SourceDefinitions =
            new ReadOnlyCollection<WindowsEventSourceDefinition>(
            [
                new(
                    "windows-system",
                    "System",
                    EventMetadataFields),
                new(
                    "windows-application",
                    "Application",
                    EventMetadataFields)
            ]);

    public static WindowsEventSourceReadinessPlan BuildPlan() =>
        new(
            SchemaVersion: 1,
            ProbeContext: "operator-session-metadata-only",
            ServiceIdentityValidated: false,
            RuntimeCollectionEnabled: false,
            TransportEnabled: false,
            InboundListenerEnabled: false,
            CommandChannelEnabled: false,
            ArbitraryChannelsAllowed: false,
            RawEventContentAllowed: false,
            EventsRead: 0,
            Sources: SourceDefinitions);

    public static WindowsEventSourceReadinessResult Check(
        IWindowsEventLogMetadataReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        var statuses = new List<WindowsEventSourceStatus>(
            SourceDefinitions.Count);
        foreach (var source in SourceDefinitions)
        {
            try
            {
                var metadata = reader.Read(
                    source.SourceId switch
                    {
                        "windows-system" => WindowsEventLogSource.System,
                        "windows-application" =>
                            WindowsEventLogSource.Application,
                        _ => throw new InvalidDataException(
                            "SENSOR_EVENT_SOURCE_INVALID")
                    });
                var validRecordCount = metadata.RecordCount is >= 0;
                statuses.Add(
                    new WindowsEventSourceStatus(
                        source.SourceId,
                        source.LogName,
                        Accessible: validRecordCount,
                        metadata.Enabled,
                        validRecordCount ? metadata.RecordCount : null,
                        validRecordCount
                            ? null
                            : "metadata-unavailable"));
            }
            catch (EventLogNotFoundException)
            {
                statuses.Add(Unavailable(source, "not-found"));
            }
            catch (UnauthorizedAccessException)
            {
                statuses.Add(Unavailable(source, "access-denied"));
            }
            catch (SecurityException)
            {
                statuses.Add(Unavailable(source, "access-denied"));
            }
            catch (EventLogException)
            {
                statuses.Add(Unavailable(source, "metadata-unavailable"));
            }
        }

        var ready = statuses.All(
            status =>
                status.Accessible &&
                status.Enabled &&
                status.RecordCount is >= 0 &&
                status.ErrorCode is null);
        return new WindowsEventSourceReadinessResult(
            SchemaVersion: 1,
            ProbeContext: "operator-session-metadata-only",
            ServiceIdentityValidated: false,
            RuntimeCollectionEnabled: false,
            TransportEnabled: false,
            InboundListenerEnabled: false,
            CommandChannelEnabled: false,
            ArbitraryChannelsAllowed: false,
            RawEventContentRead: false,
            EventsRead: 0,
            Ready: ready,
            Sources: statuses.AsReadOnly());
    }

    private static WindowsEventSourceStatus Unavailable(
        WindowsEventSourceDefinition source,
        string errorCode) =>
        new(
            source.SourceId,
            source.LogName,
            Accessible: false,
            Enabled: false,
            RecordCount: null,
            ErrorCode: errorCode);
}
