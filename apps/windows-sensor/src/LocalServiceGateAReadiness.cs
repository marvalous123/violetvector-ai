using System.Security.Principal;
using Microsoft.Win32;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WARRoom.WindowsSensor.Readiness;

namespace WARRoom.WindowsSensor;

public static class SensorStartupArguments
{
    public const string Security4663ApprovalConsumeProofArgument =
        "--security-4663-one-shot";
    public const string Security4663LiveOneShotArgument =
        "--security-4663-live-one-shot";

    public static SensorStartupMode Parse(string[] arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        if (arguments.Length == 0)
        {
            return SensorStartupMode.Normal;
        }
        if (
            arguments.Length == 1 &&
            string.Equals(
                arguments[0],
                Security4663ApprovalConsumeProofArgument,
                StringComparison.Ordinal))
        {
            return SensorStartupMode.Security4663ApprovalConsumeProof;
        }
        if (
            arguments.Length == 1 &&
            string.Equals(
                arguments[0],
                Security4663LiveOneShotArgument,
                StringComparison.Ordinal))
        {
            return SensorStartupMode.Security4663LiveOneShot;
        }
        throw new InvalidDataException("SENSOR_STARTUP_ARGUMENTS_DENIED");
    }

    public static void Validate(string[] arguments)
    {
        _ = Parse(arguments);
    }

    public static SensorStartupMode Resolve(
        string[] arguments,
        ISensorStartupModeSource source)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(source);
        if (arguments.Length != 0)
        {
            return Parse(arguments);
        }
        var configured = source.ReadExactMode();
        if (configured is null)
        {
            return SensorStartupMode.Normal;
        }
        if (string.Equals(
            configured,
            Security4663ApprovalConsumeProofArgument,
            StringComparison.Ordinal))
        {
            return SensorStartupMode.Security4663ApprovalConsumeProof;
        }
        if (string.Equals(
            configured,
            Security4663LiveOneShotArgument,
            StringComparison.Ordinal))
        {
            return SensorStartupMode.Security4663LiveOneShot;
        }
        throw new InvalidDataException("SENSOR_STARTUP_MODE_INVALID");
    }
}

public enum SensorStartupMode
{
    Normal = 0,
    Security4663ApprovalConsumeProof = 1,
    Security4663LiveOneShot = 2
}

public interface ISensorStartupModeSource
{
    string? ReadExactMode();
}

public sealed class NativeSensorStartupModeSource : ISensorStartupModeSource
{
    public const string RegistryPath =
        @"SYSTEM\CurrentControlSet\Services\WARRoomWindowsSensor\Parameters";
    public const string RegistryValueName = "StartupMode";

    public string? ReadExactMode()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("SENSOR_WINDOWS_REQUIRED");
        }
        using var machine = RegistryKey.OpenBaseKey(
            RegistryHive.LocalMachine,
            RegistryView.Registry64);
        using var parameters = machine.OpenSubKey(RegistryPath, writable: false);
        if (parameters is null)
        {
            return null;
        }
        var value = parameters.GetValue(
            RegistryValueName,
            null,
            RegistryValueOptions.DoNotExpandEnvironmentNames);
        if (value is null)
        {
            return null;
        }
        if (
            parameters.GetValueKind(RegistryValueName) != RegistryValueKind.String ||
            value is not string text ||
            string.IsNullOrWhiteSpace(text))
        {
            throw new InvalidDataException("SENSOR_STARTUP_MODE_INVALID");
        }
        return text;
    }
}

public interface ISensorServiceIdentity
{
    string? CurrentSid { get; }
}

public sealed class WindowsSensorServiceIdentity : ISensorServiceIdentity
{
    public string? CurrentSid => WindowsIdentity.GetCurrent().User?.Value;
}

public static class LocalServiceGateAReadiness
{
    public static WindowsEventSourceReadinessResult Validate(
        ISensorServiceIdentity serviceIdentity,
        IWindowsEventLogMetadataReader metadataReader)
    {
        ArgumentNullException.ThrowIfNull(serviceIdentity);
        ArgumentNullException.ThrowIfNull(metadataReader);
        if (!StringComparer.Ordinal.Equals(
            serviceIdentity.CurrentSid,
            NativeKeyAccessPolicy.LocalServiceSid))
        {
            throw new InvalidOperationException(
                "SENSOR_LOCALSERVICE_IDENTITY_REQUIRED");
        }

        var result = WindowsEventSourceReadiness.Check(metadataReader);
        if (
            !result.Ready ||
            result.ServiceIdentityValidated ||
            result.RuntimeCollectionEnabled ||
            result.TransportEnabled ||
            result.InboundListenerEnabled ||
            result.CommandChannelEnabled ||
            result.ArbitraryChannelsAllowed ||
            result.RawEventContentRead ||
            result.EventsRead != 0 ||
            result.Sources.Count != 2)
        {
            throw new InvalidOperationException(
                "SENSOR_LOCALSERVICE_GATE_A_UNAVAILABLE");
        }
        return result;
    }
}

public sealed class LocalServiceGateAReadinessWorker(
    ISensorServiceIdentity serviceIdentity,
    IWindowsEventLogMetadataReader metadataReader,
    ILogger<LocalServiceGateAReadinessWorker> logger) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = LocalServiceGateAReadiness.Validate(
            serviceIdentity,
            metadataReader);
        logger.LogInformation(
            "WAR-R00M LocalService Gate A metadata readiness passed. Sources={SourceCount}; events read={EventsRead}; collection and transport disabled.",
            result.Sources.Count,
            result.EventsRead);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) =>
        Task.CompletedTask;
}
