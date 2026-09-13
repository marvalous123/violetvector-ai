using System.ComponentModel;
using System.Security.Principal;
using System.Text.Json;
using WARRoom.WindowsSensor;

try
{
    var command = ServiceSidToolCommandParser.Parse(args);
    object result = command switch
    {
        ServiceSidToolCommand.Plan => new
        {
            ok = true,
            command = "plan",
            plan = new
            {
                serviceName = SensorBoundary.ServiceName,
                scmLogonAccount = SensorBoundary.ExpectedServiceIdentity,
                requiredServiceSidType = "SERVICE_SID_TYPE_UNRESTRICTED",
                acceptsCallerServiceName = false,
                acceptsCallerSid = false,
                acceptsCallerPath = false,
                requiresElevationForMutation = true,
                independentReadbackRequired = true,
                rollbackValues = new[]
                {
                    "SERVICE_SID_TYPE_NONE",
                    "SERVICE_SID_TYPE_RESTRICTED"
                },
                telemetryEnabled = false,
                transportEnabled = false,
                commandChannelEnabled = false
            }
        },
        ServiceSidToolCommand.Status => Status(),
        ServiceSidToolCommand.ApplyUnrestricted => Apply(),
        ServiceSidToolCommand.RestoreNone =>
            Restore(ServiceSidConfigurator.None, "restore-none"),
        ServiceSidToolCommand.RestoreRestricted =>
            Restore(
                ServiceSidConfigurator.Restricted,
                "restore-restricted"),
        _ => throw new InvalidDataException(
            "SENSOR_SERVICE_SID_COMMAND_INVALID")
    };
    Console.WriteLine(JsonSerializer.Serialize(result, JsonOptions.Value));
    return 0;
}
catch (Exception error) when (
    error is InvalidDataException or
    InvalidOperationException or
    PlatformNotSupportedException or
    UnauthorizedAccessException or
    Win32Exception)
{
    Console.Error.WriteLine(JsonSerializer.Serialize(
        new { ok = false, error = PublicError(error) },
        JsonOptions.Value));
    return 1;
}

static object Status()
{
    RequireWindows();
    var snapshot = ServiceSidConfigurator.ReadValidated(
        new NativeServiceSidConfigurator());
    return new
    {
        ok = true,
        command = "status",
        result = Result(snapshot.ServiceSidType, snapshot.ServiceSidType, false)
    };
}

static object Apply()
{
    RequireAdministrator();
    var result = ServiceSidConfigurator.ApplyUnrestricted(
        new NativeServiceSidConfigurator());
    return new
    {
        ok = true,
        command = "apply-unrestricted",
        result = Result(
            result.PreviousSidType,
            result.CurrentSidType,
            result.Changed)
    };
}

static object Restore(uint previousSidType, string command)
{
    RequireAdministrator();
    var result = ServiceSidConfigurator.RestorePrevious(
        new NativeServiceSidConfigurator(),
        previousSidType);
    return new
    {
        ok = true,
        command,
        result = Result(
            result.PreviousSidType,
            result.CurrentSidType,
            result.Changed)
    };
}

static object Result(uint previousSidType, uint currentSidType, bool changed) =>
    new
    {
        serviceName = SensorBoundary.ServiceName,
        scmLogonAccount = SensorBoundary.ExpectedServiceIdentity,
        previousSidType,
        currentSidType,
        changed,
        independentlyReadBack = true,
        telemetryEnabled = false,
        transportEnabled = false,
        commandChannelEnabled = false
    };

static void RequireWindows()
{
    if (!OperatingSystem.IsWindows())
    {
        throw new PlatformNotSupportedException("SENSOR_WINDOWS_REQUIRED");
    }
}

static void RequireAdministrator()
{
    RequireWindows();
    using var identity = WindowsIdentity.GetCurrent();
    var principal = new WindowsPrincipal(identity);
    if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
    {
        throw new UnauthorizedAccessException(
            "SENSOR_ADMINISTRATOR_REQUIRED");
    }
}

static string PublicError(Exception error) => error.Message is
    "SENSOR_SERVICE_SID_COMMAND_INVALID" or
    "SENSOR_WINDOWS_REQUIRED" or
    "SENSOR_ADMINISTRATOR_REQUIRED" or
    "SENSOR_SERVICE_SID_TYPE_INVALID" or
    "SENSOR_SERVICE_SID_CONFIGURATION_AUTHORITY_INVALID" or
    "SENSOR_SERVICE_SID_APPLY_FAILED" or
    "SENSOR_SERVICE_SID_APPLY_RECOVERY_FAILED" or
    "SENSOR_SERVICE_SID_ROLLBACK_READBACK_INVALID"
        ? error.Message
        : "SENSOR_SERVICE_SID_TOOL_FAILED";

internal static class JsonOptions
{
    internal static JsonSerializerOptions Value { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };
}
