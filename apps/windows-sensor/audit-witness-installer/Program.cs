using System.Security.Principal;
using System.Text.Json;
using WARRoom.WindowsSensor;
using WARRoom.WindowsSensor.AuditWitnessInstaller;

try
{
    var command = args.Length == 1 ? args[0] : string.Empty;
    object result = command switch
    {
        "plan" => new
        {
            ok = true,
            command,
            plan = AuditWitnessProtectedFileInstaller.BuildPlan()
        },
        "install" => Install(command),
        _ => throw new InvalidDataException(
            "SENSOR_AUDIT_WITNESS_INSTALLER_COMMAND_INVALID")
    };
    Console.WriteLine(JsonSerializer.Serialize(result, ToolJsonOptions.Value));
    return 0;
}
catch (Exception error) when (
    error is InvalidDataException or InvalidOperationException or
    PlatformNotSupportedException or UnauthorizedAccessException)
{
    Console.Error.WriteLine(JsonSerializer.Serialize(
        new { ok = false, error = PublicError(error) },
        ToolJsonOptions.Value));
    return 1;
}

static object Install(string command)
{
    RequireAdministrator();
    return new
    {
        ok = true,
        command,
        result = AuditWitnessProtectedFileInstaller.Install()
    };
}

static void RequireAdministrator()
{
    if (!OperatingSystem.IsWindows())
    {
        throw new PlatformNotSupportedException("SENSOR_WINDOWS_REQUIRED");
    }
    using var identity = WindowsIdentity.GetCurrent();
    if (!new WindowsPrincipal(identity).IsInRole(
        WindowsBuiltInRole.Administrator))
    {
        throw new UnauthorizedAccessException(
            "SENSOR_ADMINISTRATOR_REQUIRED");
    }
}

static string PublicError(Exception error) =>
    error.Message.StartsWith(
        "SENSOR_AUDIT_WITNESS_",
        StringComparison.Ordinal) ||
    error.Message is "SENSOR_WINDOWS_REQUIRED" or
        "SENSOR_ADMINISTRATOR_REQUIRED"
            ? error.Message
            : "SENSOR_AUDIT_WITNESS_INSTALLER_FAILED";

internal static class ToolJsonOptions
{
    internal static JsonSerializerOptions Value { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };
}
