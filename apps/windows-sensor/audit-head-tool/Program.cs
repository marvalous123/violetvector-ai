using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using WARRoom.WindowsSensor;

try
{
    var command = NativeAuditHeadWriterCommandParser.Parse(args);
    object result = command switch
    {
        NativeAuditHeadWriterCommand.Plan => new
        {
            ok = true,
            command = "plan",
            plan = NativeAuditHeadWriter.BuildPlan()
        },
        NativeAuditHeadWriterCommand.Status => Status(),
        NativeAuditHeadWriterCommand.Provision => Provision(),
        _ => throw new InvalidDataException(
            "SENSOR_AUDIT_HEAD_COMMAND_INVALID")
    };
    Console.WriteLine(JsonSerializer.Serialize(result, JsonOptions.Value));
    return 0;
}
catch (Exception error) when (
    error is CryptographicException or InvalidDataException or
    InvalidOperationException or PlatformNotSupportedException or
    UnauthorizedAccessException)
{
    Console.Error.WriteLine(JsonSerializer.Serialize(
        new { ok = false, error = PublicError(error) },
        JsonOptions.Value));
    return 1;
}

static object Status()
{
    RequireWindows();
    return new
    {
        ok = true,
        command = "status",
        status = NativeAuditHeadWriter.ReadStatus(
            new CngAuditHeadWriterKeyStore(),
            new NativeAuditHeadCheckpointStateStore())
    };
}

static object Provision()
{
    RequireAdministrator();
    NativeAuditHeadWriterStorage.PrepareFixedRoots();
    NativeAuditHeadWriterStorage.ValidateFixedRoots();
    return new
    {
        ok = true,
        command = "provision",
        result = NativeAuditHeadWriter.Provision(
            new CngAuditHeadWriterKeyStore())
    };
}

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
    if (!new WindowsPrincipal(identity).IsInRole(
        WindowsBuiltInRole.Administrator))
    {
        throw new UnauthorizedAccessException(
            "SENSOR_ADMINISTRATOR_REQUIRED");
    }
}

static string PublicError(Exception error) => error.Message.StartsWith(
    "SENSOR_AUDIT_HEAD_",
    StringComparison.Ordinal) || error.Message is
        "SENSOR_WINDOWS_REQUIRED" or "SENSOR_ADMINISTRATOR_REQUIRED"
            ? error.Message
            : "SENSOR_AUDIT_HEAD_TOOL_FAILED";

internal static class JsonOptions
{
    internal static JsonSerializerOptions Value { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };
}
