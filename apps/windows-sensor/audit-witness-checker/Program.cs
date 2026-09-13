using System.Text.Json;
using WARRoom.WindowsSensor;

try
{
    if (args.Length != 1 || args[0] is not ("check" or "check-access"))
    {
        throw new InvalidDataException(
            "SENSOR_AUDIT_WITNESS_CHECKER_COMMAND_INVALID");
    }
    var result = args[0] == "check"
        ? (object)AuditWitnessProtectedFileChecker.Check()
        : AuditWitnessProtectedFileChecker.CheckEffectiveAccess();
    Console.WriteLine(JsonSerializer.Serialize(new
    {
        ok = true,
        command = args[0],
        result
    }, ToolJsonOptions.Value));
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

static string PublicError(Exception error) =>
    error.Message.StartsWith(
        "SENSOR_AUDIT_WITNESS_",
        StringComparison.Ordinal) ||
    error.Message == "SENSOR_WINDOWS_REQUIRED"
        ? error.Message
        : "SENSOR_AUDIT_WITNESS_CHECKER_FAILED";

internal static class ToolJsonOptions
{
    internal static JsonSerializerOptions Value { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };
}
