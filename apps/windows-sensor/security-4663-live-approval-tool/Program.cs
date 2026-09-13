using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using WARRoom.WindowsSensor;
using WARRoom.WindowsSensor.Readiness;

try
{
    var command =
        Security4663LiveOneShotApprovalOperatorCommandParser.Parse(args);
    object result;
    if (command == Security4663LiveOneShotApprovalOperatorCommand.Plan)
    {
        var plan = Security4663LiveOneShotApprovalOperator.BuildPlan();
        Security4663LiveOneShotApprovalOperator.ValidatePlan(plan);
        result = plan;
    }
    else
    {
        RequireWindowsAdministrator();
        var store = new NativeSecurity4663LiveOneShotApprovalFileStore();
        result = command switch
        {
            Security4663LiveOneShotApprovalOperatorCommand.Write =>
                Write(store),
            Security4663LiveOneShotApprovalOperatorCommand.Check =>
                Check(store),
            Security4663LiveOneShotApprovalOperatorCommand.AbsentCheck =>
                Security4663LiveOneShotApprovalOperator.CheckAbsent(store),
            Security4663LiveOneShotApprovalOperatorCommand.Cleanup =>
                Security4663LiveOneShotApprovalOperator.Cleanup(store),
            _ => throw new InvalidDataException(
                "SENSOR_C2F_SECURITY_4663_APPROVAL_OPERATOR_COMMAND_INVALID")
        };
    }
    Console.WriteLine(JsonSerializer.Serialize(
        new { ok = true, command = args[0], result },
        JsonOptions()));
    return 0;
}
catch (Exception error) when (error is
    CryptographicException or
    InvalidDataException or
    IOException or
    JsonException or
    PlatformNotSupportedException or
    UnauthorizedAccessException)
{
    Console.Error.WriteLine(JsonSerializer.Serialize(new
    {
        ok = false,
        error = error.Message.StartsWith("SENSOR_", StringComparison.Ordinal)
            ? error.Message
            : "SENSOR_C2F_SECURITY_4663_APPROVAL_OPERATOR_FAILED"
    }, JsonOptions()));
    return 1;
}

static Security4663LiveOneShotApprovalOperatorResult Write(
    ISecurity4663LiveOneShotApprovalStore store)
{
    using var identity = CngMachineKeySigner.OpenProvisioned();
    var manifest = new FixedInstallManifestBindingReader().Read();
    var nonce = RandomNumberGenerator.GetBytes(
        Security4663LiveOneShotApprovalLifecycle.NonceBytes);
    try
    {
        return Security4663LiveOneShotApprovalOperator.Write(
            store,
            identity,
            manifest,
            new NativeSecurity4663ReadinessProbe(),
            new NativeSecurity4663LogMetadataSource(),
            DateTime.UtcNow,
            nonce);
    }
    finally
    {
        CryptographicOperations.ZeroMemory(nonce);
    }
}

static Security4663LiveOneShotApprovalOperatorResult Check(
    ISecurity4663LiveOneShotApprovalStore store)
{
    var identity = new CngMachineIdentityDescriptorReader().ReadProvisioned();
    var manifest = new FixedInstallManifestBindingReader().Read();
    return Security4663LiveOneShotApprovalOperator.Check(
        store, identity, manifest, DateTime.UtcNow);
}

static void RequireWindowsAdministrator()
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

static JsonSerializerOptions JsonOptions() => new()
{
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    WriteIndented = true
};
