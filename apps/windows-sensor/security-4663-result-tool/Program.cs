using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using WARRoom.WindowsSensor;

try
{
    var command = Security4663OneShotResultOperatorCommandParser.Parse(args);
    object result;
    if (command == Security4663OneShotResultOperatorCommand.Plan)
    {
        var plan = Security4663OneShotResultOperator.BuildPlan();
        Security4663OneShotResultOperator.ValidatePlan(plan);
        result = plan;
    }
    else if (command == Security4663OneShotResultOperatorCommand.Cleanup)
    {
        RequireWindowsAdministrator();
        result = Security4663OneShotResultOperator.Cleanup(
            new NativeSecurity4663OneShotResultOperatorStore());
    }
    else
    {
        RequireWindowsAdministrator();
        // The checker opens the provisioned machine identity only to obtain its
        // validated public descriptor. It never calls the signing operation.
        var identity = new CngMachineIdentityDescriptorReader().ReadProvisioned();
        var manifest = new FixedInstallManifestBindingReader().Read();
        if (manifest.Fingerprint !=
            identity.CertificateFingerprintSha256)
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_RESULT_OPERATOR_IDENTITY_MISMATCH");
        }
        var store = new NativeSecurity4663OneShotResultOperatorStore();
        var now = DateTimeOffset.UtcNow;
        result = command switch
        {
            Security4663OneShotResultOperatorCommand.PrepareSlot =>
                Security4663OneShotResultOperator.PrepareSlot(
                    store, identity, manifest, now),
            Security4663OneShotResultOperatorCommand.EmptyCheck =>
                Security4663OneShotResultOperator.EmptyCheck(
                    store, identity, manifest, now),
            Security4663OneShotResultOperatorCommand.Check =>
                Security4663OneShotResultOperator.Check(
                    store, identity, manifest, now),
            Security4663OneShotResultOperatorCommand.Consume =>
                Security4663OneShotResultOperator.Consume(
                    store, identity, manifest, now),
            Security4663OneShotResultOperatorCommand.AbsentCheck =>
                Security4663OneShotResultOperator.AbsentCheck(
                    store, identity, manifest, now),
            _ => throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_RESULT_OPERATOR_COMMAND_INVALID")
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
            : "SENSOR_C2E_SECURITY_4663_RESULT_OPERATOR_FAILED"
    }, JsonOptions()));
    return 1;
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
        throw new UnauthorizedAccessException("SENSOR_ADMINISTRATOR_REQUIRED");
    }
}

static JsonSerializerOptions JsonOptions() => new()
{
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    WriteIndented = true
};
