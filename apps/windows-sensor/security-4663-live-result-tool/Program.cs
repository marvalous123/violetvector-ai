using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using WARRoom.WindowsSensor;

try
{
    var executionPlanRequested = args.Length == 1 &&
        string.Equals(args[0], "execution-plan", StringComparison.Ordinal);
    var genuineMatchPlanRequested = args.Length == 1 &&
        string.Equals(args[0], "genuine-match-plan", StringComparison.Ordinal);
    var command = executionPlanRequested || genuineMatchPlanRequested
        ? Security4663LiveOneShotResultOperatorCommand.Plan
        : Security4663LiveOneShotResultOperatorCommandParser.Parse(args);
    object result;
    if (executionPlanRequested)
    {
        var plan = Security4663LiveOneShotExecution.BuildPlan();
        Security4663LiveOneShotExecution.ValidatePlan(plan);
        result = plan;
    }
    else if (genuineMatchPlanRequested)
    {
        var plan = Security4663GenuineMatchValidation.BuildPlan();
        Security4663GenuineMatchValidation.ValidatePlan(plan);
        result = plan;
    }
    else if (command == Security4663LiveOneShotResultOperatorCommand.Plan)
    {
        var plan = Security4663LiveOneShotResultOperator.BuildPlan();
        Security4663LiveOneShotResultOperator.ValidatePlan(plan);
        result = plan;
    }
    else if (command == Security4663LiveOneShotResultOperatorCommand.Cleanup)
    {
        RequireWindowsAdministrator();
        result = Security4663LiveOneShotResultOperator.Cleanup(
            new NativeSecurity4663LiveOneShotResultOperatorStore());
    }
    else
    {
        RequireWindowsAdministrator();
        // Public descriptor only: this process never receives signing authority.
        var identity = new CngMachineIdentityDescriptorReader().ReadProvisioned();
        var manifest = new FixedInstallManifestBindingReader().Read();
        if (manifest.Fingerprint != identity.CertificateFingerprintSha256)
        {
            throw new InvalidDataException(
                "SENSOR_C2F_SECURITY_4663_RESULT_OPERATOR_IDENTITY_MISMATCH");
        }
        var store = new NativeSecurity4663LiveOneShotResultOperatorStore();
        var now = DateTimeOffset.UtcNow;
        result = command switch
        {
            Security4663LiveOneShotResultOperatorCommand.PrepareSlot =>
                Security4663LiveOneShotResultOperator.PrepareSlot(
                    store, identity, manifest, now),
            Security4663LiveOneShotResultOperatorCommand.EmptyCheck =>
                Security4663LiveOneShotResultOperator.EmptyCheck(
                    store, identity, manifest, now),
            Security4663LiveOneShotResultOperatorCommand.Check =>
                Security4663LiveOneShotResultOperator.Check(
                    store, identity, manifest, now),
            Security4663LiveOneShotResultOperatorCommand.Consume =>
                Security4663LiveOneShotResultOperator.Consume(
                    store, identity, manifest, now),
            Security4663LiveOneShotResultOperatorCommand.AbsentCheck =>
                Security4663LiveOneShotResultOperator.AbsentCheck(
                    store, identity, manifest, now),
            _ => throw new InvalidDataException(
                "SENSOR_C2F_SECURITY_4663_RESULT_OPERATOR_COMMAND_INVALID")
        };
    }
    Console.WriteLine(JsonSerializer.Serialize(
        new { ok = true, command = args[0], result }, JsonOptions()));
    return 0;
}
catch (Exception error) when (error is
    CryptographicException or InvalidDataException or IOException or
    JsonException or PlatformNotSupportedException or UnauthorizedAccessException)
{
    Console.Error.WriteLine(JsonSerializer.Serialize(new
    {
        ok = false,
        error = error.Message.StartsWith("SENSOR_", StringComparison.Ordinal)
            ? error.Message
            : "SENSOR_C2F_SECURITY_4663_RESULT_OPERATOR_FAILED"
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
    if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
    {
        throw new UnauthorizedAccessException("SENSOR_ADMINISTRATOR_REQUIRED");
    }
}

static JsonSerializerOptions JsonOptions() => new()
{
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    WriteIndented = true
};
