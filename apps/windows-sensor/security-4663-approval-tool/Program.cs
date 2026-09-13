using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using WARRoom.WindowsSensor;

try
{
    var command = Security4663OneShotApprovalOperatorCommandParser.Parse(args);
    object result;
    if (command == Security4663OneShotApprovalOperatorCommand.Plan)
    {
        var plan = Security4663OneShotApprovalOperator.BuildPlan();
        Security4663OneShotApprovalOperator.ValidatePlan(plan);
        result = plan;
    }
    else if (command ==
        Security4663OneShotApprovalOperatorCommand.ConsumeProofPlan)
    {
        var plan = Security4663OneShotApprovalConsumeProof.BuildPlan();
        Security4663OneShotApprovalConsumeProof.ValidatePlan(plan);
        result = plan;
    }
    else
    {
        RequireWindowsAdministrator();
        using var identity = CngMachineKeySigner.OpenProvisioned();
        var manifest = new FixedInstallManifestBindingReader().Read();
        if (manifest.Fingerprint !=
            identity.Descriptor.CertificateFingerprintSha256)
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_APPROVAL_OPERATOR_IDENTITY_MISMATCH");
        }
        var store = new NativeSecurity4663OneShotApprovalFileStore();
        var now = DateTime.UtcNow;
        result = command switch
        {
            Security4663OneShotApprovalOperatorCommand.Write =>
                Write(store, identity, manifest, now),
            Security4663OneShotApprovalOperatorCommand.Check =>
                Security4663OneShotApprovalOperator.Check(
                    store,
                    identity.Descriptor,
                    manifest,
                    now),
            Security4663OneShotApprovalOperatorCommand.AbsentCheck =>
                Security4663OneShotApprovalOperator.CheckAbsent(
                    store,
                    identity.Descriptor,
                    manifest,
                    now),
            Security4663OneShotApprovalOperatorCommand.ConsumeExercise =>
                Security4663OneShotApprovalOperator.ConsumeExercise(
                    store,
                    identity.Descriptor,
                    manifest,
                    now),
            Security4663OneShotApprovalOperatorCommand.Cleanup =>
                Security4663OneShotApprovalOperator.Cleanup(
                    store,
                    identity.Descriptor,
                    manifest,
                    now),
            _ => throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_APPROVAL_OPERATOR_COMMAND_INVALID")
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
            : "SENSOR_C2E_SECURITY_4663_APPROVAL_OPERATOR_FAILED"
    }, JsonOptions()));
    return 1;
}

static Security4663OneShotApprovalOperatorResult Write(
    ISecurity4663OneShotApprovalStore store,
    ISensorIdentitySigner identity,
    InstallManifestBinding manifest,
    DateTime now)
{
    var nonce = RandomNumberGenerator.GetBytes(
        Security4663OneShotApprovalLifecycle.NonceBytes);
    try
    {
        return Security4663OneShotApprovalOperator.Write(
            store,
            identity,
            manifest,
            new NativeSecurity4663LogMetadataSource(),
            now,
            nonce);
    }
    finally
    {
        CryptographicOperations.ZeroMemory(nonce);
    }
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
