using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using WARRoom.WindowsSensor;

try
{
    var command = NativeIdentityProvisionerCommandParser.Parse(args);
    object result = command switch
    {
        NativeIdentityProvisionerCommand.Plan =>
            new { ok = true, command = "plan", plan = NativeIdentityProvisioner.BuildPlan() },
        NativeIdentityProvisionerCommand.Status =>
            ReadStatus(),
        NativeIdentityProvisionerCommand.Provision =>
            Provision(),
        NativeIdentityProvisionerCommand.EnrollmentIdentity =>
            ReadEnrollmentIdentity(),
        NativeIdentityProvisionerCommand.SignEnrollmentChallenge =>
            SignEnrollmentChallenge(),
        NativeIdentityProvisionerCommand.ProbePlan =>
            new
            {
                ok = true,
                command = "probe-plan",
                plan = DiagnosticProbeCleanup.BuildPlan()
            },
        NativeIdentityProvisionerCommand.ProbeStatus =>
            ReadProbeStatus(),
        NativeIdentityProvisionerCommand.ProbeCleanup =>
            CleanupProbe(),
        _ => throw new InvalidDataException("SENSOR_PROVISIONER_COMMAND_INVALID")
    };
    Console.WriteLine(JsonSerializer.Serialize(result, JsonOutput.Options));
    return 0;
}
catch (Exception error) when (
    error is CryptographicException or
    InvalidDataException or
    PlatformNotSupportedException or
    UnauthorizedAccessException)
{
    Console.Error.WriteLine(JsonSerializer.Serialize(
        new { ok = false, error = ToPublicErrorCode(error) },
        JsonOutput.Options));
    return 1;
}

static object ReadStatus()
{
    RequireWindows();
    return new
    {
        ok = true,
        command = "status",
        status = NativeIdentityProvisioner.ReadStatus(new CngNativeIdentityKeyStore())
    };
}

static object Provision()
{
    RequireWindows();
    RequireAdministrator();
    return new
    {
        ok = true,
        command = "provision",
        result = NativeIdentityProvisioner.Provision(new CngNativeIdentityKeyStore())
    };
}

static object ReadProbeStatus()
{
    RequireWindows();
    return new
    {
        ok = true,
        command = "probe-status",
        status = DiagnosticProbeCleanup.ReadStatus(
            new CngDiagnosticProbeKeyStore())
    };
}

static object ReadEnrollmentIdentity()
{
    RequireWindows();
    RequireAdministrator();
    using var identity = CngMachineKeySigner.OpenProvisioned();
    return new
    {
        ok = true,
        command = "enrollment-identity",
        identity = identity.Descriptor,
        privateExportBlocked = true,
        commandChannelEnabled = false
    };
}

static object SignEnrollmentChallenge()
{
    RequireWindows();
    RequireAdministrator();
    var input = ReadBoundedEnrollmentInput();
    using var identity = CngMachineKeySigner.OpenProvisioned();
    return new
    {
        ok = true,
        command = "sign-enrollment-challenge",
        result = NativeEnrollmentChallenge.Sign(input, identity, DateTime.UtcNow),
        commandChannelEnabled = false
    };
}

static string ReadBoundedEnrollmentInput()
{
    var buffer = new char[NativeEnrollmentChallenge.MaximumInputBytes + 1];
    var total = 0;
    while (total < buffer.Length)
    {
        var read = Console.In.Read(buffer, total, buffer.Length - total);
        if (read == 0) break;
        total += read;
    }
    if (
        total > NativeEnrollmentChallenge.MaximumInputBytes ||
        Console.In.Peek() != -1)
    {
        throw new InvalidDataException("SENSOR_ENROLLMENT_CHALLENGE_INPUT_INVALID");
    }
    var input = new string(buffer, 0, total);
    if (Encoding.UTF8.GetByteCount(input) > NativeEnrollmentChallenge.MaximumInputBytes)
    {
        throw new InvalidDataException("SENSOR_ENROLLMENT_CHALLENGE_INPUT_INVALID");
    }
    return input;
}

static object CleanupProbe()
{
    RequireWindows();
    RequireAdministrator();
    return new
    {
        ok = true,
        command = "probe-cleanup",
        result = DiagnosticProbeCleanup.Cleanup(
            new CngDiagnosticProbeKeyStore())
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
    using var identity = WindowsIdentity.GetCurrent();
    var principal = new WindowsPrincipal(identity);
    if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
    {
        throw new UnauthorizedAccessException("SENSOR_ADMINISTRATOR_REQUIRED");
    }
}

static string ToPublicErrorCode(Exception error) =>
    error.Message is
        "SENSOR_PROVISIONER_COMMAND_INVALID" or
        "SENSOR_WINDOWS_REQUIRED" or
        "SENSOR_ADMINISTRATOR_REQUIRED" or
        "SENSOR_NATIVE_KEY_ALREADY_EXISTS" or
        "SENSOR_NATIVE_KEY_POLICY_INVALID" or
        "SENSOR_NATIVE_KEY_ACL_INVALID" or
        "SENSOR_NATIVE_KEY_EXPORTABLE" or
        "SENSOR_NATIVE_KEY_PROOF_INVALID" or
        "SENSOR_ENROLLMENT_CHALLENGE_INPUT_INVALID" or
        "SENSOR_ENROLLMENT_CHALLENGE_FIELDS_INVALID" or
        "SENSOR_ENROLLMENT_CHALLENGE_VALUE_INVALID" or
        "SENSOR_ENROLLMENT_CHALLENGE_TIME_INVALID" or
        "SENSOR_ENROLLMENT_CHALLENGE_HASH_INVALID" or
        "SENSOR_ENROLLMENT_CHALLENGE_PROOF_INVALID" or
        "SENSOR_DIAGNOSTIC_PROBE_POLICY_INVALID" or
        "SENSOR_DIAGNOSTIC_PROBE_CLEANUP_FAILED"
            ? error.Message
            : "SENSOR_NATIVE_KEY_PROVISIONING_FAILED";

internal static class JsonOutput
{
    public static JsonSerializerOptions Options { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };
}
