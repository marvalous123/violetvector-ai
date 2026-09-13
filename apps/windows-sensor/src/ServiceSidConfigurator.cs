using System.ComponentModel;
using System.Collections.Frozen;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace WARRoom.WindowsSensor;

internal enum ServiceSidToolCommand
{
    Plan,
    Status,
    ApplyUnrestricted,
    RestoreNone,
    RestoreRestricted
}

internal static class ServiceSidToolCommandParser
{
    private static readonly IReadOnlySet<string> SupportedCommands =
        new[]
        {
            "plan",
            "status",
            "apply-unrestricted",
            "restore-none",
            "restore-restricted"
        }.ToFrozenSet(StringComparer.Ordinal);

    internal static ServiceSidToolCommand Parse(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Length != 1 || !SupportedCommands.Contains(args[0]))
        {
            throw new InvalidDataException(
                "SENSOR_SERVICE_SID_COMMAND_INVALID");
        }

        return args[0] switch
        {
            "plan" => ServiceSidToolCommand.Plan,
            "status" => ServiceSidToolCommand.Status,
            "apply-unrestricted" =>
                ServiceSidToolCommand.ApplyUnrestricted,
            "restore-none" => ServiceSidToolCommand.RestoreNone,
            "restore-restricted" =>
                ServiceSidToolCommand.RestoreRestricted,
            _ => throw new InvalidDataException(
                "SENSOR_SERVICE_SID_COMMAND_INVALID")
        };
    }
}

internal interface IServiceSidConfigurationNative : IServiceSidNativeAuthority
{
    void SetFixedServiceSidType(uint serviceSidType);
}

internal sealed record ServiceSidConfigurationResult(
    uint PreviousSidType,
    uint CurrentSidType,
    bool Changed);

internal static class ServiceSidConfigurator
{
    internal const uint None = 0;
    internal const uint Restricted = 3;

    internal static ServiceSidConfigurationResult ApplyUnrestricted(
        IServiceSidConfigurationNative native)
    {
        ArgumentNullException.ThrowIfNull(native);
        var before = ReadValidated(native);
        if (before.ServiceSidType == ServiceSidAuthority.Unrestricted)
        {
            return new(before.ServiceSidType, before.ServiceSidType, false);
        }

        try
        {
            native.SetFixedServiceSidType(ServiceSidAuthority.Unrestricted);
            var after = ReadValidated(native);
            if (after.ServiceSidType != ServiceSidAuthority.Unrestricted)
            {
                throw new InvalidOperationException(
                    "SENSOR_SERVICE_SID_APPLY_READBACK_INVALID");
            }

            return new(before.ServiceSidType, after.ServiceSidType, true);
        }
        catch (Exception applyError)
        {
            try
            {
                native.SetFixedServiceSidType(before.ServiceSidType);
                var recovered = ReadValidated(native);
                if (recovered.ServiceSidType != before.ServiceSidType)
                {
                    throw new InvalidOperationException(
                        "SENSOR_SERVICE_SID_APPLY_RECOVERY_READBACK_INVALID");
                }
            }
            catch (Exception recoveryError)
            {
                throw new InvalidOperationException(
                    "SENSOR_SERVICE_SID_APPLY_RECOVERY_FAILED",
                    new AggregateException(applyError, recoveryError));
            }

            throw new InvalidOperationException(
                "SENSOR_SERVICE_SID_APPLY_FAILED",
                applyError);
        }
    }

    internal static ServiceSidConfigurationResult RestorePrevious(
        IServiceSidConfigurationNative native,
        uint previousSidType)
    {
        ArgumentNullException.ThrowIfNull(native);
        ValidateSidType(previousSidType);
        var before = ReadValidated(native);
        if (before.ServiceSidType == previousSidType)
        {
            return new(before.ServiceSidType, before.ServiceSidType, false);
        }

        native.SetFixedServiceSidType(previousSidType);
        var after = ReadValidated(native);
        if (after.ServiceSidType != previousSidType)
        {
            throw new InvalidOperationException(
                "SENSOR_SERVICE_SID_ROLLBACK_READBACK_INVALID");
        }

        return new(before.ServiceSidType, after.ServiceSidType, true);
    }

    internal static void ValidateSidType(uint serviceSidType)
    {
        if (serviceSidType is not None and
            not ServiceSidAuthority.Unrestricted and
            not Restricted)
        {
            throw new InvalidOperationException(
                "SENSOR_SERVICE_SID_TYPE_INVALID");
        }
    }

    internal static ServiceSidNativeSnapshot ReadValidated(
        IServiceSidNativeAuthority native)
    {
        ArgumentNullException.ThrowIfNull(native);
        var snapshot = native.ReadFixedService();
        ValidateSidType(snapshot.ServiceSidType);
        if (
            !StringComparer.Ordinal.Equals(
                snapshot.ServiceName,
                SensorBoundary.ServiceName) ||
            !StringComparer.Ordinal.Equals(
                snapshot.ScmLogonAccount,
                SensorBoundary.ExpectedServiceIdentity) ||
            !StringComparer.Ordinal.Equals(
                snapshot.AccountName,
                ServiceSidAuthority.AccountName) ||
            !StringComparer.Ordinal.Equals(
                snapshot.DomainName,
                ServiceSidAuthority.DomainName) ||
            !snapshot.Sid.StartsWith(
                ServiceSidAuthority.SidPrefix,
                StringComparison.Ordinal) ||
            StringComparer.Ordinal.Equals(
                snapshot.Sid,
                NativeKeyAccessPolicy.LocalServiceSid))
        {
            throw new InvalidOperationException(
                "SENSOR_SERVICE_SID_CONFIGURATION_AUTHORITY_INVALID");
        }

        return snapshot;
    }
}

internal sealed class NativeServiceSidConfigurator :
    IServiceSidConfigurationNative
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceChangeConfig = 0x0002;
    private const uint ServiceConfigServiceSidInfo = 5;
    private readonly NativeServiceSidAuthority reader = new();

    public ServiceSidNativeSnapshot ReadFixedService() =>
        reader.ReadFixedService();

    public void SetFixedServiceSidType(uint serviceSidType)
    {
        ServiceSidConfigurator.ValidateSidType(serviceSidType);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("SENSOR_WINDOWS_REQUIRED");
        }

        using var manager = OpenSCManager(null, null, ScManagerConnect);
        if (manager.IsInvalid)
        {
            throw NativeFailure("SENSOR_SERVICE_SID_SCM_OPEN_FAILED");
        }

        using var service = OpenService(
            manager,
            SensorBoundary.ServiceName,
            ServiceChangeConfig);
        if (service.IsInvalid)
        {
            throw NativeFailure("SENSOR_SERVICE_SID_SERVICE_OPEN_FAILED");
        }

        var info = new ServiceSidInfo { ServiceSidType = serviceSidType };
        var buffer = Marshal.AllocHGlobal(Marshal.SizeOf<ServiceSidInfo>());
        try
        {
            Marshal.StructureToPtr(info, buffer, false);
            if (!ChangeServiceConfig2(
                service,
                ServiceConfigServiceSidInfo,
                buffer))
            {
                throw NativeFailure("SENSOR_SERVICE_SID_CHANGE_FAILED");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static Win32Exception NativeFailure(string code) =>
        new(Marshal.GetLastWin32Error(), code);

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceSidInfo
    {
        public uint ServiceSidType;
    }

    private sealed class ServiceHandle :
        SafeHandleZeroOrMinusOneIsInvalid
    {
        private ServiceHandle() : base(ownsHandle: true) { }

        protected override bool ReleaseHandle() =>
            CloseServiceHandle(handle);
    }

    [DllImport(
        "advapi32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern ServiceHandle OpenSCManager(
        string? machineName,
        string? databaseName,
        uint desiredAccess);

    [DllImport(
        "advapi32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern ServiceHandle OpenService(
        ServiceHandle serviceManager,
        string serviceName,
        uint desiredAccess);

    [DllImport(
        "advapi32.dll",
        EntryPoint = "ChangeServiceConfig2W",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig2(
        ServiceHandle service,
        uint infoLevel,
        IntPtr info);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr serviceHandle);
}
