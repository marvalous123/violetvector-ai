using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace WARRoom.WindowsSensor;

public sealed record ServiceSidNativeSnapshot(
    string ServiceName,
    string ScmLogonAccount,
    string AccountName,
    string DomainName,
    string Sid,
    uint ServiceSidType);

public sealed record ResolvedServiceSid
{
    internal ResolvedServiceSid(
        string serviceName,
        string accountName,
        string sid)
    {
        ServiceName = serviceName;
        AccountName = accountName;
        Sid = sid;
    }

    public string ServiceName { get; }
    public string AccountName { get; }
    public string Sid { get; }
}

public interface IServiceSidNativeAuthority
{
    ServiceSidNativeSnapshot ReadFixedService();
}

public static class ServiceSidAuthority
{
    public const string AccountName = @"NT SERVICE\WARRoomWindowsSensor";
    public const string DomainName = "NT SERVICE";
    public const string SidPrefix = "S-1-5-80-";
    public const uint Unrestricted = 1;

    public static ResolvedServiceSid ResolveAndValidate(
        IServiceSidNativeAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);
        var snapshot = authority.ReadFixedService();
        if (
            !StringComparer.Ordinal.Equals(snapshot.ServiceName, SensorBoundary.ServiceName) ||
            !StringComparer.Ordinal.Equals(snapshot.ScmLogonAccount, SensorBoundary.ExpectedServiceIdentity) ||
            !StringComparer.Ordinal.Equals(snapshot.AccountName, AccountName) ||
            !StringComparer.Ordinal.Equals(snapshot.DomainName, DomainName) ||
            snapshot.ServiceSidType != Unrestricted ||
            !snapshot.Sid.StartsWith(SidPrefix, StringComparison.Ordinal) ||
            StringComparer.Ordinal.Equals(snapshot.Sid, NativeKeyAccessPolicy.LocalServiceSid))
        {
            throw new InvalidOperationException("SENSOR_SERVICE_SID_AUTHORITY_INVALID");
        }

        try
        {
            var parsed = new SecurityIdentifier(snapshot.Sid);
            if (!StringComparer.Ordinal.Equals(parsed.Value, snapshot.Sid))
            {
                throw new InvalidOperationException("SENSOR_SERVICE_SID_AUTHORITY_INVALID");
            }
        }
        catch (ArgumentException error)
        {
            throw new InvalidOperationException(
                "SENSOR_SERVICE_SID_AUTHORITY_INVALID",
                error);
        }

        return new ResolvedServiceSid(
            snapshot.ServiceName,
            snapshot.AccountName,
            snapshot.Sid);
    }
}

public sealed record ServiceSidHardeningPlan(
    int SchemaVersion,
    string ServiceName,
    string ScmLogonAccount,
    string ResourceAuthorityAccount,
    string RequiredServiceSidType,
    string ExistingKeyName,
    string ReplacementKeyName,
    string ReplacementProfile,
    IReadOnlyList<string> OrderedSteps,
    bool ResolvesSidThroughWindowsApis,
    bool AcceptsCallerSuppliedSid,
    bool ConfiguresSidBeforeResourceAcls,
    bool ConfiguresSidBeforeServiceStart,
    bool GrantsGenericLocalServiceResourceAccess,
    bool RequiresFreshEnrollment,
    bool RevokesOldIdentityAfterAtomicCutover,
    bool PermitsLegacyAclRollback,
    bool PerformsMachineMutation,
    bool TelemetryEnabled,
    bool TransportEnabled,
    bool RetryEnabled,
    bool PollingEnabled,
    bool ListenerEnabled,
    bool CommandChannelEnabled,
    bool ResponseActionsEnabled);

public static class ServiceSidHardeningCheckpoint
{
    private static readonly IReadOnlyList<string> Steps =
        new ReadOnlyCollection<string>(
        [
            "stop-and-validate-fixed-service",
            "enable-and-read-back-unrestricted-service-sid",
            "resolve-fixed-service-account-through-windows",
            "create-non-exportable-v2-key-with-service-sid-read-only",
            "apply-service-sid-only-resource-acls",
            "prove-v2-key-and-complete-fresh-endpoint-enrollment",
            "atomically-activate-v2-and-revoke-v1",
            "start-and-read-back-fixed-service",
            "remove-v1-key-after-independent-validation"
        ]);

    public static ServiceSidHardeningPlan BuildSourceOnlyPlan() =>
        new(
            1,
            SensorBoundary.ServiceName,
            SensorBoundary.ExpectedServiceIdentity,
            ServiceSidAuthority.AccountName,
            "SERVICE_SID_TYPE_UNRESTRICTED",
            SensorBoundary.IdentityKeyName,
            "WAR-R00M.WindowsSensor.Identity.v2",
            "software-ksp-service-sid-machine-v2",
            Steps,
            ResolvesSidThroughWindowsApis: true,
            AcceptsCallerSuppliedSid: false,
            ConfiguresSidBeforeResourceAcls: true,
            ConfiguresSidBeforeServiceStart: true,
            GrantsGenericLocalServiceResourceAccess: false,
            RequiresFreshEnrollment: true,
            RevokesOldIdentityAfterAtomicCutover: true,
            PermitsLegacyAclRollback: false,
            PerformsMachineMutation: false,
            TelemetryEnabled: false,
            TransportEnabled: false,
            RetryEnabled: false,
            PollingEnabled: false,
            ListenerEnabled: false,
            CommandChannelEnabled: false,
            ResponseActionsEnabled: false);

    public static void Validate(ServiceSidHardeningPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var expected = BuildSourceOnlyPlan();
        if (
            plan.SchemaVersion != expected.SchemaVersion ||
            !StringComparer.Ordinal.Equals(plan.ServiceName, expected.ServiceName) ||
            !StringComparer.Ordinal.Equals(plan.ScmLogonAccount, expected.ScmLogonAccount) ||
            !StringComparer.Ordinal.Equals(plan.ResourceAuthorityAccount, expected.ResourceAuthorityAccount) ||
            !StringComparer.Ordinal.Equals(plan.RequiredServiceSidType, expected.RequiredServiceSidType) ||
            !StringComparer.Ordinal.Equals(plan.ExistingKeyName, expected.ExistingKeyName) ||
            !StringComparer.Ordinal.Equals(plan.ReplacementKeyName, expected.ReplacementKeyName) ||
            !StringComparer.Ordinal.Equals(plan.ReplacementProfile, expected.ReplacementProfile) ||
            !plan.OrderedSteps.SequenceEqual(expected.OrderedSteps, StringComparer.Ordinal) ||
            !plan.ResolvesSidThroughWindowsApis ||
            plan.AcceptsCallerSuppliedSid ||
            !plan.ConfiguresSidBeforeResourceAcls ||
            !plan.ConfiguresSidBeforeServiceStart ||
            plan.GrantsGenericLocalServiceResourceAccess ||
            !plan.RequiresFreshEnrollment ||
            !plan.RevokesOldIdentityAfterAtomicCutover ||
            plan.PermitsLegacyAclRollback ||
            plan.PerformsMachineMutation ||
            plan.TelemetryEnabled ||
            plan.TransportEnabled ||
            plan.RetryEnabled ||
            plan.PollingEnabled ||
            plan.ListenerEnabled ||
            plan.CommandChannelEnabled ||
            plan.ResponseActionsEnabled)
        {
            throw new InvalidOperationException("SENSOR_SERVICE_SID_PLAN_INVALID");
        }
    }
}

public sealed class NativeServiceSidAuthority : IServiceSidNativeAuthority
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryConfig = 0x0001;
    private const uint ServiceConfigServiceSidInfo = 5;
    private const int ErrorInsufficientBuffer = 122;

    public ServiceSidNativeSnapshot ReadFixedService()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("SENSOR_WINDOWS_REQUIRED");
        }

        using var manager = OpenSCManager(null, null, ScManagerConnect);
        if (manager.IsInvalid)
        {
            throw NativeFailure("SENSOR_SERVICE_SID_SCM_OPEN_FAILED");
        }
        using var service = OpenService(manager, SensorBoundary.ServiceName, ServiceQueryConfig);
        if (service.IsInvalid)
        {
            throw NativeFailure("SENSOR_SERVICE_SID_SERVICE_OPEN_FAILED");
        }

        var bytesNeeded = 0u;
        var scmLogonAccount = ReadScmLogonAccount(service);
        _ = QueryServiceConfig2(
            service,
            ServiceConfigServiceSidInfo,
            IntPtr.Zero,
            0,
            out bytesNeeded);
        if (bytesNeeded != sizeof(uint) || Marshal.GetLastWin32Error() != ErrorInsufficientBuffer)
        {
            throw NativeFailure("SENSOR_SERVICE_SID_CONFIG_READ_FAILED");
        }
        var buffer = Marshal.AllocHGlobal(checked((int)bytesNeeded));
        try
        {
            if (!QueryServiceConfig2(
                service,
                ServiceConfigServiceSidInfo,
                buffer,
                bytesNeeded,
                out var returned) ||
                returned != bytesNeeded)
            {
                throw NativeFailure("SENSOR_SERVICE_SID_CONFIG_READ_FAILED");
            }
            var sidType = unchecked((uint)Marshal.ReadInt32(buffer));
            var (sid, domain) = LookupFixedAccount();
            return new ServiceSidNativeSnapshot(
                SensorBoundary.ServiceName,
                scmLogonAccount,
                ServiceSidAuthority.AccountName,
                domain,
                sid,
                sidType);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static string ReadScmLogonAccount(ServiceHandle service)
    {
        var bytesNeeded = 0u;
        _ = QueryServiceConfig(service, IntPtr.Zero, 0, out bytesNeeded);
        if (
            bytesNeeded < Marshal.SizeOf<QueryServiceConfigNative>() ||
            bytesNeeded > 4_096 ||
            Marshal.GetLastWin32Error() != ErrorInsufficientBuffer)
        {
            throw NativeFailure("SENSOR_SERVICE_SID_LOGON_READ_FAILED");
        }

        var buffer = Marshal.AllocHGlobal(checked((int)bytesNeeded));
        try
        {
            if (!QueryServiceConfig(service, buffer, bytesNeeded, out var returned) ||
                returned > bytesNeeded)
            {
                throw NativeFailure("SENSOR_SERVICE_SID_LOGON_READ_FAILED");
            }
            var config = Marshal.PtrToStructure<QueryServiceConfigNative>(buffer);
            var startName = config.StartName == IntPtr.Zero
                ? null
                : Marshal.PtrToStringUni(config.StartName);
            return startName ??
                throw new InvalidOperationException("SENSOR_SERVICE_SID_LOGON_READ_FAILED");
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static (string Sid, string Domain) LookupFixedAccount()
    {
        var sidBytes = 0u;
        var domainChars = 0u;
        _ = LookupAccountName(
            null,
            ServiceSidAuthority.AccountName,
            IntPtr.Zero,
            ref sidBytes,
            null,
            ref domainChars,
            out _);
        if (
            sidBytes is < 12 or > 1_024 ||
            domainChars is < 1 or > 256 ||
            Marshal.GetLastWin32Error() != ErrorInsufficientBuffer)
        {
            throw NativeFailure("SENSOR_SERVICE_SID_LOOKUP_FAILED");
        }

        var sidBuffer = Marshal.AllocHGlobal(checked((int)sidBytes));
        try
        {
            var domain = new char[domainChars];
            if (!LookupAccountName(
                null,
                ServiceSidAuthority.AccountName,
                sidBuffer,
                ref sidBytes,
                domain,
                ref domainChars,
                out var use))
            {
                throw NativeFailure("SENSOR_SERVICE_SID_LOOKUP_FAILED");
            }
            if (use != SidNameUse.WellKnownGroup)
            {
                throw new InvalidOperationException("SENSOR_SERVICE_SID_LOOKUP_FAILED");
            }
            var sid = new SecurityIdentifier(sidBuffer).Value;
            var domainValue = new string(domain, 0, checked((int)domainChars));
            return (sid, domainValue);
        }
        finally
        {
            Marshal.FreeHGlobal(sidBuffer);
        }
    }

    private static Win32Exception NativeFailure(string code) =>
        new(Marshal.GetLastWin32Error(), code);

    private enum SidNameUse
    {
        User = 1,
        Group = 2,
        Domain = 3,
        Alias = 4,
        WellKnownGroup = 5,
        DeletedAccount = 6,
        Invalid = 7,
        Unknown = 8,
        Computer = 9,
        Label = 10,
        LogonSession = 11
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct QueryServiceConfigNative
    {
        public uint ServiceType;
        public uint StartType;
        public uint ErrorControl;
        public IntPtr BinaryPathName;
        public IntPtr LoadOrderGroup;
        public uint TagId;
        public IntPtr Dependencies;
        public IntPtr StartName;
        public IntPtr DisplayName;
    }

    private sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private ServiceHandle() : base(ownsHandle: true) { }

        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceHandle OpenSCManager(
        string? machineName,
        string? databaseName,
        uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceHandle OpenService(
        ServiceHandle serviceManager,
        string serviceName,
        uint desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfig2W", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfig2(
        ServiceHandle service,
        uint infoLevel,
        IntPtr buffer,
        uint bufferSize,
        out uint bytesNeeded);

    [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfigW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfig(
        ServiceHandle service,
        IntPtr serviceConfig,
        uint bufferSize,
        out uint bytesNeeded);

    [DllImport("advapi32.dll", EntryPoint = "LookupAccountNameW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupAccountName(
        string? systemName,
        string accountName,
        IntPtr sid,
        ref uint sidSize,
        [Out] char[]? referencedDomainName,
        ref uint domainNameSize,
        out SidNameUse use);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr serviceHandle);
}
