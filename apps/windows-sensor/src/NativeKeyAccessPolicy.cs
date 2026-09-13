using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace WARRoom.WindowsSensor;

public sealed record NativeKeyAccessSummary(
    string OwnerSid,
    string GroupSid,
    bool DaclProtected,
    int AllowedPrincipalCount,
    string ServiceSid,
    string ServiceAccess);

public static class NativeKeyAccessPolicy
{
    public const string SecurityDescriptorPropertyName = "Security Descr";
    public const string LocalSystemSid = "S-1-5-18";
    public const string LocalServiceSid = "S-1-5-19";
    public const string BuiltinAdministratorsSid = "S-1-5-32-544";
    public const string ProtectedDescriptorSddl =
        "O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;LS)";

    public static readonly CngPropertyOptions ReadOptions =
        (CngPropertyOptions)0x00000007;

    public static readonly CngPropertyOptions CreateOptions =
        unchecked((CngPropertyOptions)(int)0x80000007);

    private const int GenericAllMask = 0x10000000;
    private const int GenericReadMask = unchecked((int)0x80000000);
    private const int SoftwareKspFullControlMask = unchecked((int)0xd01f01ff);
    private const int SoftwareKspReadMask = unchecked((int)0x80120089);

    public static byte[] CreateProtectedDescriptor()
    {
        var descriptor = new RawSecurityDescriptor(ProtectedDescriptorSddl);
        var binary = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(binary, 0);
        Validate(binary);
        return binary;
    }

    public static byte[] CreateServiceSidProtectedDescriptor(
        ResolvedServiceSid serviceSid)
    {
        ValidateResolvedServiceSid(serviceSid);
        var descriptor = new RawSecurityDescriptor(
            $"O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;{serviceSid.Sid})");
        var binary = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(binary, 0);
        ValidateServiceSidProtectedDescriptor(binary, serviceSid);
        return binary;
    }

    public static NativeKeyAccessSummary Validate(byte[] binaryDescriptor)
        => ValidateCore(
            binaryDescriptor,
            LocalServiceSid,
            "generic-read-only");

    public static NativeKeyAccessSummary ValidateServiceSidProtectedDescriptor(
        byte[] binaryDescriptor,
        ResolvedServiceSid serviceSid)
    {
        ValidateResolvedServiceSid(serviceSid);
        return ValidateCore(
            binaryDescriptor,
            serviceSid.Sid,
            "service-sid-read-only");
    }

    private static NativeKeyAccessSummary ValidateCore(
        byte[] binaryDescriptor,
        string expectedServiceSid,
        string serviceAccess)
    {
        ArgumentNullException.ThrowIfNull(binaryDescriptor);
        if (binaryDescriptor.Length is < 1 or > 16_384)
        {
            throw new CryptographicException("SENSOR_NATIVE_KEY_ACL_INVALID");
        }

        RawSecurityDescriptor descriptor;
        try
        {
            descriptor = new RawSecurityDescriptor(binaryDescriptor, 0);
        }
        catch (ArgumentException error)
        {
            throw new CryptographicException("SENSOR_NATIVE_KEY_ACL_INVALID", error);
        }

        var owner = descriptor.Owner?.Value;
        var group = descriptor.Group?.Value;
        var flags = descriptor.ControlFlags;
        if (
            !StringComparer.Ordinal.Equals(owner, BuiltinAdministratorsSid) ||
            !StringComparer.Ordinal.Equals(group, BuiltinAdministratorsSid) ||
            !flags.HasFlag(ControlFlags.DiscretionaryAclPresent) ||
            !flags.HasFlag(ControlFlags.DiscretionaryAclProtected) ||
            flags.HasFlag(ControlFlags.DiscretionaryAclAutoInherited) ||
            flags.HasFlag(ControlFlags.DiscretionaryAclAutoInheritRequired) ||
            descriptor.DiscretionaryAcl is null ||
            descriptor.DiscretionaryAcl.Count != 3)
        {
            throw new CryptographicException("SENSOR_NATIVE_KEY_ACL_INVALID");
        }

        var accessBySid = new Dictionary<string, int>(StringComparer.Ordinal);
        for (var index = 0; index < descriptor.DiscretionaryAcl.Count; index++)
        {
            if (
                descriptor.DiscretionaryAcl[index] is not CommonAce ace ||
                ace.AceQualifier != AceQualifier.AccessAllowed ||
                ace.IsInherited ||
                ace.AceFlags != AceFlags.None ||
                ace.SecurityIdentifier is null ||
                !accessBySid.TryAdd(ace.SecurityIdentifier.Value, ace.AccessMask))
            {
                throw new CryptographicException("SENSOR_NATIVE_KEY_ACL_INVALID");
            }
        }

        if (
            accessBySid.Count != 3 ||
            !HasExactAccess(accessBySid, LocalSystemSid, GenericAllMask, SoftwareKspFullControlMask) ||
            !HasExactAccess(accessBySid, BuiltinAdministratorsSid, GenericAllMask, SoftwareKspFullControlMask) ||
            !HasExactAccess(accessBySid, expectedServiceSid, GenericReadMask, SoftwareKspReadMask))
        {
            throw new CryptographicException("SENSOR_NATIVE_KEY_ACL_INVALID");
        }

        return new NativeKeyAccessSummary(
            owner!,
            group!,
            DaclProtected: true,
            accessBySid.Count,
            expectedServiceSid,
            serviceAccess);
    }

    private static void ValidateResolvedServiceSid(ResolvedServiceSid serviceSid)
    {
        ArgumentNullException.ThrowIfNull(serviceSid);
        if (
            !StringComparer.Ordinal.Equals(serviceSid.ServiceName, SensorBoundary.ServiceName) ||
            !StringComparer.Ordinal.Equals(serviceSid.AccountName, ServiceSidAuthority.AccountName) ||
            !serviceSid.Sid.StartsWith(ServiceSidAuthority.SidPrefix, StringComparison.Ordinal) ||
            StringComparer.Ordinal.Equals(serviceSid.Sid, LocalServiceSid))
        {
            throw new CryptographicException("SENSOR_NATIVE_KEY_SERVICE_SID_INVALID");
        }
    }

    private static bool HasExactAccess(
        IReadOnlyDictionary<string, int> accessBySid,
        string sid,
        int configuredMask,
        int softwareKspReadbackMask)
    {
        return accessBySid.TryGetValue(sid, out var mask) &&
            (mask == configuredMask || mask == softwareKspReadbackMask);
    }
}
