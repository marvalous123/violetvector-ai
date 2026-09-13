using System.Security.AccessControl;
using System.Security.Principal;

namespace WARRoom.WindowsSensor;

public sealed record AuditWitnessAppendFileShape(
    bool Exists,
    bool IsDirectory,
    bool IsReparsePoint,
    int HardLinkCount,
    long Length);

public sealed record AuditWitnessAppendBoundaryPlan(
    string RootPath,
    string FilePath,
    string Claim,
    int MaximumBytes,
    int UsersAppendFileMask,
    bool SourceOnly,
    bool InstallerWiringEnabled,
    bool RuntimeWiringEnabled,
    bool CanCreate,
    bool CanTruncate,
    bool CanDelete,
    bool CanReplace);

public static class AuditWitnessAppendFilePolicy
{
    public const string BaseRootPath =
        @"C:\ProgramData\Project15 Audit Head";
    public const string RootPath =
        @"C:\ProgramData\Project15 Audit Head\Witness";
    public const string FilePath =
        @"C:\ProgramData\Project15 Audit Head\Witness\audit-witness-v1.log";
    public const string Claim = "historical-rewrite-detection-only";
    public const int MaximumBytes = 1_048_576;
    public const string LocalSystemSidValue = "S-1-5-18";
    public const string AdministratorsSidValue = "S-1-5-32-544";
    public const string UsersSidValue = "S-1-5-32-545";
    public const int UsersAppendFileMask = 0x0012008D;
    public const int UsersDirectoryMask = 0x001200A9;

    public static AuditWitnessAppendBoundaryPlan BuildPlan() => new(
        RootPath,
        FilePath,
        Claim,
        MaximumBytes,
        UsersAppendFileMask,
        SourceOnly: true,
        InstallerWiringEnabled: false,
        RuntimeWiringEnabled: false,
        CanCreate: false,
        CanTruncate: false,
        CanDelete: false,
        CanReplace: false);

    public static DirectorySecurity CreateRootSecurity()
    {
        var security = new DirectorySecurity();
        security.SetOwner(new SecurityIdentifier(
            WellKnownSidType.BuiltinAdministratorsSid,
            null));
        security.SetAccessRuleProtection(true, false);
        AddDirectoryRule(
            security,
            WellKnownSidType.LocalSystemSid,
            FileSystemRights.FullControl);
        AddDirectoryRule(
            security,
            WellKnownSidType.BuiltinAdministratorsSid,
            FileSystemRights.FullControl);
        AddDirectoryRule(
            security,
            WellKnownSidType.BuiltinUsersSid,
            (FileSystemRights)UsersDirectoryMask);
        return security;
    }

    public static FileSecurity CreateFileSecurity()
    {
        var security = new FileSecurity();
        security.SetOwner(new SecurityIdentifier(
            WellKnownSidType.BuiltinAdministratorsSid,
            null));
        security.SetAccessRuleProtection(true, false);
        AddFileRule(
            security,
            WellKnownSidType.LocalSystemSid,
            FileSystemRights.FullControl);
        AddFileRule(
            security,
            WellKnownSidType.BuiltinAdministratorsSid,
            FileSystemRights.FullControl);
        AddFileRule(
            security,
            WellKnownSidType.BuiltinUsersSid,
            (FileSystemRights)UsersAppendFileMask);
        return security;
    }

    public static void ValidateRootSecurity(DirectorySecurity security) =>
        ValidateSecurity(
            security,
            UsersDirectoryMask,
            requireDirectoryInheritance: true,
            "SENSOR_AUDIT_WITNESS_ROOT_ACL_INVALID");

    public static void ValidateFileSecurity(FileSecurity security) =>
        ValidateSecurity(
            security,
            UsersAppendFileMask,
            requireDirectoryInheritance: false,
            "SENSOR_AUDIT_WITNESS_FILE_ACL_INVALID");

    public static void ValidateFileShape(AuditWitnessAppendFileShape shape)
    {
        if (!shape.Exists || shape.IsDirectory || shape.IsReparsePoint ||
            shape.HardLinkCount != 1 || shape.Length is < 0 or > MaximumBytes)
        {
            throw new InvalidDataException(
                "SENSOR_AUDIT_WITNESS_FILE_INVALID");
        }
    }

    private static void ValidateSecurity(
        FileSystemSecurity security,
        int expectedUsersMask,
        bool requireDirectoryInheritance,
        string failure)
    {
        ArgumentNullException.ThrowIfNull(security);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as
            SecurityIdentifier;
        var rules = security.GetAccessRules(
            true,
            true,
            typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            LocalSystemSidValue,
            AdministratorsSidValue,
            UsersSidValue
        };
        if (owner?.Value != AdministratorsSidValue ||
            !security.AreAccessRulesProtected ||
            rules.Length != 3 ||
            rules.Any(rule =>
                rule.IsInherited ||
                rule.AccessControlType != AccessControlType.Allow ||
                !expected.Remove(rule.IdentityReference.Value) ||
                !HasExactFlags(rule, requireDirectoryInheritance) ||
                !HasExactRights(rule, expectedUsersMask)) ||
            expected.Count != 0)
        {
            throw new InvalidDataException(failure);
        }
    }

    private static bool HasExactFlags(
        FileSystemAccessRule rule,
        bool requireDirectoryInheritance)
    {
        var inheritance = requireDirectoryInheritance
            ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit
            : InheritanceFlags.None;
        return rule.InheritanceFlags == inheritance &&
            rule.PropagationFlags == PropagationFlags.None;
    }

    private static bool HasExactRights(
        FileSystemAccessRule rule,
        int expectedUsersMask)
    {
        var actual = unchecked((int)rule.FileSystemRights);
        return rule.IdentityReference.Value switch
        {
            LocalSystemSidValue or AdministratorsSidValue =>
                actual is 0x001F01FF or 0x10000000,
            UsersSidValue => actual == expectedUsersMask,
            _ => false
        };
    }

    private static void AddDirectoryRule(
        DirectorySecurity security,
        WellKnownSidType sid,
        FileSystemRights rights) => security.AddAccessRule(
            new FileSystemAccessRule(
                new SecurityIdentifier(sid, null),
                rights,
                InheritanceFlags.ContainerInherit |
                    InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

    private static void AddFileRule(
        FileSecurity security,
        WellKnownSidType sid,
        FileSystemRights rights) => security.AddAccessRule(
            new FileSystemAccessRule(
                new SecurityIdentifier(sid, null),
                rights,
                AccessControlType.Allow));
}
