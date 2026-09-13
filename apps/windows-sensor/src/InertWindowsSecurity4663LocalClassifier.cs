using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace WARRoom.WindowsSensor;

public enum InertWindowsSecurityActorTrust
{
    Managed = 1,
    Untrusted = 2,
    Unknown = 3
}

public enum InertWindowsSecuritySubjectClass
{
    Browser = 1,
    PasswordManager = 2,
    Other = 3
}

public enum InertWindowsSecurityTrustEvidence
{
    ManagedInventory = 1,
    ExplicitUntrustedHash = 2,
    Unresolved = 3
}

public sealed record InertWindowsSecurity4663TargetBinding(
    InertWindowsSecurityEvent4663Profile Profile,
    string ObjectPathTagHmacSha256,
    bool TargetSaclConfigured);

public sealed record InertWindowsSecurity4663ProcessBinding(
    string ProcessPathTagHmacSha256,
    InertWindowsSecuritySubjectClass SubjectClass,
    InertWindowsSecurityActorTrust ActorTrust,
    InertWindowsSecurityTrustEvidence TrustEvidence);

public sealed record InertWindowsSecurity4663LocalClassification(
    string Provider,
    string Channel,
    string EventFamily,
    DateTimeOffset OccurredAtUtc,
    long SourceRecordId,
    InertWindowsSecurityEvent4663Profile Profile,
    BoundedFactMapping Mapping,
    string BaselineState,
    string VisibilityState,
    bool TargetSaclVerified,
    bool LocalClassificationComplete,
    bool GenuineLiveEligible,
    bool RawEventContentRetained);

// Gate C2c pure classification contract. It has no event reader, filesystem
// access, trust lookup, persistence or transport and remains runtime-unwired.
public static partial class InertWindowsSecurity4663LocalClassifier
{
    private const int ClassificationKeyBytes = 32;
    private const int MaximumPriorObservationCount = 1_000_000;

    public const bool RuntimeWired = false;

    public static string CreateObjectPathTagHmacSha256(
        string path,
        ReadOnlySpan<byte> classificationKey) =>
        CreatePathTagHmacSha256(
            path,
            classificationKey,
            "WAR-R00M.C2C.OBJECT.v1\0");

    public static string CreateProcessPathTagHmacSha256(
        string path,
        ReadOnlySpan<byte> classificationKey) =>
        CreatePathTagHmacSha256(
            path,
            classificationKey,
            "WAR-R00M.C2C.PROCESS.v1\0");

    private static string CreatePathTagHmacSha256(
        string path,
        ReadOnlySpan<byte> classificationKey,
        string domain)
    {
        if (classificationKey.Length != ClassificationKeyBytes)
        {
            throw new InvalidDataException("SENSOR_C2C_CLASSIFIER_KEY_INVALID");
        }

        var canonicalPath = CanonicalizeLocalPath(path);
        var tag = HMACSHA256.HashData(classificationKey, Encoding.UTF8.GetBytes(
            domain + canonicalPath));
        return Convert.ToHexString(tag).ToLowerInvariant();
    }

    public static InertWindowsSecurity4663LocalClassification Classify(
        InertWindowsSecurityEventRecord record,
        InertWindowsSecurityEvent4663Profile profile,
        InertWindowsSecurity4663TargetBinding targetBinding,
        InertWindowsSecurity4663ProcessBinding processBinding,
        int? priorObservationCount,
        FileAttributes? postEventFileAttributes,
        ReadOnlySpan<byte> classificationKey)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(targetBinding);
        ArgumentNullException.ThrowIfNull(processBinding);

        var candidate = InertWindowsSecurityEvent4663Parser.ParseCandidate(
            record,
            profile);
        if (
            targetBinding.Profile != profile ||
            !targetBinding.TargetSaclConfigured ||
            !Sha256Pattern().IsMatch(targetBinding.ObjectPathTagHmacSha256) ||
            !Sha256Pattern().IsMatch(processBinding.ProcessPathTagHmacSha256))
        {
            throw new InvalidDataException("SENSOR_C2C_CLASSIFIER_BINDING_INVALID");
        }

        ValidateTrustBinding(processBinding);
        if (
            !FixedTimeEquals(
                targetBinding.ObjectPathTagHmacSha256,
                CreateObjectPathTagHmacSha256(
                    record.EventData["ObjectName"], classificationKey)) ||
            !FixedTimeEquals(
                processBinding.ProcessPathTagHmacSha256,
                CreateProcessPathTagHmacSha256(
                    record.EventData["ProcessName"], classificationKey)))
        {
            throw new InvalidDataException("SENSOR_C2C_CLASSIFIER_PATH_BINDING_INVALID");
        }

        var baselineState = ClassifyBaseline(priorObservationCount);
        var visibilityState = ClassifyVisibility(profile, postEventFileAttributes);
        var actorTrust = processBinding.ActorTrust switch
        {
            InertWindowsSecurityActorTrust.Managed => "managed",
            InertWindowsSecurityActorTrust.Untrusted => "untrusted",
            InertWindowsSecurityActorTrust.Unknown => "unknown",
            _ => throw new InvalidDataException("SENSOR_C2C_CLASSIFIER_TRUST_INVALID")
        };
        var subjectClass = processBinding.SubjectClass switch
        {
            InertWindowsSecuritySubjectClass.Browser => "browser",
            InertWindowsSecuritySubjectClass.PasswordManager => "password-manager",
            InertWindowsSecuritySubjectClass.Other => "other",
            _ => throw new InvalidDataException("SENSOR_C2C_CLASSIFIER_SUBJECT_INVALID")
        };
        var action = profile ==
            InertWindowsSecurityEvent4663Profile.HiddenAttributeWrite
                ? "hide"
                : "read";
        var complete = actorTrust != "unknown" &&
            (profile == InertWindowsSecurityEvent4663Profile.HiddenAttributeWrite
                ? visibilityState != "unknown"
                : baselineState != "unknown");

        return new InertWindowsSecurity4663LocalClassification(
            candidate.Provider,
            candidate.Channel,
            candidate.EventFamily,
            candidate.OccurredAtUtc,
            candidate.SourceRecordId,
            profile,
            new BoundedFactMapping(
                actorTrust,
                action,
                subjectClass,
                candidate.RequiredObjectClass,
                "success"),
            baselineState,
            visibilityState,
            true,
            complete,
            false,
            false);
    }

    private static string CanonicalizeLocalPath(string path)
    {
        if (
            string.IsNullOrWhiteSpace(path) ||
            path.Length > 1024 ||
            path.Any(char.IsControl))
        {
            throw new InvalidDataException("SENSOR_C2C_CLASSIFIER_PATH_INVALID");
        }

        var canonical = path.Replace('/', '\\').Normalize(NormalizationForm.FormC);
        var segments = canonical.Split('\\', StringSplitOptions.None);
        if (
            canonical.Length > 1024 ||
            !DriveAbsolutePathPattern().IsMatch(canonical) ||
            segments.Any(segment => segment is "." or ".." or "") ||
            segments.Skip(1).Any(segment =>
                segment.EndsWith(' ') || segment.EndsWith('.')))
        {
            throw new InvalidDataException("SENSOR_C2C_CLASSIFIER_PATH_INVALID");
        }

        return canonical.ToUpperInvariant();
    }

    private static void ValidateTrustBinding(
        InertWindowsSecurity4663ProcessBinding binding)
    {
        var valid = (binding.ActorTrust, binding.TrustEvidence) switch
        {
            (InertWindowsSecurityActorTrust.Managed,
                InertWindowsSecurityTrustEvidence.ManagedInventory) => true,
            (InertWindowsSecurityActorTrust.Untrusted,
                InertWindowsSecurityTrustEvidence.ExplicitUntrustedHash) => true,
            (InertWindowsSecurityActorTrust.Unknown,
                InertWindowsSecurityTrustEvidence.Unresolved) => true,
            _ => false
        };
        if (!valid)
        {
            throw new InvalidDataException("SENSOR_C2C_CLASSIFIER_TRUST_INVALID");
        }
    }

    private static string ClassifyBaseline(int? priorObservationCount)
    {
        if (priorObservationCount is null) return "unknown";
        if (priorObservationCount is < 0 or > MaximumPriorObservationCount)
        {
            throw new InvalidDataException("SENSOR_C2C_CLASSIFIER_BASELINE_INVALID");
        }

        return priorObservationCount switch
        {
            0 => "new",
            <= 3 => "rare",
            _ => "expected"
        };
    }

    private static string ClassifyVisibility(
        InertWindowsSecurityEvent4663Profile profile,
        FileAttributes? postEventFileAttributes)
    {
        if (profile != InertWindowsSecurityEvent4663Profile.HiddenAttributeWrite)
        {
            if (postEventFileAttributes is not null)
            {
                throw new InvalidDataException(
                    "SENSOR_C2C_CLASSIFIER_VISIBILITY_UNEXPECTED");
            }

            return "unknown";
        }

        if (postEventFileAttributes is null) return "unknown";
        return postEventFileAttributes.Value.HasFlag(FileAttributes.Hidden)
            ? "hidden"
            : "visible";
    }

    private static bool FixedTimeEquals(string left, string right) =>
        CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(left),
            Convert.FromHexString(right));

    [GeneratedRegex(@"^[a-f0-9]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256Pattern();

    [GeneratedRegex(@"^[A-Za-z]:\\[^\x00-\x1F\x7F]{1,1019}$", RegexOptions.CultureInvariant)]
    private static partial Regex DriveAbsolutePathPattern();
}
