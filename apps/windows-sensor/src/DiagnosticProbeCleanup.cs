using System.Security.Cryptography;

namespace WARRoom.WindowsSensor;

public sealed record DiagnosticProbeCleanupPlan(
    string ProbeName,
    string Provider,
    string Algorithm,
    string Scope,
    bool RequiresElevation,
    bool RemovesOnlyExactProbe,
    bool DeletesProductionMachineIdentity);

public sealed record DiagnosticProbeStatus(
    bool Exists,
    bool PolicyValid,
    string? ErrorCode,
    string ProbeName,
    string Provider);

public sealed record DiagnosticProbeCleanupResult(
    bool Removed,
    bool AlreadyAbsent,
    string ProbeName,
    bool ProductionMachineIdentityPreserved);

public interface IDiagnosticProbeKey : IDisposable
{
    NativeKeyMetadata Metadata { get; }
    void Delete();
}

public interface IDiagnosticProbeKeyStore
{
    bool Exists();
    IDiagnosticProbeKey Open();
}

public static class DiagnosticProbeCleanup
{
    public const string ProbeName =
        "WAR-R00M-Acl-Probe-397bf4da663d4a7b985eab7565aa2806";

    public static DiagnosticProbeCleanupPlan BuildPlan() =>
        new(
            ProbeName,
            SensorBoundary.SoftwareProviderName,
            SensorBoundary.SignatureAlgorithm,
            "current-user",
            RequiresElevation: true,
            RemovesOnlyExactProbe: true,
            DeletesProductionMachineIdentity: false);

    public static DiagnosticProbeStatus ReadStatus(
        IDiagnosticProbeKeyStore keyStore)
    {
        ArgumentNullException.ThrowIfNull(keyStore);
        if (!keyStore.Exists())
        {
            return new DiagnosticProbeStatus(
                Exists: false,
                PolicyValid: true,
                ErrorCode: null,
                ProbeName,
                SensorBoundary.SoftwareProviderName);
        }

        try
        {
            using var key = keyStore.Open();
            Validate(key.Metadata);
            return new DiagnosticProbeStatus(
                Exists: true,
                PolicyValid: true,
                ErrorCode: null,
                ProbeName,
                SensorBoundary.SoftwareProviderName);
        }
        catch (CryptographicException)
        {
            return new DiagnosticProbeStatus(
                Exists: true,
                PolicyValid: false,
                ErrorCode: "SENSOR_DIAGNOSTIC_PROBE_POLICY_INVALID",
                ProbeName,
                SensorBoundary.SoftwareProviderName);
        }
    }

    public static DiagnosticProbeCleanupResult Cleanup(
        IDiagnosticProbeKeyStore keyStore)
    {
        ArgumentNullException.ThrowIfNull(keyStore);
        if (!keyStore.Exists())
        {
            return new DiagnosticProbeCleanupResult(
                Removed: false,
                AlreadyAbsent: true,
                ProbeName,
                ProductionMachineIdentityPreserved: true);
        }

        using (var key = keyStore.Open())
        {
            Validate(key.Metadata);
            key.Delete();
        }
        if (keyStore.Exists())
        {
            throw new CryptographicException(
                "SENSOR_DIAGNOSTIC_PROBE_CLEANUP_FAILED");
        }

        return new DiagnosticProbeCleanupResult(
            Removed: true,
            AlreadyAbsent: false,
            ProbeName,
            ProductionMachineIdentityPreserved: true);
    }

    public static void Validate(NativeKeyMetadata key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (
            StringComparer.Ordinal.Equals(
                key.KeyName,
                SensorBoundary.IdentityKeyName) ||
            !StringComparer.Ordinal.Equals(key.KeyName, ProbeName) ||
            !StringComparer.Ordinal.Equals(
                key.ProviderName,
                SensorBoundary.SoftwareProviderName) ||
            !StringComparer.Ordinal.Equals(
                key.Algorithm,
                CngAlgorithm.ECDsaP256.Algorithm) ||
            !StringComparer.Ordinal.Equals(
                key.AlgorithmGroup,
                CngAlgorithmGroup.ECDsa.AlgorithmGroup) ||
            key.KeySize != 256 ||
            key.IsMachineKey ||
            key.IsEphemeral ||
            key.ExportPolicy != CngExportPolicies.None ||
            key.KeyUsage != CngKeyUsages.Signing)
        {
            throw new CryptographicException(
                "SENSOR_DIAGNOSTIC_PROBE_POLICY_INVALID");
        }
    }
}

public sealed class CngDiagnosticProbeKeyStore : IDiagnosticProbeKeyStore
{
    private static readonly CngProvider Provider =
        new(SensorBoundary.SoftwareProviderName);

    public bool Exists()
    {
        RequireWindows();
        return CngKey.Exists(
            DiagnosticProbeCleanup.ProbeName,
            Provider,
            CngKeyOpenOptions.None);
    }

    public IDiagnosticProbeKey Open()
    {
        RequireWindows();
        return new CngDiagnosticProbeKey(CngKey.Open(
            DiagnosticProbeCleanup.ProbeName,
            Provider,
            CngKeyOpenOptions.None));
    }

    private static void RequireWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("SENSOR_WINDOWS_REQUIRED");
        }
    }
}

internal sealed class CngDiagnosticProbeKey(CngKey key)
    : IDiagnosticProbeKey
{
    private CngKey? key =
        key ?? throw new ArgumentNullException(nameof(key));

    public NativeKeyMetadata Metadata
    {
        get
        {
            var current = GetKey();
            return new NativeKeyMetadata(
                current.KeyName ?? string.Empty,
                current.Provider?.Provider ?? string.Empty,
                current.Algorithm.Algorithm,
                current.AlgorithmGroup?.AlgorithmGroup ?? string.Empty,
                current.KeySize,
                current.IsMachineKey,
                current.IsEphemeral,
                current.ExportPolicy,
                current.KeyUsage);
        }
    }

    public void Delete()
    {
        var current = GetKey();
        current.Delete();
        current.Dispose();
        key = null;
    }

    public void Dispose()
    {
        key?.Dispose();
        key = null;
    }

    private CngKey GetKey() =>
        key ?? throw new ObjectDisposedException(
            nameof(CngDiagnosticProbeKey));
}
