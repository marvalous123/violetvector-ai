using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WARRoom.WindowsSensor;

public sealed record Security4663OneShotApprovalConsumeProofPlan(
    int SchemaVersion,
    string Checkpoint,
    string StartupArgument,
    string StartupModeRegistryPath,
    string StartupModeRegistryValueName,
    string ServiceIdentity,
    bool RequiresLocalServiceBeforeProtectedRead,
    bool ConsumesApprovalExactlyOnce,
    bool WritesResult,
    int MaximumEventsRead,
    bool RawEventContentRead,
    bool EventReaderEnabled,
    bool RetryEnabled,
    bool PollingEnabled,
    bool TransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    bool ResponseActionEnabled,
    bool ChangesServiceImagePath,
    bool RequiresStartupModeRollback,
    bool NormalStartupEnabled,
    bool GuardedOperatorInvocationWired);

public sealed record Security4663OneShotApprovalConsumeProofResult(
    int SchemaVersion,
    string Checkpoint,
    string State,
    long BaselineRecordId,
    bool LocalServiceIdentityValidated,
    bool ApprovalConsumed,
    int EventsRead,
    bool RawEventContentRead,
    bool EventReaderEnabled,
    bool RetryEnabled,
    bool PollingEnabled,
    bool TransportEnabled,
    bool InboundListenerEnabled,
    bool CommandChannelEnabled,
    bool ResponseActionEnabled);

// Disabled Gate C2e service mode. It proves only that LocalService can consume
// the existing signed approval through the protected store. It performs no
// event, target, result-file, network or control-channel operation.
public static class Security4663OneShotApprovalConsumeProof
{
    public const bool RuntimeWired = true;

    public static Security4663OneShotApprovalConsumeProofPlan BuildPlan() =>
        new(
            1,
            Readiness.Security4663OneShotMachinePlan.Checkpoint,
            SensorStartupArguments.Security4663ApprovalConsumeProofArgument,
            NativeSensorStartupModeSource.RegistryPath,
            NativeSensorStartupModeSource.RegistryValueName,
            SensorBoundary.ExpectedServiceIdentity,
            true,
            true,
            false,
            0,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            false,
            true);

    public static void ValidatePlan(
        Security4663OneShotApprovalConsumeProofPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (plan != BuildPlan())
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_CONSUME_PROOF_PLAN_INVALID");
        }
    }

    public static Security4663OneShotApprovalConsumeProofResult Consume(
        ISensorServiceIdentity serviceIdentity,
        IInstallManifestBindingReader manifestReader,
        ISecurity4663OneShotApprovalStore store,
        ISensorIdentitySigner identity,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(serviceIdentity);
        ArgumentNullException.ThrowIfNull(manifestReader);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(timeProvider);

        var plan = BuildPlan();
        ValidatePlan(plan);
        if (!string.Equals(
            serviceIdentity.CurrentSid,
            NativeKeyAccessPolicy.LocalServiceSid,
            StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "SENSOR_LOCALSERVICE_IDENTITY_REQUIRED");
        }

        cancellationToken.ThrowIfCancellationRequested();
        var manifest = manifestReader.Read();
        if (!string.Equals(
            manifest.Fingerprint,
            identity.Descriptor.CertificateFingerprintSha256,
            StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_CONSUME_PROOF_CONTEXT_INVALID");
        }

        var approval = Security4663OneShotApprovalLifecycle.Consume(
            store,
            identity.Descriptor,
            manifest.Commit,
            timeProvider.GetUtcNow().UtcDateTime);
        if (
            !approval.Approved ||
            approval.Checkpoint != plan.Checkpoint ||
            approval.Profile !=
                InertWindowsSecurityEvent4663Profile.CredentialStoreRead)
        {
            throw new InvalidDataException(
                "SENSOR_C2E_SECURITY_4663_CONSUME_PROOF_RESULT_INVALID");
        }

        return new Security4663OneShotApprovalConsumeProofResult(
            1,
            plan.Checkpoint,
            "consumed",
            approval.BaselineRecordId,
            true,
            true,
            0,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false);
    }
}

public sealed class Security4663OneShotApprovalConsumeProofWorker(
    ISensorServiceIdentity serviceIdentity,
    IInstallManifestBindingReader manifestReader,
    ISecurity4663OneShotApprovalStore store,
    ISensorIdentitySigner identity,
    TimeProvider timeProvider,
    IHostApplicationLifetime applicationLifetime,
    ILogger<Security4663OneShotApprovalConsumeProofWorker> logger) :
    BackgroundService
{
    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        await WaitForServiceStartedAsync(stoppingToken);
        try
        {
            var result = Security4663OneShotApprovalConsumeProof.Consume(
                serviceIdentity,
                manifestReader,
                store,
                identity,
                timeProvider,
                stoppingToken);
            logger.LogInformation(
                "WAR-R00M Gate C2e LocalService consumed one signed approval; events read={EventsRead}; event reader, telemetry, transport and commands disabled.",
                result.EventsRead);
        }
        catch
        {
            Environment.ExitCode = 2;
            throw;
        }
        finally
        {
            applicationLifetime.StopApplication();
        }
    }

    private async Task WaitForServiceStartedAsync(
        CancellationToken stoppingToken)
    {
        if (applicationLifetime.ApplicationStarted.IsCancellationRequested)
        {
            return;
        }
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            applicationLifetime.ApplicationStarted,
            stoppingToken);
        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, linked.Token);
        }
        catch (OperationCanceledException) when (
            applicationLifetime.ApplicationStarted.IsCancellationRequested)
        {
            // Host startup is complete; the SCM has observed the service start.
        }
        stoppingToken.ThrowIfCancellationRequested();
    }
}
