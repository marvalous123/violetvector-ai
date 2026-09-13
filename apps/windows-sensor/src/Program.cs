using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using WARRoom.WindowsSensor;
using WARRoom.WindowsSensor.Readiness;

var startupMode = SensorStartupArguments.Resolve(
    args,
    new NativeSensorStartupModeSource());
var builder = Host.CreateApplicationBuilder();
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = SensorBoundary.ServiceName;
});
builder.Services.AddSingleton<ISensorIdentitySigner>(_ => CngMachineKeySigner.OpenProvisioned());
builder.Services.AddSingleton<ISensorServiceIdentity, WindowsSensorServiceIdentity>();
builder.Services.AddSingleton<IInstallManifestBindingReader,
    FixedInstallManifestBindingReader>();
builder.Services.AddSingleton(TimeProvider.System);

if (startupMode == SensorStartupMode.Security4663ApprovalConsumeProof)
{
    builder.Services.AddSingleton<ISecurity4663OneShotApprovalStore,
        NativeSecurity4663OneShotApprovalFileStore>();
    builder.Services.AddHostedService<
        Security4663OneShotApprovalConsumeProofWorker>();
    await builder.Build().RunAsync();
    return;
}

if (startupMode == SensorStartupMode.Security4663LiveOneShot)
{
    builder.Services.AddSingleton<ISecurity4663LiveOneShotApprovalStore,
        NativeSecurity4663LiveOneShotApprovalFileStore>();
    builder.Services.AddSingleton<ISecurity4663OneShotEventSource,
        NativeSecurity4663LiveOneShotEventSource>();
    builder.Services.AddSingleton<ISecurity4663OneShotReader,
        Security4663LiveOneShotBoundedReader>();
    builder.Services.AddSingleton<ISecurity4663LiveOneShotResultStore,
        NativeSecurity4663LiveOneShotResultFileStore>();
    builder.Services.AddHostedService<Security4663LiveOneShotExecutionWorker>();
    await builder.Build().RunAsync();
    return;
}

builder.Services.AddSingleton<IWindowsEventLogMetadataReader, NativeWindowsEventLogMetadataReader>();
builder.Services.AddHostedService<LocalServiceGateAReadinessWorker>();
builder.Services.AddSingleton<ILocalSyntheticBatchProofStore, FixedLocalSyntheticBatchProofStore>();
builder.Services.AddHostedService<LocalSyntheticBatchProofWorker>();
builder.Services.AddSingleton<IGenuineScmEventReader, NativeGenuineScmEventReader>();
builder.Services.AddSingleton<IGenuineScmProofStore, FixedGenuineScmProofStore>();
builder.Services.AddHostedService<GenuineScmBatchProofWorker>();
builder.Services.AddSingleton<IEndpointBindingStore, FixedEndpointBindingStore>();
builder.Services.AddHostedService<EndpointCapabilityProofWorker>();
builder.Services.AddSingleton<IEndpointDeliveryStore, FixedEndpointDeliveryStore>();
builder.Services.AddSingleton<IInstallManifestTimestampReader,
    FixedInstallManifestTimestampReader>();
builder.Services.AddSingleton<LoopbackFactTransport>();
builder.Services.AddSingleton<ILoopbackFactTransport>(services =>
    services.GetRequiredService<LoopbackFactTransport>());
builder.Services.AddHostedService<EndpointOneShotDeliveryWorker>();
builder.Services.AddSingleton<IBoundedEventMetadataReader,
    NativeBoundedEventMetadataReader>();
builder.Services.AddSingleton<IMultiEventCollector, BoundedMultiEventCollector>();
builder.Services.AddSingleton<IBoundedCollectorProofStore,
    FixedBoundedCollectorProofStore>();
builder.Services.AddHostedService<BoundedCollectorProofWorker>();
builder.Services.AddHostedService<SensorWorker>();

await builder.Build().RunAsync();
