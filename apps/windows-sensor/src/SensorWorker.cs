using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WARRoom.WindowsSensor;

public sealed class SensorWorker(
    ISensorIdentitySigner identity,
    ILogger<SensorWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var descriptor = identity.Descriptor;
        var proof = NativeStartupProof.Create(identity);
        logger.LogInformation(
            "WAR-R00M sensor boundary ready. Algorithm={Algorithm}; Provider={Provider}; Fingerprint={Fingerprint}; StartupProof={StartupProof}; inbound and command channels disabled.",
            descriptor.Algorithm,
            descriptor.KeyProvider,
            descriptor.CertificateFingerprintSha256,
            proof.SignatureSha256);

        // Gate C0c may perform one exact loopback delivery before this worker, but
        // only from a fresh final binding and only when no fixed receipt exists.
        // Gate C1 may also write one bounded local metadata snapshot before
        // this worker. There is no continuous collector, retry, remote
        // transport, listener, job loop or action handler.
        await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken);
    }
}
