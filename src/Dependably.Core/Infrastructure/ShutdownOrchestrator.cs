namespace Dependably.Infrastructure;

/// <summary>
/// Hosted service that implements the HA shutdown sequence:
/// 1. Marks /ready as not-ready immediately on ApplicationStopping.
/// 2. Sleeps SHUTDOWN_PRESTOP_DELAY so the ALB can remove this replica from rotation.
/// 3. Returns so the host can drain Kestrel and other services (governed by ShutdownTimeout).
///
/// <para>The pre-stop delay defaults to 0 — it buys nothing on a single node, and it is spent
/// BEFORE any hosted service's StopAsync runs, so a non-zero default would eat the whole of Docker's
/// 10s default stop timeout and let SIGKILL land before the queues flush and the SQLite instance
/// lock is released. Deployments that front several replicas with a load balancer set it explicitly
/// alongside a termination grace period wide enough to cover both this delay and the drain.</para>
///
/// Environment variables:
///   SHUTDOWN_PRESTOP_DELAY  — seconds to wait before accepting shutdown (default 0)
///   SHUTDOWN_GRACE_PERIOD   — passed to host ShutdownTimeout; max time for in-flight drain (default 30)
/// </summary>
public sealed class ShutdownOrchestrator : IHostedService
{
    // Default pre-stop delay seconds. Zero: see the class remarks — a load-balanced deployment opts
    // in, and pays for it with a matching termination grace period.
    private const int DefaultPreStopDelaySeconds = 0;

    private readonly ShutdownState _state;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ILogger<ShutdownOrchestrator> _logger;
    private readonly TimeSpan _preStopDelay;

    public ShutdownOrchestrator(
        ShutdownState state,
        IHostApplicationLifetime lifetime,
        IConfiguration config,
        ILogger<ShutdownOrchestrator> logger)
    {
        _state = state;
        _lifetime = lifetime;
        _logger = logger;
        _preStopDelay = TimeSpan.FromSeconds(
            int.TryParse(config["SHUTDOWN_PRESTOP_DELAY"], out int d) ? d : DefaultPreStopDelaySeconds);
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _lifetime.ApplicationStopping.Register(() =>
        {
            _state.MarkShuttingDown();
            _logger.LogInformation(
                "Shutdown initiated — pre-stop delay {Delay}s. /ready returning 503.",
                _preStopDelay.TotalSeconds);

            // Block the ApplicationStopping callback for the pre-stop delay.
            // This keeps Kestrel accepting connections while the LB drains.
            // now-ok: the blocking is the mechanism, not an incidental wait — ApplicationStopping
            // is a synchronous callback, and Kestrel begins its drain the moment it returns. The
            // delay must be real elapsed time because the thing being waited for is an external
            // load balancer noticing /ready has gone 503; a substitutable clock has nothing to
            // advance it and would return immediately, dropping in-flight requests.
            Thread.Sleep(_preStopDelay);

            _logger.LogInformation("Pre-stop delay elapsed. Kestrel drain starting.");
        });

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
