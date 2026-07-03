namespace Dependably.Infrastructure;

/// <summary>
/// Hosted service that implements the HA shutdown sequence:
/// 1. Marks /ready as not-ready immediately on ApplicationStopping.
/// 2. Sleeps SHUTDOWN_PRESTOP_DELAY so the ALB can remove this replica from rotation.
/// 3. Returns so the host can drain Kestrel and other services (governed by ShutdownTimeout).
///
/// Environment variables:
///   SHUTDOWN_PRESTOP_DELAY  — seconds to wait before accepting shutdown (default 10)
///   SHUTDOWN_GRACE_PERIOD   — passed to host ShutdownTimeout; max time for in-flight drain (default 30)
/// </summary>
public sealed class ShutdownOrchestrator : IHostedService
{
    // Default pre-stop delay seconds; allows the load balancer to drain this replica.
    private const int DefaultPreStopDelaySeconds = 10;

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
            Thread.Sleep(_preStopDelay);

            _logger.LogInformation("Pre-stop delay elapsed. Kestrel drain starting.");
        });

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
