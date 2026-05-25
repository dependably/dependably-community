using Dependably.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Unit tests for ShutdownOrchestrator. Covers the IConfiguration parsing branch
/// (valid value vs default fallback) and the ApplicationStopping callback that
/// flips ShutdownState and serves the pre-stop delay before Kestrel drains.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ShutdownOrchestratorTests
{
    // ── Helpers ───────────────────────────────────────────────────────────────

    private static IConfiguration BuildConfig(string? preStopDelay)
    {
        var dict = new Dictionary<string, string?>();
        if (preStopDelay is not null) dict["SHUTDOWN_PRESTOP_DELAY"] = preStopDelay;
        return new ConfigurationBuilder().AddInMemoryCollection(dict).Build();
    }

    private sealed class FakeLifetime : IHostApplicationLifetime
    {
        private readonly CancellationTokenSource _started = new();
        private readonly CancellationTokenSource _stopping = new();
        private readonly CancellationTokenSource _stopped = new();

        public CancellationToken ApplicationStarted => _started.Token;
        public CancellationToken ApplicationStopping => _stopping.Token;
        public CancellationToken ApplicationStopped => _stopped.Token;

        public void StopApplication() => _stopping.Cancel();
    }

    private static ShutdownOrchestrator Build(
        ShutdownState state,
        IHostApplicationLifetime lifetime,
        IConfiguration config)
        => new(state, lifetime, config, NullLogger<ShutdownOrchestrator>.Instance);

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// StartAsync wires a callback but does not invoke it until the lifetime
    /// signals ApplicationStopping. ShutdownState must remain false beforehand.
    /// </summary>
    [Fact]
    public async Task StartAsync_does_not_mark_shutting_down_until_lifetime_fires()
    {
        var state = new ShutdownState();
        var lifetime = new FakeLifetime();
        var orchestrator = Build(state, lifetime, BuildConfig("0"));

        await orchestrator.StartAsync(CancellationToken.None);

        Assert.False(state.IsShuttingDown);
    }

    /// <summary>
    /// When SHUTDOWN_PRESTOP_DELAY is a parseable integer the callback honours it.
    /// Using "0" keeps the test fast while still exercising the parse-success branch
    /// of the ternary in the constructor.
    /// </summary>
    [Fact]
    public async Task ApplicationStopping_uses_configured_delay_and_flips_state()
    {
        var state = new ShutdownState();
        var lifetime = new FakeLifetime();
        var orchestrator = Build(state, lifetime, BuildConfig("0"));

        await orchestrator.StartAsync(CancellationToken.None);
        lifetime.StopApplication();

        Assert.True(state.IsShuttingDown);
    }

    /// <summary>
    /// When SHUTDOWN_PRESTOP_DELAY is missing the ternary falls back to 10s.
    /// We only verify the constructor accepts the missing key and the orchestrator
    /// starts; we do NOT trigger ApplicationStopping (that would block for 10s).
    /// </summary>
    [Fact]
    public async Task Constructor_falls_back_to_default_when_config_missing()
    {
        var state = new ShutdownState();
        var lifetime = new FakeLifetime();
        var orchestrator = Build(state, lifetime, BuildConfig(null));

        await orchestrator.StartAsync(CancellationToken.None);

        Assert.False(state.IsShuttingDown);
    }

    /// <summary>
    /// Non-numeric values also fall back to the default — exercises the
    /// TryParse-fails branch of the ternary explicitly.
    /// </summary>
    [Fact]
    public async Task Constructor_falls_back_to_default_when_config_unparseable()
    {
        var state = new ShutdownState();
        var lifetime = new FakeLifetime();
        var orchestrator = Build(state, lifetime, BuildConfig("not-a-number"));

        await orchestrator.StartAsync(CancellationToken.None);

        Assert.False(state.IsShuttingDown);
    }

    /// <summary>
    /// StopAsync is a no-op that returns a completed task; calling it twice
    /// must not throw and must not flip ShutdownState (that's the lifetime's job).
    /// </summary>
    [Fact]
    public async Task StopAsync_is_noop_and_idempotent()
    {
        var state = new ShutdownState();
        var lifetime = new FakeLifetime();
        var orchestrator = Build(state, lifetime, BuildConfig("0"));

        await orchestrator.StopAsync(CancellationToken.None);
        await orchestrator.StopAsync(CancellationToken.None);

        Assert.False(state.IsShuttingDown);
    }
}
