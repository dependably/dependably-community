using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Xunit;

namespace Dependably.Tests.Unit.Observability;

/// <summary>
/// Branch coverage for <see cref="TenantCountPoller"/>. The <c>ExecuteAsync</c> path
/// blocks on a 5-second startup delay, so the cancellation-at-startup branch is
/// covered by pre-cancelling the token before <c>StartAsync</c>. The inner poll
/// helper carries the actual logic and is exercised directly to cover the
/// success, non-cancellation error, and cancellation rethrow branches.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TenantCountPollerTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static IConfiguration Config(IDictionary<string, string?>? values = null) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values ?? new Dictionary<string, string?>())
            .Build();

    [Fact]
    public async Task PollOnceAsync_RecordsActiveTenantCount()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o2', 'beta')");
        // Soft-deleted org — must be excluded by the WHERE deleted_at IS NULL clause.
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug, deleted_at) VALUES ('o3', 'old', CURRENT_TIMESTAMP)");

        var poller = new TenantCountPoller(_db, Config(), NullLogger<TenantCountPoller>.Instance);
        await poller.PollOnceAsync(CancellationToken.None);

        Assert.Equal(2L, DependablyMeter.ReadTenantCount());
    }

    [Fact]
    public async Task PollOnceAsync_DatabaseFailure_LogsAndSwallows()
    {
        // Substitute store that throws on OpenAsync — the catch block should log a warning
        // and return without rethrowing, so the last-known meter value is retained.
        var failingStore = Substitute.For<IMetadataStore>();
        failingStore.OpenAsync(Arg.Any<CancellationToken>())
            .ThrowsAsync(new InvalidOperationException("simulated DB failure"));
        var logger = Substitute.For<ILogger<TenantCountPoller>>();

        var poller = new TenantCountPoller(failingStore, Config(), logger);
        await poller.PollOnceAsync(CancellationToken.None);

        logger.Received(1).Log(
            LogLevel.Warning,
            Arg.Any<EventId>(),
            Arg.Any<object>(),
            Arg.Any<Exception>(),
            Arg.Any<Func<object, Exception?, string>>());
    }

    [Fact]
    public async Task PollOnceAsync_Cancelled_Rethrows()
    {
        // OperationCanceledException must propagate so the ExecuteAsync loop can exit cleanly
        // rather than being swallowed by the generic Exception catch.
        var poller = new TenantCountPoller(_db, Config(), NullLogger<TenantCountPoller>.Instance);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => poller.PollOnceAsync(cts.Token));
    }

    [Fact]
    public async Task ExecuteAsync_CancelledDuringStartupDelay_ReturnsImmediately()
    {
        // Pre-cancelling the stopping token makes the initial Task.Delay throw at the start,
        // exercising the `catch (OperationCanceledException) { return; }` branch without
        // having to wait through the full 5-second startup wait.
        var poller = new TenantCountPoller(_db, Config(), NullLogger<TenantCountPoller>.Instance);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await poller.StartAsync(cts.Token);
        await poller.StopAsync(CancellationToken.None);

        // No exception propagated; service has stopped cleanly.
        Assert.True(poller.ExecuteTask is null || poller.ExecuteTask.IsCompleted);
    }
}
