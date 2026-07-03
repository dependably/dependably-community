using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;

namespace Dependably.Tests.Unit.Observability;

/// <summary>
/// Branch coverage for <see cref="AdvisoryInventoryPoller"/>. Mirrors
/// <see cref="TenantCountPollerTests"/>: the <c>ExecuteAsync</c> path blocks on a 5-second
/// startup delay, so the cancellation-at-startup branch is covered by pre-cancelling the
/// token before <c>StartAsync</c>. The inner poll helper carries the actual logic and is
/// exercised directly to cover the success, non-cancellation error, and cancellation
/// rethrow branches, plus the snapshot-replace semantics of the observable gauge.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AdvisoryInventoryPollerTests : IAsyncLifetime
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

    private static async Task InsertVulnAsync(
        System.Data.Common.DbConnection conn, string id, string ecosystem, string? severity)
    {
        await conn.ExecuteAsync(
            "INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, severity) " +
            "VALUES (@id, @osvId, @ecosystem, @packageName, @severity)",
            new { id, osvId = $"OSV-{id}", ecosystem, packageName = $"pkg-{id}", severity });
    }

    [Fact]
    public async Task PollOnceAsync_GroupsByEcosystemAndSeverity()
    {
        await using var conn = await _db.OpenAsync();
        await InsertVulnAsync(conn, "v1", "npm", "HIGH");
        await InsertVulnAsync(conn, "v2", "npm", "HIGH");
        await InsertVulnAsync(conn, "v3", "npm", "LOW");
        await InsertVulnAsync(conn, "v4", "pypi", "CRITICAL");

        var poller = new AdvisoryInventoryPoller(_db, Config(), NullLogger<AdvisoryInventoryPoller>.Instance);
        await poller.PollOnceAsync(CancellationToken.None);

        var snapshot = DependablyMeter.ReadAdvisoryInventory();
        Assert.Equal(2, snapshot.Single(x => x.Ecosystem == "npm" && x.Severity == "HIGH").Count);
        Assert.Equal(1, snapshot.Single(x => x.Ecosystem == "npm" && x.Severity == "LOW").Count);
        Assert.Equal(1, snapshot.Single(x => x.Ecosystem == "pypi" && x.Severity == "CRITICAL").Count);
        Assert.Equal(3, snapshot.Count);
    }

    [Fact]
    public async Task PollOnceAsync_NullSeverity_ReportedAsUnscored()
    {
        await using var conn = await _db.OpenAsync();
        await InsertVulnAsync(conn, "v1", "maven", null);

        var poller = new AdvisoryInventoryPoller(_db, Config(), NullLogger<AdvisoryInventoryPoller>.Instance);
        await poller.PollOnceAsync(CancellationToken.None);

        var snapshot = DependablyMeter.ReadAdvisoryInventory();
        var (ecosystem, severity, count) = Assert.Single(snapshot, x => x.Ecosystem == "maven");
        Assert.Equal("maven", ecosystem);
        Assert.Equal("unscored", severity);
        Assert.Equal(1, count);
    }

    [Fact]
    public async Task PollOnceAsync_EmptyTable_ProducesEmptySnapshot()
    {
        var poller = new AdvisoryInventoryPoller(_db, Config(), NullLogger<AdvisoryInventoryPoller>.Instance);
        await poller.PollOnceAsync(CancellationToken.None);

        Assert.Empty(DependablyMeter.ReadAdvisoryInventory());
    }

    [Fact]
    public async Task PollOnceAsync_SecondPoll_ReplacesSnapshotRatherThanMerging()
    {
        await using var conn = await _db.OpenAsync();
        await InsertVulnAsync(conn, "v1", "npm", "HIGH");
        await InsertVulnAsync(conn, "v2", "rpm", "MEDIUM");

        var poller = new AdvisoryInventoryPoller(_db, Config(), NullLogger<AdvisoryInventoryPoller>.Instance);
        await poller.PollOnceAsync(CancellationToken.None);

        var firstSnapshot = DependablyMeter.ReadAdvisoryInventory();
        Assert.Equal(2, firstSnapshot.Count);
        Assert.Contains(firstSnapshot, x => x.Ecosystem == "rpm" && x.Severity == "MEDIUM");

        // Remove the rpm group entirely and re-poll — the gauge must drop it, not retain
        // its last observed value.
        await conn.ExecuteAsync("DELETE FROM vulnerabilities WHERE ecosystem = 'rpm'");
        await poller.PollOnceAsync(CancellationToken.None);

        var secondSnapshot = DependablyMeter.ReadAdvisoryInventory();
        Assert.Single(secondSnapshot);
        Assert.DoesNotContain(secondSnapshot, x => x.Ecosystem == "rpm");
        Assert.Contains(secondSnapshot, x => x.Ecosystem == "npm" && x.Severity == "HIGH");
    }

    [Fact]
    public async Task PollOnceAsync_DatabaseFailure_LogsAndSwallows()
    {
        // Substitute store that throws on OpenAsync — the catch block should log a warning
        // and return without rethrowing, so the last-known meter value is retained.
        var failingStore = Substitute.For<IMetadataStore>();
        failingStore.OpenAsync(Arg.Any<CancellationToken>())
            .ThrowsAsync(new InvalidOperationException("simulated DB failure"));
        var logger = Substitute.For<ILogger<AdvisoryInventoryPoller>>();

        var poller = new AdvisoryInventoryPoller(failingStore, Config(), logger);
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
        var poller = new AdvisoryInventoryPoller(_db, Config(), NullLogger<AdvisoryInventoryPoller>.Instance);
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
        var poller = new AdvisoryInventoryPoller(_db, Config(), NullLogger<AdvisoryInventoryPoller>.Instance);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await poller.StartAsync(cts.Token);
        await poller.StopAsync(CancellationToken.None);

        // No exception propagated; service has stopped cleanly.
        Assert.True(poller.ExecuteTask is null || poller.ExecuteTask.IsCompleted);
    }
}
