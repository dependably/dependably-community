using System.Data.Common;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// Pins the resilience of the per-pass refresh loop: a transient database failure in one pass
/// (e.g. SQLITE_BUSY while a large import holds the single writer) must be logged and swallowed
/// so the background loop survives, not escape ExecuteAsync and stop the whole host. Genuine
/// shutdown cancellation must still propagate for a clean stop.
/// </summary>
[Trait("Category", "Unit")]
public sealed class StatsRefreshServiceTests
{
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    [Fact]
    public async Task RunRefreshPassAsync_TransientDbFailureListingOrgs_DoesNotThrow()
    {
        // ListActiveOrgIdsAsync opens a connection and runs a bare Dapper query; a transient DB
        // error there previously rethrew out of the pass and — via ExecuteAsync's only catch being
        // OperationCanceledException — escaped and stopped the host under BackgroundService's
        // default StopHost behavior. The pass must now log-and-continue instead.
        var service = BuildService(
            new ThrowingMetadataStore(() => new InvalidOperationException("SQLITE_BUSY: database is locked")),
            new InProcessDistributedLock(_clock));

        // The transient failure must be logged and swallowed, not escape the pass.
        var exception = await Record.ExceptionAsync(() => service.RunRefreshPassAsync(CancellationToken.None));
        Assert.Null(exception);
    }

    [Fact]
    public async Task RunRefreshPassAsync_MidPassShutdownCancellation_Propagates()
    {
        // Once the sweep lock is held, a cancellation that surfaces mid-pass (here from the first
        // org-listing query) must propagate as OperationCanceledException so ExecuteAsync's
        // normal-shutdown catch handles it — rather than being logged as a spurious pass failure.
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var service = BuildService(
            new ThrowingMetadataStore(() => new OperationCanceledException(cts.Token)),
            new GrantingLock());

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => service.RunRefreshPassAsync(cts.Token));
    }

    private StatsRefreshService BuildService(IMetadataStore store, IDistributedLock locks)
    {
        var config = new ConfigurationBuilder().Build();
        var snapshots = new StatsSnapshotRepository(store);
        var analytics = new PackageAnalyticsRepository(store);
        return new StatsRefreshService(
            snapshots,
            analytics,
            config,
            new AirGapMode(config),
            locks,
            NullLogger<StatsRefreshService>.Instance,
            _clock);
    }

    /// <summary>
    /// Metadata store whose <see cref="OpenAsync"/> always throws, simulating a transient DB
    /// failure (busy writer, connection blip) at the first query of a refresh pass.
    /// </summary>
    private sealed class ThrowingMetadataStore : IMetadataStore
    {
        private readonly Func<Exception> _factory;

        public ThrowingMetadataStore(Func<Exception> factory) => _factory = factory;

        public DbProvider Provider => DbProvider.Sqlite;

        public Task<DbConnection> OpenAsync(CancellationToken ct = default) => throw _factory();
    }

    /// <summary>
    /// Distributed lock that always grants (regardless of cancellation), so a test can drive the
    /// pass past the sweep-lock gate and exercise the query path under a cancelled token.
    /// </summary>
    private sealed class GrantingLock : IDistributedLock
    {
        public Task<ILockHandle?> TryAcquireAsync(string name, TimeSpan ttl, CancellationToken ct = default)
            => Task.FromResult<ILockHandle?>(new NoopHandle(name));

        public Task<ILockHandle> AcquireAsync(
            string name, TimeSpan ttl, TimeSpan wait, TimeSpan retryInterval, CancellationToken ct = default)
            => Task.FromResult<ILockHandle>(new NoopHandle(name));

        private sealed class NoopHandle : ILockHandle
        {
            public NoopHandle(string name) => Name = name;

            public string Name { get; }
            public DateTimeOffset AcquiredAt => default;

            public Task<bool> ExtendAsync(TimeSpan additional, CancellationToken ct = default)
                => Task.FromResult(true);

            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        }
    }
}
