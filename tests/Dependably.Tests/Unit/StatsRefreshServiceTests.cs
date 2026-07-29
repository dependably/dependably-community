using System.Data.Common;
using System.Diagnostics.Metrics;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Infrastructure.Redis;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// Pins the resilience of the per-pass refresh loop: a transient database failure in one pass
/// (e.g. SQLITE_BUSY while a large import holds the single writer) must be logged and swallowed
/// so the background loop survives, not escape ExecuteAsync and stop the whole host. Genuine
/// shutdown cancellation must still propagate for a clean stop.
///
/// Also covers the sweep lease: the pass renews its lock for as long as it runs (so a second
/// replica cannot recompute the same snapshots concurrently), and a stopped pass — shutdown or a
/// lost lease — is recorded as cancelled rather than as a job failure.
/// </summary>
// One test asserts the outcome recorded on dependably.background_job.duration via a MeterListener
// filtered by DependablyMeter.MeterName, so the class runs alone against the process-wide static
// meter. See MeterSensitiveCollection.
[Trait("Category", "Unit")]
[Collection("MeterSensitive")]
public sealed class StatsRefreshServiceTests
{
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    // The sweep-lock name and TTL RunRefreshPassInnerAsync acquires with, mirrored here because
    // the service keeps them private.
    private const string RefreshLockName = "stats-refresh:sweep";
    private static readonly TimeSpan RefreshLockTtl = TimeSpan.FromMinutes(5);

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

    /// <summary>
    /// A stopped pass is not a failed pass. The scope wrapper used to record <c>server_error</c>
    /// for any exception, so a shutdown landing mid-pass persisted a failed job-run row and an
    /// error-status span for what is a clean stop. The scope's default outcome — <c>cancelled</c>
    /// — is what a cancellation must leave in place.
    /// </summary>
    [Fact]
    public async Task RunRefreshPassAsync_MidPassShutdownCancellation_RecordsCancelledNotFailure()
    {
        var outcomes = new List<string>();
        using var listener = JobOutcomeListener("stats-refresh", outcome => outcomes.Add(outcome));

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var service = BuildService(
            new ThrowingMetadataStore(() => new OperationCanceledException(cts.Token)),
            new GrantingLock());

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => service.RunRefreshPassAsync(cts.Token));

        string recorded = Assert.Single(outcomes);
        Assert.Equal("cancelled", recorded);
    }

    /// <summary>
    /// A refresh pass over a large instance can outrun the sweep-lock TTL. While it runs, the lock
    /// must be renewed so a second replica cannot acquire it and recompute the same snapshots
    /// concurrently — the lock is acquired once per pass, so without renewal it lapses under the
    /// running pass.
    /// </summary>
    [Fact]
    public async Task RunRefreshPassAsync_PassOutrunsLockTtl_LeaseRenewed_SecondReplicaRefused()
    {
        await using var store = new TestMetadataStore();
        await new SchemaInitializer(store).InitializeAsync();
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme'), ('o2', 'globex')");
        }

        var locks = new LeasedTestLock(_clock);
        // Open 1 lists the orgs; the pass is inside the per-org work by open 2.
        var slowStore = new LeaseProbeStore(
            store, _clock, locks, RefreshLockName, RefreshLockTtl, probeOnOpen: 2);
        var service = BuildService(slowStore, locks);

        await service.RunRefreshPassAsync(CancellationToken.None);

        Assert.True(locks.ExtendSuccesses >= 4,
            $"expected the pass to renew its lease while running; got {locks.ExtendSuccesses} renewal(s)");
        Assert.True(slowStore.SecondAcquirerRefusedMidPass,
            "a second replica must not be able to acquire the sweep lock while the pass is still running");
        Assert.False(locks.IsHeld(RefreshLockName), "the lease must release the lock when the pass finishes");
    }

    /// <summary>
    /// The pass used to swallow any OperationCanceledException whose cancellation token was not the
    /// caller's own (<c>!ct.IsCancellationRequested</c>) as a proxy for "the sweep lease was lost" —
    /// with no log statement in that branch. An OCE from a genuinely unrelated source (the lease was
    /// never lost, and the caller token was never cancelled) took the same silent path. The pass
    /// must still swallow it (a stopped pass is not fatal), but must now recognize precisely via
    /// <see cref="LeaderLease.LeaseLost"/> that this was NOT a lease abort, and log it rather than
    /// let an unrecognized cancellation vanish.
    /// </summary>
    [Fact]
    public async Task RunRefreshPassAsync_UnrelatedCancellation_NotLeaseAbortOrShutdown_LogsAndDoesNotThrow()
    {
        var warnings = new List<string>();
        var service = BuildService(
            new ThrowingMetadataStore(() => new OperationCanceledException("unrelated cancellation, no token")),
            new GrantingLock(),
            new CapturingLogger(warnings));

        var exception = await Record.ExceptionAsync(() => service.RunRefreshPassAsync(CancellationToken.None));

        Assert.Null(exception);
        Assert.Contains(warnings, w => w.Contains("unrecognized", StringComparison.OrdinalIgnoreCase));
    }

    // Captures rendered messages for log calls at or above Warning, mirroring the pattern used to
    // assert startup-guard warnings elsewhere in the suite.
    private sealed class CapturingLogger(List<string> sink) : ILogger<StatsRefreshService>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => level >= LogLevel.Warning;

        public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? ex,
            Func<TState, Exception?, string> formatter)
        {
            if (level >= LogLevel.Warning)
            {
                sink.Add(formatter(state, ex));
            }
        }
    }

    // Captures the outcome tag recorded on dependably.background_job.duration for one job name.
    private static MeterListener JobOutcomeListener(string jobName, Action<string> onOutcome)
    {
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == DependablyMeter.MeterName
                    && instrument.Name == "dependably.background_job.duration")
                {
                    l.EnableMeasurementEvents(instrument);
                }
            },
        };

        listener.SetMeasurementEventCallback<double>((_, _, tags, _) =>
        {
            string? name = null;
            string? outcome = null;
            foreach (var tag in tags)
            {
                if (tag.Key == "job_name") { name = tag.Value as string; }
                else if (tag.Key == "outcome") { outcome = tag.Value as string; }
            }

            if (name == jobName && outcome is not null)
            {
                onOutcome(outcome);
            }
        });

        listener.Start();
        return listener;
    }

    private StatsRefreshService BuildService(IMetadataStore store, IDistributedLock locks, ILogger<StatsRefreshService>? logger = null)
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
            logger ?? NullLogger<StatsRefreshService>.Instance,
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
