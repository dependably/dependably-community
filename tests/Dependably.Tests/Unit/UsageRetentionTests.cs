using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Usage;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// <see cref="RetentionService"/>'s fixed, unconditional horizons for usage_events (396 days) and
/// usage_hourly (425 days) — a billing input bounded the same way for every org, never by the
/// per-org activity_retention_days knob that governs the (unrelated) activity table.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UsageRetentionTests : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 9, 24, 3, 0, 0, TimeSpan.Zero);

    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen(Now);
    private UsageEventRepository _events = null!;
    private UsageRollupRepository _rollups = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug, status) VALUES ('o1', 'acme', 'active')");
        // A tenant-controlled activity window of just 1 day — proving usage_events/usage_hourly
        // retention is NOT driven by this column.
        await conn.ExecuteAsync("INSERT INTO org_settings (org_id, activity_retention_days) VALUES ('o1', 1)");
        _events = new UsageEventRepository(_db);
        _rollups = new UsageRollupRepository(_db);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private RetentionService Build()
    {
        var cfg = new ConfigurationBuilder().Build();
        var jwt = new JwtRevocationRepository(_db, time: _clock);
        var invites = new InviteRepository(_db, _clock);
        var samlConfig = new SamlConfigRepository(_db, _clock);
        return new RetentionService(new RetentionService.Dependencies(
            _db, new TieredBlobStorage(_blobs, _blobs), jwt, invites, samlConfig,
            new TrustedDeviceService(_db, _clock, cfg), cfg, new AirGapMode(cfg),
            NullLogger<RetentionService>.Instance, _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock),
            new Dependably.Protocol.OciOrphanBlobDeleter(
                _db, new Dependably.Storage.TieredBlobStorage(_blobs, _blobs),
                new Dependably.Protocol.OciBlobKeyLock()),
            new Dependably.Infrastructure.Mail.EmailOutboxRepository(_db, _clock),
            new Dependably.Infrastructure.Mail.EmailOutboxPolicy(cfg),
            new OrgStatsHistoryRepository(_db),
            new BackgroundJobRunRepository(_db),
            _events,
            _rollups));
    }

    [Fact]
    public async Task Usage_events_older_than_396_days_are_deleted_and_the_org_is_1_day_activity_window_is_ignored()
    {
        await _events.InsertBatchAsync(
        [
            UsageEvent.Create(Guid.NewGuid(), "o1", UsageMeters.EgressBytes, UsageDelivery.Streamed, 1, "npm", null,
                Now.AddDays(-400)), // past the 396-day horizon
            UsageEvent.Create(Guid.NewGuid(), "o1", UsageMeters.EgressBytes, UsageDelivery.Streamed, 2, "npm", null,
                Now.AddDays(-5)),   // 5 days old — would be gone under a 1-day activity window, but
                                    // usage_events is not governed by activity_retention_days.
        ]);

        await Build().PruneUsageEventsAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        int remaining = await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM usage_events");
        Assert.Equal(1, remaining);
        long survivingQuantity = await conn.ExecuteScalarAsync<long>("SELECT quantity FROM usage_events");
        Assert.Equal(2L, survivingQuantity);
    }

    [Fact]
    public async Task Usage_events_at_exactly_the_horizon_survive_and_the_pass_is_idempotent()
    {
        await _events.InsertBatchAsync(
        [
            UsageEvent.Create(Guid.NewGuid(), "o1", UsageMeters.EgressBytes, UsageDelivery.Streamed, 1, "npm", null,
                Now.AddDays(-395)),
        ]);

        var svc = Build();
        await svc.PruneUsageEventsAsync(CancellationToken.None);
        await svc.PruneUsageEventsAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM usage_events"));
    }

    [Fact]
    public async Task Usage_hourly_older_than_425_days_is_deleted_and_the_org_is_1_day_activity_window_is_ignored()
    {
        var old = Now.AddDays(-500);
        var recent = Now.AddDays(-10);
        await _events.InsertBatchAsync(
        [
            UsageEvent.Create(Guid.NewGuid(), "o1", UsageMeters.EgressBytes, UsageDelivery.Streamed, 1, "npm", null, old),
            UsageEvent.Create(Guid.NewGuid(), "o1", UsageMeters.EgressBytes, UsageDelivery.Streamed, 2, "npm", null, recent),
        ]);
        await _rollups.RecomputeHourlyAsync(old, old.AddHours(1), Now);
        await _rollups.RecomputeHourlyAsync(recent, recent.AddHours(1), Now);

        await Build().PruneUsageHourlyAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        int remaining = await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM usage_hourly");
        Assert.Equal(1, remaining);
    }
}
