using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// Pins <see cref="RetentionService.PruneStatsHistoryAsync"/>: the sweep deletes
/// <c>org_stats_history</c> rows older than <c>STATS_HISTORY_RETENTION_DAYS</c> (default 365),
/// honours a configured override, respects the injected <see cref="TimeProvider"/> exactly at the
/// cutoff boundary, and runs cross-tenant in one pass — each org's rows age out independently, so
/// a single sweep can delete one org's old row while leaving another org's recent row untouched
/// (the mixed-outcome shape a fan-out sweep needs pinned, not just an all-or-nothing case).
/// </summary>
[Trait("Category", "Unit")]
public sealed class OrgStatsHistoryRetentionTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme'), ('o2', 'globex')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private RetentionService Build(IConfiguration cfg)
    {
        var jwt = new JwtRevocationRepository(_db, time: _clock);
        var invites = new InviteRepository(_db, _clock);
        var samlConfig = new SamlConfigRepository(_db, _clock);
        var trusted = new TrustedDeviceService(_db, _clock, cfg);
        var blobs = new Dependably.Storage.InMemoryBlobStore();
        return new RetentionService(new RetentionService.Dependencies(
            _db, blobs, jwt, invites, samlConfig, trusted, cfg, new AirGapMode(cfg),
            NullLogger<RetentionService>.Instance, _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock),
            new Dependably.Protocol.OciOrphanBlobDeleter(
                _db, new Dependably.Storage.TieredBlobStorage(blobs, blobs),
                new Dependably.Protocol.OciBlobKeyLock()),
            new Dependably.Infrastructure.Mail.EmailOutboxRepository(_db, _clock),
            new Dependably.Infrastructure.Mail.EmailOutboxPolicy(cfg),
            new OrgStatsHistoryRepository(_db)));
    }

    private async Task SeedRowAsync(string orgId, string day)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO org_stats_history (org_id, day, trend_json, computed_at)
            VALUES (@orgId, @day, '{"totalVulnerabilities":0,"blockedPulls30d":0,"totalDownloads30d":0}', @computedAt)
            """,
            new { orgId, day, computedAt = day + "T00:00:00Z" });
    }

    private async Task<bool> RowExistsAsync(string orgId, string day)
    {
        await using var conn = await _db.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM org_stats_history WHERE org_id = @orgId AND day = @day",
            new { orgId, day });
        return count > 0;
    }

    // TestTime.KnownNow is 2026-06-15T12:00:00Z. Seed offsets sit far from the 365-day default
    // cutoff (400 days back is well past it; 10 days back is well inside it) rather than exactly
    // at the boundary, so a leap-year shift in the cutoff date cannot flip either assertion.
    [Fact]
    public async Task PruneStatsHistoryAsync_DefaultBound_DeletesOlderThan365Days_KeepsNewer()
    {
        await SeedRowAsync("o1", "2025-05-11"); // ~400 days before KnownNow — past the default.
        await SeedRowAsync("o1", "2026-06-05"); // ~10 days before KnownNow — inside the default.

        var cfg = new ConfigurationBuilder().Build();
        await Build(cfg).PruneStatsHistoryAsync(CancellationToken.None);

        Assert.False(await RowExistsAsync("o1", "2025-05-11"));
        Assert.True(await RowExistsAsync("o1", "2026-06-05"));
    }

    [Fact]
    public async Task PruneStatsHistoryAsync_ConfiguredOverride_Honoured()
    {
        // A 30-day override must delete a row 60 days old, which the 365-day default would keep —
        // proving the sweep reads STATS_HISTORY_RETENTION_DAYS rather than the hardcoded default.
        await SeedRowAsync("o1", "2026-04-16"); // 60 days before KnownNow.

        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["STATS_HISTORY_RETENTION_DAYS"] = "30" })
            .Build();
        await Build(cfg).PruneStatsHistoryAsync(CancellationToken.None);

        Assert.False(await RowExistsAsync("o1", "2026-04-16"));
    }

    [Fact]
    public async Task PruneStatsHistoryAsync_CrossTenant_OneOrgsOldRowDeleted_AnotherOrgsRecentRowSurvives_SamePass()
    {
        await SeedRowAsync("o1", "2025-05-11"); // o1: past the default bound.
        await SeedRowAsync("o2", "2026-06-05"); // o2: inside the default bound.

        var cfg = new ConfigurationBuilder().Build();
        await Build(cfg).PruneStatsHistoryAsync(CancellationToken.None);

        Assert.False(await RowExistsAsync("o1", "2025-05-11"));
        Assert.True(await RowExistsAsync("o2", "2026-06-05"));
    }
}
