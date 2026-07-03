using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class AuditEventReaperTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private RetentionService Build(string? retentionDays = null)
    {
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["AUDIT_EVENT_RETENTION_DAYS"] = retentionDays,
            })
            .Build();
        var clock = TestTime.Frozen();
        var jwt = new JwtRevocationRepository(_db, time: clock);
        var invites = new InviteRepository(_db, clock);
        var samlConfig = new SamlConfigRepository(_db, clock);
        return new RetentionService(new RetentionService.Dependencies(_db, _blobs, jwt, invites, samlConfig, cfg, new AirGapMode(cfg), NullLogger<RetentionService>.Instance, clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(clock)));
    }

    private async Task SeedEventAsync(string id, DateTimeOffset occurredAt)
    {
        var repo = new AuditEventRepository(_db);
        await repo.InsertAsync(new AuditEvent
        {
            EventId = id,
            SchemaVersion = 1,
            EventType = "test.event",
            OrgId = "o1",
            TenantResolver = "single",
            ActorType = "user",
            ActorId = "u1",
            Outcome = "accepted",
            Payload = "{}",
            OccurredAt = occurredAt,
        });
    }

    [Fact]
    public async Task PrunePastRetentionWindow_DeletesOldRowsOnly()
    {
        // Seeds and the reaper's cutoff both derive from the same frozen instant, so the
        // -366/-364 margins around the 365-day window are exact regardless of calendar.
        var now = TestTime.KnownNow;
        await SeedEventAsync("old1", now.AddDays(-400));
        await SeedEventAsync("old2", now.AddDays(-366));
        await SeedEventAsync("borderline", now.AddDays(-364));   // inside default 365-day window
        await SeedEventAsync("recent", now.AddDays(-1));

        var svc = Build();
        await using var conn = await _db.OpenAsync();
        await svc.PruneAuditEventsAsync(conn, default);

        var remaining = (await conn.QueryAsync<string>(
            "SELECT event_id FROM audit_event ORDER BY occurred_at"))
            .ToList();
        Assert.Equal(["borderline", "recent"], remaining);
    }

    [Fact]
    public async Task ConfigurableRetentionWindow_HonoursOverride()
    {
        var now = TestTime.KnownNow;
        await SeedEventAsync("five-days-old", now.AddDays(-5));
        await SeedEventAsync("two-days-old", now.AddDays(-2));

        var svc = Build(retentionDays: "3");   // window of 3 days; 5-day-old gets pruned
        await using var conn = await _db.OpenAsync();
        await svc.PruneAuditEventsAsync(conn, default);

        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_event WHERE event_id = 'five-days-old'");
        Assert.Equal(0, count);

        long twoDayCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_event WHERE event_id = 'two-days-old'");
        Assert.Equal(1, twoDayCount);
    }

    [Fact]
    public async Task NothingPastWindow_NoOp()
    {
        var now = TestTime.KnownNow;
        await SeedEventAsync("recent1", now.AddHours(-1));
        await SeedEventAsync("recent2", now.AddHours(-2));

        var svc = Build();
        await using var conn = await _db.OpenAsync();
        await svc.PruneAuditEventsAsync(conn, default);

        long remaining = await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM audit_event");
        Assert.Equal(2, remaining);
    }

    // Mixed partial-failure shape for a batch sweep: a backlog that spans multiple
    // AuditEventPruneBatchSize-sized chunks, plus one row that must survive every chunk. Pins
    // the batching loop's continuation condition — an off-by-one there would silently strand
    // rows in the tail chunk instead of draining the whole backlog.
    [Fact]
    public async Task PrunePastRetentionWindow_BacklogSpanningMultipleChunks_DeletesEveryStaleRow()
    {
        var now = TestTime.KnownNow;
        string oldCutoff = now.AddDays(-400).ToString("yyyy-MM-ddTHH:mm:ssZ");
        string recentCutoff = now.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ");

        // Spans two full chunks plus a partial tail chunk (batch size + a fraction of it).
        int staleRowCount = RetentionService.AuditEventPruneBatchSize + RetentionService.AuditEventPruneBatchSize / 2;

        await using (var conn = await _db.OpenAsync())
        {
            // Bulk-generate the stale backlog in one statement (a recursive CTE) rather than
            // one-connection-per-row inserts, which would make a 7500-row seed prohibitively slow.
            await conn.ExecuteAsync(
                """
                WITH RECURSIVE seq(n) AS (
                    SELECT 1
                    UNION ALL
                    SELECT n + 1 FROM seq WHERE n < @count
                )
                INSERT INTO audit_event (
                    event_id, schema_version, event_type, org_id, tenant_resolver,
                    actor_type, actor_id, outcome, payload, occurred_at)
                SELECT 'stale-' || n, 1, 'test.event', 'o1', 'single', 'user', 'u1',
                       'accepted', '{}', @oldCutoff
                FROM seq
                """,
                new { count = staleRowCount, oldCutoff });

            await conn.ExecuteAsync(
                """
                INSERT INTO audit_event (
                    event_id, schema_version, event_type, org_id, tenant_resolver,
                    actor_type, actor_id, outcome, payload, occurred_at)
                VALUES ('recent', 1, 'test.event', 'o1', 'single', 'user', 'u1',
                        'accepted', '{}', @recentCutoff)
                """,
                new { recentCutoff });
        }

        var svc = Build();
        await using var conn2 = await _db.OpenAsync();
        await svc.PruneAuditEventsAsync(conn2, default);

        var remaining = (await conn2.QueryAsync<string>("SELECT event_id FROM audit_event")).ToList();
        Assert.Equal(["recent"], remaining);
    }
}
