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
        var jwt = new JwtRevocationRepository(_db);
        var samlConfig = new SamlConfigRepository(_db);
        return new RetentionService(_db, _blobs, jwt, samlConfig, cfg, NullLogger<RetentionService>.Instance);
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
        var now = DateTimeOffset.UtcNow;
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
        var now = DateTimeOffset.UtcNow;
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
        var now = DateTimeOffset.UtcNow;
        await SeedEventAsync("recent1", now.AddHours(-1));
        await SeedEventAsync("recent2", now.AddHours(-2));

        var svc = Build();
        await using var conn = await _db.OpenAsync();
        await svc.PruneAuditEventsAsync(conn, default);

        long remaining = await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM audit_event");
        Assert.Equal(2, remaining);
    }
}
