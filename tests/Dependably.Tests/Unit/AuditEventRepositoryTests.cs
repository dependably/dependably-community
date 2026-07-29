using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class AuditEventRepositoryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o2', 'globex')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static AuditEvent Sample(string orgId, string type, DateTimeOffset at) => new()
    {
        EventId = Guid.NewGuid().ToString("D"),
        SchemaVersion = 1,
        EventType = type,
        OrgId = orgId,
        TenantResolver = "single",
        ActorType = "user",
        ActorId = "u1",
        RequestId = "req-1",
        SourceIp = "127.0.0.1",
        UserAgent = "test",
        Outcome = "accepted",
        Payload = "{\"x\":1}",
        OccurredAt = at
    };

    [Fact]
    public async Task InsertAndList_RoundTrip()
    {
        var repo = new AuditEventRepository(_db);
        var ev = Sample("o1", "package.publish", TestTime.KnownNow);
        await repo.InsertAsync(ev);

        var list = await repo.ListByTenantAsync("o1", limit: 10);
        Assert.Single(list);
        Assert.Equal(ev.EventId, list[0].EventId);
        Assert.Equal("package.publish", list[0].EventType);
        Assert.Equal("{\"x\":1}", list[0].Payload);
    }

    [Fact]
    public async Task InsertAsync_OccurredAt_StoredAsCanonicalUtcMillisecondText()
    {
        // InsertAsync binds OccurredAt explicitly via ToUtcIsoMillis() (not the whole `ev` record
        // through the global DateTimeOffsetHandler default, which is second precision) — this
        // append-only forensic table needs sub-second ordering for events sharing a wall-clock
        // second, the same reason audit_log/activity are millisecond. A +03:00 offset instant
        // must normalize to UTC `Z` text at millisecond precision, matching
        // audit_event.occurred_at's schema DEFAULT.
        var repo = new AuditEventRepository(_db);
        var instant = new DateTimeOffset(2026, 4, 10, 9, 0, 0, 500, TimeSpan.FromHours(3));
        var ev = Sample("o1", "package.publish", instant);
        await repo.InsertAsync(ev);

        await using var conn = await _db.OpenAsync();
        string stored = await conn.QuerySingleAsync<string>(
            "SELECT occurred_at FROM audit_event WHERE event_id = @id", new { id = ev.EventId });

        Assert.Equal("2026-04-10T06:00:00.500Z", stored);
    }

    [Fact]
    public async Task ListByTenant_ScopedToOrg()
    {
        var repo = new AuditEventRepository(_db);
        await repo.InsertAsync(Sample("o1", "a", TestTime.KnownNow));
        await repo.InsertAsync(Sample("o2", "b", TestTime.KnownNow));

        var list = await repo.ListByTenantAsync("o1", limit: 10);
        Assert.Single(list);
        Assert.Equal("a", list[0].EventType);
    }

    [Fact]
    public async Task ListByTenant_OrderedDescByOccurredAt()
    {
        var repo = new AuditEventRepository(_db);
        var t = TestTime.KnownNow;
        await repo.InsertAsync(Sample("o1", "old", t.AddMinutes(-10)));
        await repo.InsertAsync(Sample("o1", "new", t));

        var list = await repo.ListByTenantAsync("o1", limit: 10);
        Assert.Equal(2, list.Count);
        Assert.Equal("new", list[0].EventType);
        Assert.Equal("old", list[1].EventType);
    }

    [Fact]
    public async Task Insert_RejectsInvalidOutcomeViaCheckConstraint()
    {
        var repo = new AuditEventRepository(_db);
        var ev = Sample("o1", "x", TestTime.KnownNow);
        var bad = new AuditEvent
        {
            EventId = ev.EventId,
            SchemaVersion = ev.SchemaVersion,
            EventType = ev.EventType,
            OrgId = ev.OrgId,
            TenantResolver = ev.TenantResolver,
            ActorType = ev.ActorType,
            ActorId = ev.ActorId,
            RequestId = ev.RequestId,
            SourceIp = ev.SourceIp,
            UserAgent = ev.UserAgent,
            Outcome = "maybe",
            Payload = ev.Payload,
            OccurredAt = ev.OccurredAt
        };
        await Assert.ThrowsAnyAsync<Exception>(() => repo.InsertAsync(bad));
    }
}
