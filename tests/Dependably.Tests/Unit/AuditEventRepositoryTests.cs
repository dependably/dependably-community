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
        var ev = Sample("o1", "package.publish", DateTimeOffset.UtcNow);
        await repo.InsertAsync(ev);

        var list = await repo.ListByTenantAsync("o1", limit: 10);
        Assert.Single(list);
        Assert.Equal(ev.EventId, list[0].EventId);
        Assert.Equal("package.publish", list[0].EventType);
        Assert.Equal("{\"x\":1}", list[0].Payload);
    }

    [Fact]
    public async Task ListByTenant_ScopedToOrg()
    {
        var repo = new AuditEventRepository(_db);
        await repo.InsertAsync(Sample("o1", "a", DateTimeOffset.UtcNow));
        await repo.InsertAsync(Sample("o2", "b", DateTimeOffset.UtcNow));

        var list = await repo.ListByTenantAsync("o1", limit: 10);
        Assert.Single(list);
        Assert.Equal("a", list[0].EventType);
    }

    [Fact]
    public async Task ListByTenant_OrderedDescByOccurredAt()
    {
        var repo = new AuditEventRepository(_db);
        var t = DateTimeOffset.UtcNow;
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
        var ev = Sample("o1", "x", DateTimeOffset.UtcNow);
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
