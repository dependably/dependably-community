using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class ActivitySourceIpTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task LogActivity_persists_source_ip_and_round_trips_through_list()
    {
        var repo = new AuditRepository(_db);

        await repo.LogActivityAsync("o1", "npm", "pkg:npm/left-pad@1.0.0", "download",
            actorId: null, detail: null, sourceIp: "10.1.2.3");
        await repo.LogActivityAsync("o1", "auth", null, "login.failure",
            actorId: null, detail: null /* background path */, sourceIp: null);

        var (items, total) = await repo.ListActivityAsync("o1", limit: 50, offset: 0);

        Assert.Equal(2, total);
        var download = items.Single(i => i.EventType == "download");
        var login = items.Single(i => i.EventType == "login.failure");
        Assert.Equal("10.1.2.3", download.SourceIp);
        Assert.Null(login.SourceIp);
    }
}
