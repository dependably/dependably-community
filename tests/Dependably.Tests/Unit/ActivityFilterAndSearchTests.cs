using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Covers the activity-feed filter semantics surfaced on the Audit page: the 'blocked' token
/// is a group selector matching the whole block-gate family (so it agrees with the dashboard's
/// 'blocked%' tally), specific 'blocked_&lt;gate&gt;' values stay exact, and the free-text
/// search spans purl / event_type / detail / actor across both list and total.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ActivityFilterAndSearchTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        await conn.ExecuteAsync(
            "INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES ('u1', 'o1', 'dev@acme.test', 'x', 'member')");

        var repo = new AuditRepository(_db);
        // One bare legacy 'blocked' plus several gate variants, and an unrelated event.
        await repo.LogActivityAsync("o1", "npm", "pkg:npm/a@1", "blocked");
        await repo.LogActivityAsync("o1", "npm", "pkg:npm/b@1", "blocked_release_age");
        await repo.LogActivityAsync("o1", "npm", "pkg:npm/c@1", "blocked_malicious");
        await repo.LogActivityAsync("o1", "npm", "pkg:npm/d@1", "blocked_kev");
        await repo.LogActivityAsync("o1", "npm", "pkg:npm/e@1", "blocked_manual");
        await repo.LogActivityAsync("o1", "npm", "pkg:npm/left-pad@1", "download",
            actorId: "u1", detail: "served from cache");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task Blocked_token_matches_the_whole_block_gate_family()
    {
        var repo = new AuditRepository(_db);

        var (items, total) = await repo.ListActivityAsync("o1", limit: 50, offset: 0, eventType: "blocked");

        // bare 'blocked' + the four gate variants = 5; the 'download' row is excluded.
        Assert.Equal(5, total);
        Assert.Equal(5, items.Count);
        Assert.All(items, i => Assert.StartsWith("blocked", i.EventType));
    }

    [Fact]
    public async Task Specific_gate_token_stays_an_exact_match()
    {
        var repo = new AuditRepository(_db);

        var (items, total) = await repo.ListActivityAsync("o1", limit: 50, offset: 0, eventType: "blocked_malicious");

        Assert.Equal(1, total);
        Assert.Equal("blocked_malicious", Assert.Single(items).EventType);
    }

    [Fact]
    public async Task Search_spans_purl_event_and_detail_with_matching_total()
    {
        var repo = new AuditRepository(_db);

        // Matches the 'download' row by detail substring and nothing else.
        var (byDetail, detailTotal) = await repo.ListActivityAsync("o1", limit: 50, offset: 0, search: "from cache");
        Assert.Equal(1, detailTotal);
        Assert.Equal("download", Assert.Single(byDetail).EventType);

        // Matches by purl substring (only the 'b' package).
        var (byPurl, purlTotal) = await repo.ListActivityAsync("o1", limit: 50, offset: 0, search: "npm/b@");
        Assert.Equal(1, purlTotal);
        Assert.Equal("blocked_release_age", Assert.Single(byPurl).EventType);

        // Matches by actor email — total must include the joined-actor row (no paging drift).
        var (byActor, actorTotal) = await repo.ListActivityAsync("o1", limit: 50, offset: 0, search: "dev@acme");
        Assert.Equal(1, actorTotal);
        Assert.Single(byActor);
    }

    [Fact]
    public async Task Filter_and_search_combine()
    {
        var repo = new AuditRepository(_db);

        // 'blocked' group narrowed by a purl search that only the malicious row satisfies.
        var (items, total) = await repo.ListActivityAsync(
            "o1", limit: 50, offset: 0, eventType: "blocked", search: "npm/c@");

        Assert.Equal(1, total);
        Assert.Equal("blocked_malicious", Assert.Single(items).EventType);
    }
}
