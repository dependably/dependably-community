using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// audit_log.source_ip is written by the login and lockout paths but was not projected by any
/// read surface, so a SOC consuming the audit list, the system audit list, or the auth-event
/// feed received login.failure and lockout.triggered with no source address. These pin the
/// column onto all three read paths; the sibling coverage for the activity feed lives in
/// ActivitySourceIpTests.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuditSourceIpTests : IAsyncLifetime
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
    public async Task ListAudit_projects_source_ip_and_leaves_background_rows_null()
    {
        var repo = new AuditRepository(_db);

        await repo.LogAsync("token.created", orgId: "o1", sourceIp: "10.1.2.3");
        await repo.LogAsync("retention.swept", orgId: "o1", sourceIp: null);

        var (items, _, _) = await repo.ListAuditAsync("o1", limit: 50, offset: 0);

        Assert.Equal("10.1.2.3", items.Single(i => i.Action == "token.created").SourceIp);
        Assert.Null(items.Single(i => i.Action == "retention.swept").SourceIp);
    }

    [Fact]
    public async Task ListSystemAudit_projects_source_ip()
    {
        var repo = new AuditRepository(_db);

        await repo.LogSystemAsync("system.settings.updated", orgId: "o1", sourceIp: "198.51.100.9");

        var (items, _) = await repo.ListSystemAuditAsync(limit: 50, offset: 0);

        Assert.Equal("198.51.100.9", Assert.Single(items).SourceIp);
    }

    /// <summary>
    /// The SOC-facing path: the auth-event feed is what forwards login.failure and
    /// lockout.triggered onward, so a null source address here is the difference between an
    /// actionable brute-force signal and an unattributable one.
    /// </summary>
    [Fact]
    public async Task ListAuthEvents_projects_source_ip_for_login_failure_and_lockout()
    {
        var repo = new AuditRepository(_db);

        await repo.LogAsync("login.failure", orgId: "o1", sourceIp: "203.0.113.7");
        await repo.LogAsync("lockout.triggered", orgId: "o1", sourceIp: "203.0.113.7");

        var (items, _) = await repo.ListAuthEventsAsync(
            since: DateTimeOffset.UnixEpoch,
            until: DateTimeOffset.UnixEpoch.AddYears(200),
            orgId: "o1",
            actionFilter: null,
            limit: 50,
            afterCursor: null);

        Assert.Equal(2, items.Count);
        Assert.All(items, i => Assert.Equal("203.0.113.7", i.SourceIp));
    }

    /// <summary>
    /// Mixed partial-failure shape: one HTTP-originated row and one background row in the same
    /// result set. The populated address must survive and the background row must stay null —
    /// neither outcome masking the other, so a regression that hardcodes either value fails.
    /// </summary>
    [Fact]
    public async Task ListAuthEvents_mixed_http_and_background_rows_keep_their_own_source_ip()
    {
        var repo = new AuditRepository(_db);

        await repo.LogAsync("login.failure", orgId: "o1", sourceIp: "203.0.113.7");
        await repo.LogAsync("token.expired", orgId: "o1", sourceIp: null);

        var (items, _) = await repo.ListAuthEventsAsync(
            since: DateTimeOffset.UnixEpoch,
            until: DateTimeOffset.UnixEpoch.AddYears(200),
            orgId: "o1",
            actionFilter: null,
            limit: 50,
            afterCursor: null);

        Assert.Equal("203.0.113.7", items.Single(i => i.Action == "login.failure").SourceIp);
        Assert.Null(items.Single(i => i.Action == "token.expired").SourceIp);
    }
}
