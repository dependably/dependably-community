using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Covers the paged audit/activity total strategy: totals stop probing at
/// <see cref="AuditRepository.ListTotalCap"/> and report <c>TotalCapped</c> instead of
/// counting an org's entire history (the unbounded count is what made the audit page time
/// out on large instances), rows past the cap remain pageable, and callers that discard
/// the total (CSV export) can skip the count entirely.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuditListTotalCapTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    /// <summary>
    /// Bulk-inserts <paramref name="count"/> activity rows in one statement. Timestamps
    /// step by one second so ordering is deterministic; detail carries a fixed marker so
    /// search tests can match every generated row.
    /// </summary>
    private async Task SeedActivityRowsAsync(int count)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO activity (id, org_id, ecosystem, purl, event_type, detail, created_at)
            WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < @count)
            SELECT 'act' || n, 'o1', 'npm', 'pkg:npm/bulk-package@1.0.' || n, 'download',
                   'bulk seeded row',
                   strftime('%Y-%m-%dT%H:%M:%f', 1700000000 + n, 'unixepoch') || 'Z'
            FROM seq
            """,
            new { count });
    }

    private async Task SeedAuditRowsAsync(int count)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO audit_log (id, scope, org_id, action, detail, created_at)
            WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < @count)
            SELECT 'aud' || n, 'tenant', 'o1', 'org_settings_updated', 'bulk seeded row',
                   strftime('%Y-%m-%dT%H:%M:%f', 1700000000 + n, 'unixepoch') || 'Z'
            FROM seq
            """,
            new { count });
    }

    [Fact]
    public async Task Activity_total_past_the_cap_is_capped_and_flagged()
    {
        await SeedActivityRowsAsync(AuditRepository.ListTotalCap + 5);
        var repo = new AuditRepository(_db);

        var (items, total, capped) = await repo.ListActivityAsync("o1", limit: 50, offset: 0);

        Assert.Equal(AuditRepository.ListTotalCap, total);
        Assert.True(capped);
        Assert.Equal(50, items.Count);
    }

    [Fact]
    public async Task Activity_rows_past_the_cap_stay_pageable()
    {
        await SeedActivityRowsAsync(AuditRepository.ListTotalCap + 5);
        var repo = new AuditRepository(_db);

        // The cap bounds the reported total only — the list query itself is uncapped, so a
        // client paging past the cap still gets rows.
        var (items, _, _) = await repo.ListActivityAsync("o1", limit: 50, offset: AuditRepository.ListTotalCap);

        Assert.Equal(5, items.Count);
    }

    [Fact]
    public async Task Activity_total_below_the_cap_stays_exact_and_unflagged()
    {
        await SeedActivityRowsAsync(7);
        var repo = new AuditRepository(_db);

        var (items, total, capped) = await repo.ListActivityAsync("o1", limit: 50, offset: 0);

        Assert.Equal(7, total);
        Assert.False(capped);
        Assert.Equal(7, items.Count);
    }

    [Fact]
    public async Task Activity_search_total_is_capped_too()
    {
        await SeedActivityRowsAsync(AuditRepository.ListTotalCap + 5);
        var repo = new AuditRepository(_db);

        // Every seeded row matches on detail, so the joined search count would be cap+5
        // uncapped. It must stop at the cap like the join-free count does.
        var (items, total, capped) = await repo.ListActivityAsync(
            "o1", limit: 50, offset: 0, search: "bulk seeded");

        Assert.Equal(AuditRepository.ListTotalCap, total);
        Assert.True(capped);
        Assert.Equal(50, items.Count);
    }

    [Fact]
    public async Task Activity_includeTotal_false_skips_the_count_but_returns_rows()
    {
        await SeedActivityRowsAsync(7);
        var repo = new AuditRepository(_db);

        var (items, total, capped) = await repo.ListActivityAsync(
            "o1", limit: 50, offset: 0, includeTotal: false);

        Assert.Equal(7, items.Count);
        Assert.Equal(0, total);
        Assert.False(capped);
    }

    [Fact]
    public async Task Audit_total_past_the_cap_is_capped_and_flagged()
    {
        await SeedAuditRowsAsync(AuditRepository.ListTotalCap + 5);
        var repo = new AuditRepository(_db);

        var (items, total, capped) = await repo.ListAuditAsync("o1", limit: 50, offset: 0);

        Assert.Equal(AuditRepository.ListTotalCap, total);
        Assert.True(capped);
        Assert.Equal(50, items.Count);
    }

    [Fact]
    public async Task Audit_total_below_the_cap_stays_exact_and_unflagged()
    {
        await SeedAuditRowsAsync(3);
        var repo = new AuditRepository(_db);

        var (items, total, capped) = await repo.ListAuditAsync("o1", limit: 50, offset: 0);

        Assert.Equal(3, total);
        Assert.False(capped);
        Assert.Equal(3, items.Count);
    }

    [Fact]
    public async Task Audit_includeTotal_false_skips_the_count_but_returns_rows()
    {
        await SeedAuditRowsAsync(3);
        var repo = new AuditRepository(_db);

        var (items, total, capped) = await repo.ListAuditAsync(
            "o1", limit: 50, offset: 0, includeTotal: false);

        Assert.Equal(3, items.Count);
        Assert.Equal(0, total);
        Assert.False(capped);
    }
}
