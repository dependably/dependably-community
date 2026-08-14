using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Covers the search-scan bound on the paged audit/activity lists. The search predicates are
/// leading-wildcard <c>LIKE</c>s across six columns, which no index can serve, so an unbounded
/// search reads every row in the filtered window — on a large instance that is what turned the
/// debounced search box into a stream of gateway timeouts. A search is therefore bounded to the
/// newest <see cref="AuditRepository.SearchScanCap"/> rows.
/// <para>
/// The bound is what these tests pin: matches older than the scan window are not returned, the
/// count and the list agree over the one window (no paging drift), small windows keep exact
/// unflagged totals, and the CSV export is bounded on the same terms — one <c>read:audit</c>
/// holder must not be able to re-issue a full-history scan at will. A CSV export with no search
/// term stays unbounded, which is what keeps a complete compliance export available.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuditSearchScanCapTests : IAsyncLifetime
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
    /// Seeds <paramref name="filler"/> activity rows that do NOT match the needle, then one
    /// older row that does. Timestamps ascend with n, so the filler is strictly newer than the
    /// needle row and pushes it past the scan window once filler exceeds the cap.
    /// </summary>
    private async Task SeedActivityWithOldNeedleAsync(int filler)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO activity (id, org_id, ecosystem, purl, event_type, detail, created_at)
            VALUES ('act-needle', 'o1', 'npm', 'pkg:npm/needle-package@1.0.0', 'download',
                    'the needle', strftime('%Y-%m-%dT%H:%M:%f', 1700000000, 'unixepoch') || 'Z')
            """);
        await conn.ExecuteAsync(
            """
            INSERT INTO activity (id, org_id, ecosystem, purl, event_type, detail, created_at)
            WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < @filler)
            SELECT 'act' || n, 'o1', 'npm', 'pkg:npm/filler-package@1.0.' || n, 'download',
                   'filler row',
                   strftime('%Y-%m-%dT%H:%M:%f', 1700000000 + n, 'unixepoch') || 'Z'
            FROM seq
            """,
            new { filler });
    }

    private async Task SeedAuditWithOldNeedleAsync(int filler)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO audit_log (id, scope, org_id, action, detail, created_at)
            VALUES ('aud-needle', 'tenant', 'o1', 'org_settings_updated', 'the needle',
                    strftime('%Y-%m-%dT%H:%M:%f', 1700000000, 'unixepoch') || 'Z')
            """);
        await conn.ExecuteAsync(
            """
            INSERT INTO audit_log (id, scope, org_id, action, detail, created_at)
            WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < @filler)
            SELECT 'aud' || n, 'tenant', 'o1', 'org_settings_updated', 'filler row',
                   strftime('%Y-%m-%dT%H:%M:%f', 1700000000 + n, 'unixepoch') || 'Z'
            FROM seq
            """,
            new { filler });
    }

    [Fact]
    public async Task Activity_search_does_not_scan_past_the_cap()
    {
        // One matching row, buried under more filler than the scan window admits.
        await SeedActivityWithOldNeedleAsync(AuditRepository.SearchScanCap + 10);
        var repo = new AuditRepository(_db);

        var (items, total, capped) = await repo.ListActivityAsync(
            "o1", limit: 50, offset: 0, search: "the needle");

        // Unbounded, this returns the needle after reading every row in the org's history.
        Assert.Empty(items);
        Assert.Equal(0, total);
        // The window was truncated, so the caller must not read the total as exact.
        Assert.True(capped);
    }

    [Fact]
    public async Task Activity_search_inside_the_cap_stays_exact_and_finds_the_row()
    {
        // Comfortably under the cap: no floor is applied, so behaviour is unchanged.
        await SeedActivityWithOldNeedleAsync(10);
        var repo = new AuditRepository(_db);

        var (items, total, capped) = await repo.ListActivityAsync(
            "o1", limit: 50, offset: 0, search: "the needle");

        Assert.Single(items);
        Assert.Equal("act-needle", items[0].Id);
        Assert.Equal(1, total);
        Assert.False(capped);
    }

    [Fact]
    public async Task Activity_search_paging_stops_at_the_scan_window()
    {
        // Every filler row matches, so the only thing that can end the result set is the scan
        // window itself. The floor is the timestamp of the row at offset SearchScanCap and is
        // admitted by the >= comparison, so the window holds SearchScanCap + 1 rows.
        await SeedActivityWithOldNeedleAsync(AuditRepository.SearchScanCap + 10);
        var repo = new AuditRepository(_db);

        var (lastPage, _, capped) = await repo.ListActivityAsync(
            "o1", limit: 5, offset: AuditRepository.SearchScanCap, search: "filler row");
        var (pastEnd, _, _) = await repo.ListActivityAsync(
            "o1", limit: 5, offset: AuditRepository.SearchScanCap + 1, search: "filler row");

        Assert.True(capped);
        Assert.Single(lastPage);
        Assert.Empty(pastEnd);
    }

    [Fact]
    public async Task Activity_csv_export_search_is_bounded_and_reports_the_truncation()
    {
        // includeTotal:false is the CSV export. Left unbounded it is a full-history scan any
        // read:audit holder can re-issue with a term that matches nothing, so it takes the same
        // bound as the paged list — and reports the truncation through TotalCapped, which is
        // what the endpoint turns into the X-Export-Truncated response header.
        await SeedActivityWithOldNeedleAsync(AuditRepository.SearchScanCap + 10);
        var repo = new AuditRepository(_db);

        var (items, _, capped) = await repo.ListActivityAsync(
            "o1", limit: 50_000, offset: 0, search: "the needle", includeTotal: false);

        Assert.Empty(items);
        Assert.True(capped);
    }

    /// <summary>
    /// Adversarial twin: the bound is scoped to the search predicates alone. A CSV export with no
    /// search term still reads the whole window, which is what keeps a complete compliance export
    /// available — the indexed <c>event_type</c>/<c>since</c> filters, not the unindexable
    /// free-text box, are how a large history is exported.
    /// </summary>
    [Fact]
    public async Task Activity_csv_export_without_a_search_term_stays_unbounded()
    {
        await SeedActivityWithOldNeedleAsync(AuditRepository.SearchScanCap + 10);
        var repo = new AuditRepository(_db);

        // The needle is the oldest row of SearchScanCap + 11, so it is reachable only if no scan
        // floor was applied — a bounded window would return nothing at this offset.
        var (items, _, capped) = await repo.ListActivityAsync(
            "o1", limit: 50, offset: AuditRepository.SearchScanCap + 10, includeTotal: false);

        Assert.Single(items);
        Assert.Equal("act-needle", items[0].Id);
        Assert.False(capped);
    }

    [Fact]
    public async Task Activity_no_search_is_not_bounded_by_the_scan_cap()
    {
        // The scan floor exists only to bound the LIKE predicates. Applying it to the
        // unfiltered feed would stop rows past the cap from being pageable.
        await SeedActivityWithOldNeedleAsync(AuditRepository.SearchScanCap + 10);
        var repo = new AuditRepository(_db);

        var (items, _, _) = await repo.ListActivityAsync(
            "o1", limit: 5, offset: AuditRepository.SearchScanCap + 6);

        Assert.Equal(5, items.Count);
    }

    [Fact]
    public async Task Audit_search_does_not_scan_past_the_cap()
    {
        await SeedAuditWithOldNeedleAsync(AuditRepository.SearchScanCap + 10);
        var repo = new AuditRepository(_db);

        var (items, total, capped) = await repo.ListAuditAsync(
            "o1", limit: 50, offset: 0, search: "the needle");

        Assert.Empty(items);
        Assert.Equal(0, total);
        Assert.True(capped);
    }

    [Fact]
    public async Task Audit_search_inside_the_cap_stays_exact_and_finds_the_row()
    {
        await SeedAuditWithOldNeedleAsync(10);
        var repo = new AuditRepository(_db);

        var (items, total, capped) = await repo.ListAuditAsync(
            "o1", limit: 50, offset: 0, search: "the needle");

        Assert.Single(items);
        Assert.Equal("aud-needle", items[0].Id);
        Assert.Equal(1, total);
        Assert.False(capped);
    }

    [Fact]
    public async Task Audit_csv_export_search_is_bounded_and_reports_the_truncation()
    {
        await SeedAuditWithOldNeedleAsync(AuditRepository.SearchScanCap + 10);
        var repo = new AuditRepository(_db);

        var (items, _, capped) = await repo.ListAuditAsync(
            "o1", limit: 50_000, offset: 0, search: "the needle", includeTotal: false);

        Assert.Empty(items);
        Assert.True(capped);
    }

    /// <summary>Adversarial twin, over <c>audit_log</c>: see the activity counterpart.</summary>
    [Fact]
    public async Task Audit_csv_export_without_a_search_term_stays_unbounded()
    {
        await SeedAuditWithOldNeedleAsync(AuditRepository.SearchScanCap + 10);
        var repo = new AuditRepository(_db);

        var (items, _, capped) = await repo.ListAuditAsync(
            "o1", limit: 50, offset: AuditRepository.SearchScanCap + 10, includeTotal: false);

        Assert.Single(items);
        Assert.Equal("aud-needle", items[0].Id);
        Assert.False(capped);
    }
}
