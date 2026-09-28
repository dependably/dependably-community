using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Usage;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Fleet-wide usage reporting: per-tenant sums/averages, the orphaned-org (hard-deleted but
/// still metered) arm, the sort allowlist, server-side pagination, fleet totals, and the
/// per-ecosystem breakdown. <see cref="Dependably.Api.SystemController.Usage"/>'s own tests cover
/// range validation and the HTTP surface; this covers the SQL underneath it.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UsageReportRepositoryTests : IAsyncLifetime
{
    private static readonly DateOnly Day1 = new(2026, 9, 1);
    private static readonly DateOnly Day2 = new(2026, 9, 2);
    private static readonly DateOnly Day3 = new(2026, 9, 3);
    private static readonly DateOnly RangeStart = Day1;
    private static readonly DateOnly RangeEndExclusive = new(2026, 9, 4);

    private readonly TestMetadataStore _db = new();
    private UsageReportRepository _reports = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES ('o1', 'acme'), ('o2', 'globex'), ('o3', 'initech')");
        _reports = new UsageReportRepository(_db);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task Fleet_row_sums_egress_and_metadata_and_averages_only_the_marked_days()
    {
        // o1: egress_bytes on two days (100 + 200, redirect 40 + 0), metadata on one day (10),
        // storage marks of 1000 and 3000 on two of the three range days — averages to 2000, not
        // (1000+3000)/3.
        await InsertDaily("o1", UsageMeters.EgressBytes, Day1, quantity: 100, redirect: 40);
        await InsertDaily("o1", UsageMeters.EgressBytes, Day2, quantity: 200, redirect: 0);
        await InsertDaily("o1", UsageMeters.EgressMetadataBytes, Day1, quantity: 10);
        await InsertDaily("o1", UsageMeters.StorageBytes, Day1, quantity: 1000);
        await InsertDaily("o1", UsageMeters.StorageBytes, Day3, quantity: 3000);

        var (items, total) = await _reports.ListFleetUsageAsync(RangeStart, RangeEndExclusive, null, null, 50, 0);

        Assert.Equal(3, total); // every seeded org appears even with zero usage
        var o1 = Assert.Single(items, i => i.OrgId == "o1");
        Assert.Equal("acme", o1.Slug);
        Assert.Equal(300L, o1.EgressBytes);
        Assert.Equal(40L, o1.EgressRedirectBytes);
        Assert.Equal(10L, o1.EgressMetadataBytes);
        Assert.Equal(2, o1.StorageMarkCount);
        Assert.Equal(2000L, o1.BillableStorageBytes);

        var o2 = Assert.Single(items, i => i.OrgId == "o2");
        Assert.Equal(0L, o2.EgressBytes);
        Assert.Equal(0L, o2.BillableStorageBytes);
        Assert.Equal(0, o2.StorageMarkCount);
    }

    /// <summary>
    /// Usage tables carry no FK to orgs — a hard-deleted org's usage must still surface in the
    /// fleet listing, with a null slug/status rather than being silently dropped.
    /// </summary>
    [Fact]
    public async Task Orphaned_org_surfaces_with_a_null_slug_instead_of_being_dropped()
    {
        await InsertDaily("o4-gone", UsageMeters.EgressBytes, Day1, quantity: 500);
        await using (var conn = await _db.OpenAsync())
        {
            // Never had an orgs row in this test — mirrors a hard delete, which leaves usage_daily
            // untouched because there is no FK.
            Assert.Equal(0, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM orgs WHERE id = 'o4-gone'"));
        }

        var (items, total) = await _reports.ListFleetUsageAsync(RangeStart, RangeEndExclusive, null, null, 50, 0);

        Assert.Equal(4, total);
        var orphan = Assert.Single(items, i => i.OrgId == "o4-gone");
        Assert.Null(orphan.Slug);
        Assert.Null(orphan.Status);
        Assert.Equal(500L, orphan.EgressBytes);
    }

    [Fact]
    public async Task Sort_resolves_through_the_allowlist_and_falls_back_on_an_unrecognised_value()
    {
        await InsertDaily("o1", UsageMeters.EgressBytes, Day1, quantity: 50);
        await InsertDaily("o2", UsageMeters.EgressBytes, Day1, quantity: 500);
        await InsertDaily("o3", UsageMeters.EgressBytes, Day1, quantity: 5);

        var (asc, _) = await _reports.ListFleetUsageAsync(RangeStart, RangeEndExclusive, "egressBytes", "asc", 50, 0);
        Assert.Equal(["o3", "o1", "o2"], asc.Select(i => i.OrgId).ToArray());

        var (desc, _) = await _reports.ListFleetUsageAsync(RangeStart, RangeEndExclusive, "egressBytes", "desc", 50, 0);
        Assert.Equal(["o2", "o1", "o3"], desc.Select(i => i.OrgId).ToArray());

        // Not in the allowlist — must fall back to the default sort (egressBytes desc) rather
        // than erroring or letting caller text reach the SQL.
        var (fallback, _) = await _reports.ListFleetUsageAsync(
            RangeStart, RangeEndExclusive, "'; DROP TABLE orgs; --", null, 50, 0);
        Assert.Equal(["o2", "o1", "o3"], fallback.Select(i => i.OrgId).ToArray());
    }

    [Fact]
    public async Task Listing_paginates_server_side()
    {
        await InsertDaily("o1", UsageMeters.EgressBytes, Day1, quantity: 300);
        await InsertDaily("o2", UsageMeters.EgressBytes, Day1, quantity: 200);
        await InsertDaily("o3", UsageMeters.EgressBytes, Day1, quantity: 100);

        var (page1, total) = await _reports.ListFleetUsageAsync(RangeStart, RangeEndExclusive, "egressBytes", "desc", 2, 0);
        var (page2, _) = await _reports.ListFleetUsageAsync(RangeStart, RangeEndExclusive, "egressBytes", "desc", 2, 2);

        Assert.Equal(3, total);
        Assert.Equal(["o1", "o2"], page1.Select(i => i.OrgId).ToArray());
        Assert.Equal(["o3"], page2.Select(i => i.OrgId).ToArray());
    }

    [Fact]
    public async Task Fleet_totals_sum_across_every_tenant_including_orphans()
    {
        await InsertDaily("o1", UsageMeters.EgressBytes, Day1, quantity: 100, redirect: 10);
        await InsertDaily("o2", UsageMeters.EgressBytes, Day1, quantity: 50);
        await InsertDaily("o1", UsageMeters.EgressMetadataBytes, Day1, quantity: 7);
        await InsertDaily("o1", UsageMeters.StorageBytes, Day1, quantity: 1000);
        await InsertDaily("o1", UsageMeters.StorageBytes, Day2, quantity: 3000);
        await InsertDaily("o2", UsageMeters.StorageBytes, Day1, quantity: 200);
        await InsertDaily("orphan", UsageMeters.EgressBytes, Day1, quantity: 9);

        var totals = await _reports.GetFleetTotalsAsync(RangeStart, RangeEndExclusive);

        Assert.Equal(159L, totals.EgressBytes); // 100 + 50 + 9
        Assert.Equal(10L, totals.EgressRedirectBytes);
        Assert.Equal(7L, totals.EgressMetadataBytes);
        // o1's own average is (1000+3000)/2 = 2000; o2's is 200; fleet total is their sum.
        Assert.Equal(2200L, totals.BillableStorageBytes);
    }

    [Fact]
    public async Task Ecosystem_breakdown_groups_by_source_and_stays_bounded_to_the_range()
    {
        await InsertEvent("o1", UsageMeters.EgressBytes, "npm", 100, redirect: false, day: Day1);
        await InsertEvent("o1", UsageMeters.EgressBytes, "npm", 25, redirect: true, day: Day1);
        await InsertEvent("o1", UsageMeters.EgressBytes, "oci", 40, redirect: false, day: Day2);
        await InsertEvent("o1", UsageMeters.EgressMetadataBytes, "npm", 5, redirect: false, day: Day1);
        // Outside the range — must not contribute.
        await InsertEvent("o1", UsageMeters.EgressBytes, "npm", 999, redirect: false, day: new DateOnly(2026, 9, 10));

        var rows = await _reports.GetEcosystemBreakdownAsync(RangeStart, RangeEndExclusive);

        var npmEgress = Assert.Single(rows, r => r.Ecosystem == "npm" && r.Meter == UsageMeters.EgressBytes);
        Assert.Equal(125L, npmEgress.Bytes);
        Assert.Equal(25L, npmEgress.RedirectBytes);

        var ociEgress = Assert.Single(rows, r => r.Ecosystem == "oci" && r.Meter == UsageMeters.EgressBytes);
        Assert.Equal(40L, ociEgress.Bytes);
        Assert.Equal(0L, ociEgress.RedirectBytes);

        var npmMeta = Assert.Single(rows, r => r.Ecosystem == "npm" && r.Meter == UsageMeters.EgressMetadataBytes);
        Assert.Equal(5L, npmMeta.Bytes);
    }

    [Fact]
    public async Task Fleet_row_carries_request_counts_and_the_latest_snapshots_counts()
    {
        await InsertDaily("o1", UsageMeters.EgressBytes, Day1, quantity: 100, requests: 4);
        await InsertDaily("o1", UsageMeters.EgressBytes, Day2, quantity: 200, requests: 6);
        await InsertDaily("o1", UsageMeters.EgressMetadataBytes, Day1, quantity: 10, requests: 30);
        await InsertDaily("o1", UsageMeters.StorageBytes, Day1, quantity: 1000);
        // An older snapshot, then the latest: only the latest's counts surface.
        await InsertSnapshot("o1", Day1, hostedVersions: 1, ociManifests: 1, ociBlobs: 1, cacheEntries: 1, dbRows: 1);
        await InsertSnapshot("o1", Day2, hostedVersions: 5, ociManifests: 2, ociBlobs: 7, cacheEntries: 11, dbRows: 1234);

        var (items, _) = await _reports.ListFleetUsageAsync(RangeStart, RangeEndExclusive, null, null, 50, 0);

        var o1 = Assert.Single(items, i => i.OrgId == "o1");
        Assert.Equal(10L, o1.RequestCount);
        Assert.Equal(30L, o1.MetadataRequestCount);
        Assert.Equal(5L, o1.SnapshotHostedVersionCount);
        Assert.Equal(2L, o1.SnapshotOciManifestCount);
        Assert.Equal(7L, o1.SnapshotOciBlobCount);
        Assert.Equal(11L, o1.SnapshotCacheEntryCount);
        Assert.Equal(1234L, o1.SnapshotDbRowCount);
        Assert.Equal(7L, o1.SnapshotArtifactCount);

        // No snapshot: the counts are absent rather than zero, and requests read 0.
        var o2 = Assert.Single(items, i => i.OrgId == "o2");
        Assert.Equal(0L, o2.RequestCount);
        Assert.Null(o2.SnapshotDbRowCount);
        Assert.Null(o2.SnapshotArtifactCount);
    }

    [Fact]
    public async Task Orphaned_org_carries_its_request_counts_and_snapshot_counts()
    {
        await InsertDaily("gone", UsageMeters.EgressBytes, Day1, quantity: 5, requests: 2);
        await InsertSnapshot("gone", Day1, hostedVersions: 3, ociManifests: 0, ociBlobs: 0, cacheEntries: 0, dbRows: 9);

        var (items, _) = await _reports.ListFleetUsageAsync(RangeStart, RangeEndExclusive, null, null, 50, 0);

        var orphan = Assert.Single(items, i => i.OrgId == "gone");
        Assert.Null(orphan.Slug);
        Assert.Equal(2L, orphan.RequestCount);
        Assert.Equal(3L, orphan.SnapshotArtifactCount);
        Assert.Equal(9L, orphan.SnapshotDbRowCount);
    }

    [Theory]
    [InlineData("requestCount")]
    [InlineData("metadataRequestCount")]
    [InlineData("artifactCount")]
    [InlineData("dbRowCount")]
    public async Task Each_signal_column_sorts_through_the_allowlist(string sort)
    {
        // o2 leads every signal, o3 trails it, o1 has no snapshot and no usage at all.
        await InsertDaily("o2", UsageMeters.EgressBytes, Day1, quantity: 1, requests: 50);
        await InsertDaily("o2", UsageMeters.EgressMetadataBytes, Day1, quantity: 1, requests: 50);
        await InsertDaily("o3", UsageMeters.EgressBytes, Day1, quantity: 1, requests: 5);
        await InsertDaily("o3", UsageMeters.EgressMetadataBytes, Day1, quantity: 1, requests: 5);
        await InsertSnapshot("o2", Day1, hostedVersions: 40, ociManifests: 10, ociBlobs: 0, cacheEntries: 0, dbRows: 500);
        await InsertSnapshot("o3", Day1, hostedVersions: 4, ociManifests: 1, ociBlobs: 0, cacheEntries: 0, dbRows: 50);

        var (desc, _) = await _reports.ListFleetUsageAsync(RangeStart, RangeEndExclusive, sort, "desc", 50, 0);
        Assert.Equal(["o2", "o3", "o1"], desc.Select(i => i.OrgId).ToArray());

        var (asc, _) = await _reports.ListFleetUsageAsync(RangeStart, RangeEndExclusive, sort, "asc", 50, 0);
        Assert.Equal(["o1", "o3", "o2"], asc.Select(i => i.OrgId).ToArray());
    }

    [Fact]
    public async Task Fleet_totals_sum_request_counts_per_meter()
    {
        await InsertDaily("o1", UsageMeters.EgressBytes, Day1, quantity: 1, requests: 3);
        await InsertDaily("o2", UsageMeters.EgressBytes, Day2, quantity: 1, requests: 4);
        await InsertDaily("o1", UsageMeters.EgressMetadataBytes, Day1, quantity: 1, requests: 20);
        await InsertDaily("orphan", UsageMeters.EgressMetadataBytes, Day1, quantity: 1, requests: 1);
        // Outside the range — must not contribute.
        await InsertDaily("o1", UsageMeters.EgressBytes, new DateOnly(2026, 9, 10), quantity: 1, requests: 999);

        var totals = await _reports.GetFleetTotalsAsync(RangeStart, RangeEndExclusive);

        Assert.Equal(7L, totals.RequestCount);
        Assert.Equal(21L, totals.MetadataRequestCount);
    }

    private async Task InsertSnapshot(
        string orgId, DateOnly day, long hostedVersions, long ociManifests, long ociBlobs, long cacheEntries, long dbRows)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO storage_snapshot
                (org_id, day_utc, hosted_bytes, oci_uploaded_bytes, cache_attributed_bytes, billable_bytes,
                 hosted_version_count, oci_manifest_count, oci_blob_count, cache_entry_count, db_row_count, captured_at)
            VALUES (@orgId, @dayUtc, 0, 0, 0, 0, @hostedVersions, @ociManifests, @ociBlobs, @cacheEntries, @dbRows, @capturedAt)
            """,
            new
            {
                orgId,
                dayUtc = UsageRollupRepository.DayLabel(day),
                hostedVersions,
                ociManifests,
                ociBlobs,
                cacheEntries,
                dbRows,
                capturedAt = day.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc).ToUtcIso(),
            });
    }

    private async Task InsertDaily(
        string orgId, string meter, DateOnly day, long quantity, long redirect = 0, long requests = 0)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO usage_daily (org_id, meter, bucket, quantity, redirect_quantity, request_count, computed_at)
            VALUES (@orgId, @meter, @bucket, @quantity, @redirect, @requests, @computedAt)
            """,
            new
            {
                orgId,
                meter,
                bucket = UsageRollupRepository.DayLabel(day),
                quantity,
                redirect,
                requests,
                computedAt = day.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc).ToUtcIso(),
            });
    }

    private async Task InsertEvent(string orgId, string meter, string source, long quantity, bool redirect, DateOnly day)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO usage_events (event_id, org_id, meter, delivery, quantity, source, occurred_at)
            VALUES (@eventId, @orgId, @meter, @delivery, @quantity, @source, @occurredAt)
            """,
            new
            {
                eventId = Guid.NewGuid().ToString("N"),
                orgId,
                meter,
                delivery = redirect ? UsageDelivery.Redirect : UsageDelivery.Streamed,
                quantity,
                source,
                occurredAt = day.ToDateTime(new TimeOnly(12, 0), DateTimeKind.Utc).ToUtcIso(),
            });
    }
}
