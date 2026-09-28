using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Usage;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// The usage rollups, the storage capture and the fleet report executed against live Postgres.
/// <see cref="Unit.Infrastructure.UsageMeteringRepositoryTests"/> pins the same numbers on SQLite;
/// this proves the statements run to completion on the other provider, where <c>COUNT</c> and
/// <c>SUM</c> return different types and the snapshot's count columns are <c>BIGINT</c>.
///
/// Tagged <c>Category=SchemaPostgres</c> so it runs only where <c>TEST_POSTGRES_CONNECTION</c> is
/// set (the <c>schema-integrity</c> CI job); it fails loudly rather than skipping when it is not.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class UsageMeteringPostgresTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 24, 10, 0, 0, TimeSpan.Zero);
    private static readonly DateOnly Day = new(2026, 9, 24);

    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    [Fact]
    public async Task Request_counts_and_snapshot_counts_execute_against_live_postgres()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();

        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme'), ('o2', 'empty')");
            await conn.ExecuteAsync(
                """
                INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES
                  ('pa', 'o1', 'npm', 'a', 'a', 0)
                """);
            await conn.ExecuteAsync(
                """
                INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, origin) VALUES
                  ('va1', 'pa', '1.0.0', 'pkg:npm/a@1.0.0', 'registry/va1', 10, 'uploaded'),
                  ('va2', 'pa', '2.0.0', 'pkg:npm/a@2.0.0', 'registry/va2', 10, 'uploaded')
                """);
            await conn.ExecuteAsync(
                """
                INSERT INTO oci_blobs (digest, org_id, blob_key, size_bytes, media_type, origin) VALUES
                  ('sha256:m1', 'o1', 'oci/sha256/m1', 1, 'application/vnd.oci.image.manifest.v1+json', 'uploaded'),
                  ('sha256:l1', 'o1', 'oci/sha256/l1', 1, 'application/vnd.oci.image.layer.v1.tar+gzip', 'uploaded')
                """);
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes)
                VALUES ('ca1', 'npm', 'x', '1.0.0', 'x-1.0.0.tgz', 'proxy/ca1', 'ca1', 1)
                """);
            await conn.ExecuteAsync("INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1', 'ca1')");
        }

        var events = new UsageEventRepository(store);
        await events.InsertBatchAsync(
        [
            Event(UsageMeters.EgressBytes, 100, T0.AddMinutes(1)),
            Event(UsageMeters.EgressBytes, 200, T0.AddMinutes(2)),
            Event(UsageMeters.EgressMetadataBytes, 5, T0.AddHours(1)),
        ]);

        var rollups = new UsageRollupRepository(store);
        await rollups.RecomputeHourlyAsync(T0, T0.AddDays(1), T0.AddDays(1));
        await rollups.RecomputeDailyEgressAsync(Day, Day.AddDays(1), T0.AddDays(1));

        var hourly = await rollups.GetHourlyAsync("o1", Day, Day.AddDays(1));
        Assert.Equal(2L, hourly.Single(r => r.Meter == UsageMeters.EgressBytes).RequestCount);
        var daily = await rollups.GetDailyAsync("o1", Day, Day.AddDays(1));
        Assert.Equal(2L, daily.Single(r => r.Meter == UsageMeters.EgressBytes).RequestCount);
        Assert.Equal(1L, daily.Single(r => r.Meter == UsageMeters.EgressMetadataBytes).RequestCount);

        var stored = await rollups.ListDailyEgressAsync(Day, Day.AddDays(1));
        var recomputed = await rollups.ComputeDailyEgressFromEventsAsync(Day, Day.AddDays(1));
        Assert.Empty(UsageReconciliationService.FindMismatches(stored, recomputed));

        var snapshots = new StorageSnapshotRepository(store);
        Assert.Equal(2, await snapshots.CaptureAsync(Day, T0));

        var o1 = await snapshots.GetLatestAsync("o1");
        Assert.NotNull(o1);
        Assert.Equal(2L, o1.HostedVersionCount);
        Assert.Equal(1L, o1.OciManifestCount);
        Assert.Equal(1L, o1.OciBlobCount);
        Assert.Equal(1L, o1.CacheEntryCount);
        // packages 1 + oci_blobs 2 + tenant_artifact_access 1 + usage_events 3.
        Assert.Equal(7L, o1.DbRowCount);

        var empty = await snapshots.GetAsync("o2", Day);
        Assert.NotNull(empty);
        Assert.Equal(0L, empty.DbRowCount);
        Assert.Equal(0L, empty.ArtifactCount);

        var reports = new UsageReportRepository(store);
        foreach (string sort in new[] { "requestCount", "metadataRequestCount", "artifactCount", "dbRowCount" })
        {
            var (items, total) = await reports.ListFleetUsageAsync(Day, Day.AddDays(1), sort, "desc", 50, 0);
            Assert.Equal(2, total);
            Assert.Equal("o1", items[0].OrgId);
        }

        var (fleet, _) = await reports.ListFleetUsageAsync(Day, Day.AddDays(1), null, null, 50, 0);
        var row = fleet.Single(r => r.OrgId == "o1");
        Assert.Equal(2L, row.RequestCount);
        Assert.Equal(1L, row.MetadataRequestCount);
        Assert.Equal(3L, row.SnapshotArtifactCount);
        Assert.Equal(7L, row.SnapshotDbRowCount);

        var totals = await reports.GetFleetTotalsAsync(Day, Day.AddDays(1));
        Assert.Equal(2L, totals.RequestCount);
        Assert.Equal(1L, totals.MetadataRequestCount);
    }

    private static UsageEvent Event(string meter, long bytes, DateTimeOffset at) =>
        UsageEvent.Create(Guid.NewGuid(), "o1", meter, UsageDelivery.Streamed, bytes, "npm", null, at);
}
