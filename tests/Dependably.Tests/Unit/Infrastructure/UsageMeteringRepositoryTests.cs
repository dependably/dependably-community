using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Usage;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The metering record and its rollups. Each property pinned here is one a bill regenerated from
/// raw events depends on: a replay never double-counts, a recompute is idempotent, a bucket
/// boundary puts every event in exactly one hour, and a storage mark never falls within its day.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UsageMeteringRepositoryTests : IAsyncLifetime
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 24, 10, 0, 0, TimeSpan.Zero);
    private static readonly DateOnly Day = new(2026, 9, 24);

    private readonly TestMetadataStore _db = new();
    private UsageEventRepository _events = null!;
    private UsageRollupRepository _rollups = null!;
    private StorageSnapshotRepository _snapshots = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme'), ('o2', 'other'), ('o3', 'empty')");
        _events = new UsageEventRepository(_db);
        _rollups = new UsageRollupRepository(_db);
        _snapshots = new StorageSnapshotRepository(_db);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task Replaying_a_batch_never_double_counts()
    {
        var batch = new[]
        {
            Egress("o1", 100, T0.AddMinutes(1)),
            Egress("o1", 200, T0.AddMinutes(2)),
        };

        await _events.InsertBatchAsync(batch);
        await _events.InsertBatchAsync(batch);

        await using var conn = await _db.OpenAsync();
        Assert.Equal(2, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM usage_events WHERE org_id = 'o1'"));
        Assert.Equal(300, await conn.ExecuteScalarAsync<long>("SELECT SUM(quantity) FROM usage_events WHERE org_id = 'o1'"));
    }

    [Fact]
    public void Create_rejects_what_the_schema_would_reject()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => UsageEvent.Create(
            Guid.NewGuid(), "o1", UsageMeters.StorageBytes, UsageDelivery.Streamed, 1, "npm", null, T0));
        Assert.Throws<ArgumentOutOfRangeException>(() => UsageEvent.Create(
            Guid.NewGuid(), "o1", UsageMeters.EgressBytes, "cdn", 1, "npm", null, T0));
        Assert.Throws<ArgumentOutOfRangeException>(() => UsageEvent.Create(
            Guid.NewGuid(), "o1", UsageMeters.EgressBytes, UsageDelivery.Streamed, -1, "npm", null, T0));
    }

    [Fact]
    public async Task Hourly_rollup_splits_by_org_meter_hour_and_delivery()
    {
        await _events.InsertBatchAsync(
        [
            Egress("o1", 100, T0.AddMinutes(5)),
            Egress("o1", 50, T0.AddMinutes(10), UsageDelivery.Redirect),
            Egress("o1", 7, T0.AddMinutes(20), meter: UsageMeters.EgressMetadataBytes),
            Egress("o1", 1000, T0.AddHours(1).AddMinutes(1)),
            Egress("o2", 9, T0.AddMinutes(30)),
        ]);

        await _rollups.RecomputeHourlyAsync(T0, T0.AddHours(2), T0.AddHours(2));

        var rows = await HourlyAsync();
        Assert.Equal(4, rows.Count);
        Assert.Contains(("o1", UsageMeters.EgressBytes, "2026-09-24T10:00:00Z", 150L, 50L), rows);
        Assert.Contains(("o1", UsageMeters.EgressMetadataBytes, "2026-09-24T10:00:00Z", 7L, 0L), rows);
        Assert.Contains(("o1", UsageMeters.EgressBytes, "2026-09-24T11:00:00Z", 1000L, 0L), rows);
        Assert.Contains(("o2", UsageMeters.EgressBytes, "2026-09-24T10:00:00Z", 9L, 0L), rows);
    }

    [Fact]
    public async Task Hourly_rollup_counts_the_metered_events_in_each_bucket()
    {
        await _events.InsertBatchAsync(
        [
            Egress("o1", 100, T0.AddMinutes(5)),
            Egress("o1", 50, T0.AddMinutes(10), UsageDelivery.Redirect),
            Egress("o1", 0, T0.AddMinutes(15)),
            Egress("o1", 7, T0.AddMinutes(20), meter: UsageMeters.EgressMetadataBytes),
            Egress("o1", 1000, T0.AddHours(1).AddMinutes(1)),
            Egress("o2", 9, T0.AddMinutes(30)),
        ]);

        await _rollups.RecomputeHourlyAsync(T0, T0.AddHours(2), T0.AddHours(2));
        // A second pass overwrites the counts rather than adding to them.
        await _rollups.RecomputeHourlyAsync(T0, T0.AddHours(2), T0.AddHours(2));

        var counts = await HourlyCountsAsync();
        Assert.Equal(4, counts.Count);
        Assert.Contains(("o1", UsageMeters.EgressBytes, "2026-09-24T10:00:00Z", 3L), counts);
        Assert.Contains(("o1", UsageMeters.EgressMetadataBytes, "2026-09-24T10:00:00Z", 1L), counts);
        Assert.Contains(("o1", UsageMeters.EgressBytes, "2026-09-24T11:00:00Z", 1L), counts);
        Assert.Contains(("o2", UsageMeters.EgressBytes, "2026-09-24T10:00:00Z", 1L), counts);

        var hourly = await _rollups.GetHourlyAsync("o1", Day, Day.AddDays(1));
        Assert.Equal(3L, hourly.Single(r => r.Meter == UsageMeters.EgressBytes && r.Bucket == "2026-09-24T10:00:00Z").RequestCount);
    }

    [Fact]
    public async Task Daily_request_count_is_the_sum_of_its_hours()
    {
        await _events.InsertBatchAsync(
        [
            Egress("o1", 100, T0.AddMinutes(5)),
            Egress("o1", 200, T0.AddMinutes(6)),
            Egress("o1", 300, T0.AddHours(3)),
            Egress("o1", 4, T0.AddHours(3), meter: UsageMeters.EgressMetadataBytes),
            Egress("o1", 999, new DateTimeOffset(2026, 9, 25, 0, 0, 0, TimeSpan.Zero)),
        ]);
        await _rollups.RecomputeHourlyAsync(T0, T0.AddDays(1), T0.AddDays(1));

        await _rollups.RecomputeDailyEgressAsync(Day, Day.AddDays(1), T0.AddDays(1));
        await _rollups.RecomputeDailyEgressAsync(Day, Day.AddDays(1), T0.AddDays(1));

        var daily = await _rollups.GetDailyAsync("o1", Day, Day.AddDays(1));
        Assert.Equal(3L, daily.Single(r => r.Meter == UsageMeters.EgressBytes).RequestCount);
        Assert.Equal(1L, daily.Single(r => r.Meter == UsageMeters.EgressMetadataBytes).RequestCount);
    }

    [Fact]
    public async Task Events_recompute_counts_the_same_requests_the_rollups_do()
    {
        await _events.InsertBatchAsync(
        [
            Egress("o1", 100, T0.AddMinutes(5)),
            Egress("o1", 200, T0.AddHours(2)),
            Egress("o2", 1, T0.AddHours(2)),
        ]);
        await _rollups.RecomputeHourlyAsync(T0, T0.AddDays(1), T0.AddDays(1));
        await _rollups.RecomputeDailyEgressAsync(Day, Day.AddDays(1), T0.AddDays(1));

        var stored = await _rollups.ListDailyEgressAsync(Day, Day.AddDays(1));
        var recomputed = await _rollups.ComputeDailyEgressFromEventsAsync(Day, Day.AddDays(1));

        Assert.Equal(2L, stored.Single(r => r.OrgId == "o1").RequestCount);
        Assert.Equal(2L, recomputed.Single(r => r.OrgId == "o1").RequestCount);
        Assert.Equal(1L, stored.Single(r => r.OrgId == "o2").RequestCount);
        Assert.Equal(1L, recomputed.Single(r => r.OrgId == "o2").RequestCount);
    }

    [Fact]
    public async Task Recomputing_the_same_window_twice_yields_the_same_rows()
    {
        await _events.InsertBatchAsync([Egress("o1", 100, T0.AddMinutes(5))]);

        await _rollups.RecomputeHourlyAsync(T0, T0.AddHours(1), T0.AddHours(1));
        var first = await HourlyAsync();
        await _rollups.RecomputeHourlyAsync(T0, T0.AddHours(1), T0.AddHours(1));
        var second = await HourlyAsync();

        Assert.Equal(first, second);
        Assert.Single(second);
    }

    [Fact]
    public async Task A_late_event_is_absorbed_by_the_next_recompute_rather_than_added_twice()
    {
        await _events.InsertBatchAsync([Egress("o1", 100, T0.AddMinutes(5))]);
        await _rollups.RecomputeHourlyAsync(T0, T0.AddHours(1), T0.AddHours(1));

        await _events.InsertBatchAsync([Egress("o1", 25, T0.AddMinutes(59))]);
        await _rollups.RecomputeHourlyAsync(T0, T0.AddHours(1), T0.AddHours(1));
        var (_, _, _, Quantity, _) = Assert.Single(await HourlyAsync());
        Assert.Equal(125L, Quantity);
    }

    /// <summary>
    /// An event stamped exactly on the hour belongs to that hour, never the one before, whatever
    /// precision it was stored at. A second-precision value sorts after its millisecond siblings
    /// ('Z' > '.'), which is why the bounds are written at millisecond precision.
    /// </summary>
    [Fact]
    public async Task An_event_on_the_hour_boundary_lands_in_exactly_one_bucket()
    {
        await _events.InsertBatchAsync([Egress("o1", 1, T0.AddHours(1))]);
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO usage_events (event_id, org_id, meter, delivery, quantity, source, occurred_at)
                VALUES ('second-precision', 'o1', 'egress_bytes', 'streamed', 10, 'npm', '2026-09-24T11:00:00Z')
                """);
        }

        await _rollups.RecomputeHourlyAsync(T0, T0.AddHours(1), T0.AddHours(2));
        Assert.Empty(await HourlyAsync());

        await _rollups.RecomputeHourlyAsync(T0.AddHours(1), T0.AddHours(2), T0.AddHours(2));
        var (_, _, Bucket, Quantity, _) = Assert.Single(await HourlyAsync());
        Assert.Equal("2026-09-24T11:00:00Z", Bucket);
        Assert.Equal(11L, Quantity);
    }

    [Fact]
    public async Task A_window_ending_mid_hour_is_widened_to_cover_the_whole_hour()
    {
        await _events.InsertBatchAsync([Egress("o1", 5, T0.AddMinutes(50))]);

        await _rollups.RecomputeHourlyAsync(T0.AddMinutes(10), T0.AddMinutes(20), T0.AddHours(1));
        var (_, _, _, Quantity, _) = Assert.Single(await HourlyAsync());
        Assert.Equal(5L, Quantity);
    }

    [Fact]
    public async Task Daily_egress_is_the_sum_of_its_hours_and_recomputes_idempotently()
    {
        await _events.InsertBatchAsync(
        [
            Egress("o1", 100, T0.AddMinutes(5), UsageDelivery.Redirect),
            Egress("o1", 200, T0.AddHours(3)),
            Egress("o1", 999, new DateTimeOffset(2026, 9, 25, 0, 0, 0, TimeSpan.Zero)),
        ]);
        await _rollups.RecomputeHourlyAsync(T0, T0.AddDays(1), T0.AddDays(1));

        await _rollups.RecomputeDailyEgressAsync(Day, Day.AddDays(1), T0.AddDays(1));
        await _rollups.RecomputeDailyEgressAsync(Day, Day.AddDays(1), T0.AddDays(1));

        var daily = await _rollups.GetDailyAsync("o1", Day, Day.AddDays(1));
        var row = Assert.Single(daily);
        Assert.Equal(UsageMeters.EgressBytes, row.Meter);
        Assert.Equal("2026-09-24", row.Bucket);
        Assert.Equal(300L, row.Quantity);
        Assert.Equal(100L, row.RedirectQuantity);
    }

    [Fact]
    public async Task Daily_read_is_scoped_to_the_requested_org()
    {
        await _events.InsertBatchAsync([Egress("o1", 1, T0), Egress("o2", 2, T0)]);
        await _rollups.RecomputeHourlyAsync(T0, T0.AddHours(1), T0.AddHours(1));
        await _rollups.RecomputeDailyEgressAsync(Day, Day.AddDays(1), T0.AddHours(1));

        var o2 = await _rollups.GetDailyAsync("o2", Day, Day.AddDays(1));

        var row = Assert.Single(o2);
        Assert.Equal("o2", row.OrgId);
        Assert.Equal(2L, row.Quantity);
    }

    [Fact]
    public async Task Storage_capture_bills_uploads_and_attributes_the_cache_separately()
    {
        await SeedStorageAsync();

        int captured = await _snapshots.CaptureAsync(Day, T0);

        Assert.Equal(3, captured);

        var o1 = await _snapshots.GetAsync("o1", Day);
        Assert.NotNull(o1);
        Assert.Equal(100L, o1.HostedBytes);
        Assert.Equal(5000L, o1.OciUploadedBytes);
        Assert.Equal(5100L, o1.BillableBytes);
        // The proxied npm artifact (200) and the proxy-cached OCI layer (70) count toward quota
        // but not toward the bill.
        Assert.Equal(270L, o1.CacheAttributedBytes);

        var empty = await _snapshots.GetAsync("o3", Day);
        Assert.NotNull(empty);
        Assert.Equal(0L, empty.BillableBytes);
        Assert.Equal(0L, empty.CacheAttributedBytes);

        var mark = Assert.Single(await _rollups.GetDailyAsync("o1", Day, Day.AddDays(1)));
        Assert.Equal(UsageMeters.StorageBytes, mark.Meter);
        Assert.Equal(5100L, mark.Quantity);
    }

    [Fact]
    public async Task A_later_smaller_capture_updates_the_snapshot_but_never_lowers_the_days_mark()
    {
        await SeedStorageAsync();
        await _snapshots.CaptureAsync(Day, T0);

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("DELETE FROM oci_blobs WHERE org_id = 'o1' AND origin = 'uploaded'");
        }

        await _snapshots.CaptureAsync(Day, T0.AddHours(6));

        var snapshot = await _snapshots.GetAsync("o1", Day);
        Assert.NotNull(snapshot);
        Assert.Equal(100L, snapshot.BillableBytes);

        var mark = Assert.Single(await _rollups.GetDailyAsync("o1", Day, Day.AddDays(1)));
        Assert.Equal(5100L, mark.Quantity);
    }

    [Fact]
    public async Task Storage_capture_counts_artefacts_blobs_cache_entries_and_database_rows()
    {
        await SeedCountsAsync();

        await _snapshots.CaptureAsync(Day, T0);

        var o1 = await _snapshots.GetAsync("o1", Day);
        Assert.NotNull(o1);
        // Two uploaded npm versions; the proxied npm version and the OCI catalogue row are not
        // hosted versions.
        Assert.Equal(2L, o1.HostedVersionCount);
        // The uploaded image manifest and index; the proxy-cached manifest is not uploaded.
        Assert.Equal(2L, o1.OciManifestCount);
        // The uploaded layer and config.
        Assert.Equal(2L, o1.OciBlobCount);
        Assert.Equal(2L, o1.CacheEntryCount);
        // packages 3 + tenant_artifact_access 2 + oci_blobs 5 + oci_tags 1 + activity 3.
        Assert.Equal(14L, o1.DbRowCount);
        Assert.Equal(4L, o1.ArtifactCount);

        var o2 = await _snapshots.GetAsync("o2", Day);
        Assert.NotNull(o2);
        Assert.Equal(1L, o2.HostedVersionCount);
        Assert.Equal(0L, o2.OciManifestCount);
        Assert.Equal(0L, o2.OciBlobCount);
        Assert.Equal(0L, o2.CacheEntryCount);
        // packages 1 + activity 1.
        Assert.Equal(2L, o2.DbRowCount);

        // An org with nothing still gets a row, with every count at zero.
        var o3 = await _snapshots.GetAsync("o3", Day);
        Assert.NotNull(o3);
        Assert.Equal(0L, o3.HostedVersionCount);
        Assert.Equal(0L, o3.OciManifestCount);
        Assert.Equal(0L, o3.OciBlobCount);
        Assert.Equal(0L, o3.CacheEntryCount);
        Assert.Equal(0L, o3.DbRowCount);
        Assert.Equal(0L, o3.ArtifactCount);

        var latest = await _snapshots.GetLatestAsync("o1");
        Assert.NotNull(latest);
        Assert.Equal(14L, latest.DbRowCount);
    }

    [Fact]
    public async Task A_later_capture_in_the_same_day_replaces_the_counts()
    {
        await SeedCountsAsync();
        await _snapshots.CaptureAsync(Day, T0);

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("DELETE FROM activity WHERE org_id = 'o1'");
            await conn.ExecuteAsync("DELETE FROM tenant_artifact_access WHERE org_id = 'o1'");
        }

        await _snapshots.CaptureAsync(Day, T0.AddHours(6));

        var o1 = await _snapshots.GetAsync("o1", Day);
        Assert.NotNull(o1);
        Assert.Equal(0L, o1.CacheEntryCount);
        Assert.Equal(9L, o1.DbRowCount);
    }

    /// <summary>
    /// The capture's manifest list is a SQL literal; every media type a push accepts as a manifest
    /// must count as one, or a new accepted type would silently be counted as a layer.
    /// </summary>
    [Fact]
    public async Task Every_accepted_manifest_media_type_counts_as_a_manifest()
    {
        await using (var conn = await _db.OpenAsync())
        {
            int i = 0;
            foreach (string mediaType in Dependably.Protocol.OciManifestParser.AcceptedMediaTypes)
            {
                i++;
                await conn.ExecuteAsync(
                    """
                    INSERT INTO oci_blobs (digest, org_id, blob_key, size_bytes, media_type, origin)
                    VALUES (@digest, 'o2', @blobKey, 1, @mediaType, 'uploaded')
                    """,
                    new { digest = $"sha256:m{i}", blobKey = $"oci/sha256/m{i}", mediaType });
            }
        }

        await _snapshots.CaptureAsync(Day, T0);

        var o2 = await _snapshots.GetAsync("o2", Day);
        Assert.NotNull(o2);
        Assert.Equal(Dependably.Protocol.OciManifestParser.AcceptedMediaTypes.Count, (int)o2.OciManifestCount);
        Assert.Equal(0L, o2.OciBlobCount);
    }

    /// <summary>
    /// Metering rows deliberately carry no foreign key to orgs: a hard-deleted org's final period
    /// must still be invoiceable.
    /// </summary>
    [Fact]
    public async Task Metering_rows_outlive_the_org_they_describe()
    {
        await _events.InsertBatchAsync([Egress("o2", 42, T0)]);
        await _rollups.RecomputeHourlyAsync(T0, T0.AddHours(1), T0.AddHours(1));
        await _rollups.RecomputeDailyEgressAsync(Day, Day.AddDays(1), T0.AddHours(1));
        await _snapshots.CaptureAsync(Day, T0);

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("DELETE FROM orgs WHERE id = 'o2'");

        Assert.Equal(1, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM usage_events WHERE org_id = 'o2'"));
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM usage_hourly WHERE org_id = 'o2'"));
        Assert.Equal(2, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM usage_daily WHERE org_id = 'o2'"));
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM storage_snapshot WHERE org_id = 'o2'"));
    }

    [Fact]
    public async Task Retention_removes_only_what_is_older_than_the_cutoff()
    {
        await _events.InsertBatchAsync([Egress("o1", 1, T0), Egress("o1", 2, T0.AddHours(2))]);
        await _rollups.RecomputeHourlyAsync(T0, T0.AddHours(3), T0.AddHours(3));

        int events = await _events.PruneOlderThanAsync(T0.AddHours(1));
        int hours = await _rollups.PruneHourlyOlderThanAsync(T0.AddHours(1));

        Assert.Equal(1, events);
        Assert.Equal(1, hours);
        var (_, _, Bucket, _, _) = Assert.Single(await HourlyAsync());
        Assert.Equal("2026-09-24T12:00:00Z", Bucket);
    }

    private static UsageEvent Egress(
        string orgId,
        long bytes,
        DateTimeOffset at,
        string delivery = UsageDelivery.Streamed,
        string meter = UsageMeters.EgressBytes) =>
        UsageEvent.Create(Guid.NewGuid(), orgId, meter, delivery, bytes, "npm", null, at);

    private async Task<List<(string OrgId, string Meter, string Bucket, long Quantity, long RedirectQuantity)>> HourlyAsync()
    {
        await using var conn = await _db.OpenAsync();
        var rows = await conn.QueryAsync<(string, string, string, long, long)>(
            "SELECT org_id, meter, bucket, quantity, redirect_quantity FROM usage_hourly ORDER BY org_id, meter, bucket");
        return rows.ToList();
    }

    private async Task<List<(string OrgId, string Meter, string Bucket, long RequestCount)>> HourlyCountsAsync()
    {
        await using var conn = await _db.OpenAsync();
        var rows = await conn.QueryAsync<(string, string, string, long)>(
            "SELECT org_id, meter, bucket, request_count FROM usage_hourly ORDER BY org_id, meter, bucket");
        return rows.ToList();
    }

    /// <summary>
    /// o1 holds two uploaded npm versions and one proxied npm version under two packages, one
    /// pushed OCI image (a catalogue row under a third package, one tag, and uploaded manifest,
    /// index, layer and config blobs), one proxy-cached OCI manifest, two proxy-cache entries,
    /// and three activity rows. o2 holds one uploaded npm version and one activity row. o3 holds
    /// nothing.
    /// </summary>
    private async Task SeedCountsAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES
              ('pa', 'o1', 'npm', 'a',     'a',     0),
              ('pb', 'o1', 'npm', 'b',     'b',     0),
              ('po', 'o1', 'oci', 'img',   'img',   0),
              ('pt', 'o2', 'npm', 'theirs', 'theirs', 0)
            """);
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, origin) VALUES
              ('va1', 'pa', '1.0.0', 'pkg:npm/a@1.0.0', 'registry/va1', 1, 'uploaded'),
              ('va2', 'pa', '2.0.0', 'pkg:npm/a@2.0.0', 'registry/va2', 1, 'uploaded'),
              ('vb1', 'pb', '1.0.0', 'pkg:npm/b@1.0.0', 'proxy/vb1',    1, 'proxy'),
              ('vo1', 'po', 'sha256:m1', 'pkg:oci/img@sha256:m1', 'oci/sha256/m1', 1, 'uploaded'),
              ('vt1', 'pt', '1.0.0', 'pkg:npm/theirs@1.0.0', 'registry/vt1', 1, 'uploaded')
            """);
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, blob_key, size_bytes, media_type, origin) VALUES
              ('sha256:m1', 'o1', 'oci/sha256/m1', 1, 'application/vnd.oci.image.manifest.v1+json', 'uploaded'),
              ('sha256:i1', 'o1', 'oci/sha256/i1', 1, 'application/vnd.oci.image.index.v1+json', 'uploaded'),
              ('sha256:l1', 'o1', 'oci/sha256/l1', 1, 'application/vnd.oci.image.layer.v1.tar+gzip', 'uploaded'),
              ('sha256:c1', 'o1', 'oci/sha256/c1', 1, 'application/vnd.oci.image.config.v1+json', 'uploaded'),
              ('sha256:pm', 'o1', 'oci/sha256/pm', 1, 'application/vnd.docker.distribution.manifest.v2+json', 'proxy')
            """);
        await conn.ExecuteAsync(
            "INSERT INTO oci_tags (org_id, repository, tag, digest) VALUES ('o1', 'img', 'latest', 'sha256:m1')");
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes) VALUES
              ('ca1', 'npm', 'x', '1.0.0', 'x-1.0.0.tgz', 'proxy/ca1', 'ca1', 1),
              ('ca2', 'npm', 'y', '1.0.0', 'y-1.0.0.tgz', 'proxy/ca2', 'ca2', 1)
            """);
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1', 'ca1'), ('o1', 'ca2')");
        await conn.ExecuteAsync(
            """
            INSERT INTO activity (id, org_id, ecosystem, event_type) VALUES
              ('a1', 'o1', 'npm', 'pull'),
              ('a2', 'o1', 'npm', 'pull'),
              ('a3', 'o1', 'npm', 'push'),
              ('a4', 'o2', 'npm', 'pull')
            """);
    }

    /// <summary>
    /// o1 holds one hosted npm version (100), one pushed OCI layer (5000), one proxied npm
    /// artifact (200) and one proxy-cached OCI layer (70). o2 holds one hosted version (999).
    /// o3 holds nothing.
    /// </summary>
    private async Task SeedStorageAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES
              ('ph', 'o1', 'npm', 'hosted-pkg', 'hosted-pkg', 0),
              ('pt', 'o2', 'npm', 'theirs',     'theirs',     0)
            """);
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, origin) VALUES
              ('vh', 'ph', '1.0.0', 'pkg:npm/hosted-pkg@1.0.0', 'registry/vh', 100, 'uploaded'),
              ('vt', 'pt', '1.0.0', 'pkg:npm/theirs@1.0.0',     'registry/vt', 999, 'uploaded')
            """);
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes) VALUES
              ('cap', 'npm', 'proxied-pkg', '2.0.0', 'proxied-pkg-2.0.0.tgz', 'proxy/cap', 'cap', 200)
            """);
        await conn.ExecuteAsync("INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1', 'cap')");
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, blob_key, size_bytes, media_type, origin) VALUES
              ('sha256:aaaa', 'o1', 'oci/sha256/aaaa', 5000, 'application/vnd.oci.image.layer.v1.tar+gzip', 'uploaded'),
              ('sha256:bbbb', 'o1', 'oci/sha256/bbbb', 70,   'application/vnd.oci.image.layer.v1.tar+gzip', 'proxy')
            """);
    }
}
