using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Usage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// <see cref="UsagePostureRepository"/>: where each meter's usage is read from (month-to-date
/// <c>usage_hourly</c>, the latest <c>storage_snapshot</c>), how caps are set and cleared, and the
/// fleet sweep's handling of a mixed fleet — over, throttled, cleared, pilot and untouched orgs in
/// one pass, each judged only by its own rows, with only changed postures written.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UsagePostureRepositoryTests : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 9, 24, 12, 30, 0, TimeSpan.Zero);

    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen(Now);
    private UsagePostureRepository _repo = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES ('o1', 'one'), ('o2', 'two'), ('o3', 'three'), ('o4', 'four'), ('o5', 'five')");
        _repo = new UsagePostureRepository(_db, _clock);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private async Task SeedHourlyAsync(string orgId, string meter, string bucket, long quantity)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO usage_hourly (org_id, meter, bucket, quantity, redirect_quantity, request_count, computed_at)
            VALUES (@orgId, @meter, @bucket, @quantity, 0, 1, '2026-09-24T12:00:00Z')
            """,
            new { orgId, meter, bucket, quantity });
    }

    private async Task SeedSnapshotAsync(string orgId, string day, long billable, long hostedVersions, long ociManifests)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO storage_snapshot
                (org_id, day_utc, hosted_bytes, oci_uploaded_bytes, cache_attributed_bytes, billable_bytes,
                 hosted_version_count, oci_manifest_count, oci_blob_count, cache_entry_count, db_row_count, captured_at)
            VALUES (@orgId, @day, 0, 0, 0, @billable, @hostedVersions, @ociManifests, 0, 0, 0, @day || 'T00:05:00Z')
            """,
            new { orgId, day, billable, hostedVersions, ociManifests });
    }

    private async Task SetPostureAsync(string orgId, string posture)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("UPDATE orgs SET usage_posture = @posture WHERE id = @orgId", new { orgId, posture });
    }

    private Task SetCapsAsync(string orgId, params (string Meter, long? Cap)[] caps) =>
        _repo.SetCapsAsync(orgId, caps.ToDictionary(c => c.Meter, c => c.Cap, StringComparer.Ordinal));

    [Fact]
    public async Task A_new_org_is_normal_with_no_caps()
    {
        Assert.Equal(UsagePostures.Normal, await _repo.GetPostureAsync("o1"));
        Assert.Empty(await _repo.GetCapsAsync("o1"));
    }

    [Fact]
    public async Task SetCaps_upserts_clears_and_leaves_unnamed_meters_alone()
    {
        await SetCapsAsync("o1", (UsageCapMeters.EgressBytes, 100), (UsageCapMeters.StorageBytes, 200));
        await SetCapsAsync("o1", (UsageCapMeters.EgressBytes, 150), (UsageCapMeters.ArtifactCount, 5));
        await SetCapsAsync("o1", (UsageCapMeters.StorageBytes, null));

        var caps = await _repo.GetCapsAsync("o1");
        Assert.Equal(2, caps.Count);
        Assert.Equal(150, caps[UsageCapMeters.EgressBytes]);
        Assert.Equal(5, caps[UsageCapMeters.ArtifactCount]);
        Assert.Empty(await _repo.GetCapsAsync("o2"));
    }

    [Fact]
    public async Task Egress_counts_only_this_UTC_months_buckets()
    {
        await SetCapsAsync("o1", (UsageCapMeters.EgressBytes, 1000));
        // The last hour of August is last month's usage, however large.
        await SeedHourlyAsync("o1", UsageMeters.EgressBytes, "2026-08-31T23:00:00Z", 1_000_000);
        await SeedHourlyAsync("o1", UsageMeters.EgressBytes, "2026-09-01T00:00:00Z", 600);
        await SeedHourlyAsync("o1", UsageMeters.EgressBytes, "2026-09-24T11:00:00Z", 399);

        Assert.Equal(UsagePostures.Normal, await _repo.RecomputeForOrgAsync("o1"));

        // One more byte in this month reaches the cap exactly.
        await SeedHourlyAsync("o1", UsageMeters.EgressBytes, "2026-09-24T12:00:00Z", 1);
        Assert.Equal(UsagePostures.UploadsRefused, await _repo.RecomputeForOrgAsync("o1"));
        Assert.Equal(UsagePostures.UploadsRefused, await _repo.GetPostureAsync("o1"));
    }

    [Fact]
    public async Task Egress_meters_are_measured_separately()
    {
        await SetCapsAsync("o1", (UsageCapMeters.EgressMetadataBytes, 100));
        await SeedHourlyAsync("o1", UsageMeters.EgressBytes, "2026-09-24T11:00:00Z", 10_000);
        await SeedHourlyAsync("o1", UsageMeters.EgressMetadataBytes, "2026-09-24T11:00:00Z", 109);

        Assert.Equal(UsagePostures.UploadsRefused, await _repo.RecomputeForOrgAsync("o1"));

        await SeedHourlyAsync("o1", UsageMeters.EgressMetadataBytes, "2026-09-24T12:00:00Z", 1);
        Assert.Equal(UsagePostures.DownloadsThrottled, await _repo.RecomputeForOrgAsync("o1"));
    }

    [Fact]
    public async Task Storage_and_artifact_count_read_the_latest_snapshot_only()
    {
        await SetCapsAsync("o1", (UsageCapMeters.StorageBytes, 5000), (UsageCapMeters.ArtifactCount, 10));
        // An older snapshot over both caps no longer counts.
        await SeedSnapshotAsync("o1", "2026-09-22", billable: 9000, hostedVersions: 50, ociManifests: 50);
        await SeedSnapshotAsync("o1", "2026-09-23", billable: 4999, hostedVersions: 6, ociManifests: 3);

        Assert.Equal(UsagePostures.Normal, await _repo.RecomputeForOrgAsync("o1"));

        // hosted_version_count + oci_manifest_count is the artefact count: 7 + 3 reaches the cap.
        await SeedSnapshotAsync("o1", "2026-09-24", billable: 10, hostedVersions: 7, ociManifests: 3);
        Assert.Equal(UsagePostures.UploadsRefused, await _repo.RecomputeForOrgAsync("o1"));
    }

    [Fact]
    public async Task Storage_cap_trips_on_billable_bytes_exactly_at_the_cap()
    {
        await SetCapsAsync("o1", (UsageCapMeters.StorageBytes, 5000));
        await SeedSnapshotAsync("o1", "2026-09-24", billable: 5000, hostedVersions: 0, ociManifests: 0);

        Assert.Equal(UsagePostures.UploadsRefused, await _repo.RecomputeForOrgAsync("o1"));
    }

    [Fact]
    public async Task No_snapshot_yet_measures_zero_storage_and_artifacts()
    {
        await SetCapsAsync("o1", (UsageCapMeters.StorageBytes, 1), (UsageCapMeters.ArtifactCount, 1));

        Assert.Equal(UsagePostures.Normal, await _repo.RecomputeForOrgAsync("o1"));
    }

    [Fact]
    public async Task Clearing_every_cap_returns_the_org_to_normal()
    {
        await SetCapsAsync("o1", (UsageCapMeters.EgressBytes, 10));
        await SeedHourlyAsync("o1", UsageMeters.EgressBytes, "2026-09-24T11:00:00Z", 100);
        Assert.Equal(UsagePostures.DownloadsThrottled, await _repo.RecomputeForOrgAsync("o1"));

        await SetCapsAsync("o1", (UsageCapMeters.EgressBytes, null));

        Assert.Equal(UsagePostures.Normal, await _repo.RecomputeForOrgAsync("o1"));
        Assert.Equal(UsagePostures.Normal, await _repo.GetPostureAsync("o1"));
    }

    [Fact]
    public async Task Sweep_settles_a_mixed_fleet_in_one_pass_and_writes_only_changes()
    {
        // o1: over its storage cap → uploads_refused.
        await SetCapsAsync("o1", (UsageCapMeters.StorageBytes, 100));
        await SeedSnapshotAsync("o1", "2026-09-24", billable: 100, hostedVersions: 0, ociManifests: 0);

        // o2: 110 % of its egress cap → downloads_throttled.
        await SetCapsAsync("o2", (UsageCapMeters.EgressBytes, 100));
        await SeedHourlyAsync("o2", UsageMeters.EgressBytes, "2026-09-24T10:00:00Z", 110);

        // o3: caps cleared while it was enforced → back to normal.
        await SetPostureAsync("o3", UsagePostures.UploadsRefused);

        // o4: a pilot with no caps and far more usage than anyone → stays normal, never touched.
        await SeedHourlyAsync("o4", UsageMeters.EgressBytes, "2026-09-24T10:00:00Z", 1_000_000_000);
        await SeedSnapshotAsync("o4", "2026-09-24", billable: 1_000_000_000, hostedVersions: 999, ociManifests: 999);

        // o5: capped but well under, sharing a bucket with o2's heavy usage → stays normal.
        await SetCapsAsync("o5", (UsageCapMeters.EgressBytes, 1000));
        await SeedHourlyAsync("o5", UsageMeters.EgressBytes, "2026-09-24T10:00:00Z", 1);

        int changed = await _repo.RecomputeAsync();

        Assert.Equal(3, changed);
        Assert.Equal(UsagePostures.UploadsRefused, await _repo.GetPostureAsync("o1"));
        Assert.Equal(UsagePostures.DownloadsThrottled, await _repo.GetPostureAsync("o2"));
        Assert.Equal(UsagePostures.Normal, await _repo.GetPostureAsync("o3"));
        Assert.Equal(UsagePostures.Normal, await _repo.GetPostureAsync("o4"));
        Assert.Equal(UsagePostures.Normal, await _repo.GetPostureAsync("o5"));

        // A second pass over the same data changes nothing.
        Assert.Equal(0, await _repo.RecomputeAsync());
    }

    [Fact]
    public async Task A_cap_lifted_mid_sweep_is_not_overwritten_by_the_sweeps_stale_posture()
    {
        // o1 was refused, and its usage has since grown past 110 % of the egress cap.
        await SetCapsAsync("o1", (UsageCapMeters.EgressBytes, 10));
        await SeedHourlyAsync("o1", UsageMeters.EgressBytes, "2026-09-24T11:00:00Z", 100);
        await SetPostureAsync("o1", UsagePostures.UploadsRefused);

        await using var conn = await _db.OpenAsync();
        var changes = await _repo.EvaluateFleetAsync(conn);
        Assert.Equal(
            new UsagePostureRepository.PostureChange("o1", UsagePostures.UploadsRefused, UsagePostures.DownloadsThrottled),
            Assert.Single(changes));

        // Between the sweep's read and its write, the operator lifts the cap (the usage-limits
        // PATCH: set caps, then recompute that org).
        await SetCapsAsync("o1", (UsageCapMeters.EgressBytes, null));
        Assert.Equal(UsagePostures.Normal, await _repo.RecomputeForOrgAsync("o1"));

        int written = await UsagePostureRepository.ApplyFleetAsync(conn, changes);

        Assert.Equal(0, written);
        Assert.Equal(UsagePostures.Normal, await _repo.GetPostureAsync("o1"));
    }

    [Fact]
    public async Task Without_a_concurrent_change_the_sweeps_write_lands()
    {
        await SetCapsAsync("o1", (UsageCapMeters.EgressBytes, 10));
        await SeedHourlyAsync("o1", UsageMeters.EgressBytes, "2026-09-24T11:00:00Z", 100);
        await SetPostureAsync("o1", UsagePostures.UploadsRefused);

        await using var conn = await _db.OpenAsync();
        int written = await UsagePostureRepository.ApplyFleetAsync(conn, await _repo.EvaluateFleetAsync(conn));

        Assert.Equal(1, written);
        Assert.Equal(UsagePostures.DownloadsThrottled, await _repo.GetPostureAsync("o1"));
    }

    [Fact]
    public async Task Sweep_matches_the_single_org_recompute()
    {
        await SetCapsAsync("o1", (UsageCapMeters.EgressBytes, 1000), (UsageCapMeters.ArtifactCount, 3));
        await SeedHourlyAsync("o1", UsageMeters.EgressBytes, "2026-08-31T23:00:00Z", 5000);
        await SeedHourlyAsync("o1", UsageMeters.EgressBytes, "2026-09-02T03:00:00Z", 999);
        await SeedSnapshotAsync("o1", "2026-09-20", billable: 0, hostedVersions: 3, ociManifests: 0);
        await SeedSnapshotAsync("o1", "2026-09-23", billable: 0, hostedVersions: 1, ociManifests: 1);

        await _repo.RecomputeAsync();
        string swept = await _repo.GetPostureAsync("o1");
        string single = await _repo.RecomputeForOrgAsync("o1");

        Assert.Equal(UsagePostures.Normal, swept);
        Assert.Equal(swept, single);
    }

    [Fact]
    public async Task The_schema_rejects_a_zero_cap_and_an_unknown_meter()
    {
        await Assert.ThrowsAnyAsync<Exception>(() => SetCapsAsync("o1", (UsageCapMeters.EgressBytes, 0)));
        await Assert.ThrowsAnyAsync<Exception>(() => SetCapsAsync("o1", ("requests", 10)));
        Assert.Empty(await _repo.GetCapsAsync("o1"));
    }

    [Fact]
    public void Month_start_is_the_first_hour_of_the_UTC_month()
    {
        Assert.Equal("2026-09-01T00:00:00Z", UsagePostureRepository.MonthStartBucket(Now));
        // 23:30 on the 30th at UTC-5 is already October in UTC.
        Assert.Equal(
            "2026-10-01T00:00:00Z",
            UsagePostureRepository.MonthStartBucket(new DateTimeOffset(2026, 9, 30, 23, 30, 0, TimeSpan.FromHours(-5))));
    }
}
