using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Usage;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// The posture sweep and the single-org recompute with <see cref="DefaultUsageCaps"/> configured,
/// against a LIVE Postgres: the sweep's all-orgs switch is a bound integer compared in SQL, so
/// the candidate, egress and snapshot reads must each widen to every org on Postgres as they do
/// on SQLite (<see cref="Unit.Infrastructure.UsagePostureRepositoryTests"/>), and stay narrowed to
/// capped orgs with no defaults.
///
/// Tagged <c>Category=SchemaPostgres</c> — see <c>PostgresSchemaApplyTests</c> for why this only
/// runs where a live Postgres is attached.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class UsagePostureDefaultCapsPostgresTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 24, 12, 30, 0, TimeSpan.Zero);

    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    private static async Task SeedAsync(IMetadataStore store)
    {
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES ('o1', 'one'), ('o2', 'two'), ('o3', 'three'), ('o4', 'four')");
        // o1: at the default storage cap. o2: 110 % of the default egress cap. o3: under both.
        // o4: far over the egress default, exempted by an explicit higher cap.
        await conn.ExecuteAsync(
            """
            INSERT INTO storage_snapshot
                (org_id, day_utc, hosted_bytes, oci_uploaded_bytes, cache_attributed_bytes, billable_bytes,
                 hosted_version_count, oci_manifest_count, oci_blob_count, cache_entry_count, db_row_count, captured_at)
            VALUES ('o1', '2026-09-24', 0, 0, 0, 1000, 0, 0, 0, 0, 0, '2026-09-24T00:05:00Z')
            """);
        await conn.ExecuteAsync(
            """
            INSERT INTO usage_hourly (org_id, meter, bucket, quantity, redirect_quantity, request_count, computed_at)
            VALUES ('o2', 'egress_bytes', '2026-09-24T10:00:00Z', 110, 0, 1, '2026-09-24T12:00:00Z'),
                   ('o3', 'egress_bytes', '2026-09-24T10:00:00Z', 99, 0, 1, '2026-09-24T12:00:00Z'),
                   ('o4', 'egress_bytes', '2026-09-24T10:00:00Z', 1000000, 0, 1, '2026-09-24T12:00:00Z')
            """);
    }

    [Fact]
    public async Task Default_caps_enforce_every_org_on_postgres_and_no_defaults_enforce_none()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        await SeedAsync(pg.Store);
        var clock = TestTime.Frozen(Now);

        // Unset: nobody has a cap, so the sweep evaluates and changes nothing.
        var unset = new UsagePostureRepository(pg.Store, clock);
        Assert.Equal(0, await unset.RecomputeAsync());

        var repo = new UsagePostureRepository(
            pg.Store, clock, DefaultUsageCaps.Parse("egress_bytes=100,storage_bytes=1000"));
        await repo.SetCapsAsync(
            "o4", new Dictionary<string, long?> { [UsageCapMeters.EgressBytes] = long.MaxValue });

        Assert.Equal(2, await repo.RecomputeAsync());
        Assert.Equal(UsagePostures.UploadsRefused, await repo.GetPostureAsync("o1"));
        Assert.Equal(UsagePostures.DownloadsThrottled, await repo.GetPostureAsync("o2"));
        Assert.Equal(UsagePostures.Normal, await repo.GetPostureAsync("o3"));
        Assert.Equal(UsagePostures.Normal, await repo.GetPostureAsync("o4"));

        foreach (string org in new[] { "o1", "o2", "o3", "o4" })
        {
            Assert.Equal(await repo.GetPostureAsync(org), await repo.RecomputeForOrgAsync(org));
        }

        // Clearing o4's explicit cap returns it to the default it is far over.
        await repo.SetCapsAsync("o4", new Dictionary<string, long?> { [UsageCapMeters.EgressBytes] = null });
        Assert.Equal(UsagePostures.DownloadsThrottled, await repo.RecomputeForOrgAsync("o4"));
    }
}
