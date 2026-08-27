using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Runs <see cref="ProjectRepository.DeleteVersionAsync"/>'s <c>DELETE … RETURNING is_latest</c>
/// against a live Postgres server through the production <see cref="NpgsqlMetadataStore"/>.
///
/// <para>The SQLite path is covered by <c>ProjectDeleteVersionLatestPromotionTests</c>, and that
/// coverage is precisely what does not settle this: the reason the method reads the flag through
/// RETURNING rather than a preceding SELECT is a Postgres READ COMMITTED hazard that SQLite's
/// writer serialization hides. A two-statement form passes every SQLite test and still leaves a
/// Postgres replica set able to reach zero-latest, so the statement that replaces it has to be
/// proven on the provider it exists for — including that Dapper materializes the returned column
/// as a scalar over Npgsql, and that a no-match delete surfaces as NULL rather than as an
/// exception.</para>
///
/// <para>Tagged <c>Category=SchemaPostgres</c> so it runs in the <c>schema-integrity</c> CI job,
/// which attaches a Postgres service and sets <c>TEST_POSTGRES_CONNECTION</c>. Fails loudly when
/// the variable is absent rather than skipping silently.</para>
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class ProjectDeleteVersionPromotionPostgresTests
{
    private const string OrgId = "o1";

    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    [Fact]
    public async Task DeleteVersion_OnLivePostgres_ReturnsTheFlagAndPromotesTheNewestSurvivor()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();

        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@OrgId, 'acme')", new { OrgId });
        await conn.ExecuteAsync(
            "INSERT INTO projects (id, org_id, name) VALUES ('p1', @OrgId, 'billing-api')",
            new { OrgId });

        string older = await SeedVersionAsync(conn, "1.0.0", ageDays: 40, isLatest: false);
        string newer = await SeedVersionAsync(conn, "2.0.0", ageDays: 20, isLatest: false);
        string latest = await SeedVersionAsync(conn, "3.0.0", ageDays: 10, isLatest: true);

        var repo = new ProjectRepository(store, TestTime.Frozen());

        // RETURNING reports the deleted row's own flag, so the promotion branch fires.
        Assert.True(await repo.DeleteVersionAsync(OrgId, "p1", latest));
        Assert.Equal(newer, await LatestIdAsync(conn));
        Assert.Equal(1, await LatestCountAsync(conn));

        // A non-latest delete returns 0 from RETURNING and moves nothing.
        Assert.True(await repo.DeleteVersionAsync(OrgId, "p1", older));
        Assert.Equal(newer, await LatestIdAsync(conn));
        Assert.Equal(1, await LatestCountAsync(conn));

        // A no-match delete returns no rows at all; Dapper reads that as a null int? rather than
        // throwing, which is the branch that answers false.
        Assert.False(await repo.DeleteVersionAsync(OrgId, "p1", Guid.NewGuid().ToString("N")));
        Assert.Equal(newer, await LatestIdAsync(conn));

        // Deleting the last remaining version correctly leaves the project latest-less.
        Assert.True(await repo.DeleteVersionAsync(OrgId, "p1", newer));
        Assert.Equal(0, await LatestCountAsync(conn));
    }

    private static async Task<string> SeedVersionAsync(
        System.Data.Common.DbConnection conn, string version, int ageDays, bool isLatest)
    {
        string id = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO project_versions (id, org_id, project_id, version, is_latest, created_at)
            VALUES (@id, @OrgId, 'p1', @version, @isLatest, @createdAt)
            """,
            new
            {
                id,
                OrgId,
                version,
                isLatest = isLatest ? 1 : 0,
                createdAt = TestTime.KnownNow.AddDays(-ageDays).ToUtcIso(),
            });
        return id;
    }

    private static async Task<string?> LatestIdAsync(System.Data.Common.DbConnection conn) =>
        await conn.ExecuteScalarAsync<string?>(
            "SELECT id FROM project_versions WHERE project_id = 'p1' AND is_latest = 1");

    private static async Task<long> LatestCountAsync(System.Data.Common.DbConnection conn) =>
        await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM project_versions WHERE project_id = 'p1' AND is_latest = 1");
}
