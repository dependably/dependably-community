using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// The deprecation-refresh group enumeration and its per-org stamp executed against live Postgres.
/// <see cref="Unit.DeprecationRefreshBatchBoundaryTests"/> pins the scheduling on SQLite; this
/// proves the same order on the other provider, where <c>ORDER BY … ASC</c> sorts NULL last rather
/// than first, so a never-processed group would otherwise queue behind every stale one.
///
/// Tagged <c>Category=SchemaPostgres</c> so it runs only where <c>TEST_POSTGRES_CONNECTION</c> is
/// set (the <c>schema-integrity</c> CI job); it fails loudly rather than skipping when it is not.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class DeprecationRefreshSchedulingPostgresTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    [Fact]
    public async Task NeverProcessedGroupsLead_AndOneOrgsStampLeavesTheOtherOrgDue()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();
        var clock = TestTime.Frozen();

        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o-a', 'a'), ('o-b', 'b')");
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash)
                VALUES ('ca-shared', 'npm', 'shared', '1.0.0', 'shared-1.0.0.tgz', 'proxy/s', 's'),
                       ('ca-stale', 'npm', 'aaa-stale', '1.0.0', 'aaa-stale-1.0.0.tgz', 'proxy/t', 't')
                """);
            await conn.ExecuteAsync(
                """
                INSERT INTO tenant_artifact_access (org_id, cache_artifact_id, refresh_checked_at)
                VALUES ('o-a', 'ca-shared', NULL),
                       ('o-b', 'ca-shared', NULL),
                       ('o-a', 'ca-stale', @stale)
                """,
                new { stale = clock.GetUtcNow().AddDays(-30).ToUtcIso() });
        }

        var repo = new CacheArtifactRepository(store);

        // Both never-processed groups lead, tie broken on org id, ahead of the stale one even
        // though its name sorts first.
        Assert.Equal(
            new[] { ("npm", "shared", "o-a"), ("npm", "shared", "o-b"), ("npm", "aaa-stale", "o-a") },
            await repo.ListGroupsNeedingDeprecationRefreshAsync(24, 10, clock));

        Assert.Equal(1, await repo.StampRefreshCheckedAtForOrgAsync("o-a", "npm", "shared", clock));

        // A's stamp settles A's group only; B's group for the same shared row is still due, and
        // still leads.
        Assert.Equal(
            new[] { ("npm", "shared", "o-b"), ("npm", "aaa-stale", "o-a") },
            await repo.ListGroupsNeedingDeprecationRefreshAsync(24, 10, clock));
    }
}
