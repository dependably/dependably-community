using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Compliance;

namespace Dependably.Tests.Integration;

/// <summary>
/// The upgrade boot against a LIVE Postgres server, starting from the previous release's
/// <c>Schema.pg.sql</c> rather than from an empty database. Every other schema test applies the
/// current schema to a pristine slate, which is the one shape that cannot see an ordering fault
/// between the declarative schema file and <c>RunAdditiveMigrationsAsync</c>: on a fresh database
/// the <c>CREATE TABLE</c> blocks put every column in place before anything else runs.
///
/// <para>On an existing database those blocks are no-ops, so any other statement in the file
/// resolves against the shape the database already has. Postgres reports that as
/// <c>42703 column … does not exist</c> and aborts the apply, which is a crash loop on every
/// upgrade boot — the loudest possible form of the fault, and the one this test detects. SQLite
/// takes the same fault silently, so its arm of the check is the object-inventory assertion in
/// <c>SchemaUpgradeFromPreviousReleaseTests</c> plus the static
/// <see cref="SchemaUpgradeOrderComplianceTests"/> gate.</para>
///
/// <para>Tagged <c>Category=SchemaPostgres</c> — see <c>PostgresSchemaApplyTests</c> for why this
/// only runs where a live Postgres is attached.</para>
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class SchemaUpgradeFromPreviousReleasePostgresTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    [Fact]
    public async Task Initializing_APreviousReleaseDatabase_Succeeds()
    {
        var resolution = SchemaBaselineResolver.Resolve();
        if (resolution.Baseline is null)
        {
            Assert.True(
                SchemaBaselineResolver.IsTolerable(
                    resolution,
                    string.Equals(
                        Environment.GetEnvironmentVariable("SCHEMA_BACKCOMPAT_REQUIRE_BASELINE"),
                        "true",
                        StringComparison.OrdinalIgnoreCase)),
                $"the previous release's schema could not be resolved ({resolution.Absence}), so "
                + "the upgrade boot was never exercised: " + resolution.Log);
            return;
        }

        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);

        // The previous release's database, as a live slot running that release would have it.
        await using (var conn = await pg.Store.OpenAsync())
        {
            await conn.ExecuteAsync(resolution.Baseline.PostgresSql);
        }

        // The whole point: this is the boot an operator performs when they roll this build out.
        var thrown = await Record.ExceptionAsync(() => new SchemaInitializer(pg.Store).InitializeAsync());
        Assert.True(
            thrown is null,
            $"upgrading a {resolution.Baseline.Tag} database threw, so this build crash-loops on "
            + $"every upgrade boot: {thrown}");

        await using (var conn = await pg.Store.OpenAsync())
        {
            var columns = (await conn.QueryAsync<string>(
                """
                SELECT column_name FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'tenant_artifact_access'
                """)).ToList();
            Assert.Contains("content_hash", columns);
            Assert.Contains("blob_key", columns);
            Assert.Contains("size_bytes", columns);

            Assert.Equal(1, await conn.ExecuteScalarAsync<long>(
                """
                SELECT COUNT(*) FROM pg_indexes
                WHERE schemaname = 'public' AND indexname = 'idx_tenant_artifact_access_blob_key'
                """));
        }
    }
}
