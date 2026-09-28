using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// The upstream-credential-history convergence on a real Postgres: the pass reads
/// <c>upstream_registry</c> (its secret flag is an <c>int4</c> there, not SQLite's integer) and
/// <c>upstream_registry_added</c> audit rows, and records credentialed ones, including an upstream
/// only the audit log still remembers. Tagged <c>Category=SchemaPostgres</c> like the other
/// live-Postgres schema tests.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class UpstreamCredentialHistoryPostgresTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    [Fact]
    public async Task Boot_RecordsCurrentAndAuditedCredentialedUpstreams()
    {
        var clock = TestTime.Frozen();
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store, time: clock).InitializeAsync();

        await using (var conn = await pg.Store.OpenAsync())
        {
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
            await conn.ExecuteAsync(
                """
                INSERT INTO upstream_registry (id, org_id, ecosystem, url, position, auth_type, username, secret)
                VALUES ('u1', 'o1', 'npm', 'https://registry.npmjs.org', 0, 'anonymous', NULL, NULL),
                       ('u2', 'o1', 'pypi', 'https://pypi.private.example', 0, 'bearer', NULL, 'legacy-plaintext')
                """);
            await conn.ExecuteAsync(
                """
                INSERT INTO audit_log (id, scope, org_id, action, detail, created_at)
                VALUES ('a1', 'tenant', 'o1', 'upstream_registry_added', @detail, @createdAt)
                """,
                new
                {
                    detail = """{"id":"gone","ecosystem":"oci","host":"registry.private.example","authType":"basic","prefixes":["t/"],"hasSecret":true,"name":null}""",
                    createdAt = clock.GetUtcNow().AddDays(-1).ToUtcIso(),
                });
        }

        await new SchemaInitializer(pg.Store, time: clock).InitializeAsync();

        await using var verify = await pg.Store.OpenAsync();
        var history = (await verify.QueryAsync<(string, string)>(
            "SELECT org_id, ecosystem FROM upstream_credential_history ORDER BY ecosystem")).ToList();
        Assert.Equal([("o1", "oci"), ("o1", "pypi")], history);
    }
}
