using Dapper;
using Dependably.Infrastructure;
using Npgsql;

namespace Dependably.Tests.Integration;

/// <summary>
/// Proves the Postgres side of the canonical-timestamp CHECK constraint against a LIVE server:
/// fresh installs reject a bad-shaped INSERT and accept every canonical shape, via the constraint
/// declared inline in <c>Schema.pg.sql</c>'s <c>CREATE TABLE</c> block.
///
/// The existing-database retrofit is proven separately, by
/// <see cref="TemporalCheckRetrofitPostgresTests"/>.
///
/// Tagged <c>Category=SchemaPostgres</c> — see <see cref="PostgresSchemaApplyTests"/> for why this
/// only runs in the dedicated <c>schema-integrity</c> CI job.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class TemporalCheckConstraintPostgresTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    public static TheoryData<string> AcceptedShapes() => new()
    {
        "2026-03-04T05:06:07Z",
        "2026-03-04T05:06:07.123Z",
        "2026-03-04T05:06:07.123456Z",
    };

    public static TheoryData<string> RejectedShapes() => new()
    {
        "2026-03-04 05:06:07+02:00",
        "2026-03-04T05:06:07.0000000+00:00",
        "",
        "not a date",
        "20260304050607",
    };

    [Theory]
    [MemberData(nameof(AcceptedShapes))]
    public async Task FreshInstall_AcceptsEveryCanonicalShape(string value)
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();

        await using var conn = await pg.Store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug, deleted_at) VALUES ('o1', 'acme', @value)", new { value });

        string stored = await conn.QuerySingleAsync<string>("SELECT deleted_at FROM orgs WHERE id = 'o1'");
        Assert.Equal(value, stored);
    }

    [Theory]
    [MemberData(nameof(RejectedShapes))]
    public async Task FreshInstall_RejectsEveryObservedBadShape(string value)
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();

        await using var conn = await pg.Store.OpenAsync();
        var ex = await Assert.ThrowsAsync<PostgresException>(() => conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug, deleted_at) VALUES ('o1', 'acme', @value)", new { value }));

        Assert.Equal("23514", ex.SqlState); // check_violation
    }

    [Fact]
    public async Task FreshInstall_PermitsNull()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();

        await using var conn = await pg.Store.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug, deleted_at) VALUES ('o1', 'acme', NULL)");

        string? stored = await conn.QuerySingleAsync<string?>(
            "SELECT deleted_at FROM orgs WHERE id = 'o1'");
        Assert.Null(stored);
    }

    [Fact]
    public async Task SecondApply_IsANoOp_AndConstraintStaysValidated()
    {
        // A second InitializeAsync (a replica boot, a restart) must be a clean no-op against the
        // fresh-install CHECK: the retrofit's pg_constraint probe sees a validated constraint and
        // leaves it alone rather than re-adding or re-validating it.
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var initializer = new SchemaInitializer(pg.Store);
        await initializer.InitializeAsync();

        var ex = await Record.ExceptionAsync(() => initializer.InitializeAsync());
        Assert.Null(ex);

        await using var conn = await pg.Store.OpenAsync();
        bool validated = await conn.ExecuteScalarAsync<bool>(
            "SELECT convalidated FROM pg_constraint WHERE conname = 'orgs_deleted_at_check'");
        Assert.True(validated);
    }
}
