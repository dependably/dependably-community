using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.RowLevelSecurity;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Dependably.Tests.Integration;

/// <summary>
/// Pins the integration hosts to the database <c>TEST_INTEGRATION_DB</c> names, so a CI job meant to
/// run the suite on enforced Postgres cannot quietly run it on SQLite and pass — and pins the harness
/// seam that separates test-code database access from host work.
/// </summary>
[Trait("Category", "Integration")]
public sealed class IntegrationDatabaseModeTests(DependablyFactory factory) : IClassFixture<DependablyFactory>
{
    [Fact]
    public void Host_RunsOnTheDatabaseTheModeNames() =>
        AssertModeMatches(factory.Services.GetRequiredService<IMetadataStore>());

    // The enforced-Postgres CI job exists to run on enforced Postgres; a dropped or mistyped
    // TEST_INTEGRATION_DB would otherwise run it on SQLite and still pass every other test.
    [Fact]
    public void EnforcedPostgresJob_RunsInEnforcedMode()
    {
        if (Environment.GetEnvironmentVariable("CI_JOB_NAME") == "integration-tests-postgres-rls")
        {
            Assert.Equal("postgres-rls", DependablyFactory.IntegrationDatabase);
        }
    }

    [Fact]
    public void TestBody_IsMarkedAsHarnessAccess()
    {
        // Seeding through a repository resolved before the test body must not be read as the
        // host's own undeclared background work.
        Assert.True(TestHarnessDbScope.IsActive);
    }

    // Host work a test drives directly runs without the harness privilege: an undeclared scope
    // raises exactly as it would in production, so a pass that forgot its DbScope cannot pass here.
    [Fact]
    public async Task AsHost_StripsTheHarnessPrivilege()
    {
        var store = factory.Services.GetRequiredService<IMetadataStore>();

        await using (var seeding = await store.OpenAsync())
        {
            Assert.True(await seeding.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM org_settings") > 0);
        }

        if (DependablyFactory.IntegrationDatabase != "postgres-rls")
        {
            return;
        }

        var ex = await Assert.ThrowsAsync<PostgresException>(() => TestHarnessDbScope.AsHostAsync(async () =>
        {
            await using var host = await store.OpenAsync();
            return await host.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM org_settings");
        }));
        Assert.Equal(PostgresRowLevelSecurityInstaller.NoTenantContextSqlState, ex.SqlState);

        long declared = await TestHarnessDbScope.AsHostAsync(async () =>
        {
            using (DbScope.CrossTenant("test: a declared sweep"))
            {
                await using var host = await store.OpenAsync();
                return await host.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM org_settings");
            }
        });
        Assert.True(declared > 0);
    }

    internal static void AssertModeMatches(IMetadataStore store)
    {
        switch (DependablyFactory.IntegrationDatabase)
        {
            case "sqlite":
                Assert.Equal(DbProvider.Sqlite, store.Provider);
                break;
            case "postgres":
                Assert.False(Assert.IsType<NpgsqlMetadataStore>(store).RowLevelSecurity.Enforced);
                break;
            default:
                Assert.True(Assert.IsType<NpgsqlMetadataStore>(store).RowLevelSecurity.Enforced);
                break;
        }
    }
}

/// <summary>The multi-org host follows the same mode as the single-org one.</summary>
[Trait("Category", "Integration")]
public sealed class MultiTenantIntegrationDatabaseModeTests(DependablyMultiFactory factory)
    : IClassFixture<DependablyMultiFactory>
{
    [Fact]
    public void MultiTenantHost_RunsOnTheDatabaseTheModeNames() =>
        IntegrationDatabaseModeTests.AssertModeMatches(factory.Services.GetRequiredService<IMetadataStore>());
}
