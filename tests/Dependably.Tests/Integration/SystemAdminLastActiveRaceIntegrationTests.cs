using Dependably.Infrastructure;
using Dependably.Infrastructure.Startup;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;

namespace Dependably.Tests.Integration;

/// <summary>
/// The last-active system admin guard against the production stores rather than the in-memory
/// unit store: a file-backed <see cref="SqliteMetadataStore"/> (WAL, <c>busy_timeout</c>) in the
/// SQLite integration job, and a real Postgres database under READ COMMITTED in the
/// <c>TEST_INTEGRATION_DB=postgres</c>/<c>postgres-rls</c> jobs, where two transactions touching
/// different rows genuinely interleave unless the guard serializes them.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SystemAdminLastActiveRaceIntegrationTests : IAsyncLifetime
{
    private const int FreeRunningRounds = 20;

    private readonly string _sqliteFile = Path.Combine(
        Path.GetTempPath(), $"dependably_last_admin_{Guid.NewGuid():N}.db");
    private PostgresTestDatabase? _postgres;
    private IMetadataStore _store = null!;

    public async Task InitializeAsync()
    {
        if (DependablyFactory.IntegrationDatabase == "sqlite")
        {
            _store = new SqliteMetadataStore(StorageStartupExtensions.BuildSqliteConnectionString(_sqliteFile));
            await new SchemaInitializer(_store).InitializeAsync();
            return;
        }

        // The template the database is cloned from already carries the converged schema.
        _postgres = await PostgresTestDatabase.CreateAsync();
        _store = new NpgsqlMetadataStore(_postgres.OwnerConnectionString);
    }

    public async Task DisposeAsync()
    {
        if (_postgres is not null)
        {
            await _postgres.DisposeAsync();
            return;
        }

        SqliteConnection.ClearAllPools();
        foreach (string suffix in new[] { "", "-wal", "-shm" })
        {
            File.Delete(_sqliteFile + suffix);
        }
    }

    [Theory]
    [InlineData("disabled", "disabled")]
    [InlineData("disabled", "locked")]
    public async Task MutualStatusChange_InLockstep_LeavesExactlyOneActiveAdmin(string statusForB, string statusForA)
    {
        await LastActiveAdminRace.DisableAllAsync(_store);
        string a = await SystemAdminSeeder.InsertAsync(_store, $"a-{Guid.NewGuid():N}@x.test");
        string b = await SystemAdminSeeder.InsertAsync(_store, $"b-{Guid.NewGuid():N}@x.test");

        var (byA, byB) = await LastActiveAdminRace.MutualAsync(_store, a, b, statusForB, statusForA);

        AssertExactlyOneWinner(byA, byB);
        string survivor = Assert.Single(await LastActiveAdminRace.ActiveIdsAsync(_store));
        Assert.Equal(byA.Status == StatusCodes.Status204NoContent ? a : b, survivor);
    }

    [Fact]
    public async Task MutualDisable_FreeRunning_NeverEmptiesTheActiveSet()
    {
        // No lockstep: the pair runs at whatever interleaving the engine produces, many times
        // over, and the invariant has to hold on every round.
        for (int round = 0; round < FreeRunningRounds; round++)
        {
            await LastActiveAdminRace.DisableAllAsync(_store);
            string a = await SystemAdminSeeder.InsertAsync(_store, $"a{round}-{Guid.NewGuid():N}@x.test");
            string b = await SystemAdminSeeder.InsertAsync(_store, $"b{round}-{Guid.NewGuid():N}@x.test");
            var byA = LastActiveAdminRace.Controller(_store, _store, actorId: a);
            var byB = LastActiveAdminRace.Controller(_store, _store, actorId: b);

            var results = await Task.WhenAll(
                Task.Run(() => byA.SetAdminAccountStatus(
                    b, new Dependably.Api.SetAdminAccountStatusRequest("disabled"), CancellationToken.None)),
                Task.Run(() => byB.SetAdminAccountStatus(
                    a, new Dependably.Api.SetAdminAccountStatusRequest("disabled"), CancellationToken.None)));

            AssertExactlyOneWinner(LastActiveAdminRace.Describe(results[0]), LastActiveAdminRace.Describe(results[1]));
            Assert.Single(await LastActiveAdminRace.ActiveIdsAsync(_store));
        }
    }

    private static void AssertExactlyOneWinner(LastActiveAdminRace.Response byA, LastActiveAdminRace.Response byB)
    {
        var both = new[] { byA, byB };
        Assert.Single(both, r => r.Status == StatusCodes.Status204NoContent);
        var refused = Assert.Single(both, r => r.Status == StatusCodes.Status409Conflict);
        Assert.Equal("last_active_admin", refused.Reason);
    }
}
