using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Npgsql;

namespace Dependably.Tests.Integration;

/// <summary>
/// Live-Postgres race for <see cref="OrgRepository.UpdateOrgStatusAsync"/>. Under READ COMMITTED a
/// status write that decided whether to revoke from an unlocked read could see the status from
/// before a concurrent, still-uncommitted suspension, skip the revocation, and then land
/// <c>active</c> on top of the suspension once it committed. The write locks the org row before
/// it decides, so it waits for the suspension and then revokes on leaving it.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class TenantStatusRevocationPostgresRaceTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    [Fact]
    public async Task RestoreRacingAnUncommittedSuspension_WaitsForIt_AndRevokesOnLeavingIt()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();

        string orgId = await OrgSeeder.InsertAsync(store, "pg-status-race");
        string userId = await UserSeeder.InsertAsync(store, orgId, "race@x.test");
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE orgs SET status = 'read_only' WHERE id = @orgId", new { orgId });
        }

        long before = await ReadTokenVersionAsync(store, userId);

        // The suspension: written and holding the org row's lock, not yet committed.
        await using var suspender = new NpgsqlConnection(ConnectionString);
        await suspender.OpenAsync();
        await using var suspension = await suspender.BeginTransactionAsync();
        await suspender.ExecuteAsync(
            "UPDATE orgs SET status = 'suspended' WHERE id = @orgId", new { orgId }, suspension);

        var restore = new OrgRepository(store, time: TestTime.Frozen()).UpdateOrgStatusAsync(orgId, "active");
        await WaitUntilABackendIsBlockedOnALockAsync();
        Assert.False(restore.IsCompleted, "the restore must wait for the uncommitted suspension");

        await suspension.CommitAsync();
        Assert.True((await restore).Applied);

        await using (var conn = await store.OpenAsync())
        {
            Assert.Equal("active", await conn.ExecuteScalarAsync<string>(
                "SELECT status FROM orgs WHERE id = @orgId", new { orgId }));
        }

        Assert.Equal(before + 1, await ReadTokenVersionAsync(store, userId));
    }

    private static async Task<long> ReadTokenVersionAsync(IMetadataStore store, string userId)
    {
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT token_version FROM users WHERE id = @userId", new { userId });
    }

    private static async Task WaitUntilABackendIsBlockedOnALockAsync()
    {
        await using var probe = new NpgsqlConnection(ConnectionString);
        await probe.OpenAsync();
        for (int i = 0; i < 200; i++)
        {
            long waiting = await probe.ExecuteScalarAsync<long>(
                """
                SELECT COUNT(*) FROM pg_stat_activity
                WHERE datname = current_database() AND wait_event_type = 'Lock'
                """);
            if (waiting > 0)
            {
                return;
            }

            // now-ok: polls for a real backend on another connection to block on a row lock.
            await Task.Delay(TimeSpan.FromMilliseconds(50), TimeProvider.System);
        }

        throw new TimeoutException("no backend blocked on the org row lock within 10 s");
    }
}
