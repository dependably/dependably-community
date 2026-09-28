using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Live-Postgres regression for the <c>SystemTokenRepository.DeleteByOwnerAsync</c> /
/// <c>CreateAsync</c> serialization race: under READ COMMITTED, a mint whose <c>INSERT</c> runs
/// before a concurrent admin-password-reset's <c>token_version</c> bump commits, but whose own
/// <c>COMMIT</c> lands after that reset's <c>DELETE</c>, would otherwise survive the reset. Both
/// operations take the same <c>"system-tokens"</c> <c>BeginTenantSerializedAsync</c> advisory
/// lock, so they can never interleave.
///
/// SQLite's own single-writer <c>BEGIN IMMEDIATE</c> would mask a missing lock here (every write
/// is already serialized file-wide), so this proves the mutual exclusion holds against a real
/// Postgres backend, where two ordinary transactions genuinely can interleave without it.
///
/// Tagged <c>Category=SchemaPostgres</c> so it runs only in the <c>schema-integrity</c> CI job
/// (which attaches a Postgres service and sets <c>TEST_POSTGRES_CONNECTION</c>). Fails loudly
/// when the environment variable is absent rather than skipping silently.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class SystemTokenRepositoryPostgresRaceTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    /// <summary>
    /// Holds the same <c>"system-tokens"</c> advisory lock on a dedicated connection and confirms
    /// a concurrent <c>DeleteByOwnerAsync</c> call blocks until the lock is released — direct
    /// proof the two operations are mutually exclusive on Postgres, not an inference from timing.
    /// </summary>
    [Fact]
    public async Task DeleteByOwnerAsync_TakesTheSameAdvisoryLockAsCreateAsync_BlocksUntilReleased()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();

        string adminId = Guid.NewGuid().ToString("N");
        await using (var seed = await store.OpenAsync())
        {
            await seed.ExecuteAsync(
                "INSERT INTO system_admins (id, email, password_hash) VALUES (@id, @email, 'x')",
                new { id = adminId, email = $"{adminId}@example.com" });
        }

        var repo = new SystemTokenRepository(store, TestTime.Frozen());

        // Same lock key SystemTokenRepository.CreateAsync/DeleteByOwnerAsync use, held open on
        // our own connection so we control exactly when it releases.
        await using var lockConn = await store.OpenAsync();
        await lockConn.BeginTenantSerializedAsync(store.Provider, "system-tokens");

        var deleteTask = repo.DeleteByOwnerAsync(adminId);

        // now-ok: a bounded real-time wait proving the concurrent call is genuinely blocked on
        // the held lock, not merely slow — elapsed wall-clock time is the entire point here.
        await Task.WhenAny(deleteTask, Task.Delay(TimeSpan.FromMilliseconds(500)));
        Assert.False(deleteTask.IsCompleted,
            "DeleteByOwnerAsync completed while the shared 'system-tokens' advisory lock was still held — it is not serialized against CreateAsync on Postgres.");

        await lockConn.ExecuteAsync("COMMIT");

        int deleted = await deleteTask;
        Assert.Equal(0, deleted);
    }
}
