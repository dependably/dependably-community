using Dapper;
using Dependably.Infrastructure;
using Npgsql;

namespace Dependably.Tests.Integration;

/// <summary>
/// Resets the shared live-Postgres <c>public</c> schema for <c>Category=SchemaPostgres</c>
/// tests, guarded by a session-level <c>pg_advisory_lock</c> so two SEPARATE <c>dotnet test</c>
/// PROCESSES that both point <c>TEST_POSTGRES_CONNECTION</c> at the same server (e.g. a
/// worktree agent running integration tests alongside the main checkout) never race the
/// <c>DROP SCHEMA public CASCADE</c> reset against each other. The <c>[Collection("LivePostgres")]</c>
/// xunit collection only serializes test classes WITHIN one process — it cannot serialize
/// across processes, so this lock is the cross-process half of the guarantee.
///
/// The lock is held on its own dedicated connection for the lifetime of the returned handle —
/// from just before the reset until the caller disposes it — covering the whole window during
/// which the test's fresh schema must not be touched by anyone else. Postgres releases a
/// session-level advisory lock automatically when the holding connection closes (including a
/// crashed process), so a hard-killed test run cannot leave the lock permanently held.
/// </summary>
internal static class LivePostgresReset
{
    // Arbitrary fixed key: every process/test resetting this shared schema must contend for
    // the SAME advisory lock, so the key is a constant, not per-call.
    private const long AdvisoryLockKey = 0x0DE9_ED87_57A6_10CC;

    /// <summary>
    /// Acquires the cross-process advisory lock, resets <c>public</c> to a pristine slate, and
    /// returns a store plus a disposable handle that releases the lock. Callers should
    /// <c>await using</c> the handle for the whole test so no other process's reset can land
    /// mid-test.
    /// </summary>
    public static async Task<LivePostgresHandle> FreshAsync(string connectionString)
    {
        // Pooling=false is load-bearing: a session-level advisory lock is tied to the physical
        // backend session, not to the .NET NpgsqlConnection object. With the default pool,
        // DisposeAsync() only returns the connection to the pool — the backend session (and the
        // lock it holds) stays alive indefinitely, so the NEXT test's lock acquisition (a
        // different pooled connection) hangs forever waiting for a lock nobody will ever release.
        // Disabling pooling for this one dedicated connection makes Dispose() truly end the
        // session, which is what actually releases the lock (and is also what makes the lock
        // crash-safe: a killed process's TCP connection drops, ending the session either way).
        string lockConnectionString = new NpgsqlConnectionStringBuilder(connectionString) { Pooling = false }.ToString();
        var lockConnection = new NpgsqlConnection(lockConnectionString);
        await lockConnection.OpenAsync();
        await lockConnection.ExecuteAsync("SELECT pg_advisory_lock(@key)", new { key = AdvisoryLockKey });

        var store = new NpgsqlMetadataStore(connectionString);
        await using (var conn = await store.OpenAsync())
        {
            // Pristine slate: drop everything from a prior run so the apply starts from zero.
            await conn.ExecuteAsync("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
        }

        return new LivePostgresHandle(store, lockConnection);
    }
}

/// <summary>
/// Owns the live-Postgres store plus the advisory-lock connection for one test's reset window.
/// Disposing releases the lock by closing the dedicated lock connection.
/// </summary>
internal sealed class LivePostgresHandle(NpgsqlMetadataStore store, NpgsqlConnection lockConnection)
    : IAsyncDisposable
{
    public NpgsqlMetadataStore Store { get; } = store;

    public async ValueTask DisposeAsync() => await lockConnection.DisposeAsync();
}
