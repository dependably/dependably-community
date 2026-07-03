using System.Data.Common;
using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Provider-aware serialization primitive for the bootstrap/first-boot critical sections.
///
/// SQLite serialises concurrent first-boot attempts (blue/green deploys racing the same DB
/// file) with <c>BEGIN IMMEDIATE</c>, which takes a write lock at transaction start. PostgreSQL's
/// <c>BEGIN</c> grammar accepts only ISOLATION LEVEL / READ WRITE / READ ONLY / [NOT] DEFERRABLE,
/// so <c>BEGIN IMMEDIATE</c> is a 42601 syntax error there. On Postgres this opens a plain
/// transaction and takes a transaction-scoped advisory lock, which reproduces the
/// concurrent-start serialization the SQLite immediate write lock provides and is released
/// automatically on COMMIT/ROLLBACK.
///
/// COMMIT and ROLLBACK are grammar-identical on both providers, so callers close the
/// transaction with the plain statements after calling this.
/// </summary>
public static class MetadataTransactionExtensions
{
    // Stable 64-bit key shared by every serialized-bootstrap site so concurrent replica starts
    // contend on the same Postgres advisory lock. The exact value is arbitrary; only its
    // stability across call sites matters.
    private const long BootstrapAdvisoryLockKey = 0x6465_7062_6C79_0001;

    /// <summary>
    /// Opens a transaction that serialises concurrent bootstrap attempts, using the correct
    /// primitive for the store's provider. Pair with a plain <c>COMMIT</c>/<c>ROLLBACK</c>.
    /// </summary>
    public static async Task BeginSerializedAsync(this DbConnection conn, DbProvider provider, CancellationToken ct = default)
    {
        if (provider == DbProvider.Postgres)
        {
            // Raw ADO.NET, not Dapper: Dapper infers CommandType.StoredProcedure for a
            // single-word command text, which Npgsql then tries to call as begin() and fails
            // with 42883 "procedure begin() does not exist" (the same trap documented on
            // InstanceLock.ExecRawAsync for Microsoft.Data.Sqlite). Pin READ COMMITTED explicitly
            // rather than inheriting the server's default_transaction_isolation: if an operator
            // has that set to REPEATABLE READ or SERIALIZABLE, a losing replica's snapshot would
            // predate the winner's commit and it would not see the already-seeded rows after
            // acquiring the advisory lock, silently reseeding on top of them.
            await ExecRawAsync(conn, "BEGIN ISOLATION LEVEL READ COMMITTED", ct);
            await conn.ExecuteAsync(new CommandDefinition(
                "SELECT pg_advisory_xact_lock(@key)",
                new { key = BootstrapAdvisoryLockKey },
                cancellationToken: ct));
        }
        else
        {
            await conn.ExecuteAsync(new CommandDefinition("BEGIN IMMEDIATE", cancellationToken: ct));
        }
    }

    /// <summary>
    /// Opens a transaction that serialises concurrent operations for one tenant only — unlike
    /// <see cref="BeginSerializedAsync"/>, which shares a single fixed lock key across every
    /// caller (fine for the one-shot bootstrap critical section, wrong for a per-tenant resource
    /// cap check that different tenants must be able to hit concurrently without blocking each
    /// other). Closes check-then-act races on a per-tenant cap (e.g. concurrent session-start
    /// calls all reading the same "count so far" before any of them inserts) without adding a
    /// unique constraint or schema change.
    ///
    /// SQLite takes its write lock at transaction start via <c>BEGIN IMMEDIATE</c> — this
    /// serialises all writers file-wide, not just same-tenant ones, but SQLite is already
    /// single-writer and the critical section here is tight (one COUNT + one INSERT), so the
    /// extra cross-tenant contention is negligible. PostgreSQL takes a transaction-scoped
    /// advisory lock keyed by a stable hash of the tenant id, so concurrent callers for
    /// different tenants do not contend with each other.
    ///
    /// Pair with a plain <c>COMMIT</c>/<c>ROLLBACK</c> (grammar-identical on both providers).
    /// </summary>
    public static async Task BeginTenantSerializedAsync(
        this DbConnection conn, DbProvider provider, string tenantId, CancellationToken ct = default)
    {
        if (provider == DbProvider.Postgres)
        {
            await ExecRawAsync(conn, "BEGIN ISOLATION LEVEL READ COMMITTED", ct);
            await conn.ExecuteAsync(new CommandDefinition(
                "SELECT pg_advisory_xact_lock(@key)",
                new { key = TenantAdvisoryLockKey(tenantId) },
                cancellationToken: ct));
        }
        else
        {
            await conn.ExecuteAsync(new CommandDefinition("BEGIN IMMEDIATE", cancellationToken: ct));
        }
    }

    // FNV-1a: a fast, dependency-free, process-stable string hash (unlike string.GetHashCode,
    // which is randomized per process and would make two replicas hashing the same tenant id
    // contend on different locks). Purely a stable-hash role, no cryptographic property needed.
    private const ulong FnvOffsetBasis = 14695981039346656037;
    private const ulong FnvPrime = 1099511628211;

    /// <summary>
    /// Derives a stable advisory-lock key from a tenant id. Masked to 63 bits (the sign bit
    /// cleared) so the value round-trips cleanly as a Postgres <c>bigint</c> parameter.
    /// </summary>
    private static long TenantAdvisoryLockKey(string tenantId)
    {
        ulong hash = FnvOffsetBasis;
        foreach (byte b in System.Text.Encoding.UTF8.GetBytes(tenantId))
        {
            hash ^= b;
            hash *= FnvPrime;
        }

        return (long)(hash & 0x7FFFFFFFFFFFFFFF);
    }

    private static async Task ExecRawAsync(DbConnection conn, string sql, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        await cmd.ExecuteNonQueryAsync(ct);
    }
}
