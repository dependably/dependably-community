using System.Data.Common;
using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Cross-process serialization of schema application on Postgres.
///
/// <para>Applying the schema is a check-then-act sequence throughout: <c>CREATE TABLE IF NOT
/// EXISTS</c>, the additive column probes, and above all <c>RunOnceAsync</c>, which reads the
/// <c>_applied_migrations</c> ledger and then runs the migration body. Replicas that boot together
/// against one Postgres — a green task set launching, an autoscaling scale-out — all observe the
/// pre-migration state, all run the body, and the losers' ledger <c>INSERT</c> hits the
/// <c>name</c> primary key. That exception surfaces from <c>CoreStartupService.StartAsync</c>, so it
/// is a failed host start, not a retried statement.</para>
///
/// <para>A Postgres session-level advisory lock held for the duration of the apply closes it: the
/// first replica in runs the migrations, the rest block until it finishes and then read a ledger
/// that already records them, so they skip instead of re-running.</para>
///
/// <para>Postgres only, mirroring <see cref="InstanceLock.AppliesToThisStore"/> from the other
/// side. SQLite is a single-writer store and <see cref="InstanceLock"/> already refuses a second
/// process on the same database file, so it needs no second mechanism.</para>
/// </summary>
public sealed partial class SchemaInitializer
{
    // Fixed 64-bit key: every replica of every version must contend for the SAME lock, so it is a
    // constant rather than anything derived from the schema or the process.
    private const long MigrationLockKey = 0x0DE9_ED87_5C4E_3A17;

    // Longest a replica waits for a peer's apply before giving up. Generous relative to the whole
    // migration set, so a legitimately slow apply is waited out rather than aborted; a waiter that
    // does exceed it fails startup loudly and the supervisor's restart finds the ledger complete.
    private static readonly TimeSpan MigrationLockMaxWait = TimeSpan.FromMinutes(10);

    // Acquisition polls pg_try_advisory_lock instead of blocking on pg_advisory_lock: a blocking
    // wait is bounded by the ADO.NET command timeout (30s by default), which would abort a waiter
    // with an opaque timeout while the holder's apply is still legitimately running.
    private static readonly TimeSpan MigrationLockPollInterval = TimeSpan.FromMilliseconds(250);

    /// <summary>
    /// True when the migration lock applies to this deployment: a Postgres store, where several
    /// processes legitimately write the same database concurrently. SQLite is exempt — it is
    /// single-writer and guarded by <see cref="InstanceLock"/>.
    /// </summary>
    internal bool MigrationLockAppliesToThisStore => _db.Provider == DbProvider.Postgres;

    /// <summary>
    /// Takes the advisory lock on <paramref name="conn"/>, waiting out a peer's in-flight apply.
    /// Returns false — without waiting or locking — for stores the lock does not apply to, so the
    /// caller knows not to release. Throws <see cref="SchemaMigrationLockException"/> when the lock
    /// is still held after <see cref="MigrationLockMaxWait"/>.
    /// </summary>
    private async Task<bool> TryAcquireMigrationLockAsync(DbConnection conn, CancellationToken ct)
    {
        if (!MigrationLockAppliesToThisStore)
        {
            return false;
        }

        var deadline = _time.GetUtcNow() + MigrationLockMaxWait;
        bool announced = false;

        while (true)
        {
            // The lock is bound to the backend session behind this connection, so a process killed
            // mid-migration drops the session and the lock with it — there is no stale lock to
            // clear by hand.
            bool acquired = await conn.ExecuteScalarAsync<bool>(
                "SELECT pg_try_advisory_lock(@key)", new { key = MigrationLockKey });

            if (acquired)
            {
                if (announced)
                {
                    _logger.LogInformation(
                        "Schema migration lock acquired; the peer that held it has finished applying.");
                }

                return true;
            }

            if (_time.GetUtcNow() >= deadline)
            {
                throw new SchemaMigrationLockException(MigrationLockMaxWait);
            }

            if (!announced)
            {
                announced = true;
                _logger.LogInformation(
                    "Another instance is applying the schema. Waiting up to {MaxWaitSeconds:F0}s for "
                    + "it to finish before continuing startup.",
                    MigrationLockMaxWait.TotalSeconds);
            }

            await Task.Delay(MigrationLockPollInterval, _time, ct);
        }
    }

    /// <summary>
    /// Releases the advisory lock so the next waiting replica proceeds. Called from a finally, so a
    /// failed apply hands the lock on rather than wedging every peer until this process exits.
    /// </summary>
    private async Task ReleaseMigrationLockAsync(DbConnection conn)
    {
        try
        {
            await conn.ExecuteScalarAsync<bool>(
                "SELECT pg_advisory_unlock(@key)", new { key = MigrationLockKey });
        }
        catch (DbException ex)
        {
            // A broken connection has already ended its backend session, which releases the lock
            // anyway. Swallowing keeps this from replacing the apply's own exception on the way out
            // of the finally block.
            _logger.LogDebug(
                ex, "Releasing the schema migration lock failed; the closing session releases it.");
        }
    }
}

/// <summary>
/// Thrown when a replica waits out the whole migration-lock window without the holder finishing.
/// Startup fails rather than applying the schema concurrently with the holder; the supervisor's
/// restart then finds either a free lock or a completed ledger.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization ctor on Exception is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain or binary boundary.")]
public sealed class SchemaMigrationLockException(TimeSpan waited)
    : Exception(
        $"Refusing to start: another instance has held the schema migration lock for more than "
        + $"{waited.TotalSeconds:F0}s. Applying the schema alongside it would race the one-time "
        + "migrations, so this node stops instead. Check whether a peer is stuck mid-migration "
        + "(SELECT * FROM pg_locks WHERE locktype = 'advisory'); the lock releases on its own when "
        + "that session ends.");
