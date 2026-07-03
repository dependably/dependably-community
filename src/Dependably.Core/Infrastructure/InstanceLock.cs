using System.Data.Common;
using System.Globalization;
using Dapper;
using Microsoft.Data.Sqlite;

namespace Dependably.Infrastructure;

/// <summary>
/// Guards a shared SQLite database file against a second dependably process. SQLite tolerates
/// exactly one writing process; two nodes pointed at one shared volume (a Kubernetes PVC accessed
/// by two replicas, a docker-compose scale &gt; 1, a bind-mounted host directory) silently corrupt
/// each other's write assumptions. The guard is a heartbeat row in the <c>instance_lock</c> table,
/// robust across containers and networked filesystems where OS advisory locks (flock) are not.
///
/// <para>On acquisition (<see cref="TryAcquireAsync"/>): a foreign holder whose heartbeat is FRESH
/// (within <c>INSTANCE_LOCK_STALE_SECONDS</c>, default 90) fails startup fast with a message naming
/// the other instance; a stale holder (a crashed predecessor) is taken over; an empty table or a
/// row already owned by this instance is (re)claimed. The heartbeat is refreshed on a timer while
/// the node runs (<see cref="InstanceLockHeartbeatService"/>) and the row is released on graceful
/// shutdown so an immediate restart need not wait out the staleness window.</para>
///
/// <para>Applies to a file-backed SQLite store only. Postgres is a legitimately multi-writer store,
/// and an in-memory SQLite store (tests) is private to its process — both skip the guard.</para>
/// </summary>
public sealed class InstanceLock
{
    // The single sentinel primary key: the table holds at most this one row.
    internal const string RowId = "primary";

    // Default staleness window: a foreign heartbeat older than this marks a crashed predecessor
    // whose lock can be taken over. Env-tunable via INSTANCE_LOCK_STALE_SECONDS.
    internal const int DefaultStaleSeconds = 90;

    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;
    private readonly ILogger<InstanceLock> _logger;

    /// <summary>Random GUID minted once for this process; identifies this node as the lock holder.</summary>
    public string InstanceId { get; } = Guid.NewGuid().ToString("N");

    /// <summary>Container/host name recorded on the lock so a takeover error can name the holder.</summary>
    public string Hostname { get; } = Environment.MachineName;

    /// <summary>The configured staleness window; a heartbeat older than this is a crashed predecessor.</summary>
    public TimeSpan StaleWindow { get; }

    public InstanceLock(
        IMetadataStore db,
        IConfiguration config,
        TimeProvider time,
        ILogger<InstanceLock> logger)
    {
        _db = db;
        _time = time;
        _logger = logger;
        int seconds = int.TryParse(config["INSTANCE_LOCK_STALE_SECONDS"], out int s) && s > 0
            ? s
            : DefaultStaleSeconds;
        StaleWindow = TimeSpan.FromSeconds(seconds);
    }

    /// <summary>
    /// True when the guard applies to this deployment: a file-backed SQLite store. Postgres and
    /// in-memory SQLite (Mode=Memory / :memory:, used by the test suite) are exempt.
    /// </summary>
    public bool AppliesToThisStore(DbConnection conn)
    {
        if (_db.Provider != DbProvider.Sqlite)
        {
            return false;
        }

        // An in-memory SQLite database is private to the process that opened it, so a cross-process
        // lock is meaningless. Detect it from the connection string / data source rather than a
        // config flag so the test suite's TestMetadataStore is exempt without special-casing.
        string dataSource = conn is SqliteConnection sqlite ? sqlite.DataSource : "";
        string connString = conn.ConnectionString ?? "";
        bool inMemory =
            dataSource.Equals(":memory:", StringComparison.OrdinalIgnoreCase)
            || connString.Contains("Mode=Memory", StringComparison.OrdinalIgnoreCase)
            || connString.Contains(":memory:", StringComparison.OrdinalIgnoreCase);
        return !inMemory;
    }

    /// <summary>
    /// Acquires the lock or throws <see cref="InstanceLockHeldException"/> when a live foreign
    /// instance already holds it. No-op (returns) for stores the guard does not apply to. Runs
    /// inside BEGIN IMMEDIATE so two racing startups cannot both read an empty table and both claim.
    /// </summary>
    public async Task TryAcquireAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        if (!AppliesToThisStore(conn))
        {
            return;
        }

        var now = _time.GetUtcNow();
        string nowIso = ToIso(now);

        await ExecRawAsync(conn, "BEGIN IMMEDIATE");
        try
        {
            var existing = await conn.QuerySingleOrDefaultAsync<LockRow>(
                // xtenant: instance-global single-writer lock; the instance_lock table is not
                // tenant-scoped (one lock guards the whole database file).
                "SELECT id AS Id, instance_id AS InstanceId, hostname AS Hostname, "
                + "heartbeat_at AS HeartbeatAt, acquired_at AS AcquiredAt "
                + "FROM instance_lock WHERE id = @id",
                new { id = RowId });

            if (existing is not null
                && !string.Equals(existing.InstanceId, InstanceId, StringComparison.Ordinal))
            {
                var lastBeat = ParseIso(existing.HeartbeatAt);
                var age = now - lastBeat;
                if (age < StaleWindow)
                {
                    // Fail fast — a second live process on one shared SQLite file corrupts writes.
                    await ExecRawAsync(conn, "ROLLBACK");
                    throw new InstanceLockHeldException(
                        existing.InstanceId, existing.Hostname, age, StaleWindow);
                }

                _logger.LogWarning(
                    "Instance lock held by {ForeignInstance} (host {ForeignHost}) was last seen "
                    + "{AgeSeconds:F0}s ago, exceeding the {StaleSeconds:F0}s staleness window — "
                    + "treating it as a crashed predecessor and taking over the lock.",
                    existing.InstanceId, existing.Hostname ?? "(unknown)", age.TotalSeconds,
                    StaleWindow.TotalSeconds);
            }

            // Claim (or re-claim) the row. acquired_at is preserved on a self-refresh and reset on
            // a fresh takeover, so the operator sees when THIS holder took ownership.
            string acquiredAt = existing is not null
                && string.Equals(existing.InstanceId, InstanceId, StringComparison.Ordinal)
                ? existing.AcquiredAt
                : nowIso;

            // xtenant: instance-global single-writer lock, not tenant-scoped.
            await conn.ExecuteAsync(
                """
                INSERT INTO instance_lock (id, instance_id, hostname, heartbeat_at, acquired_at)
                VALUES (@id, @instanceId, @hostname, @heartbeat, @acquired)
                ON CONFLICT (id) DO UPDATE SET
                    instance_id = excluded.instance_id,
                    hostname = excluded.hostname,
                    heartbeat_at = excluded.heartbeat_at,
                    acquired_at = excluded.acquired_at
                """,
                new
                {
                    id = RowId,
                    instanceId = InstanceId,
                    hostname = Hostname,
                    heartbeat = nowIso,
                    acquired = acquiredAt,
                });

            await ExecRawAsync(conn, "COMMIT");
        }
        catch (InstanceLockHeldException)
        {
            throw;
        }
        catch
        {
            try { await ExecRawAsync(conn, "ROLLBACK"); }
            catch (DbException) { /* nothing to roll back */ }
            throw;
        }

        _logger.LogInformation(
            "Acquired instance lock {InstanceId} (host {Hostname}); heartbeat every {RefreshSeconds:F0}s, "
            + "staleness window {StaleSeconds:F0}s.",
            InstanceId, Hostname, RefreshInterval.TotalSeconds, StaleWindow.TotalSeconds);
    }

    /// <summary>
    /// Refreshes this instance's heartbeat. No-op when the row is no longer owned by this instance
    /// (a takeover happened) or when the guard does not apply to the store.
    /// </summary>
    public async Task RefreshAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        if (!AppliesToThisStore(conn))
        {
            return;
        }

        string nowIso = ToIso(_time.GetUtcNow());
        // xtenant: instance-global single-writer lock, not tenant-scoped. The instance_id predicate
        // means a node that was taken over does not resurrect its heartbeat.
        int rows = await conn.ExecuteAsync(
            "UPDATE instance_lock SET heartbeat_at = @heartbeat WHERE id = @id AND instance_id = @instanceId",
            new { heartbeat = nowIso, id = RowId, instanceId = InstanceId });

        if (rows == 0)
        {
            _logger.LogWarning(
                "Instance lock heartbeat for {InstanceId} updated no row — the lock was taken over "
                + "by another instance. This node should be restarted.",
                InstanceId);
        }
    }

    /// <summary>
    /// Releases the lock on graceful shutdown by deleting the row IFF this instance still owns it,
    /// so an immediate restart (docker compose recreate) claims it without waiting out the window.
    /// </summary>
    public async Task ReleaseAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        if (!AppliesToThisStore(conn))
        {
            return;
        }

        // xtenant: instance-global single-writer lock, not tenant-scoped.
        int rows = await conn.ExecuteAsync(
            "DELETE FROM instance_lock WHERE id = @id AND instance_id = @instanceId",
            new { id = RowId, instanceId = InstanceId });

        if (rows > 0)
        {
            _logger.LogInformation("Released instance lock {InstanceId} on shutdown.", InstanceId);
        }
    }

    /// <summary>Heartbeat cadence: a third of the staleness window, so at least two beats are missed
    /// before a peer treats this node as crashed. Floored at 5s for very small windows.</summary>
    public TimeSpan RefreshInterval
    {
        get
        {
            double seconds = Math.Max(5, StaleWindow.TotalSeconds / 3.0);
            return TimeSpan.FromSeconds(seconds);
        }
    }

    private static string ToIso(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);

    private static DateTimeOffset ParseIso(string value) =>
        DateTimeOffset.TryParse(
            value, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
            ? parsed
            // An unparseable heartbeat is treated as the epoch (maximally stale) so a corrupt row
            // is taken over rather than deadlocking startup forever.
            : DateTimeOffset.UnixEpoch;

    // Transaction-control statements go through raw ADO.NET, not Dapper: Dapper infers
    // CommandType.StoredProcedure for a single-word command, which Microsoft.Data.Sqlite rejects.
    private static async Task ExecRawAsync(DbConnection conn, string sql)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        await cmd.ExecuteNonQueryAsync();
    }

    private sealed record LockRow(
        string Id, string InstanceId, string? Hostname, string HeartbeatAt, string AcquiredAt);
}

/// <summary>
/// Thrown at startup when a live foreign instance already holds the shared-SQLite instance lock.
/// The message names the holder and states the takeover procedure so an operator can distinguish a
/// genuine two-process misconfiguration from a false positive after an unclean crash.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization ctor on Exception is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain or binary boundary.")]
public sealed class InstanceLockHeldException : Exception
{
    public InstanceLockHeldException(
        string foreignInstanceId,
        string? foreignHostname,
        TimeSpan age,
        TimeSpan staleWindow)
        : base(BuildMessage(foreignInstanceId, foreignHostname, age, staleWindow))
    {
    }

    private static string BuildMessage(
        string foreignInstanceId,
        string? foreignHostname,
        TimeSpan age,
        TimeSpan staleWindow) =>
        $"Refusing to start: another dependably instance ({foreignInstanceId}, host "
        + $"{foreignHostname ?? "unknown"}) holds the lock on this shared SQLite database and its "
        + $"heartbeat is fresh (last seen {age.TotalSeconds:F0}s ago, within the "
        + $"{staleWindow.TotalSeconds:F0}s staleness window). SQLite supports exactly one writing "
        + "process per database file; running two corrupts the data. Point this node at its own "
        + "database file, or if the other instance has definitively crashed, wait "
        + $"{staleWindow.TotalSeconds:F0}s for its lock to go stale, or delete the row "
        + "(DELETE FROM instance_lock) before restarting.";
}
