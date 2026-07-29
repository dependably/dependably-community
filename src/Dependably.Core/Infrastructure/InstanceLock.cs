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
/// <para>On acquisition (<see cref="TryAcquireAsync"/>): an empty table, a row already owned by this
/// instance, or a holder whose heartbeat is already STALE (older than <c>INSTANCE_LOCK_STALE_SECONDS</c>,
/// default 90) is claimed outright. A foreign holder whose heartbeat is FRESH is ambiguous — the row
/// alone cannot say whether a live peer is beating it or a predecessor died without releasing it — so
/// acquisition WAITS and watches the heartbeat: a beat identifies a live peer and fails startup with a
/// message naming it, while a frozen heartbeat is an orphaned row that is taken over as soon as the
/// staleness window expires. The heartbeat is refreshed on a timer while the node runs
/// (<see cref="InstanceLockHeartbeatService"/>) and the row is released on graceful shutdown, so a
/// clean restart claims immediately and only an ungraceful death (SIGKILL, OOM, power loss) pays the
/// wait.</para>
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
    /// Acquires the lock, waiting out an orphaned row if necessary, or throws
    /// <see cref="InstanceLockHeldException"/> when a live foreign instance holds it. No-op
    /// (returns) for stores the guard does not apply to.
    /// </summary>
    public async Task TryAcquireAsync(CancellationToken ct = default)
    {
        var (applicable, blocker) = await ClaimOnceAsync(ct);
        if (!applicable)
        {
            return;
        }

        if (blocker is null)
        {
            LogAcquired();
            return;
        }

        // A foreign holder with a fresh heartbeat is one of two things and the row alone cannot tell
        // them apart: a LIVE peer (two processes on one SQLite file — the misconfiguration this guard
        // exists to refuse) or an ORPHANED row from a predecessor that died without releasing it
        // (SIGKILL, OOM, power loss — a redeploy this node must survive). Watching the heartbeat
        // separates them: a live peer keeps beating, an orphan's heartbeat is frozen. Failing fast on
        // both makes the orphan case a crash loop for the whole staleness window, which is exactly
        // the moment an operator needs the node to come up.
        var waitStartedAt = _time.GetUtcNow();
        var maxWait = StaleWindow + PollInterval;

        _logger.LogInformation(
            "Instance lock is held by {ForeignInstance} (host {ForeignHost}), last seen "
            + "{AgeSeconds:F0}s ago. Waiting up to {MaxWaitSeconds:F0}s for its heartbeat to go "
            + "stale: a frozen heartbeat means a crashed predecessor whose lock this node takes "
            + "over, while a beat means it is live and startup fails.",
            blocker.InstanceId, blocker.Hostname ?? "(unknown)",
            (waitStartedAt - ParseIso(blocker.HeartbeatAt)).TotalSeconds, maxWait.TotalSeconds);

        while (true)
        {
            await Task.Delay(PollInterval, _time, ct);

            // Re-claim first, deadline second: a clock that jumped past the window during the wait
            // should take the lock over, not time out one poll short of it.
            var (_, current) = await ClaimOnceAsync(ct);
            if (current is null)
            {
                LogAcquired();
                return;
            }

            // A changed heartbeat (or a different holder taking over ahead of us) means someone else
            // is alive on this database file. Refuse, naming them.
            bool holderIsAlive =
                !string.Equals(current.HeartbeatAt, blocker.HeartbeatAt, StringComparison.Ordinal)
                || !string.Equals(current.InstanceId, blocker.InstanceId, StringComparison.Ordinal);
            if (holderIsAlive)
            {
                throw InstanceLockHeldException.LivePeer(current.InstanceId, current.Hostname);
            }

            var waited = _time.GetUtcNow() - waitStartedAt;
            if (waited > maxWait)
            {
                throw InstanceLockHeldException.WaitTimedOut(
                    current.InstanceId, current.Hostname, waited, StaleWindow);
            }
        }
    }

    /// <summary>
    /// One claim attempt. Returns <c>(false, null)</c> for a store the guard does not apply to,
    /// <c>(true, null)</c> when the lock is now held by this instance (claimed, re-claimed, or taken
    /// over from a stale holder), and <c>(true, row)</c> when a foreign holder's heartbeat is still
    /// fresh — the caller decides whether to wait it out. Runs inside BEGIN IMMEDIATE so two racing
    /// startups cannot both read an empty table and both claim.
    /// </summary>
    private async Task<(bool Applicable, LockRow? Blocker)> ClaimOnceAsync(CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        if (!AppliesToThisStore(conn))
        {
            return (false, null);
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
                    // Still fresh: the holder is either live or newly orphaned. Do not claim — hand
                    // the row back so the caller can watch the heartbeat and tell the two apart.
                    await ExecRawAsync(conn, "ROLLBACK");
                    return (true, existing);
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
        catch
        {
            try { await ExecRawAsync(conn, "ROLLBACK"); }
            catch (DbException) { /* nothing to roll back */ }
            throw;
        }

        return (true, null);
    }

    private void LogAcquired() =>
        _logger.LogInformation(
            "Acquired instance lock {InstanceId} (host {Hostname}); heartbeat every {RefreshSeconds:F0}s, "
            + "staleness window {StaleSeconds:F0}s.",
            InstanceId, Hostname, RefreshInterval.TotalSeconds, StaleWindow.TotalSeconds);

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

    /// <summary>How often acquisition re-reads a fresh foreign holder's heartbeat while waiting to
    /// see whether it beats (live peer) or stays frozen (orphaned row). Several polls per heartbeat
    /// cadence, so a live peer is detected within roughly one beat.</summary>
    public TimeSpan PollInterval =>
        TimeSpan.FromSeconds(Math.Clamp(StaleWindow.TotalSeconds / 18.0, 1, 5));

    private static string ToIso(DateTimeOffset value) =>
        value.UtcDateTime.ToUtcIso();

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
/// Thrown at startup when the shared-SQLite instance lock cannot be taken. The message names the
/// holder and states what to do, so an operator can tell a genuine two-process misconfiguration
/// (<see cref="LivePeer"/> — the holder kept beating) from the clock-skew case
/// (<see cref="WaitTimedOut"/> — a frozen heartbeat that never aged past the staleness window).
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization ctor on Exception is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain or binary boundary.")]
public sealed class InstanceLockHeldException : Exception
{
    private InstanceLockHeldException(string message)
        : base(message)
    {
    }

    /// <summary>The holder's heartbeat advanced while this node waited: it is running, and a second
    /// writing process on one SQLite file corrupts the database.</summary>
    public static InstanceLockHeldException LivePeer(string foreignInstanceId, string? foreignHostname) =>
        new($"Refusing to start: another dependably instance ({foreignInstanceId}, host "
            + $"{foreignHostname ?? "unknown"}) is live on this shared SQLite database — its heartbeat "
            + "advanced while this node waited for the lock. SQLite supports exactly one writing "
            + "process per database file; running two corrupts the data. Point this node at its own "
            + "database file (DB_PATH), or stop the other instance.");

    /// <summary>The heartbeat never advanced, yet never aged past the staleness window either — the
    /// two hosts' clocks disagree, or the row carries a timestamp from the future.</summary>
    public static InstanceLockHeldException WaitTimedOut(
        string foreignInstanceId,
        string? foreignHostname,
        TimeSpan waited,
        TimeSpan staleWindow) =>
        new($"Refusing to start: the instance lock held by {foreignInstanceId} (host "
            + $"{foreignHostname ?? "unknown"}) did not go stale after waiting {waited.TotalSeconds:F0}s "
            + $"(staleness window {staleWindow.TotalSeconds:F0}s) and its heartbeat never advanced. "
            + "The holder's clock is ahead of this node's, or its heartbeat is dated in the future. "
            + "Reconcile the clocks, or delete the row (DELETE FROM instance_lock) if that instance is "
            + "definitively gone.");
}
