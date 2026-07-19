using Dapper;
using Dependably.Infrastructure.Redis;
using Dependably.Storage;

namespace Dependably.Infrastructure;

/// <summary>
/// Background GC worker that runs on a cron schedule (GC_SCHEDULE env var, default daily at 3am).
/// Enforces per-org retention policies:
///   - keep_versions: delete oldest versions beyond the limit per package
///   - keep_days: evict proxy blobs unused beyond this many days
///   - activity_retention_days: delete old activity rows
/// Respects the shutdown CancellationToken — stops at the next checkpoint.
/// </summary>
public sealed class RetentionService : ScheduledBackgroundService
{
    /// <summary>
    /// Injected dependencies for <see cref="RetentionService"/>. Bundles all DI services into
    /// one record so the constructor stays within the parameter-count gate (S107).
    /// </summary>
    public sealed record Dependencies(
        IMetadataStore Db,
        IBlobStore Blobs,
        JwtRevocationRepository JwtRevocations,
        InviteRepository Invites,
        SamlConfigRepository SamlConfig,
        IConfiguration Config,
        IAirGapMode AirGap,
        ILogger<RetentionService> Logger,
        TimeProvider Time,
        IDistributedLock Locks);

    private readonly IMetadataStore _db;
    private readonly IBlobStore _blobs;
    private readonly JwtRevocationRepository _jwtRevocations;
    private readonly InviteRepository _invites;
    private readonly SamlConfigRepository _samlConfig;
    private readonly IConfiguration _config;
    private readonly IAirGapMode _airGap;
    private readonly ILogger<RetentionService> _logger;
    private readonly TimeProvider _time;

    protected override string CronEnvKey => "GC_SCHEDULE";
    protected override string DefaultCron => "0 3 * * *";
    protected override string ScopeJobName => "retention";
    protected override string ScopeMetricName => "retention.gc";

    // Deletes shared version rows, blobs, and expired security/invite state — one replica per tick.
    protected override bool RequiresLeaderLock => true;

    public RetentionService(Dependencies deps)
        : base(deps.Config, deps.Logger, deps.Time, deps.Locks)
    {
        _db = deps.Db;
        _blobs = deps.Blobs;
        _jwtRevocations = deps.JwtRevocations;
        _invites = deps.Invites;
        _samlConfig = deps.SamlConfig;
        _config = deps.Config;
        _airGap = deps.AirGap;
        _logger = deps.Logger;
        _time = deps.Time;
    }

    protected override Task RunTickAsync(CancellationToken ct) => RunGcPassAsync(ct);

    private async Task RunGcPassAsync(CancellationToken ct)
    {
        // A headless edge node holds no durable registry tier and no per-tenant retention
        // policy, so GC is inert there — edge mode force-disables retention (not in the allowlist).
        if (_airGap.IsJobDisabled("retention"))
        {
            _logger.LogInformation(
                "Retention GC skipped (disabled by AIR_GAPPED, DISABLE_BACKGROUND_JOBS, or edge mode).");
            return;
        }

        _logger.LogInformation("Retention GC pass starting.");

        await using var conn = await _db.OpenAsync(ct);

        // Fetch active orgs with retention settings (skip soft-deleted — TenantHardDeleteService
        // owns those, and retention work on a tenant pending hard-delete is wasted I/O).
        var orgs = await conn.QueryAsync<(string OrgId, int? KeepVersions, int? KeepDays, int? ActivityRetentionDays, int? PurgeUnlistedAfterDays)>(
            """
            SELECT o.id, s.keep_versions, s.keep_days, s.activity_retention_days, s.purge_unlisted_after_days
            FROM orgs o
            JOIN org_settings s ON s.org_id = o.id
            WHERE o.deleted_at IS NULL
              AND (s.keep_versions IS NOT NULL OR s.keep_days IS NOT NULL
                   OR s.activity_retention_days IS NOT NULL OR s.purge_unlisted_after_days IS NOT NULL)
            """);

        foreach (var (OrgId, KeepVersions, KeepDays, ActivityRetentionDays, PurgeUnlistedAfterDays) in orgs)
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            if (KeepVersions.HasValue)
            {
                await EnforceVersionLimitAsync(conn, OrgId, KeepVersions.Value, ct);
            }

            if (KeepDays.HasValue)
            {
                await EvictStaleBlobsAsync(conn, OrgId, KeepDays.Value, ct);
            }

            if (ActivityRetentionDays.HasValue)
            {
                await PruneActivityAsync(conn, OrgId, ActivityRetentionDays.Value, _time.GetUtcNow(), ct);
            }

            if (PurgeUnlistedAfterDays.HasValue)
            {
                await PurgeUnlistedAsync(conn, OrgId, PurgeUnlistedAfterDays.Value, ct);
            }
        }

        // Prune expired JWT revocations (global — not org-scoped)
        await _jwtRevocations.PruneExpiredAsync(ct);

        // Prune expired, unconsumed invite rows (global sweep — see PruneExpiredAsync xtenant comment).
        int prunedInvites = await _invites.PruneExpiredAsync(ct);
        if (prunedInvites > 0)
        {
            _logger.LogInformation("Retention GC: pruned {Count} expired invite rows.", prunedInvites);
        }

        // Prune typed audit_event rows past the retention window. Default window is 365
        // days, set in cross-cutting-decisions.md section 4 (audit_event is append-only and
        // archived after one year). Hard delete for now; once archive support lands, the
        // reaper will write to cold storage first.
        await PruneAuditEventsAsync(conn, ct);

        // Reclaim expired SAML one-shot rows (pending requests, consumed assertions, test runs).
        // These prune on write too; this sweep bounds them when a tenant goes idle.
        await _samlConfig.PurgeExpiredSamlAsync(ct);

        _logger.LogInformation("Retention GC pass complete.");
    }

    // Chunk size for the batched audit_event delete below. Small enough that each chunk's
    // DELETE releases the writer lock quickly, large enough that a year-scale backlog drains
    // in a bounded number of round-trips. Internal (not private) so tests can seed a multi-chunk
    // backlog scaled to this exact size rather than hardcoding a copy of the production value.
    internal const int AuditEventPruneBatchSize = 5000;

    internal async Task PruneAuditEventsAsync(System.Data.Common.DbConnection conn, CancellationToken ct)
    {
        int retentionDays = int.TryParse(_config["AUDIT_EVENT_RETENTION_DAYS"], out int d) && d > 0
            ? d : 365;
        string cutoff = _time.GetUtcNow().AddDays(-retentionDays).ToString("yyyy-MM-ddTHH:mm:ssZ");

        // Hard-delete is the right shape today: there's no archive destination yet (decision
        // deferred per cross-cutting-decisions.md). When archive lands, this becomes a copy
        // followed by a delete behind a single transaction.
        //
        // Deletes in bounded chunks keyed by the event_id primary key (portable across SQLite
        // and Postgres — both support LIMIT inside the subselect) so a year-scale backlog
        // never holds the writer lock for one long-running statement; the lock is released
        // between chunks for other writers to make progress.
        int totalDeleted = 0;
        int deletedInChunk;
        do
        {
            // xtenant: instance-wide retention sweep by age, same as JwtRevocationRepository /
            // InviteRepository's expiry-only prunes — every org's stale rows age out together.
            deletedInChunk = await conn.ExecuteAsync(new CommandDefinition(
                """
                DELETE FROM audit_event
                WHERE event_id IN (
                    SELECT event_id FROM audit_event WHERE occurred_at < @cutoff LIMIT @batchSize
                )
                """,
                new { cutoff, batchSize = AuditEventPruneBatchSize },
                cancellationToken: ct));
            totalDeleted += deletedInChunk;
        }
        while (deletedInChunk >= AuditEventPruneBatchSize && !ct.IsCancellationRequested);

        if (totalDeleted > 0)
        {
            _logger.LogInformation("Audit reaper: pruned {Count} audit_event rows older than {Days} days.",
                totalDeleted, retentionDays);
        }
    }

    // internal (not private) so RetentionServiceCacheExclusionTests can drive it directly without
    // the full cron/config scheduling machinery — mirrors PurgeUnlistedAsync below.
    internal async Task EnforceVersionLimitAsync(
        System.Data.Common.DbConnection conn, string orgId, int keepVersions, CancellationToken ct)
    {
        // Uploaded versions: keep the most recent N per package; delete older ones from package_versions.
        // OCI is excluded here for the same reason it is excluded from the proxy eviction below: a
        // tag push catalogues the image as a package_versions row whose blob_key is the manifest,
        // so deleting it destroys the manifest while the oci_blobs row, the tags, and every layer
        // blob survive — a broken serve path and orphaned layers. An image reaches the catalogue
        // through either plane, so both arms carry the guard.
        var uploadedToDelete = await conn.QueryAsync<(string VersionId, string BlobKey)>(
            // plane-ok: uploaded-plane version-limit driver; the proxy plane is evicted by the sibling cache_artifact/tenant_artifact_access query below in this method (OCI excluded on both arms).
            """
            SELECT pv.id as VersionId, pv.blob_key as BlobKey
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND pv.origin = 'uploaded'
              AND p.ecosystem != 'oci'
              AND pv.id NOT IN (
                  SELECT id FROM package_versions pv2
                  WHERE pv2.package_id = pv.package_id
                    AND pv2.origin = 'uploaded'
                  ORDER BY pv2.created_at DESC
                  LIMIT @keepVersions
              )
            """,
            new { orgId, keepVersions });

        foreach (var (VersionId, BlobKey) in uploadedToDelete)
        {
            if (ct.IsCancellationRequested) { break; }
            // xtenant: keyed by a version PK from the p.org_id = @orgId SELECT above.
            await _blobs.DeleteAsync(BlobKeys.StoreKey(BlobKey), ct);
            await conn.ExecuteAsync("DELETE FROM package_versions WHERE id = @id", new { id = VersionId });
            _logger.LogDebug("GC: deleted uploaded version {Id} (blob {Key})", VersionId, BlobKey);
        }

        // Proxy versions: keep this org's @keepVersions least-recently-accessed VERSIONS per name
        // and evict every row of every version below that cut. Removes the tenant_artifact_access
        // row; cascade-deletes the cache_artifact and its blob when no other tenant retains access.
        //
        // The keep-set ranks versions, not rows, because cache_artifact is keyed
        // UNIQUE (ecosystem, name, version, filename): one version owns one row per file, so a
        // Maven version spans jar+pom+sources+javadoc. Ranking rows would make keep_versions=5
        // retain about one real Maven version, and — because the cut could fall between two files
        // of the same version — could evict a version's .pom while keeping its .jar, leaving a
        // partial version that resolves broken. A version's recency is its most recently accessed
        // file (MAX), and the NOT IN predicate matches on ca.version, so a version is always
        // wholly kept or wholly evicted. Versions are ordered by recency then by version as a
        // tiebreak, so two versions cached within the same second cut deterministically rather
        // than by plan order.
        // OCI is excluded: evicting an OCI cache_artifact row would delete the manifest blob
        // while its oci_blobs row and layer blobs survive, leaving a broken serve path and
        // orphaned layers. Correct OCI eviction needs layer refcounting, which is out of scope —
        // OCI stays never-evicted from the cache plane, matching its pre-existing behavior.
        // xtenant: cache_artifact is global; org_id filter is in tenant_artifact_access.
        var proxyToEvict = await conn.QueryAsync<(string CacheArtifactId, string Ecosystem, string Name, string Version, string BlobKey)>(
            """
            SELECT ca.id AS CacheArtifactId, ca.ecosystem AS Ecosystem, ca.name AS Name,
                   ca.version AS Version, ca.blob_key AS BlobKey
            FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId
              AND ca.ecosystem != 'oci'
              AND ca.version NOT IN (
                  SELECT ca2.version
                  FROM tenant_artifact_access taa2
                  JOIN cache_artifact ca2 ON ca2.id = taa2.cache_artifact_id
                  WHERE taa2.org_id = @orgId AND ca2.name = ca.name AND ca2.ecosystem = ca.ecosystem
                  GROUP BY ca2.version
                  ORDER BY MAX(taa2.last_accessed_at) DESC, ca2.version DESC
                  LIMIT @keepVersions
              )
            """,
            new { orgId, keepVersions });

        // Grouped by full version identity — (ecosystem, name, version), since two names or two
        // ecosystems can share a version string — so the cancellation checkpoint falls on a version
        // boundary. Checking it per row would let a shutdown land mid-version and leave exactly the
        // partial version the keep-set is shaped to prevent; a version whose eviction has started
        // runs to completion.
        foreach (var versionGroup in proxyToEvict.GroupBy(r => (r.Ecosystem, r.Name, r.Version)))
        {
            if (ct.IsCancellationRequested) { break; }

            foreach (var (CacheArtifactId, _, Name, Version, BlobKey) in versionGroup)
            {
                await conn.ExecuteAsync(
                    "DELETE FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @id",
                    new { orgId, id = CacheArtifactId });

                // Delete the global cache_artifact and its blob when no tenant retains access.
                // xtenant: deliberately cross-tenant — this counts whether ANY OTHER tenant still
                // retains access to the shared cache_artifact before its blob is deleted. Filtering
                // by org_id here would always return 0 and delete a blob other tenants still use.
                long remaining = await conn.ExecuteScalarAsync<long>(
                    "SELECT COUNT(*) FROM tenant_artifact_access WHERE cache_artifact_id = @id",
                    new { id = CacheArtifactId });
                if (remaining == 0)
                {
                    // CancellationToken.None, unlike every other blob delete in this service: the
                    // version boundary above is the checkpoint, and honouring ct here would let a
                    // shutdown abort between two files of one version — dropping a version's .jar
                    // while its .pom survives. The extra work a cancelled pass takes on is bounded
                    // by one version's file count.
                    await _blobs.DeleteAsync(BlobKeys.StoreKey(BlobKey), CancellationToken.None);
                    await conn.ExecuteAsync("DELETE FROM cache_artifact WHERE id = @id", new { id = CacheArtifactId });
                }
                _logger.LogDebug("GC: evicted proxy artifact {Id} name={Name} version={Version} (blob {Key})",
                    CacheArtifactId, Name, Version, BlobKey);
            }
        }
    }

    // internal (not private) so RetentionServiceCacheExclusionTests can drive it directly — see
    // EnforceVersionLimitAsync above.
    internal async Task EvictStaleBlobsAsync(
        System.Data.Common.DbConnection conn, string orgId, int keepDays, CancellationToken ct)
    {
        string cutoff = _time.GetUtcNow().AddDays(-keepDays).ToString("yyyy-MM-ddTHH:mm:ssZ");

        // Uploaded versions: evict by last_used timestamp on package_versions. OCI is excluded on
        // both planes — deleting a pushed image's catalogue row destroys its manifest blob and
        // orphans every layer (see EnforceVersionLimitAsync).
        var uploadedStale = await conn.QueryAsync<(string VersionId, string BlobKey)>(
            // plane-ok: uploaded-plane stale-blob driver; the proxy plane is evicted by the sibling cache_artifact/tenant_artifact_access query below in this method (OCI excluded on both arms).
            """
            SELECT pv.id as VersionId, pv.blob_key as BlobKey
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND pv.origin = 'uploaded'
              AND p.ecosystem != 'oci'
              AND pv.last_used IS NOT NULL AND pv.last_used < @cutoff
            """,
            new { orgId, cutoff });

        foreach (var (VersionId, BlobKey) in uploadedStale)
        {
            if (ct.IsCancellationRequested) { break; }
            // xtenant: keyed by a version PK from the p.org_id = @orgId SELECT above.
            await _blobs.DeleteAsync(BlobKeys.StoreKey(BlobKey), ct);
            await conn.ExecuteAsync("DELETE FROM package_versions WHERE id = @id", new { id = VersionId });
        }

        // Proxy versions: evict this org's tenant_artifact_access rows where the tenant's
        // last_used is older than the cutoff. Removes the per-tenant row; cascade-deletes the
        // global cache_artifact and its blob when no other tenant retains access.
        // OCI is excluded — see the age-based eviction comment in EnforceVersionLimitAsync above;
        // the same broken-serve / orphaned-layer risk applies here.
        // xtenant: cache_artifact is global; org_id filter is in tenant_artifact_access.
        var proxyStale = await conn.QueryAsync<(string CacheArtifactId, string BlobKey)>(
            """
            SELECT ca.id AS CacheArtifactId, ca.blob_key AS BlobKey
            FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId
              AND ca.ecosystem != 'oci'
              AND taa.last_used IS NOT NULL AND taa.last_used < @cutoff
            """,
            new { orgId, cutoff });

        foreach (var (CacheArtifactId, BlobKey) in proxyStale)
        {
            if (ct.IsCancellationRequested) { break; }

            await conn.ExecuteAsync(
                "DELETE FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @id",
                new { orgId, id = CacheArtifactId });

            // xtenant: deliberately cross-tenant — this counts whether ANY OTHER tenant still
            // retains access to the shared cache_artifact before its blob is deleted. Filtering
            // by org_id here would always return 0 and delete a blob other tenants still use.
            long remaining = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM tenant_artifact_access WHERE cache_artifact_id = @id",
                new { id = CacheArtifactId });
            if (remaining == 0)
            {
                await _blobs.DeleteAsync(BlobKeys.StoreKey(BlobKey), ct);
                await conn.ExecuteAsync("DELETE FROM cache_artifact WHERE id = @id", new { id = CacheArtifactId });
            }
        }
    }

    /// <summary>
    /// Hard-deletes hosted (origin='uploaded') versions that have stayed unlisted longer than
    /// the org's purge_unlisted_after_days policy, reclaiming the row and its registry-tier blob.
    /// The age is measured from yanked_at — rows whose unlist pre-dates that column (NULL
    /// yanked_at) are never age-purgeable, so an operator can re-unlist to restart the clock.
    /// Proxy rows are excluded by the origin discriminator; cache-tier eviction is owned by
    /// CacheEvictionService.
    /// </summary>
    internal async Task PurgeUnlistedAsync(
        System.Data.Common.DbConnection conn, string orgId, int afterDays, CancellationToken ct)
    {
        string cutoff = _time.GetUtcNow().AddDays(-afterDays).ToString("yyyy-MM-ddTHH:mm:ssZ");

        // OCI is excluded on both planes — deleting a pushed image's catalogue row destroys its
        // manifest blob and orphans every layer (see EnforceVersionLimitAsync).
        var toPurge = await conn.QueryAsync<(string VersionId, string BlobKey)>(
            // plane-ok: uploaded-plane unlisted purge; proxy rows are excluded by the origin discriminator and cache-tier eviction is owned by CacheEvictionService.
            """
            SELECT pv.id as VersionId, pv.blob_key as BlobKey
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND pv.origin = 'uploaded'
              AND p.ecosystem != 'oci'
              AND pv.yanked = 1
              AND pv.yanked_at IS NOT NULL AND pv.yanked_at < @cutoff
            """,
            new { orgId, cutoff });

        foreach (var (VersionId, BlobKey) in toPurge)
        {
            if (ct.IsCancellationRequested) { break; }
            // xtenant: keyed by a version PK from the p.org_id = @orgId SELECT above.
            await _blobs.DeleteAsync(BlobKeys.StoreKey(BlobKey), ct);
            await conn.ExecuteAsync("DELETE FROM package_versions WHERE id = @id", new { id = VersionId });
            _logger.LogDebug("GC: purged unlisted version {Id} (blob {Key})", VersionId, BlobKey);
        }
    }

    private static async Task PruneActivityAsync(
        System.Data.Common.DbConnection conn, string orgId, int retentionDays, DateTimeOffset now, CancellationToken ct)
    {
        string cutoff = now.AddDays(-retentionDays).ToString("yyyy-MM-ddTHH:mm:ssZ");
        await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM activity WHERE org_id = @orgId AND created_at < @cutoff",
            new { orgId, cutoff },
            cancellationToken: ct));
    }
}
