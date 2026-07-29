using Dapper;
using Dependably.Infrastructure.Redis;
using Dependably.Protocol;
using Dependably.Storage;

namespace Dependably.Infrastructure;

/// <summary>
/// Populates <c>oci_manifest_blobs</c> for manifests that were stored before the reference graph
/// existed, by re-reading each manifest's bytes and re-parsing its references.
///
/// The graph is recorded on both write paths going forward, so this only ever has work to do for
/// pre-upgrade content — but that content is exactly the accumulated OCI storage an operator wants
/// reclaimed, and until a manifest's closure is known it is deliberately un-evictable. Without this
/// pass, enabling OCI retention on an existing deployment would reclaim nothing.
///
/// Runs as a background sweep rather than a <c>RunOnceAsync</c> schema migration because it reads
/// blob bytes: a migration that blocks boot on blob-store I/O — potentially thousands of S3 round
/// trips — turns a slow object store into a failed startup. As a sweep it is resumable, bounded per
/// tick, and a failure costs a retry rather than the process.
///
/// Idempotent and convergent: each pass claims only manifests with no edges, and
/// <see cref="OciReferenceGraph.RecordAsync"/> is an upsert, so overlapping passes and re-runs
/// converge. Leader-gated, since unlike the staging janitor there is no node-local state — every
/// replica doing the same blob reads would multiply the I/O for no benefit.
/// </summary>
public sealed class OciReferenceGraphBackfillService : ScheduledBackgroundService
{
    // Manifests re-parsed per tick. Bounds both the blob-store I/O and the time a single pass
    // holds the leader lock; the sweep resumes where it left off because completed manifests stop
    // matching the "no edges" claim query.
    private const int BatchSize = 200;

    private readonly IMetadataStore _db;
    private readonly TieredBlobStorage _blobs;
    private readonly OciReferenceGraph _graph;
    private readonly IAirGapMode _airGap;
    private readonly ILogger<OciReferenceGraphBackfillService> _logger;

    protected override string CronEnvKey => "OCI_REFERENCE_BACKFILL_SCHEDULE";
    protected override string DefaultCron => "*/10 * * * *";
    protected override string ScopeJobName => "oci-reference-graph-backfill";
    protected override string ScopeMetricName => "oci.reference_graph.backfill";
    protected override bool RequiresLeaderLock => true;

    // Deliberately no RunOnStartup. The sweep is convergent on a 10-minute cron, so a pass at boot
    // advances nothing a few minutes of uptime would not — and it would cost a full scan on every
    // process start, including every short-lived test host.

    public OciReferenceGraphBackfillService(
        IMetadataStore db,
        TieredBlobStorage blobs,
        IAirGapMode airGap,
        IConfiguration config,
        ILogger<OciReferenceGraphBackfillService> logger,
        TimeProvider time,
        IDistributedLock locks)
        : base(config, logger, time, locks)
    {
        _db = db;
        _blobs = blobs;
        _graph = new OciReferenceGraph(db);
        _airGap = airGap;
        _logger = logger;
    }

    protected override Task RunTickAsync(CancellationToken ct) => RunOnceAsync(ct);

    /// <summary>
    /// Runs a single backfill pass and returns how many manifests were resolved and how many could
    /// not be. Public so tests can drive it without the cron schedule.
    /// </summary>
    public async Task<BackfillSummary> RunOnceAsync(CancellationToken ct = default)
    {
        // Honours the operator switch and, via the edge allowlist inversion, keeps an edge node out
        // of the graph entirely: a cache node creates nothing authoritative, and the reclaim this
        // graph authorizes deletes bytes.
        if (_airGap.IsJobDisabled("oci-reference-graph-backfill"))
        {
            _logger.LogInformation(
                "OCI reference-graph backfill skipped (disabled by AIR_GAPPED or DISABLE_BACKGROUND_JOBS).");
            return new BackfillSummary(0, 0);
        }

        var pending = await ClaimPendingManifestsAsync(ct);
        if (pending.Count == 0)
        {
            return new BackfillSummary(0, 0);
        }

        int recorded = 0;
        int unresolved = 0;

        foreach (var m in pending)
        {
            ct.ThrowIfCancellationRequested();

            byte[]? bytes = await ReadManifestBytesAsync(m, ct);
            if (bytes is null)
            {
                // The row survives its bytes: the manifest was evicted from the cache tier, or a
                // proxy pull recorded the row before the body landed. Leaving it unrecorded keeps
                // it un-evictable, which is correct — we cannot enumerate a closure we cannot read.
                unresolved++;
                continue;
            }

            var refs = OciManifestParser.ParseReferences(bytes);
            if (refs is null)
            {
                unresolved++;
                continue;
            }

            await _graph.RecordAsync(m.OrgId, m.Digest, refs.Digests, ct);
            recorded++;
        }

        _logger.LogInformation(
            "OCI reference-graph backfill: recorded {Recorded} manifest closures, {Unresolved} unresolved",
            recorded, unresolved);

        return new BackfillSummary(recorded, unresolved);
    }

    /// <summary>
    /// Manifest rows with no edges yet. Restricted to manifest media types — a layer blob has no
    /// closure to record, and including layers would make every pass re-examine rows that can never
    /// produce an edge, so the sweep would never appear to converge.
    /// </summary>
    private async Task<IReadOnlyList<PendingManifest>> ClaimPendingManifestsAsync(CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);

        // xtenant: deliberately fleet-wide — this is a one-time backfill of pre-upgrade content
        // across every tenant, and each row carries the org_id it is recorded under.
        var rows = await conn.QueryAsync<PendingManifest>(
            """
            SELECT b.digest AS Digest, b.org_id AS OrgId, b.blob_key AS BlobKey, b.origin AS Origin
            FROM oci_blobs b
            WHERE b.media_type IN @mediaTypes
              AND NOT EXISTS (
                  SELECT 1 FROM oci_manifest_blobs g
                  WHERE g.org_id = b.org_id AND g.manifest_digest = b.digest)
            ORDER BY b.digest
            LIMIT @limit
            """,
            new { mediaTypes = OciManifestParser.AcceptedMediaTypes.ToArray(), limit = BatchSize });

        return rows.AsList();
    }

    /// <summary>
    /// Reads a stored manifest's bytes from the tier its origin puts it in, returning null when the
    /// bytes are gone. Mirrors the serve path's tier selection: uploaded manifests are Registry-tier
    /// and durable, proxy manifests are Cache-tier and may have been reclaimed.
    /// </summary>
    private async Task<byte[]?> ReadManifestBytesAsync(PendingManifest m, CancellationToken ct)
    {
        var tier = m.Origin == "uploaded" ? _blobs.Registry : _blobs.Cache;

        try
        {
            await using var stream = await tier.GetAsync(m.BlobKey, ct);
            if (stream is null)
            {
                return null;
            }

            using var buffer = new MemoryStream();
            await stream.CopyToAsync(buffer, ct);
            return buffer.ToArray();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or HttpRequestException)
        {
            // A transient blob-store fault must not fail the sweep: the manifest stays unrecorded
            // and therefore un-evictable, and the next tick retries it.
            _logger.LogWarning(
                "OCI reference-graph backfill could not read manifest {Digest} for org {OrgId}: {ExceptionType}",
                m.Digest, m.OrgId, ex.GetType().Name);
            return null;
        }
    }

    private sealed record PendingManifest(string Digest, string OrgId, string BlobKey, string Origin);

    /// <summary>Outcome of one backfill pass.</summary>
    public sealed record BackfillSummary(int Recorded, int Unresolved);
}
