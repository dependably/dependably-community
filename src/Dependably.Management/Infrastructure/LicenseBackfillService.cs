using Dependably.Infrastructure.Redis;
using Dependably.Protocol;
using Dependably.Storage;

namespace Dependably.Infrastructure;

/// <summary>
/// Background service that backfills SPDX licenses for proxy-cache artifacts ingested before
/// ingest-time license capture existed. Those <c>cache_artifact</c> rows carry no
/// <c>package_version_licenses</c> rows and no query rescans them, so a large slice of the cache
/// plane has no license facts. This pass reads the cached bytes for each un-checked
/// npm/PyPI/NuGet/Go artifact — and each un-checked Maven <c>.pom</c> row — runs the same
/// stream-based <see cref="LicenseExtractor"/> entry points the first-fetch recorder uses, writes
/// any SPDX identifiers to the global plane
/// (<c>LicenseRepository.SetLicensesForCacheArtifactAsync</c>, source <c>"upstream"</c>), and — in
/// every case (license found, none present, or blob missing) — stamps
/// <c>cache_artifact.license_checked_at</c> so the row is scanned exactly once.
///
/// Runs on the <c>LICENSE_BACKFILL_SCHEDULE</c> cron (default daily off-peak). Reads only the
/// cache tier, never fetches upstream, and mutates the shared cache plane — so the per-tick leader
/// lock (see <see cref="RequiresLeaderLock"/>) ensures a single replica runs each pass in HA mode.
/// </summary>
public sealed class LicenseBackfillService : ScheduledBackgroundService
{
    // Rows read per DB round-trip. Bounded so a single query never materializes a huge candidate
    // set. Pages are keyset-paginated (see RunBackfillPassAsync), so a batch a row fails to
    // process in is never re-read within the same pass — only a stamp removes a row from the
    // license_checked_at IS NULL queue permanently, but the cursor alone guarantees forward
    // progress through the plane within a single tick regardless of per-row outcome.
    private const int BatchSize = 100;

    // Upper bound on artifacts processed in one tick. Caps blob reads + extraction so a first pass
    // over a large backlog spreads across several daily runs instead of monopolizing one.
    private const int MaxPerTick = 500;

    private readonly CacheArtifactRepository _cacheArtifacts;
    private readonly LicenseRepository _licenses;
    private readonly IBlobStore _cache;   // TieredBlobStorage.Cache — proxy artifacts live here
    private readonly IAirGapMode _airGap;
    private readonly ILogger<LicenseBackfillService> _logger;
    private readonly TimeProvider _time;

    protected override string CronEnvKey => "LICENSE_BACKFILL_SCHEDULE";
    protected override string DefaultCron => "0 6 * * *";
    protected override bool RunOnStartup => true;
    protected override bool ContinueOnTickError => false;

    // Mutates authoritative cache_artifact rows — one replica per tick in HA mode.
    protected override bool RequiresLeaderLock => true;

    public LicenseBackfillService(
        CacheArtifactRepository cacheArtifacts,
        LicenseRepository licenses,
        TieredBlobStorage blobs,
        IAirGapMode airGap,
        IConfiguration config,
        ILogger<LicenseBackfillService> logger,
        TimeProvider time,
        IDistributedLock locks)
        : base(config, logger, time, locks)
    {
        _cacheArtifacts = cacheArtifacts;
        _licenses = licenses;
        // Proxy artifacts are cache-tier; in a split-tier deployment the registry tier holds no
        // proxy blobs, so always read from the cache store.
        _cache = blobs.Cache;
        _airGap = airGap;
        _logger = logger;
        _time = time;
    }

    protected override Task RunTickAsync(CancellationToken ct) => RunBackfillPassAsync(ct);

    /// <summary>
    /// Runs a single backfill pass. Internal so tests can invoke it directly without the cron loop.
    /// </summary>
    internal async Task RunBackfillPassAsync(CancellationToken ct)
    {
        if (_airGap.IsJobDisabled("license-backfill"))
        {
            _logger.LogInformation(
                "License backfill pass skipped (disabled by AIR_GAPPED or DISABLE_BACKGROUND_JOBS).");
            return;
        }

        // now-ok: measures real elapsed time for a duration log/metric only — no control
        // flow branches on the value, so a substitutable clock would change the reported
        // number without changing what the code does.
        var sw = System.Diagnostics.Stopwatch.StartNew();
        int scanned = 0;
        int found = 0;
        int stamped = 0;

        // Keyset cursor on (first_cached_at, id) — a total order. Advanced from the LAST row of
        // every batch regardless of per-row outcome, so a row that fails to process (and so is
        // never stamped) cannot re-enter a later page of THIS pass: the cursor has already moved
        // past it. A failed row stays license_checked_at IS NULL and is retried on the next
        // scheduled pass, when the cursor resets to the top — it never wedges the current pass.
        DateTimeOffset? afterFirstCachedAt = null;
        string? afterId = null;

        while (scanned < MaxPerTick && !ct.IsCancellationRequested)
        {
            int take = Math.Min(BatchSize, MaxPerTick - scanned);
            var batch = await _cacheArtifacts.ListNeedingLicenseBackfillAsync(
                take, afterFirstCachedAt, afterId, ct);
            if (batch.Count == 0)
            {
                break;
            }

            var (batchScanned, batchFound, batchStamped, lastFirstCachedAt, lastId) = await ProcessBatchAsync(batch, ct);
            scanned += batchScanned;
            found += batchFound;
            stamped += batchStamped;
            afterFirstCachedAt = lastFirstCachedAt;
            afterId = lastId;

            // A short read means the queue is drained for this pass — stop rather than issue
            // another round-trip that would return nothing.
            if (batch.Count < take)
            {
                break;
            }
        }

        sw.Stop();
        _logger.LogInformation(
            "License backfill pass complete. Scanned {Scanned} artifact(s), {Found} with a license, " +
            "{Stamped} stamped, took {ElapsedMs}ms.",
            scanned, found, stamped, sw.ElapsedMilliseconds);
    }

    // Processes one page of candidates, returning the per-batch counts and the keyset-cursor
    // position of the last row — advanced regardless of per-row outcome, per the cursor
    // invariant documented on RunBackfillPassAsync above.
    private async Task<(int Scanned, int Found, int Stamped, DateTimeOffset LastFirstCachedAt, string LastId)> ProcessBatchAsync(
        IReadOnlyList<LicenseBackfillCandidate> batch, CancellationToken ct)
    {
        int scanned = 0;
        int found = 0;
        int stamped = 0;

        foreach (var candidate in batch)
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            var outcome = await ProcessArtifactAsync(candidate, ct);
            scanned++;
            if (outcome is ArtifactOutcome.LicenseFound)
            {
                found++;
            }
            if (outcome is not ArtifactOutcome.Failed)
            {
                stamped++;
            }
        }

        var lastRow = batch[^1];
        return (scanned, found, stamped, lastRow.FirstCachedAt, lastRow.Id);
    }

    // Extracts and persists any license for one artifact, then stamps license_checked_at. The
    // extractor entry points never throw (they return Empty on malformed input) and a missing blob
    // is treated as "no license" — both still stamp so the row is scanned exactly once. Only an
    // unexpected failure (blob-backend or DB error) skips the stamp; it logs one warning and leaves
    // the row for a later pass.
    private async Task<ArtifactOutcome> ProcessArtifactAsync(
        LicenseBackfillCandidate candidate, CancellationToken ct)
    {
        try
        {
            var extracted = await ExtractLicensesAsync(candidate, ct);
            bool foundLicense = extracted.Spdx.Count > 0;
            if (foundLicense)
            {
                await _licenses.SetLicensesForCacheArtifactAsync(candidate.Id, extracted.Spdx, "upstream", ct);
            }

            await _cacheArtifacts.MarkLicenseCheckedAsync(candidate.Id, _time.GetUtcNow(), ct);
            return foundLicense ? ArtifactOutcome.LicenseFound : ArtifactOutcome.StampedNoLicense;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex,
                "License backfill failed for {Ecosystem}/{Package}@{Version}: {ExceptionType}",
                candidate.Ecosystem, candidate.Name, candidate.Version, ex.GetType().Name);
            return ArtifactOutcome.Failed;
        }
    }

    // Opens the cached bytes and dispatches to the ecosystem's stream-based extractor. The
    // extractor takes ownership of and disposes the stream. A cache miss (evicted blob whose row
    // lingered through a crash window) resolves to Empty without opening anything.
    private async Task<LicenseExtractor.ExtractedMetadata> ExtractLicensesAsync(
        LicenseBackfillCandidate candidate, CancellationToken ct)
    {
        var blob = await _cache.GetAsync(BlobKeys.StoreKey(candidate.BlobKey), ct);
        if (blob is null)
        {
            return LicenseExtractor.ExtractedMetadata.Empty;
        }

        switch (candidate.Ecosystem)
        {
            case "npm":
                return LicenseExtractor.FromNpmTarballPackageJson(blob);
            case "pypi":
                return LicenseExtractor.FromPyPiPackageBytes(blob, candidate.Filename);
            case "nuget":
                return LicenseExtractor.FromNuspec(blob);
            case "golang":
                return LicenseExtractor.FromGoModuleZip(blob, candidate.Name, candidate.Version);
            case "maven":
                return LicenseExtractor.FromPomXml(blob);
            case "cargo":
                return LicenseExtractor.FromCrateTarball(blob);
            default:
                // Unreachable — the repository query filters to the ecosystems above — but
                // dispose defensively so an unexpected row never leaks the opened stream.
                await blob.DisposeAsync();
                return LicenseExtractor.ExtractedMetadata.Empty;
        }
    }

    private enum ArtifactOutcome
    {
        LicenseFound,
        StampedNoLicense,
        Failed,
    }
}
