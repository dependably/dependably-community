using System.Threading.Channels;

namespace Dependably.Infrastructure;

/// <summary>
/// One project version queued for a component vulnerability scan. Carries <c>OrgId</c> alongside
/// <c>ProjectVersionId</c> — every query against <c>sbom_components</c>/<c>sbom_component_vulns</c>
/// must filter on <c>org_id</c>, so the enqueuing caller's already-authenticated org is threaded
/// through the queue item rather than re-derived from the id alone.
/// </summary>
public sealed record SbomScanRequest(string OrgId, string ProjectVersionId);

/// <summary>Injected dependencies, bundled so the constructor stays within S107.</summary>
public sealed record SbomScanWorkerServices(
    SbomComponentVulnRepository SbomComponents,
    SbomComponentScanner Scanner,
    Dependably.Protocol.SbomPolicyEvaluationService Policy,
    AuditRepository Audit,
    OrgRepository Orgs,
    IAirGapMode AirGap,
    IConfiguration Config,
    TimeProvider Time,
    ILogger<SbomScanWorker> Logger);

/// <summary>
/// Bounded in-process channel worker behind the SBOM upload path's <c>scanQueued: true</c>
/// response and the rescan endpoint. Drains queued project versions, batches their scannable
/// components through <see cref="SbomComponentScanner"/> (the same OSV batch-and-persist
/// primitive the nightly restart/missed-upload safety net in <see cref="VulnerabilityScanService"/>
/// uses), and writes one <c>sbom_scan_complete</c> activity row per drained version.
///
/// Overflow policy: drop-on-full, logged. What a dropped enqueue costs depends on which version it
/// named, because the nightly pass's two halves have different reach. Its scanning half still
/// covers every dropped version: those components keep a NULL or stale <c>vuln_checked_at</c> and
/// stay in that pass's work queue whatever version they hang off. Its re-evaluation half is bounded
/// to <c>is_latest</c> versions, so for a superseded version the advisory links are refreshed but
/// the verdict is not restamped — <c>policy_status</c> and <c>sbom_policy_findings</c> keep whatever
/// the last evaluation left, until an operator retries the rescan past the cooldown or the version
/// is promoted. For an <c>is_latest</c> version the nightly pass remains a complete safety net.
///
/// The wait loop is a plain <see cref="ChannelReader{T}.WaitToReadAsync"/> — no timer of its own.
/// The nightly pass already owns the scheduled-tick side of this feature; this worker only ever
/// reacts to an enqueue, so it needs no <c>Task.Delay</c>/<c>PeriodicTimer</c> poll.
///
/// <c>sbom-scan</c> is a named background job, and this worker honours that switch on the same
/// terms the nightly pass does: with the job disabled (<c>AIR_GAPPED</c>, an explicit
/// <c>DISABLE_BACKGROUND_JOBS</c> entry, or edge mode) <see cref="TryEnqueue"/> queues nothing and
/// returns false, and the drain refuses anything already in flight. Gating the enqueue rather than
/// only the drain is what keeps the upload response's <c>scanQueued</c> truthful — a request that
/// was never queued must not be reported as queued — and it is what stops an operator who has
/// switched the job off from still paying for outbound advisory queries on every upload.
/// </summary>
public sealed class SbomScanWorker : BackgroundService
{
    /// <summary>Default channel capacity used when no configuration override is supplied.</summary>
    public const int DefaultChannelCapacity = 1000;

    // OSV batch ceiling — same constant the nightly pass batches against.
    private const int OsvScanBatchSize = 100;

    private readonly Channel<SbomScanRequest> _channel;
    private readonly SbomComponentVulnRepository _sbomComponents;
    private readonly SbomComponentScanner _scanner;
    private readonly Dependably.Protocol.SbomPolicyEvaluationService _policy;
    private readonly AuditRepository _audit;
    private readonly OrgRepository _orgs;
    private readonly IAirGapMode _airGap;
    private readonly IConfiguration _config;
    private readonly TimeProvider _time;
    private readonly ILogger<SbomScanWorker> _logger;

    public SbomScanWorker(SbomScanWorkerServices services, int? channelCapacity = null)
    {
        _sbomComponents = services.SbomComponents;
        _scanner = services.Scanner;
        _policy = services.Policy;
        _audit = services.Audit;
        _orgs = services.Orgs;
        _airGap = services.AirGap;
        _config = services.Config;
        _time = services.Time;
        _logger = services.Logger;

        int capacity = channelCapacity is > 0 ? channelCapacity.Value : DefaultChannelCapacity;
        // FullMode.Wait, not a Drop* mode: TryWrite on a Drop* channel always reports success
        // (it makes room by dropping something), so a caller could never tell a queued request
        // from a discarded one. Wait's TryWrite is still non-blocking — it returns false
        // immediately instead of queuing when full — which is exactly the "false = not queued"
        // signal TryEnqueue's return value promises callers.
        _channel = Channel.CreateBounded<SbomScanRequest>(new BoundedChannelOptions(capacity)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait,
        });
    }

    /// <summary>
    /// Queues a project version for a component vulnerability scan. Non-blocking; returns false
    /// (and logs) when the channel is full rather than throwing — the nightly safety net still
    /// covers the version.
    /// </summary>
    public bool TryEnqueue(string orgId, string projectVersionId)
    {
        if (_airGap.IsJobDisabled("sbom-scan"))
        {
            _logger.LogDebug(
                "SBOM scan queue is disabled (AIR_GAPPED or DISABLE_BACKGROUND_JOBS); project version " +
                "{ProjectVersionId} was not enqueued.",
                projectVersionId);
            return false;
        }

        bool queued = _channel.Writer.TryWrite(new SbomScanRequest(orgId, projectVersionId));
        if (!queued)
        {
            _logger.LogWarning(
                "SBOM scan queue full; project version {ProjectVersionId} was not enqueued and will be " +
                "picked up by the nightly SBOM scan pass instead.",
                projectVersionId);
        }

        return queued;
    }

    /// <summary>
    /// Drains every request currently queued (a snapshot — anything enqueued mid-drain is picked
    /// up by the next call) and scans each in turn. Internal so tests drive the drain directly
    /// rather than through <see cref="BackgroundService.StartAsync"/>'s fire-and-forget loop,
    /// matching the <c>DownloadCountWriterHostedService.DrainPendingAsync</c> precedent.
    /// </summary>
    internal async Task DrainPendingAsync(CancellationToken ct = default)
    {
        var reader = _channel.Reader;
        bool disabled = _airGap.IsJobDisabled("sbom-scan");
        while (reader.TryRead(out var request))
        {
            if (disabled)
            {
                // Drained and discarded rather than left in the channel: the components still
                // carry a NULL or stale vuln_checked_at, so the nightly pass remains the queue of
                // record for them the moment the job is switched back on.
                continue;
            }

            await ScanOneAsync(request, ct);
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("SBOM scan worker starting.");
        var reader = _channel.Reader;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // Blocks until a request arrives or the channel completes (graceful shutdown —
                // there is no producer that ever calls Complete() today, so in practice this
                // exits only on cancellation).
                if (!await reader.WaitToReadAsync(stoppingToken))
                {
                    break;
                }

                await DrainPendingAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                // A failed drain iteration must never fault the hosted service — under the
                // default BackgroundServiceExceptionBehavior that stops the whole host. The
                // request that was being processed is lost from this queue, but the nightly
                // pass still covers it.
                _logger.LogError(ex,
                    "{ExceptionType} in the SBOM scan worker's drain loop; continuing.", ex.GetType().Name);
            }
        }

        _logger.LogInformation("SBOM scan worker stopping.");
    }

    private async Task ScanOneAsync(SbomScanRequest request, CancellationToken ct)
    {
        if (!await OrgIsScannableAsync(request, ct))
        {
            return;
        }

        IReadOnlyList<ScannableSbomComponent> components;
        try
        {
            components = await _sbomComponents.GetScannableComponentsForVersionAsync(
                request.OrgId, request.ProjectVersionId, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Failed to load SBOM components for project version {ProjectVersionId}; scan skipped.",
                request.ProjectVersionId);
            return;
        }

        var totals = await ScanBatchesAsync(components, ct);

        _logger.LogInformation(
            "SBOM scan complete for project version {ProjectVersionId}: {Scanned} component(s) scanned, " +
            "{Advisories} advisory hit(s), {Deferred} deferred.",
            request.ProjectVersionId, totals.Scanned, totals.Advisories, totals.Deferred);

        await EvaluatePolicyAsync(request, ct);
        await RecordCompletionAsync(request, totals, ct);
    }

    /// <summary>
    /// Whether this request's org may be scanned at all.
    ///
    /// <para>A suspended/archived/deleting org (see <see cref="TenantLifecycle"/>) is skipped: this
    /// worker's whole purpose is an outbound OSV batch query, and TenantStatusEnforcementMiddleware
    /// has already refused the upload/rescan request that would enqueue new work for a non-active
    /// org — this only matters for a request already queued when suspension landed.</para>
    ///
    /// <para>Fails closed, matching WebhookDispatchQueue.FanOutAsync and
    /// AlertSlackQueue.ResolveDestinationAsync: an org lookup that failed for its own reasons must
    /// not read as "active" and proceed with the outbound query. The nightly
    /// VulnerabilityScanService pass is this worker's own documented safety net, so skipping here
    /// loses nothing but immediacy.</para>
    /// </summary>
    private async Task<bool> OrgIsScannableAsync(SbomScanRequest request, CancellationToken ct)
    {
        Org? org;
        try
        {
            org = await _orgs.GetByIdAsync(request.OrgId, ct);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Failed to resolve org {OrgId} before SBOM scan; skipping project version {ProjectVersionId} this pass.",
                request.OrgId, request.ProjectVersionId);
            return false;
        }

        if (TenantLifecycle.IsActive(org))
        {
            return true;
        }

        _logger.LogInformation(
            "SBOM scan skipped for project version {ProjectVersionId}: org {OrgId} is {Status} (deleted={Deleted}).",
            request.ProjectVersionId, request.OrgId, org?.Status ?? "unknown", org?.DeletedAt is not null);
        return false;
    }

    private readonly record struct ScanTotals(int Scanned, int Advisories, int Deferred);

    /// <summary>
    /// Runs the components through OSV in batches, pausing between them so a large version does not
    /// burst the upstream.
    ///
    /// <para>An empty scannable set skips the loop entirely, but never the evaluation the caller
    /// runs afterwards: a version whose components all lack a parseable purl (or sit in a no-feed
    /// ecosystem) still carries declared licences, and the licence arm is the tenant's own gate —
    /// leaving it unrun means an org with license_enforcement_mode=block silently gets no verdict
    /// at all.</para>
    /// </summary>
    private async Task<ScanTotals> ScanBatchesAsync(
        IReadOnlyList<ScannableSbomComponent> components, CancellationToken ct)
    {
        int batchDelayMs = int.TryParse(_config["VULN_SCAN_BATCH_DELAY_MS"], out int d) ? d : 500;
        int scanned = 0;
        int advisories = 0;
        int deferred = 0;

        for (int offset = 0; offset < components.Count; offset += OsvScanBatchSize)
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            var batch = components.Skip(offset).Take(OsvScanBatchSize).ToList();
            var result = await _scanner.ScanBatchAsync(batch, ct);
            if (result.Deferred)
            {
                deferred += batch.Count;
            }
            else
            {
                scanned += result.ScannedComponentIds.Count;
                advisories += result.AdvisoryCountByComponentId.Values.Sum();
            }

            bool moreBatches = offset + OsvScanBatchSize < components.Count;
            if (moreBatches)
            {
                try { await Task.Delay(TimeSpan.FromMilliseconds(batchDelayMs), _time, ct); }
                catch (OperationCanceledException) { break; }
            }
        }

        return new ScanTotals(scanned, advisories, deferred);
    }

    /// <summary>
    /// Materializes the policy findings at scan completion, so an alert fires once and the list
    /// rollups do not fan out per row. A deferred batch leaves its components unscanned, which the
    /// evaluator reads as warn rather than pass.
    /// </summary>
    private async Task EvaluatePolicyAsync(SbomScanRequest request, CancellationToken ct)
    {
        try
        {
            await _policy.EvaluateAndPersistAsync(request.OrgId, request.ProjectVersionId, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Policy evaluation failed for project version {ProjectVersionId} after scan.",
                request.ProjectVersionId);
        }
    }

    private async Task RecordCompletionAsync(SbomScanRequest request, ScanTotals totals, CancellationToken ct)
    {
        try
        {
            // audit-attribution-ok: written from the async scan worker after draining a queued
            // request. By the time this runs, the HTTP request that enqueued it (an upload or a
            // rescan) has long since completed and responded, and the queue is shared across
            // every concurrent caller for the org — there is no single actor or source IP left
            // to attribute this row to.
            await _audit.LogActivityAsync(
                request.OrgId,
                ecosystem: "system",
                purl: null,
                eventType: "sbom_scan_complete",
                actorId: null,
                detail: totals.Deferred > 0
                    ? $"Scanned {totals.Scanned} component(s), {totals.Advisories} advisory hit(s), {totals.Deferred} deferred (source unreachable)"
                    : $"Scanned {totals.Scanned} component(s), {totals.Advisories} advisory hit(s)",
                ct: ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Failed to write sbom_scan_complete activity for project version {ProjectVersionId}.",
                request.ProjectVersionId);
        }
    }
}
