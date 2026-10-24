using System.Security.Claims;
using System.Text.Json;
using System.Text.RegularExpressions;
using Dependably.Infrastructure;
using Dependably.Infrastructure.OciScan;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>Injected dependencies, bundled so the controller constructor stays within S107.</summary>
public sealed record OciScanControllerServices(
    OrgAccessGuard Guard,
    OciScanOptions Options,
    OciScanRepository Jobs,
    OciScanImageReader Images,
    OciScanResultWriter Results,
    SbomIngestRepository Actors,
    AuditRepository Audit,
    ProblemResults Problems,
    TimeProvider Time);

/// <summary>
/// The scan API an out-of-process OCI image scanner drives, under <c>/api/v1/oci-scan/</c>.
///
/// <para><b>Who calls it.</b> A tenant API token (a service token, or a user token) holding
/// <c>scan:oci</c>, or an admin's session. The scanner speaks for one org: it claims that org's
/// queued images, reads them, and posts results that become that org's view of each image. No
/// call reads or writes another org's rows, and a job or digest outside the caller's org is 404,
/// never 403.</para>
///
/// <para><b>Off means absent.</b> With <c>OCI_SCAN_ENABLED</c> unset every route is 404, so a
/// deployment that never turned scanning on exposes no new surface.</para>
///
/// <para><b>Leases.</b> A claim leases a job for <c>OCI_SCAN_LEASE</c>. Reads, heartbeats, results
/// and failures all require the lease to be live; a scanner that lost it (it took longer than the
/// lease without a heartbeat, and another claim may now hold the job) gets 404 on reads and 409 on
/// writes, and its result is discarded rather than racing the new holder's.</para>
///
/// <para><b>Fencing.</b> A claim returns the job's <c>attempt</c>; heartbeat, result, fail and the
/// rematch routes require it back as <c>?attempt=</c>, and answer 422 without it or with a value
/// below 1. A re-claim bumps the counter, so a holder whose lease lapsed gets 409 even though the
/// new holder's lease is live.</para>
///
/// <para><b>Liveness.</b> Every call records the org's scanner as seen. That heartbeat is what
/// moves the org's unscanned OCI images from <c>no_feed</c> to <c>unscanned</c>, so an idle
/// scanner keeps it current by claiming even when the queue is empty.</para>
///
/// <para><b>Rematch.</b> A scanner that claims with <c>?kinds=scan,rematch</c> opts its org in to
/// rematch jobs, which re-match an image's stored inventory against OSV without reading a layer.
/// Such a job is served through <c>inventory</c> and finished with <c>matches</c>, or handed back
/// with <c>reextract</c> when the scanner's extractor is newer than the stored one; its manifest
/// and blob reads are 404. Those three routes answer 404 for a job outside the caller's org or of
/// another kind, and 409 for a lease or attempt the caller no longer holds.</para>
/// </summary>
[ApiController]
// The scanner holds an API token; an admin may also drive the API from a session, as with SBOM upload.
[Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
[Route("api/v1/oci-scan")]
public sealed partial class OciScanController : ControllerBase
{
    private readonly OciScanControllerServices _svc;

    public OciScanController(OciScanControllerServices svc) => _svc = svc;

    /// <summary>
    /// Leases up to <c>max</c> (default 1, at most 16) of the org's due jobs. <c>kinds</c> is the
    /// comma-separated job kinds the scanner handles; only one that names <c>rematch</c> is handed
    /// rematch jobs, and it is a query parameter so an older server, which binds the body
    /// strictly, ignores it. Every claim records whether the org's scanner accepts rematch jobs.
    /// The response's <c>capabilities</c> lists what this server supports beyond a plain scan.
    /// </summary>
    [HttpPost("claim")]
    [EnableRateLimiting("oci-scan")]
    [RequireCapability(Capabilities.ScanOci)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Claim(
        [FromBody] OciScanClaimRequest? body, [FromQuery] string? kinds, CancellationToken ct)
    {
        var (error, orgId) = await AuthorizeAsync(body?.Scanner, ct);
        if (error is not null)
        {
            return error;
        }

        int max = body?.Max ?? 1;
        if (max is < 1 or > OciScanLimits.MaxClaim)
        {
            return _svc.Problems.ValidationErrorActionKey("max", "error.ociScan.claimMax", OciScanLimits.MaxClaim);
        }

        bool rematch = OciScanKinds.IncludesRematch(kinds);
        await _svc.Jobs.SetAcceptsRematchAsync(orgId, rematch, ct);

        var now = _svc.Time.GetUtcNow();
        var jobs = await _svc.Jobs.ClaimAsync(
            orgId, max, _svc.Options.MaxAttempts, now.ToUtcIsoMillis(), now.Add(_svc.Options.Lease).ToUtcIsoMillis(),
            rematch, ct);
        return Ok(new
        {
            jobs = jobs.Select(j => new OciScanClaimedJob(
                j.Id, j.Kind, j.Owner.Kind, j.Repository, j.Digest, j.LeaseExpiresAt, j.Attempts)),
            capabilities = OciScanKinds.Capabilities,
        });
    }

    /// <summary>
    /// The stored inventory a leased rematch job re-matches: one entry per platform, each with its
    /// coverage id (the token <c>matches</c> echoes back), extraction and scanner versions,
    /// content gaps, and components. Streamed from the database as it is read.
    /// </summary>
    [HttpGet("{jobId}/inventory")]
    [EnableRateLimiting("oci-scan")]
    [RequireCapability(Capabilities.ScanOci)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Inventory(string jobId, [FromQuery] int? attempt, CancellationToken ct)
    {
        var (error, orgId) = await AuthorizeAsync(null, ct);
        if (error is not null)
        {
            return error;
        }

        var (refused, job) = await LeaseRematchAsync(orgId, jobId, attempt, ct);
        if (refused is not null)
        {
            return refused;
        }

        var platforms = await _svc.Jobs.GetInventoryPlatformsAsync(orgId, job!.Owner, ct);
        Response.StatusCode = StatusCodes.Status200OK;
        Response.ContentType = "application/json; charset=utf-8";
        await using var json = new Utf8JsonWriter(Response.Body);
        json.WriteStartObject();
        json.WriteStartArray("platforms");

        int index = -1;
        await foreach (var component in _svc.Jobs.StreamInventoryComponentsAsync(
            orgId, job.Owner, OciScanLimits.MaxComponents, ct))
        {
            // Both reads order by platform, so components arrive grouped in the platforms' order.
            index = AdvanceToPlatform(json, platforms, index, component.Platform);
            if (index >= platforms.Count)
            {
                // A component of a platform the first read did not see: a re-extraction replaced
                // the inventory mid-read, and the coverage ids already sent refuse the result.
                break;
            }

            WriteComponent(json, component);
            if (json.BytesPending > 16 * 1024)
            {
                await json.FlushAsync(ct);
            }
        }

        if (index >= 0 && index < platforms.Count)
        {
            EndPlatform(json);
        }

        for (index = Math.Max(index + 1, 0); index < platforms.Count; index++)
        {
            BeginPlatform(json, platforms[index]);
            EndPlatform(json);
        }

        json.WriteEndArray();
        json.WriteEndObject();
        await json.FlushAsync(ct);
        return new EmptyResult();
    }

    /// <summary>
    /// A rematch job's result: new findings for the stored inventory, replacing the image's
    /// findings and matching gaps while keeping its components and content gaps. 409 when the
    /// inventory a posted coverage id names has since been replaced.
    /// </summary>
    [HttpPost("{jobId}/matches")]
    [EnableRateLimiting("oci-scan")]
    [RequireCapability(Capabilities.ScanOci)]
    [RequestSizeLimit(OciScanLimits.MaxResultBytes)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Matches(
        string jobId, [FromBody] OciScanMatchRequest body, [FromQuery] int? attempt, CancellationToken ct)
    {
        var (error, orgId) = await AuthorizeAsync(body.Scanner, ct);
        if (error is not null)
        {
            return error;
        }

        var (refused, job) = await LeaseRematchAsync(orgId, jobId, attempt, ct);
        if (refused is not null)
        {
            return refused;
        }

        // The body is checked whole, against the caps, before anything is written; the writer then
        // checks every finding against the stored inventory.
        var (invalid, _) = OciScanResultWriter.ValidateMatches(body);
        if (invalid is not null)
        {
            return _svc.Problems.ValidationErrorActionKey(invalid.Field!, invalid.ErrorKey!, invalid.ErrorArgs ?? []);
        }

        var (status, summary) = await _svc.Results.WriteValidatedMatchesAsync(job!, body, ct);
        switch (status.Outcome)
        {
            case OciScanResultOutcome.Invalid:
                return _svc.Problems.ValidationErrorActionKey(status.Field!, status.ErrorKey!, status.ErrorArgs ?? []);
            case OciScanResultOutcome.LeaseLost:
                return LeaseLost();
            case OciScanResultOutcome.InventoryChanged:
                return _svc.Problems.ConflictActionKey("error.ociScan.inventoryChanged");
            case OciScanResultOutcome.AdvisorySourceUnavailable:
                return await RetryLaterAsync(orgId, job!, ct);
        }

        await AuditAsync(orgId, "oci_scan_rematch_result", job!,
            new { platforms = summary!.Platforms, findings = summary.Findings, advisories = summary.Advisories }, ct);
        return NoContent();
    }

    /// <summary>
    /// Hands a rematch job back because the stored inventory came from an older extractor than
    /// the scanner's: the job closes and the image is queued for a re-extraction, keeping its
    /// previous result until that posts.
    /// </summary>
    [HttpPost("{jobId}/reextract")]
    [EnableRateLimiting("oci-scan")]
    [RequireCapability(Capabilities.ScanOci)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Reextract(
        string jobId, [FromBody] OciScanReextractRequest body, [FromQuery] int? attempt, CancellationToken ct)
    {
        var (error, orgId) = await AuthorizeAsync(body.Scanner, ct);
        if (error is not null)
        {
            return error;
        }

        string reason = (body.Reason ?? "").Trim();
        if (reason.Length is 0 or > OciScanLimits.MaxReasonLength)
        {
            return _svc.Problems.ValidationErrorActionKey("reason", "error.ociScan.failReason", OciScanLimits.MaxReasonLength);
        }

        var (refused, job) = await LeaseRematchAsync(orgId, jobId, attempt, ct);
        if (refused is not null)
        {
            return refused;
        }

        var (closed, requeued) = await _svc.Jobs.ReextractAsync(job!, _svc.Time.GetUtcNow().ToUtcIsoMillis(), ct);
        if (!closed)
        {
            return LeaseLost();
        }

        await AuditAsync(orgId, "oci_scan_reextract", job!, new { reason, requeued }, ct);
        return Ok(new { state = "done", requeued });
    }

    /// <summary>A manifest or index of the leased image.</summary>
    [HttpGet("{jobId}/manifests/{digest}")]
    [EnableRateLimiting("oci-scan")]
    [RequireCapability(Capabilities.ScanOci)]
    public Task<IActionResult> GetManifest(string jobId, string digest, CancellationToken ct)
        => ReadAsync(jobId, digest, manifest: true, ct);

    /// <summary>A config or layer blob of the leased image.</summary>
    [HttpGet("{jobId}/blobs/{digest}")]
    [EnableRateLimiting("oci-scan")]
    [RequireCapability(Capabilities.ScanOci)]
    public Task<IActionResult> GetBlob(string jobId, string digest, CancellationToken ct)
        => ReadAsync(jobId, digest, manifest: false, ct);

    /// <summary>Extends the job's lease by <c>OCI_SCAN_LEASE</c> from now.</summary>
    [HttpPost("{jobId}/heartbeat")]
    [EnableRateLimiting("oci-scan")]
    [RequireCapability(Capabilities.ScanOci)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status422UnprocessableEntity)]
    // input-validation-ok: every field of the scanner report is optional and free-form; each is
    // clipped to a fixed length before it is stored (AuthorizeAsync), and none is interpreted.
    public async Task<IActionResult> Heartbeat(
        string jobId, [FromBody] OciScannerReport? body, [FromQuery] int? attempt, CancellationToken ct)
    {
        var (error, orgId) = await AuthorizeAsync(body, ct);
        if (error is not null)
        {
            return error;
        }

        if (attempt is not { } fenced || fenced < 1)
        {
            return AttemptRequired();
        }

        var now = _svc.Time.GetUtcNow();
        string until = now.Add(_svc.Options.Lease).ToUtcIsoMillis();
        return await _svc.Jobs.ExtendLeaseAsync(orgId, jobId, now.ToUtcIsoMillis(), until, fenced, ct)
            ? Ok(new { leaseExpiresAt = until })
            : LeaseLost();
    }

    /// <summary>Stores the image's components, findings and coverage, and completes the job.</summary>
    [HttpPost("{jobId}/result")]
    [EnableRateLimiting("oci-scan")]
    [RequireCapability(Capabilities.ScanOci)]
    [RequestSizeLimit(OciScanLimits.MaxResultBytes)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status422UnprocessableEntity)]
    [ProducesResponseType(StatusCodes.Status503ServiceUnavailable)]
    public async Task<IActionResult> Result(
        string jobId, [FromBody] OciScanResultRequest body, [FromQuery] int? attempt, CancellationToken ct)
    {
        var (error, orgId) = await AuthorizeAsync(body.Scanner, ct);
        if (error is not null)
        {
            return error;
        }

        if (attempt is not { } fenced || fenced < 1)
        {
            return AttemptRequired();
        }

        var job = await _svc.Jobs.GetLeasedAsync(
            orgId, jobId, _svc.Time.GetUtcNow().ToUtcIsoMillis(), fenced, ct);
        if (job is null)
        {
            return LeaseLost();
        }

        var status = await _svc.Results.WriteAsync(job, body, ct);
        switch (status.Outcome)
        {
            case OciScanResultOutcome.Invalid:
                return _svc.Problems.ValidationErrorActionKey(status.Field!, status.ErrorKey!, status.ErrorArgs ?? []);
            case OciScanResultOutcome.LeaseLost:
                return LeaseLost();
            case OciScanResultOutcome.AdvisorySourceUnavailable:
                return await RetryLaterAsync(orgId, job, ct);
        }

        int gaps = body.Platforms!.Sum(p => p.Gaps?.Count ?? 0);
        int components = body.Platforms!.Sum(p => p.Components!.Count);
        await AuditAsync(orgId, "oci_scan_result", job, new { platforms = body.Platforms!.Count, components, gaps }, ct);
        return NoContent();
    }

    /// <summary>
    /// Ends the attempt without a result. <c>retryable</c> returns the job to the queue with
    /// exponential backoff until <c>OCI_SCAN_MAX_ATTEMPTS</c>; otherwise it is parked as failed.
    /// The image is never stamped either way, so it stays unscanned.
    /// </summary>
    [HttpPost("{jobId}/fail")]
    [EnableRateLimiting("oci-scan")]
    [RequireCapability(Capabilities.ScanOci)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status422UnprocessableEntity)]
    public async Task<IActionResult> Fail(
        string jobId, [FromBody] OciScanFailRequest body, [FromQuery] int? attempt, CancellationToken ct)
    {
        var (error, orgId) = await AuthorizeAsync(null, ct);
        if (error is not null)
        {
            return error;
        }

        if (attempt is not { } fenced || fenced < 1)
        {
            return AttemptRequired();
        }

        string reason = (body.Reason ?? "").Trim();
        if (reason.Length is 0 or > OciScanLimits.MaxReasonLength)
        {
            return _svc.Problems.ValidationErrorActionKey("reason", "error.ociScan.failReason", OciScanLimits.MaxReasonLength);
        }

        var now = _svc.Time.GetUtcNow();
        var job = await _svc.Jobs.GetLeasedAsync(orgId, jobId, now.ToUtcIsoMillis(), fenced, ct);
        if (job is null)
        {
            return LeaseLost();
        }

        bool park = !body.Retryable || job.AttemptsUsed >= _svc.Options.MaxAttempts;
        string? nextAttemptAt = park ? null : now.Add(RetryDelay(job.AttemptsUsed)).ToUtcIsoMillis();
        if (!await _svc.Jobs.FailAsync(orgId, jobId, job.Attempts, now.ToUtcIsoMillis(), park, nextAttemptAt, reason, ct))
        {
            return LeaseLost();
        }

        await AuditAsync(orgId, "oci_scan_failed", job, new { reason, retryable = body.Retryable, parked = park }, ct);
        return Ok(new { state = park ? "failed" : "pending", nextAttemptAt });
    }

    /// <summary>
    /// A result refused because the advisory source could not be reached to verify the advisories
    /// it names. The claim ends as a deferral: the job returns to the queue after a backoff that
    /// doubles per deferral up to <see cref="OciScanOptions.AdvisoryDeferMaxDelay"/>, and the claim
    /// does not spend the attempt budget, so an outage of any length never parks the job. The image
    /// keeps its previous result meanwhile. 503; the scanner holds no lease afterwards.
    /// </summary>
    private async Task<IActionResult> RetryLaterAsync(string orgId, OciScanJob job, CancellationToken ct)
    {
        const string reason = "the advisory source could not be reached to verify the result's advisories";
        var now = _svc.Time.GetUtcNow();
        string nextAttemptAt = now.Add(DeferDelay(job.Deferrals)).ToUtcIsoMillis();
        if (!await _svc.Jobs.DeferAsync(orgId, job.Id, job.Attempts, now.ToUtcIsoMillis(), nextAttemptAt, reason, ct))
        {
            return LeaseLost();
        }

        await AuditAsync(orgId, "oci_scan_failed", job,
            new { reason, retryable = true, parked = false, deferred = true }, ct);
        return _svc.Problems.ServiceUnavailableActionKey("error.ociScan.advisorySourceUnavailable");
    }

    /// <summary>The wait before a deferred job is due again: the base delay doubled per earlier deferral, capped.</summary>
    internal TimeSpan DeferDelay(int deferrals)
    {
        double factor = Math.Pow(2, Math.Clamp(deferrals, 0, 20));
        return TimeSpan.FromTicks((long)Math.Min(
            _svc.Options.RetryBaseDelay.Ticks * factor, _svc.Options.AdvisoryDeferMaxDelay.Ticks));
    }

    /// <summary>Base delay doubled per attempt already made, capped.</summary>
    internal TimeSpan RetryDelay(int attempts)
    {
        double factor = Math.Pow(2, Math.Clamp(attempts - 1, 0, 20));
        var delay = TimeSpan.FromTicks((long)Math.Min(_svc.Options.RetryBaseDelay.Ticks * factor, _svc.Options.RetryMaxDelay.Ticks));
        return delay;
    }

    private async Task<IActionResult> ReadAsync(string jobId, string digest, bool manifest, CancellationToken ct)
    {
        var (error, orgId) = await AuthorizeAsync(null, ct);
        if (error is not null)
        {
            return error;
        }

        if (!DigestPattern().IsMatch(digest))
        {
            return NotFound();
        }

        var job = await _svc.Jobs.GetLeasedForReadAsync(orgId, jobId, _svc.Time.GetUtcNow().ToUtcIsoMillis(), ct);
        // A rematch job reads no layer: the server refuses its image reads, so "no blob or
        // manifest read" does not rest on the scanner's habits.
        if (job is null || job.Kind != OciScanKinds.Scan)
        {
            return NotFound();
        }

        var read = await _svc.Images.ReadAsync(job, digest, manifest, ct);
        return read.Outcome switch
        {
            OciScanReadOutcome.Found => File(read.Content!, read.MediaType!, enableRangeProcessing: false),
            // The image names it but nothing can supply it now; the scanner retries the job later.
            OciScanReadOutcome.Unavailable => _svc.Problems.ServiceUnavailableActionKey("error.ociScan.unavailable"),
            _ => NotFound(),
        };
    }

    // A missing attempt, or one no claim can have returned (a claim's first attempt is 1), is a
    // 422 on every route that writes; it never falls back to the lease alone.
    private IActionResult AttemptRequired() =>
        _svc.Problems.ValidationErrorActionKey("attempt", "error.ociScan.attemptRequired");

    // The rematch routes' fence. A job outside the org, or not a rematch, is 404; a lease or
    // attempt the caller no longer holds is 409.
    private async Task<(IActionResult? Refused, OciScanJob? Job)> LeaseRematchAsync(
        string orgId, string jobId, int? attempt, CancellationToken ct)
    {
        if (attempt is not { } fenced || fenced < 1)
        {
            return (AttemptRequired(), null);
        }

        var known = await _svc.Jobs.FindAsync(orgId, jobId, ct);
        if (known is null || known.Kind != OciScanKinds.Rematch)
        {
            return (NotFound(), null);
        }

        var job = await _svc.Jobs.GetLeasedAsync(
            orgId, jobId, _svc.Time.GetUtcNow().ToUtcIsoMillis(), fenced, ct);
        return job is null ? (LeaseLost(), null) : (null, job);
    }

    // Closes the open platform and opens each following one until the named platform is open.
    // Returns the open platform's index, or platforms.Count when the name is not among the rest.
    private static int AdvanceToPlatform(
        Utf8JsonWriter json, IReadOnlyList<OciInventoryPlatform> platforms, int index, string platform)
    {
        while (index < platforms.Count && (index < 0 || platforms[index].Platform != platform))
        {
            if (index >= 0)
            {
                EndPlatform(json);
            }

            index++;
            if (index < platforms.Count)
            {
                BeginPlatform(json, platforms[index]);
            }
        }

        return index;
    }

    private static void BeginPlatform(Utf8JsonWriter json, OciInventoryPlatform platform)
    {
        json.WriteStartObject();
        json.WriteString("platform", platform.Platform);
        json.WriteString("coverageId", platform.Id);
        json.WriteString("extractionVersion", platform.ExtractionVersion);
        json.WriteString("scannerVersion", platform.ScannerVersion);
        // Written value by value: JsonSerializer.Serialize into the writer would flush it, and a
        // synchronous flush to the response body is refused.
        if (platform.ContentGapsJson is null)
        {
            json.WriteNull("contentGaps");
        }
        else
        {
            json.WriteStartArray("contentGaps");
            foreach (string gap in JsonSerializer.Deserialize<string[]>(platform.ContentGapsJson) ?? [])
            {
                json.WriteStringValue(gap);
            }

            json.WriteEndArray();
        }

        json.WriteString("entrypointKind", platform.EntrypointKind);
        json.WriteBoolean("closureBounded", platform.ClosureBounded != 0);
        json.WriteStartArray("components");
    }

    private static void EndPlatform(Utf8JsonWriter json)
    {
        json.WriteEndArray();
        json.WriteEndObject();
    }

    private static void WriteComponent(Utf8JsonWriter json, OciInventoryComponent component)
    {
        json.WriteStartObject();
        json.WriteString("id", component.Id);
        json.WriteString("purl", component.Purl);
        json.WriteString("ecosystem", component.Ecosystem);
        json.WriteString("name", component.Name);
        json.WriteString("version", component.Version);
        json.WriteString("sourceName", component.SourceName);
        json.WriteString("sourceVersion", component.SourceVersion);
        json.WriteEndObject();
    }

    // Disabled scanning answers every route 404 before authorization, so the surface does not
    // exist; otherwise the caller must hold scan:oci in the tenant the host resolved, and every
    // call refreshes that org's scanner heartbeat.
    private async Task<(IActionResult? Error, string OrgId)> AuthorizeAsync(OciScannerReport? report, CancellationToken ct)
    {
        if (!_svc.Options.Enabled)
        {
            return (NotFound(), null!);
        }

        var deny = await _svc.Guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ScanOci, ct);
        if (deny is not null)
        {
            return (deny, null!);
        }

        string orgId = HttpContext.RequireTenantId();
        string? osvState = report?.OsvState is { ValueKind: not JsonValueKind.Undefined and not JsonValueKind.Null } state
            ? state.GetRawText()
            : null;
        await _svc.Jobs.TouchScannerAsync(
            orgId, _svc.Time.GetUtcNow().ToUtcIsoMillis(), Clip(report?.Version), Clip(report?.OsvSource),
            osvState is { Length: <= OciScanLimits.MaxTextLength } ? osvState : null, ct);
        return (null, orgId);
    }

    private async Task AuditAsync(string orgId, string action, OciScanJob job, object detail, CancellationToken ct)
    {
        string? actorId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? User.FindFirst("sub")?.Value;
        var actor = actorId is null ? null : await _svc.Actors.ResolveActorAsync(orgId, actorId, ct);
        // audit-action-ok: action is one of the declared literals its callers pass:
        // oci_scan_result, oci_scan_failed, oci_scan_rematch_result or oci_scan_reextract.
        await _svc.Audit.LogAsync(
            action, orgId, actorId,
            actorKind: actor?.Kind,
            ecosystem: "oci",
            purl: Dependably.Protocol.PurlNormalizer.Oci(job.Repository, job.Digest),
            detail: JsonSerializer.Serialize(
                new { job_id = job.Id, owner_kind = job.Owner.Kind, detail },
                Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), actorLabel: actor?.Label, ct: ct);
    }

    private IActionResult LeaseLost() => _svc.Problems.ConflictActionKey("error.ociScan.leaseLost");

    private static string? Clip(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Length <= 128 ? value : value[..128];

    [GeneratedRegex(@"\A(sha256:[a-f0-9]{64}|sha512:[a-f0-9]{128})\z")]
    private static partial Regex DigestPattern();
}
