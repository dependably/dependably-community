using System.Globalization;
using System.Security.Claims;
using Dapper;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// On-demand SBOM component vulnerability scanning.
///   POST /api/v1/projects/{projectId}/versions/{versionId}/rescan  — enqueue a scan (admin+)
///
/// The scan itself runs on <see cref="SbomScanWorker"/>'s background drain loop, not inline on
/// this request — the endpoint's own audit write carries the real caller's attribution (the
/// enqueue is what the caller did); the worker's eventual completion write is a separate,
/// genuinely actor-less background row (see its own doc comment).
/// </summary>
[ApiController]
[Authorize]
public sealed class SbomScanController : ControllerBase
{
    private static readonly TimeSpan RescanCooldown = TimeSpan.FromHours(1);

    private readonly IMetadataStore _db;
    private readonly SbomScanWorker _worker;
    private readonly OrgAccessGuard _guard;
    private readonly AuditRepository _audit;
    private readonly SbomIngestRepository _ingest;
    private readonly TimeProvider _time;

    public SbomScanController(
        IMetadataStore db,
        SbomScanWorker worker,
        OrgAccessGuard guard,
        AuditRepository audit,
        SbomIngestRepository ingest,
        TimeProvider time)
    {
        _db = db;
        _worker = worker;
        _guard = guard;
        _audit = audit;
        _ingest = ingest;
        _time = time;
    }

    /// <summary>
    /// POST /api/v1/projects/{projectId}/versions/{versionId}/rescan
    /// Enqueues an on-demand component vulnerability scan for one project version.
    /// <paramref name="versionId"/> accepts the literal <c>latest</c>, resolved against the
    /// project's current <c>is_latest</c> row. 1-hour cooldown, derived from the version's most
    /// recently scanned component (project versions carry no <c>vuln_checked_at</c> column of
    /// their own), mirroring the package rescan endpoint's cooldown shape.
    /// </summary>
    // input-validation-ok: projectId/versionId are opaque route ids resolved by an org-scoped
    // existence lookup below (404 on no match) — there is no further shape to validate.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpPost("api/v1/projects/{projectId}/versions/{versionId}/rescan")]
    [EnableRateLimiting("rescan")]
    public async Task<IActionResult> Rescan(string projectId, string versionId, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

        await using var conn = await _db.OpenAsync(ct);

        // 404-not-403: a project id from another org must read identically to a nonexistent one.
        string? realProjectId = await conn.ExecuteScalarAsync<string?>(
            "SELECT id FROM projects WHERE id = @projectId AND org_id = @orgId",
            new { projectId, orgId });
        if (realProjectId is null)
        {
            return NotFound();
        }

        string? resolvedVersionId = string.Equals(versionId, "latest", StringComparison.OrdinalIgnoreCase)
            ? await conn.ExecuteScalarAsync<string?>(
                """
                SELECT id FROM project_versions
                WHERE project_id = @realProjectId AND org_id = @orgId AND is_latest = 1
                """,
                new { realProjectId, orgId })
            : await conn.ExecuteScalarAsync<string?>(
                """
                SELECT id FROM project_versions
                WHERE id = @versionId AND project_id = @realProjectId AND org_id = @orgId
                """,
                new { versionId, realProjectId, orgId });
        if (resolvedVersionId is null)
        {
            return NotFound();
        }

        int? retryAfter = await CooldownRemainingAsync(conn, orgId, resolvedVersionId);
        if (retryAfter is not null)
        {
            Response.Headers.RetryAfter = retryAfter.Value.ToString(CultureInfo.InvariantCulture);
            return StatusCode(StatusCodes.Status429TooManyRequests,
                new { detail = "Scanned recently. Try again later.", retry_after_seconds = retryAfter.Value });
        }

        string? actorId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;

        // The route authenticates on the API-token scheme as well as the session one, and a
        // service token's subject is the token id rather than a users row. Resolved rather than
        // assumed: a 'user' discriminator over a token id names an actor the users join cannot
        // find, and the row then reads as anonymous. The label is populated for a service actor
        // only — a user's is an email, which the scrub sweeps do not cover in this column.
        (string? actorKind, string? actorLabel) = actorId is null
            ? (null, null)
            : await _ingest.ResolveActorAsync(orgId, actorId, ct);

        bool queued = _worker.TryEnqueue(orgId, resolvedVersionId);

        await _audit.LogActivityAsync(
            orgId, ecosystem: "system", purl: null, eventType: "sbom_rescan_requested",
            actorId: actorId, actorKind: actorKind,
            // The nightly pass is only a partial safety net for a dropped rescan, so this says so
            // rather than promising full cover: its scanning half re-scans the components of any
            // version, but its re-evaluation half is bounded to is_latest versions, so a superseded
            // version's verdict is not restamped until an operator retries past the cooldown.
            detail: queued
                ? "queued"
                : "queue full; the nightly SBOM pass rescans the components, and restamps the verdict only for the project's latest version",
            sourceIp: HttpContext.GetNormalizedRemoteIp(), actorLabel: actorLabel, ct: ct);

        return Accepted(new { queued });
    }

    /// <summary>
    /// Seconds remaining in the cooldown window, or null when the version is eligible for an
    /// immediate rescan (never scanned, or its most recent component scan is outside the window).
    /// </summary>
    private async Task<int?> CooldownRemainingAsync(
        System.Data.Common.DbConnection conn, string orgId, string projectVersionId)
    {
        string? lastChecked = await conn.ExecuteScalarAsync<string?>(
            """
            SELECT MAX(vuln_checked_at) FROM sbom_components
            WHERE project_version_id = @projectVersionId AND org_id = @orgId
            """,
            new { projectVersionId, orgId });

        if (lastChecked is null)
        {
            return null;
        }

        var lastCheckedAt = DateTimeOffset.Parse(
            lastChecked, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
        var elapsed = _time.GetUtcNow() - lastCheckedAt;
        return elapsed < RescanCooldown ? (int)(RescanCooldown - elapsed).TotalSeconds : null;
    }
}
