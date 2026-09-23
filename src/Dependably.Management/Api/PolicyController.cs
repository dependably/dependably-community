using Dependably.Infrastructure;
using Dependably.Infrastructure.VulnTracker;
using Dependably.Protocol;
using Dependably.Protocol.Provenance;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// GET /api/v1/policies — the member-visible governance summary: licence policy plus every
/// serve-path <c>BlockGateService</c> control, keyed by the same reason token the 403
/// <c>X-Dependably-Block-Reason</c> header carries. Gated on <see cref="Capabilities.ReadPackages"/>
/// (member and above, plus a pull-scoped PAT/service token) rather than
/// <see cref="Capabilities.ReadTenant"/> like <c>GET /api/v1/proxy-settings</c> — that endpoint's
/// admin-only gate is right for the raw settings row (it carries upstream URLs, credentials, and
/// anchor material), but it also means a member — or an MCP client holding only a pull token —
/// cannot answer "what governs whether this package gets served?" at all. This endpoint is a
/// deliberately narrower projection: machine tokens and normalized posture only, no prose (the
/// prose lives in the frontend locales and the MCP tool's own glossary), and none of the data
/// <see cref="PolicySummaryBuilder"/>'s own doc comment excludes. It is a different disclosure
/// channel from a 403 body, which withholds thresholds because those bodies end up in CI logs —
/// <c>/api/v1/lookup</c> already lets the same caller probe a verdict for a specific package.
/// </summary>
[ApiController]
[Authorize]
public sealed class PolicyController : ControllerBase
{
    private readonly OrgSettingsRepository _settings;
    private readonly LicenseRepository _licenses;
    private readonly OrgAccessGuard _guard;
    private readonly InstanceVulnTrackerConfig _vulnTracker;
    private readonly ProvenanceAnchorStatusResolver _anchors;
    private readonly IAirGapMode _airGap;

    public PolicyController(
        OrgSettingsRepository settings,
        LicenseRepository licenses,
        OrgAccessGuard guard,
        InstanceVulnTrackerConfig vulnTracker,
        ProvenanceAnchorStatusResolver anchors,
        IAirGapMode airGap)
    {
        _settings = settings;
        _licenses = licenses;
        _guard = guard;
        _vulnTracker = vulnTracker;
        _anchors = anchors;
        _airGap = airGap;
    }

    /// <summary>GET /api/v1/policies</summary>
    // Read-only: accepts a PAT/service token carrying read:packages, same as LicenseController's
    // GetPolicy.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/policies")]
    public async Task<IActionResult> Get(CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

        var settings = await _settings.GetSettingsAsync(orgId, ct);
        var allowlist = await _licenses.GetAllowlistAsync(orgId, ct);
        var blocklist = await _licenses.GetBlocklistAsync(orgId, ct);
        var tracker = await _vulnTracker.ResolveAsync(ct);
        var anchors = await _anchors.ResolveAsync(orgId, ct);
        // Same posture ThreatFeedRefreshService's own skip check uses — an instance-level signal
        // (the feeds are shared, not per-tenant), not read from the tenant's own air-gapped flag.
        bool threatFeedActive = !_airGap.IsJobDisabled("threat-feed");
        // The connection alone is not enough: malicious_live/ssvc_exploitation enrichment
        // (VulnerabilityScanService.EnrichBatchAsync) only runs from inside the scheduled scan
        // and rescan passes' shared batch pipeline (ProcessVersionsInBatchesAsync, called by both
        // RunScanPassInnerAsync and RunRescanPassInnerAsync) — the on-demand ScanVersionAsync path
        // never calls it. Either pass alone keeps enrichment flowing, so this is only inactive
        // when BOTH are disabled (AIR_GAPPED, or both named explicitly in DISABLE_BACKGROUND_JOBS).
        bool vulnTrackerActive = tracker.IsActive
            && !(_airGap.IsJobDisabled("vuln-scan") && _airGap.IsJobDisabled("vuln-rescan"));

        var summary = PolicySummaryBuilder.Build(settings, vulnTrackerActive, threatFeedActive, anchors);

        // The gate posture and thresholds this carries change what a caller can infer about the
        // tenant's serve path — never cache or let an intermediary cache a stale read.
        Response.Headers.CacheControl = "no-store";

        return Ok(new
        {
            allowlistMode = summary.AllowlistMode,
            proxyPassthroughEnabled = summary.ProxyPassthroughEnabled,
            license = new
            {
                installMode = settings?.LicenseEnforcementMode ?? "off",
                publishMode = settings?.LicensePublishEnforcementMode ?? "off",
                allowlist,
                blocklist,
            },
            controls = summary.Controls,
        });
    }
}
