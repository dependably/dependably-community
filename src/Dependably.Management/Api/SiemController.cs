using System.Text;
using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Infrastructure.Siem;
using Dependably.Security;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// SIEM integration API — read-only, machine-to-machine.
/// Accepts JWT (system_admin operator or any role with read:audit) or a Bearer token
/// carrying read:audit. Platform admins (capability <c>platform:*</c>) get cross-tenant
/// access; everyone else is scoped to their own tenant.
///
/// Deliberately carries no <c>[AllowAnonymous]</c>: auth is resolved manually below to support
/// both a JWT session and an opaque API token with <c>read:audit</c>, but the endpoints are not
/// anonymous. Leaving <c>[AllowAnonymous]</c> off keeps the global <c>RouteScopeFilter</c>,
/// <c>PasswordRotationGuard</c>, and <c>MfaEnrollmentGuard</c> filters live for JWT-session
/// callers, so a session mid-forced-password-rotation or missing required MFA enrollment cannot
/// pull audit/vuln data through this surface. The opaque-API-token path never authenticates
/// against the default JWT Bearer scheme (it isn't a JWT), so those guards remain a no-op for it,
/// exactly as before.
///
///   GET /api/v1/siem/events/auth          — auth event stream from audit_log
///   GET /api/v1/siem/events/activity      — allowlisted event stream from activity
///   GET /api/v1/siem/actions              — declared audit-action vocabulary
///   GET /api/v1/siem/vulnerabilities/summary — vuln severity totals
/// </summary>
[ApiController]
// authz-ok: no attribute by design, and not anonymous. Every action resolves auth by hand so one
// surface can accept either a JWT session or an opaque API token carrying read:audit, and returns
// an explicit Unauthorized otherwise. Omitting [AllowAnonymous] rather than adding it keeps
// RouteScopeFilter, PasswordRotationGuard, and MfaEnrollmentGuard live for JWT-session callers.
public sealed class SiemController : ControllerBase
{
    // Maximum page size for SIEM event stream responses.
    private const int MaxSiemPageSize = 500;

    private readonly AuditRepository _audit;
    private readonly VulnerabilityRepository _vulns;
    private readonly OrgRepository _orgs;
    private readonly TokenRepository _tokens;
    private readonly IConfiguration _config;
    private readonly TimeProvider _time;

    public SiemController(
        AuditRepository audit,
        VulnerabilityRepository vulns,
        OrgRepository orgs,
        TokenRepository tokens,
        IConfiguration config,
        TimeProvider time)
    {
        _audit = audit;
        _vulns = vulns;
        _orgs = orgs;
        _tokens = tokens;
        _config = config;
        _time = time;
    }

    /// <summary>
    /// GET /api/v1/siem/events/auth
    /// Returns audit_log events. With no action filter, the declared security vocabulary
    /// (<see cref="AuditActions.DefaultFilters"/>): authentication, credential lifecycle,
    /// privilege change, identity-provider trust, refusals and supply-chain integrity failures.
    ///
    /// Query parameters:
    ///   since  — ISO 8601 start time (default: 24 h ago)
    ///   until  — ISO 8601 end time (default: now)
    ///   org    — org slug filter; instance_admin only
    ///   action — repeatable; matches the action of exactly that name plus every action in its
    ///            dotted family (action=checksum_failure, action=login. / action=login).
    ///            GET /api/v1/siem/actions lists every value that resolves to something.
    ///   limit  — page size, 1–500 (default: 100)
    ///   cursor — opaque pagination cursor from previous response
    ///
    /// Accept header controls output format:
    ///   application/json (default) — JSON envelope: { items, next_cursor, latest_event_at,
    ///                                matched, matched_capped }
    ///   application/x-ndjson      — newline-delimited JSON (one object per line; envelope
    ///                                fields below are not emitted, only items + next_cursor)
    ///   application/x-cef         — Common Event Format (one record per line; same exclusion)
    ///
    /// Item fields: orgSlug is projected beside orgId so an alert names the tenant rather than a
    /// 32-hex id. actorEmail is intentionally always null on this surface — see the GDPR note in
    /// CONTRIBUTING.md → "Auth pull feed".
    ///
    /// JSON envelope fields beyond items/next_cursor:
    ///   latest_event_at — millisecond-precision timestamp of the most recent audit_log row
    ///                     visible to this caller at all, ignoring the action filter (and the
    ///                     since lower bound) so a poller can tell "my filter matched nothing"
    ///                     from "the registry is quiet" from "the audit writer is broken" — all
    ///                     three otherwise present as an empty items array with no other signal.
    ///   matched         — total row count matching the filter across the whole since/until
    ///                     window, independent of limit paging.
    ///   matched_capped  — true when matched was probed against AuditRepository.ListTotalCap
    ///                     rather than counted to completion; matched is a floor, not an exact
    ///                     count, when this is true.
    /// </summary>
    // input-validation-ok: action is a repeatable filter over the caller's own,
    // already-authenticated audit query — any string just narrows the result set (each value is
    // bound as its own equality and LIKE parameter in ListAuthEventsAsync), so there is no format
    // to reject. Only the count is checked below, because each value costs bind parameters. An
    // undeclared value is not an error either: it matches nothing, and rejecting it would make the
    // feed unreadable for a collector polling an instance older than its own action list.
    [HttpGet("api/v1/siem/events/auth")]
    public async Task<IActionResult> GetAuthEvents(
        [FromQuery] string? since,
        [FromQuery] string? until,
        [FromQuery] string? org,
        [FromQuery(Name = "action")] IReadOnlyList<string>? action,
        [FromQuery] int limit = 100,
        [FromQuery] string? cursor = null,
        CancellationToken ct = default)
    {
        var authResult = await AuthenticateAsync(ct);
        if (authResult.Error is not null)
        {
            return authResult.Error;
        }

        var (Since, Until, Error) = ParseAuthEventDateRange(since, until);
        if (Error is not null)
        {
            return Error;
        }

        var (orgId, orgError) = await ResolveOrgFilterAsync(authResult, org, ct);
        if (orgError is not null)
        {
            return orgError;
        }

        // Each value is bound individually, so an unbounded repeatable action= would push the
        // statement past the provider's bind-parameter ceiling. Rejecting the request is the
        // honest answer: silently dropping values would return a feed quietly missing events
        // the caller asked for. Both bounds are re-stated here rather than left to the repository
        // so the caller gets a 400 naming the limit it exceeded instead of a 500 from a throw.
        string[] distinctFilters = action is null
            ? []
            : [.. action.Select(AuditActions.NormalizeFilter).Distinct(StringComparer.Ordinal)];

        if (distinctFilters.Length > AuditRepository.MaxAuthEventActionFilters)
        {
            return BadRequest(new
            {
                detail = $"At most {AuditRepository.MaxAuthEventActionFilters} distinct 'action' " +
                         "values may be supplied.",
            });
        }

        // Naming a declared action is free — it becomes one entry in an IN list. Naming a dotted
        // family, or an action this release does not declare, adds an unindexable LIKE evaluated
        // per candidate row, so that half carries the tighter bound. GET /api/v1/siem/actions
        // publishes both the vocabulary and the two limits.
        int familyFilters = distinctFilters.Count(f => !AuditActions.IsDeclaredLeaf(f));
        if (familyFilters > AuditRepository.MaxAuthEventFamilyFilters)
        {
            return BadRequest(new
            {
                detail = $"At most {AuditRepository.MaxAuthEventFamilyFilters} 'action' values may " +
                         "name a dotted family or an action outside the declared vocabulary; " +
                         $"got {familyFilters}. GET /api/v1/siem/actions lists the vocabulary.",
            });
        }

        var (items, nextCursor, latestEventAt, matched, matchedCapped) = await _audit.ListAuthEventsAsync(
            Since, Until, orgId, action, Math.Clamp(limit, 1, MaxSiemPageSize), cursor, ct);

        return RenderAuthEventsResponse(items, nextCursor, latestEventAt, matched, matchedCapped);
    }

    private (DateTimeOffset Since, DateTimeOffset Until, IActionResult? Error) ParseAuthEventDateRange(string? since, string? until)
    {
        var now = _time.GetUtcNow();
        int maxLookbackDays = _config.GetValue<int>("SIEM_MAX_LOOKBACK_DAYS", 90);

        if (!TryParseIso(since, now.AddDays(-1), out var sinceDto))
        {
            return (default, default, BadRequest(new { detail = "Invalid 'since' date format. Use ISO 8601." }));
        }

        if (!TryParseIso(until, now, out var untilDto))
        {
            return (default, default, BadRequest(new { detail = "Invalid 'until' date format. Use ISO 8601." }));
        }

        var earliest = now.AddDays(-maxLookbackDays);
        if (sinceDto < earliest)
        {
            sinceDto = earliest;
        }

        if (untilDto > now)
        {
            untilDto = now;
        }

        if (sinceDto >= untilDto)
        {
            return (default, default, BadRequest(new { detail = "since must be before until." }));
        }

        return (sinceDto, untilDto, null);
    }

    private static bool TryParseIso(string? raw, DateTimeOffset fallback, out DateTimeOffset value)
    {
        if (raw is null) { value = fallback; return true; }
        return DateTimeOffset.TryParse(raw, null, System.Globalization.DateTimeStyles.RoundtripKind, out value);
    }

    private async Task<(string? OrgId, IActionResult? Error)> ResolveOrgFilterAsync(SiemAuthResult authResult, string? org, CancellationToken ct)
    {
        // Token callers are locked to their org; JWT callers may filter via ?org=
        if (authResult.TokenOrgId is not null)
        {
            return (authResult.TokenOrgId, null);
        }

        if (org is null)
        {
            return (null, null); // instance_admin with no filter → all orgs
        }

        if (!authResult.IsInstanceAdmin)
        {
            return (null, Forbid());
        }

        var orgRecord = await _orgs.GetBySlugAsync(org, ct: ct);
        return orgRecord is null ? (null, NotFound()) : (orgRecord.Id, null);
    }

    private IActionResult RenderAuthEventsResponse(
        IReadOnlyList<AuditEntry> items, string? nextCursor, DateTimeOffset? latestEventAt, int matched, bool matchedCapped)
    {
        string accept = Request.Headers.Accept.FirstOrDefault() ?? "";

        // latest_event_at/matched(_capped) are additive to the JSON envelope only — NDJSON and
        // CEF are consumed by existing collectors as one record per event line and must not
        // change shape.
        return accept.Contains("application/x-ndjson", StringComparison.OrdinalIgnoreCase)
            ? NdjsonResult(items, nextCursor is null ? null : new { next_cursor = nextCursor })
            : accept.Contains("application/x-cef", StringComparison.OrdinalIgnoreCase)
            ? CefResult(items.Select(SiemCefRow.From).ToList(), nextCursor)
            : Ok(new
            {
                items,
                next_cursor = nextCursor,
                latest_event_at = latestEventAt.ToUtcIsoMillisOrNull(),
                matched,
                matched_capped = matchedCapped,
            });
    }

    /// <summary>
    /// GET /api/v1/siem/events/activity
    /// Returns <c>activity</c>-plane events over a fixed allowlist — the block-gate refusals,
    /// plus downloads when the instance opts in. This is the delivery path for block-gate
    /// denials, which the audit-plane feed (<see cref="GetAuthEvents"/>) does not carry:
    /// <c>audit_log</c> and <c>activity</c> are disjoint planes and are never dual-written.
    ///
    /// Query parameters:
    ///   since  — ISO 8601 start time (default: 24 h ago)
    ///   until  — ISO 8601 end time (default: now, minus the write-lag cap below)
    ///   org    — org slug; required for a platform admin, ignored for a tenant-scoped caller
    ///   event  — repeatable; one of <c>blocked</c> (the whole family), a specific
    ///            <c>blocked_&lt;gate&gt;</c> value, or <c>download</c>. Default: <c>blocked</c>.
    ///   limit  — page size, 1–500 (default: 100)
    ///   cursor — opaque pagination cursor from the previous response
    ///
    /// <para>
    /// <b>Write-lag cap.</b> <c>AuditRepository.LogActivityAsync</c> stamps <c>created_at</c> when
    /// the row is enqueued, and <c>ActivityWriterHostedService</c> inserts it up to a flush
    /// interval later. A collector that read up to "now" and advanced its watermark there would
    /// permanently miss every row whose timestamp precedes the watermark but whose INSERT landed
    /// after the read. The feed therefore caps <c>until</c> at <c>now − SIEM_ACTIVITY_LAG_SECONDS</c>
    /// and reports the window it served. Under a saturated writer channel the true lag is
    /// unbounded, so the cap is a bound on the common case, not a guarantee — the operator raises
    /// it (and watches <c>dependably.activity_writer.dropped</c>) for a backlogged instance.
    /// </para>
    ///
    /// <para>
    /// <b>Watermark.</b> <c>until</c> is the instant a collector advances its watermark to, and it
    /// is served <em>only on the last page</em> (<c>next_cursor</c> null); on a truncated page it
    /// is null. Rows come newest-first, so a truncated page has served only the newest slice of
    /// the window and every older row is still behind the cursor — a collector that advanced to
    /// <c>until</c> there would step over them permanently. Withholding the value rather than
    /// documenting the rule means the page that must not be used as a watermark carries nothing
    /// that could be mistaken for one.
    /// </para>
    ///
    /// <para>
    /// Both window bounds are inclusive, so an event landing on exactly the served <c>until</c>
    /// millisecond is returned again when that value comes back as the next poll's <c>since</c>.
    /// The feed is at-least-once at that one instant, as the audit feed is; a collector dedupes
    /// on event id.
    /// </para>
    ///
    /// Accept header controls output format, exactly as <see cref="GetAuthEvents"/>:
    /// application/json (default), application/x-ndjson, or application/x-cef.
    /// </summary>
    // input-validation-ok: ResolveActivitySelection validates `event` against the allowlist and
    // answers 400 on anything else; the window, org slug, limit and cursor are parsed, clamped or
    // rejected exactly as GetAuthEvents parses its own.
    [HttpGet("api/v1/siem/events/activity")]
    public async Task<IActionResult> GetActivityEvents(
        [FromQuery] string? since,
        [FromQuery] string? until,
        [FromQuery] string? org,
        [FromQuery(Name = "event")] IReadOnlyList<string>? events,
        [FromQuery] int limit = 100,
        [FromQuery] string? cursor = null,
        CancellationToken ct = default)
    {
        var authResult = await AuthenticateAsync(ct);
        if (authResult.Error is not null)
        {
            return authResult.Error;
        }

        var (Since, Until, Error) = ParseAuthEventDateRange(since, until);
        if (Error is not null)
        {
            return Error;
        }

        var (orgId, orgError) = await ResolveOrgFilterAsync(authResult, org, ct);
        if (orgError is not null)
        {
            return orgError;
        }

        if (orgId is null)
        {
            // A tenant-scoped caller is pinned by ResolveOrgFilterAsync, so a null here is a
            // platform admin who named no org. The activity query takes a non-nullable org id by
            // design — there is no all-tenant activity read — so the cross-tenant privilege is
            // exercised by naming a tenant, one poll per tenant, rather than by omitting the
            // filter and having it mean "every tenant".
            // detail-ok: machine-to-machine collector surface; its sibling SIEM endpoints answer
            // in the same unlocalized envelope, and this text is read by a log pipeline, not the SPA.
            return BadRequest(new { detail = "org is required: a platform admin reads the activity feed one tenant at a time." });
        }

        var (selection, selectionError) = ResolveActivitySelection(events);
        if (selectionError is not null)
        {
            return selectionError;
        }

        var lag = ActivityLag();
        var effectiveUntil = _time.GetUtcNow() - lag;
        if (effectiveUntil > Until)
        {
            effectiveUntil = Until;
        }

        IReadOnlyList<ActivityEntry> rows = [];
        string? nextCursor = null;
        if (effectiveUntil > Since)
        {
            (rows, nextCursor) = await _audit.ListActivityEventsAsync(
                Since, effectiveUntil, orgId, selection.IncludeBlockedFamily, selection.EventTypes,
                Math.Clamp(limit, 1, MaxSiemPageSize), cursor, ct);
        }
        else
        {
            // The whole requested window is inside the lag horizon. The served window is empty
            // rather than negative, so a collector echoing `until` back as its next `since`
            // never moves its watermark forward over rows that have not been written yet.
            effectiveUntil = Since;
        }

        var items = rows.Select(SiemActivityEvent.From).ToList();
        return RenderActivityEventsResponse(items, nextCursor, Since, effectiveUntil, lag);
    }

    /// <summary>
    /// Wire shape of one activity-plane event. Field names mirror the audit-plane feed's
    /// (<c>action</c> carries <c>activity.event_type</c>) so one collector parser reads both
    /// streams; <c>scope</c> and <c>orgSlug</c> are audit-plane columns and have no counterpart
    /// here.
    /// </summary>
    public sealed record SiemActivityEvent(
        string Id,
        string OrgId,
        string? ActorId,
        string Action,
        string? Ecosystem,
        string? Purl,
        string? Detail,
        string? SourceIp,
        DateTimeOffset CreatedAt)
    {
        internal static SiemActivityEvent From(ActivityEntry e) => new(
            e.Id, e.OrgId, e.ActorId, e.EventType, e.Ecosystem, e.Purl, e.Detail, e.SourceIp, e.CreatedAt);
    }

    /// <summary>The allowlist token selecting the whole <c>blocked*</c> block-gate family.</summary>
    private const string BlockedFamilyToken = "blocked";

    /// <summary>Prefix a specific block-gate arm's event type carries (e.g. <c>blocked_license</c>).</summary>
    private const string BlockedArmPrefix = "blocked_";

    /// <summary>The one non-refusal event type this feed can carry, and only when opted in.</summary>
    private const string DownloadEventType = "download";

    /// <summary>
    /// Cap on distinct <c>event=</c> selectors. Each exact value becomes one bound parameter, and
    /// both engines have a per-statement parameter ceiling — an unbounded repeatable query
    /// parameter would turn into a 500 (or a refused statement) rather than a 400.
    /// </summary>
    private const int MaxEventSelectors = 50;

    /// <summary>
    /// Default write-lag cap, in seconds. Comfortably past the activity writer's flush interval
    /// and the batch insert behind it, while keeping a collector's visible delay in the range a
    /// SOC treats as real time.
    /// </summary>
    private const int DefaultActivityLagSeconds = 30;

    private TimeSpan ActivityLag() => TimeSpan.FromSeconds(
        Math.Max(0, _config.GetValue<int>("SIEM_ACTIVITY_LAG_SECONDS", DefaultActivityLagSeconds)));

    private sealed record ActivitySelection(bool IncludeBlockedFamily, IReadOnlyList<string> EventTypes)
    {
        /// <summary>
        /// What a refused request resolves to. Selecting nothing rather than everything means a
        /// refusal that somehow reached the query anyway returns an empty page, never a wider one.
        /// </summary>
        internal static readonly ActivitySelection None = new(false, []);
    }

    /// <summary>
    /// Maps the caller's <c>event=</c> values onto the allowlist. Unrecognized values are refused
    /// rather than dropped: a collector that silently gets fewer event classes than it asked for
    /// reads a quiet registry as a clean one. <c>download</c> is refused the same way while
    /// <c>SIEM_ACTIVITY_DOWNLOAD_EVENTS</c> is off, so an operator sees the switch instead of an
    /// unexplained gap. Any <c>blocked_&lt;gate&gt;</c> value is accepted without checking it
    /// against the live arm list — an arm that does not exist simply matches nothing, whereas a
    /// hard-coded arm list would start rejecting new gates the day they ship.
    /// </summary>
    private (ActivitySelection Selection, IActionResult? Error) ResolveActivitySelection(
        IReadOnlyList<string>? requested)
    {
        if (requested is null || requested.Count == 0)
        {
            return (new ActivitySelection(true, []), null);
        }

        bool downloadEnabled = _config.GetValue<bool>("SIEM_ACTIVITY_DOWNLOAD_EVENTS", false);
        bool family = false;
        var exact = new HashSet<string>(StringComparer.Ordinal);

        foreach (string raw in requested)
        {
            string value = raw.Trim().ToLowerInvariant();
            if (value == BlockedFamilyToken)
            {
                family = true;
            }
            else if (value.StartsWith(BlockedArmPrefix, StringComparison.Ordinal))
            {
                exact.Add(value);
            }
            else if (value == DownloadEventType)
            {
                if (!downloadEnabled)
                {
                    // detail-ok: machine-to-machine collector surface; its sibling SIEM endpoints
                    // answer in the same unlocalized envelope, and this text is read by a log
                    // pipeline, not the SPA.
                    return (ActivitySelection.None, BadRequest(new
                    {
                        detail = "The 'download' event type is disabled on this instance. "
                            + "Set SIEM_ACTIVITY_DOWNLOAD_EVENTS=true to enable it.",
                    }));
                }

                exact.Add(value);
            }
            else
            {
                // detail-ok: machine-to-machine collector surface; its sibling SIEM endpoints
                // answer in the same unlocalized envelope, and this text is read by a log
                // pipeline, not the SPA.
                return (ActivitySelection.None, BadRequest(new
                {
                    detail = "Unsupported 'event' value. Allowed: 'blocked' (the whole block-gate "
                        + "family), any specific 'blocked_<gate>' value, or 'download'.",
                }));
            }
        }

        if (exact.Count > MaxEventSelectors)
        {
            // detail-ok: machine-to-machine collector surface; its sibling SIEM endpoints answer
            // in the same unlocalized envelope, and this text is read by a log pipeline, not the SPA.
            return (ActivitySelection.None, BadRequest(new
            {
                detail = "Too many 'event' values. Request the 'blocked' family instead of "
                    + "enumerating arms.",
            }));
        }

        return (new ActivitySelection(family, [.. exact]), null);
    }

    private IActionResult RenderActivityEventsResponse(
        IReadOnlyList<SiemActivityEvent> items, string? nextCursor,
        DateTimeOffset since, DateTimeOffset until, TimeSpan lag)
    {
        string accept = Request.Headers.Accept.FirstOrDefault() ?? "";

        // The served window is only a watermark once the read is complete. Rows are newest-first,
        // so a page carrying a cursor has served the newest slice of [since, until] and left every
        // older row behind that cursor; a collector advancing to `until` there would skip them and
        // never come back. So `until` is withheld until the last page — the truncated page offers
        // no value to misread, rather than a documented rule not to.
        string? servedUntil = nextCursor is null ? until.ToUtcIsoMillis() : null;
        var window = new
        {
            since = since.ToUtcIsoMillis(),
            until = servedUntil,
            lag_seconds = (int)lag.TotalSeconds,
            next_cursor = nextCursor,
        };

        if (accept.Contains("application/x-ndjson", StringComparison.OrdinalIgnoreCase))
        {
            // Unlike the audit feed's trailer, this one is written on every page: it carries the
            // cursor and — on the last page — the watermark, neither derivable from the rows.
            return NdjsonResult(items, window);
        }

        return accept.Contains("application/x-cef", StringComparison.OrdinalIgnoreCase)
            ? CefResult(items.Select(SiemCefRow.From).ToList(), nextCursor,
                        nextCursor is null ? until : null)
            : Ok(new
            {
                items,
                next_cursor = nextCursor,
                since = window.since,
                until = window.until,
                lag_seconds = window.lag_seconds,
            });
    }

    /// <summary>
    /// GET /api/v1/siem/vulnerabilities/summary
    /// Returns vuln severity counts grouped by ecosystem.
    ///
    /// Query parameters:
    ///   org        — org slug filter; instance_admin only
    ///   ecosystem  — optional ecosystem filter
    /// </summary>
    [HttpGet("api/v1/siem/vulnerabilities/summary")]
    public async Task<IActionResult> GetVulnSummary(
        [FromQuery] string? org,
        [FromQuery] string? ecosystem,
        CancellationToken ct = default)
    {
        var authResult = await AuthenticateAsync(ct);
        if (authResult.Error is not null)
        {
            return authResult.Error;
        }

        string? orgId = null;
        if (authResult.TokenOrgId is not null)
        {
            orgId = authResult.TokenOrgId;
        }
        else if (org is not null)
        {
            if (!authResult.IsInstanceAdmin)
            {
                return Forbid();
            }

            var orgRecord = await _orgs.GetBySlugAsync(org, ct: ct);
            if (orgRecord is null)
            {
                return NotFound();
            }

            orgId = orgRecord.Id;
        }

        var summary = await _vulns.GetVulnSummaryAsync(orgId, ct);

        // Pivot severity rows into nested structure: { ecosystem: { severity: count } }
        var bySeverity = new Dictionary<string, Dictionary<string, long>>();
        foreach (var (eco, sev, count) in summary.Rows)
        {
            if (ecosystem is not null && !string.Equals(eco, ecosystem, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!bySeverity.TryGetValue(eco, out var sevMap))
            {
                bySeverity[eco] = sevMap = new Dictionary<string, long>();
            }

            sevMap[sev ?? "unknown"] = count;
        }

        return Ok(new
        {
            by_ecosystem = bySeverity,
            packages_total = summary.PackageTotal,
            packages_affected = summary.PackageAffected,
        });
    }

    /// <summary>
    /// GET /api/v1/siem/actions
    /// The declared <c>audit_log.action</c> vocabulary: every value <c>action=</c> can name on
    /// <see cref="GetAuthEvents"/>, and which of them the no-filter default serves.
    ///
    /// <para>
    /// This is the discovery surface, and it is deliberately the vocabulary rather than a
    /// <c>SELECT DISTINCT action</c> over the tenant's rows. A distinct-values query can only
    /// report what has already happened, so the one question a collector cannot otherwise answer —
    /// "what am I <em>not</em> receiving?" — is exactly the one it fails: an event family the
    /// instance has never emitted is indistinguishable from one that does not exist, and a family
    /// added in a later release is invisible until the day it fires. It is static for the same
    /// reason it is useful: a collector diffs it against its own subscription list and sees the
    /// gap before the event it would have missed.
    /// </para>
    ///
    /// <para>
    /// The alternative discovery mechanism, <c>action=*</c>, was not taken: it serves a collector
    /// that has already decided to ingest everything, while leaving one that wants a subset no way
    /// to enumerate the options, no way to populate an operator-facing picker, and no way to tell
    /// which names carry security weight. It also reads as a wildcard the filter would then have to
    /// define (is <c>login.*</c> one too?), where this endpoint adds no matching rules at all.
    /// </para>
    ///
    /// Response:
    ///   actions            — [{ action, security_relevant }], the whole vocabulary
    ///   default_actions    — the exact set served when no action= parameter is sent
    ///   family_prefixes    — the dotted families the vocabulary implies; the only action= values
    ///                        that count against max_family_filters, along with undeclared names
    ///   max_action_filters — how many distinct action= values one request may carry
    ///   max_family_filters — how many of those may be families or undeclared names
    /// </summary>
    [HttpGet("api/v1/siem/actions")]
    public async Task<IActionResult> GetActionCatalogue(CancellationToken ct = default)
    {
        var authResult = await AuthenticateAsync(ct);
        return authResult.Error ?? Ok(new
        {
            actions = AuditActions.All
                .Select(a => new { action = a, security_relevant = AuditActions.IsSecurityRelevant(a) })
                .ToArray(),
            default_actions = AuditActions.DefaultFilters,
            family_prefixes = AuditActions.ImpliedFamilyPrefixes,
            max_action_filters = AuditRepository.MaxAuthEventActionFilters,
            max_family_filters = AuditRepository.MaxAuthEventFamilyFilters,
        });
    }

    // ── Auth helpers ─────────────────────────────────────────────────────────

    private sealed record SiemAuthResult(
        bool IsInstanceAdmin,
        string? TokenOrgId,
        IActionResult? Error);

    /// <summary>
    /// Resolves SIEM auth from either JWT or a Bearer token with read:audit capability.
    /// Returns error result if not authenticated. Platform admin (system_admin role / any
    /// principal carrying <c>platform:*</c>) gets cross-tenant access; tenant-scoped
    /// principals are limited to their own tenant.
    /// </summary>
    private async Task<SiemAuthResult> AuthenticateAsync(CancellationToken ct)
    {
        // JWT path — set by the normal JWT middleware. Compute the effective cap set the
        // same way CapabilityHandler does so SIEM auth stays in lockstep with the
        // [RequireCapability] path on protocol routes.
        if (User.Identity?.IsAuthenticated == true)
        {
            string? role = User.FindFirst("role")?.Value;
            var granted = role == "system_admin"
                ? Capabilities.ForPlatformAdmin()
                : Capabilities.ForRole(role ?? "member");

            // Authenticated-but-uncapped (e.g. tenant member) must not reach SIEM data —
            // there's a dedicated /api/v1/audit endpoint for tenant-scoped audit reads.
            if (!Capabilities.Grants(granted, Capabilities.ReadAudit))
            {
                return new SiemAuthResult(false, null,
                    new ObjectResult(new { detail = "read:audit capability required." })
                    { StatusCode = StatusCodes.Status403Forbidden });
            }

            // Platform admin gets cross-tenant access. Everyone else (tenant admin/owner/
            // auditor with read:audit) is pinned to their own tenant by setting TokenOrgId
            // from the JWT — otherwise ResolveOrgFilterAsync's no-org-filter fallback would
            // leak rows across tenants via AuditRepository's `WHERE (@orgId IS NULL OR ...)`.
            if (Capabilities.Grants(granted, Capabilities.PlatformAll))
            {
                return new SiemAuthResult(true, null, null);
            }

            string? jwtOrgId = User.FindFirst("org_id")?.Value ?? User.FindFirst("tid")?.Value;
            return string.IsNullOrEmpty(jwtOrgId)
                ? new SiemAuthResult(false, null,
                    new ObjectResult(new { detail = "JWT missing tenant claim." })
                    { StatusCode = StatusCodes.Status401Unauthorized })
                : new SiemAuthResult(false, jwtOrgId, null);
        }

        // Token path — Bearer carrying read:audit.
        var token = await Request.ResolveTokenAsync(_tokens, ct);
        return token is not null && token.HasCapability(Capabilities.ReadAudit)
            ? new SiemAuthResult(false, token.OrgId, null)
            : new SiemAuthResult(false, null, Unauthorized(new { detail = "Authentication required. Provide a JWT or a Bearer token with read:audit capability." }));
    }

    // ── Output formatters ────────────────────────────────────────────────────

    /// <summary>
    /// One JSON object per line, optionally followed by a single trailer object. Generic over the
    /// item so both feeds render their own wire shape — the audit feed its <see cref="AuditEntry"/>
    /// rows, the activity feed its <see cref="SiemActivityEvent"/> projection — rather than one
    /// being forced through the other's columns.
    /// </summary>
    private ContentResult NdjsonResult<T>(IReadOnlyList<T> items, object? trailer)
    {
        var sb = new StringBuilder();
        var opts = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        foreach (var item in items)
        {
            sb.AppendLine(JsonSerializer.Serialize(item, opts));
        }

        if (trailer is not null)
        {
            sb.AppendLine(JsonSerializer.Serialize(trailer, opts));
        }

        return Content(sb.ToString(), "application/x-ndjson", Encoding.UTF8);
    }

    /// <summary>
    /// The fields CEF rendering reads, projected from whichever plane the row came from. CEF is a
    /// fixed extension layout, so both feeds render through one converter rather than two that
    /// drift.
    /// </summary>
    private readonly record struct SiemCefRow(
        string Action,
        string? ActorId,
        string? SourceIp,
        string? OrgId,
        string? Ecosystem,
        string? Purl,
        string? Detail,
        DateTimeOffset CreatedAt,
        // Appended rather than placed beside OrgId: the two are both string?, so inserting there
        // would silently reorder every positional construction below rather than fail to compile.
        string? OrgSlug)
    {
        internal static SiemCefRow From(AuditEntry e) => new(
            e.Action, e.ActorId, e.SourceIp, e.OrgId, e.Ecosystem, e.Purl, e.Detail, e.CreatedAt,
            e.OrgSlug);

        // The activity feed carries no slug and does not need one: it takes a non-nullable org id,
        // so a platform admin must name the tenant on every request and a tenant caller is pinned
        // to its own — the consumer already knows whose rows it asked for. The auth feed's
        // platform-admin path is the cross-tenant one, and is where the id alone is unreadable.
        internal static SiemCefRow From(SiemActivityEvent e) => new(
            e.Action, e.ActorId, e.SourceIp, e.OrgId, e.Ecosystem, e.Purl, e.Detail, e.CreatedAt,
            OrgSlug: null);
    }

    private ContentResult CefResult(
        IReadOnlyList<SiemCefRow> items, string? nextCursor, DateTimeOffset? windowUntil = null)
    {
        // CEF:Version|Device Vendor|Device Product|Device Version|SignatureID|Name|Severity|Extension
        var sb = new StringBuilder();
        foreach (var item in items)
        {
            string sig = CefFormat.Escape(item.Action);
            string name = CefFormat.FriendlyName(item.Action);
            int sev = CefFormat.Severity(item.Action);
            var ext = new StringBuilder();
            ext.Append($"rt={item.CreatedAt:yyyyMMddHHmmss.fffZ}");
            if (item.ActorId is not null)
            {
                ext.Append($" suid={CefFormat.Escape(item.ActorId)}");
            }

            if (item.SourceIp is not null)
            {
                ext.Append($" src={CefFormat.Escape(item.SourceIp)}");
            }

            if (item.OrgId is not null)
            {
                ext.Append($" cs1={CefFormat.Escape(item.OrgId)} cs1Label=OrgId");
            }

            if (item.Ecosystem is not null)
            {
                ext.Append($" cs2={CefFormat.Escape(item.Ecosystem)} cs2Label=Ecosystem");
            }

            if (item.Purl is not null)
            {
                ext.Append($" cs3={CefFormat.Escape(item.Purl)} cs3Label=Purl");
            }

            if (item.OrgSlug is not null)
            {
                ext.Append($" cs4={CefFormat.Escape(item.OrgSlug)} cs4Label=OrgSlug");
            }

            if (item.Detail is not null)
            {
                ext.Append($" msg={CefFormat.Escape(item.Detail)}");
            }

            sb.AppendLine($"CEF:0|Dependably|dependably|1.0|{sig}|{name}|{sev}|{ext}");
        }
        if (windowUntil is not null)
        {
            sb.AppendLine($"# window_until={windowUntil.Value.ToUtcIsoMillis()}");
        }

        if (nextCursor is not null)
        {
            sb.AppendLine($"# next_cursor={nextCursor}");
        }

        return Content(sb.ToString(), "application/x-cef", Encoding.UTF8);
    }
}
