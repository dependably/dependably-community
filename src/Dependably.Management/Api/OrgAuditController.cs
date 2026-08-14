using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Activity feed + tenant audit log, plus their CSV export variants. Split out of
/// <see cref="OrgController"/>. Both endpoints share <see cref="Capabilities.ReadAudit"/>
/// as the only auth check and converge on <see cref="CsvExportRowCap"/> when
/// <c>?format=csv</c> is set.
/// </summary>
[ApiController]
[Authorize]
public sealed class OrgAuditController : OrgScopedControllerBase
{
    /// <summary>
    /// Hard cap on rows pulled into a CSV export. Bounds memory; large enough to cover the
    /// common compliance / SIEM hand-off use case without paging logic on the export path.
    /// </summary>
    private const int CsvExportRowCap = 50_000;

    /// <summary>
    /// Set on a CSV export whose <em>search</em> was bounded to the newest
    /// <see cref="AuditRepository.SearchScanCap"/> rows of the filtered window, so older matches
    /// may exist that the export never examined. The bound is what keeps a repeatable
    /// <c>?format=csv&amp;search=…</c> from being an unindexable full-history scan on demand; the
    /// header is what keeps the resulting truncation from being silent, which is the property a
    /// compliance export actually needs. A search that fits inside the window sets no header.
    /// </summary>
    private const string ExportTruncatedHeader = "X-Export-Truncated";

    // Maximum page size for paged audit/activity list responses.
    private const int MaxAuditPageSize = 200;

    /// <summary>
    /// The time windows the activity feed can be scoped to. A closed vocabulary rather than a
    /// free-form date: it is what the dashboard's drill-downs need (the blocked-pull tiles count a
    /// 30-day window), it validates cleanly, and it keeps the CSV export off an unbounded range scan.
    /// </summary>
    private static readonly Dictionary<string, TimeSpan> ActivityWindows =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["24h"] = TimeSpan.FromHours(24),
            ["7d"] = TimeSpan.FromDays(7),
            ["30d"] = TimeSpan.FromDays(30),
            ["90d"] = TimeSpan.FromDays(90),
        };

    private readonly AuditRepository _audit;
    private readonly OrgAccessGuard _guard;
    private readonly TimeProvider _time;
    private readonly ProblemResults _problems;

    public OrgAuditController(AuditRepository audit, OrgAccessGuard guard, TimeProvider time, ProblemResults problems)
    {
        _audit = audit;
        _guard = guard;
        _time = time;
        _problems = problems;
    }

    /// <summary>GET /api/v1/orgs/{org}/activity</summary>
    // Read-only: accepts a PAT/service token carrying read:audit — same tier SIEM already
    // exposes over a bearer token.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/activity")]
    public async Task<IActionResult> GetActivity(
        [FromQuery] int limit = 50,
        [FromQuery] int page = 1,
        [FromQuery(Name = "event_type")] string? eventType = null,
        [FromQuery] string? search = null,
        [FromQuery] string? since = null,
        [FromQuery] string? format = null,
        CancellationToken ct = default)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadAudit, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        if (string.IsNullOrEmpty(eventType))
        {
            eventType = null;
        }

        string? sinceIso = null;
        if (!string.IsNullOrEmpty(since))
        {
            if (!ActivityWindows.TryGetValue(since, out var window))
            {
                return _problems.ValidationErrorActionKey("since", "error.activity.sinceInvalid");
            }

            // Millisecond precision — activity.created_at is written at millisecond precision
            // (AuditRepository.LogActivityAsync's NowMs()); a second-precision bound here would
            // drop rows landing in the same wall-clock second as the window boundary.
            sinceIso = _time.GetUtcNow().Subtract(window).ToUtcIsoMillis();
        }

        if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
        {
            var (csvItems, _, csvTruncated) = await _audit.ListActivityAsync(orgId, CsvExportRowCap, 0, eventType, search, sinceIso, includeTotal: false, ct);
            if (csvTruncated)
            {
                Response.Headers[ExportTruncatedHeader] = "true";
            }

            var sb = new System.Text.StringBuilder();
            CsvWriter.WriteRow(sb, "created_at", "event_type", "ecosystem", "purl", "actor_email", "source_ip", "detail");
            foreach (var item in csvItems)
            {
                // utcformat-ok: CSV export wire format, not a DB write — preserves the millisecond
                // precision activity.created_at actually carries rather than truncating it away.
                CsvWriter.WriteRow(sb,
                    item.CreatedAt.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
                    item.EventType, item.Ecosystem, item.Purl,
                    item.ActorEmail, item.SourceIp, item.Detail);
            }
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(sb.ToString());
            string filename = $"activity-{_time.GetUtcNow():yyyyMMddTHHmmssZ}.csv";
            return File(bytes, "text/csv", filename);
        }

        limit = Math.Clamp(limit, 1, MaxAuditPageSize);
        int offset = PaginationHelper.ComputeOffset(page, limit);
        var (items, total, totalCapped) = await _audit.ListActivityAsync(orgId, limit, offset, eventType, search, sinceIso, ct: ct);
        return Ok(new { items, total, totalCapped, limit, offset });
    }

    /// <summary>GET /api/v1/orgs/{org}/audit</summary>
    // Read-only: accepts a PAT/service token carrying read:audit — same tier SIEM already
    // exposes over a bearer token.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/audit")]
    public async Task<IActionResult> GetAudit(
        [FromQuery] int limit = 50, [FromQuery] int page = 1,
        [FromQuery] string? action = null,
        [FromQuery] string? search = null,
        [FromQuery] string? format = null,
        CancellationToken ct = default)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadAudit, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        if (string.IsNullOrEmpty(action))
        {
            action = null;
        }

        if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
        {
            var (csvItems, _, csvTruncated) = await _audit.ListAuditAsync(orgId, CsvExportRowCap, 0, action, search, includeTotal: false, ct);
            if (csvTruncated)
            {
                Response.Headers[ExportTruncatedHeader] = "true";
            }

            var sb = new System.Text.StringBuilder();
            CsvWriter.WriteRow(sb, "created_at", "action", "actor_email", "ecosystem", "purl", "source_ip", "detail");
            foreach (var item in csvItems)
            {
                // utcformat-ok: CSV export wire format, not a DB write — preserves the millisecond
                // precision audit_log.created_at actually carries rather than truncating it away.
                CsvWriter.WriteRow(sb,
                    item.CreatedAt.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
                    item.Action, item.ActorEmail, item.Ecosystem, item.Purl, item.SourceIp, item.Detail);
            }
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(sb.ToString());
            string filename = $"audit-{_time.GetUtcNow():yyyyMMddTHHmmssZ}.csv";
            return File(bytes, "text/csv", filename);
        }

        limit = Math.Clamp(limit, 1, MaxAuditPageSize);
        int offset = PaginationHelper.ComputeOffset(page, limit);
        var (items, total, totalCapped) = await _audit.ListAuditAsync(orgId, limit, offset, action, search, ct: ct);
        return Ok(new { items, total, totalCapped, limit, offset });
    }
}
