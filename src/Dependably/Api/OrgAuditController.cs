using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Dependably.Infrastructure;
using Dependably.Security;

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

    private readonly AuditRepository _audit;
    private readonly OrgAccessGuard _guard;

    public OrgAuditController(AuditRepository audit, OrgAccessGuard guard)
    {
        _audit = audit;
        _guard = guard;
    }

    /// <summary>GET /api/v1/orgs/{org}/activity</summary>
    [HttpGet("api/v1/activity")]
    public async Task<IActionResult> GetActivity(
        [FromQuery] int limit = 50,
        [FromQuery] int page = 1,
        [FromQuery(Name = "event_type")] string? eventType = null,
        [FromQuery] string? format = null,
        CancellationToken ct = default)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadAudit, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        if (string.IsNullOrEmpty(eventType)) eventType = null;

        if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
        {
            var (csvItems, _) = await _audit.ListActivityAsync(orgId, CsvExportRowCap, 0, eventType, ct);
            var sb = new System.Text.StringBuilder();
            CsvWriter.WriteRow(sb, "created_at", "event_type", "ecosystem", "purl", "actor_email", "source_ip", "detail");
            foreach (var item in csvItems)
            {
                CsvWriter.WriteRow(sb,
                    item.CreatedAt.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
                    item.EventType, item.Ecosystem, item.Purl,
                    item.ActorEmail, item.SourceIp, item.Detail);
            }
            var bytes = System.Text.Encoding.UTF8.GetBytes(sb.ToString());
            var filename = $"activity-{DateTimeOffset.UtcNow:yyyyMMddTHHmmssZ}.csv";
            return File(bytes, "text/csv", filename);
        }

        limit  = Math.Clamp(limit, 1, 200);
        page   = Math.Max(page, 1);
        var offset = (page - 1) * limit;
        var (items, total) = await _audit.ListActivityAsync(orgId, limit, offset, eventType, ct);
        return Ok(new { items, total, limit, offset });
    }

    /// <summary>GET /api/v1/orgs/{org}/audit</summary>
    [HttpGet("api/v1/audit")]
    public async Task<IActionResult> GetAudit(
        [FromQuery] int limit = 50, [FromQuery] int page = 1,
        [FromQuery] string? action = null,
        [FromQuery] string? format = null,
        CancellationToken ct = default)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadAudit, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        if (string.IsNullOrEmpty(action)) action = null;

        if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
        {
            var (csvItems, _) = await _audit.ListAuditAsync(orgId, CsvExportRowCap, 0, action, ct);
            var sb = new System.Text.StringBuilder();
            CsvWriter.WriteRow(sb, "created_at", "action", "actor_email", "ecosystem", "purl", "detail");
            foreach (var item in csvItems)
            {
                CsvWriter.WriteRow(sb,
                    item.CreatedAt.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
                    item.Action, item.ActorEmail, item.Ecosystem, item.Purl, item.Detail);
            }
            var bytes = System.Text.Encoding.UTF8.GetBytes(sb.ToString());
            var filename = $"audit-{DateTimeOffset.UtcNow:yyyyMMddTHHmmssZ}.csv";
            return File(bytes, "text/csv", filename);
        }

        limit  = Math.Clamp(limit, 1, 200);
        page   = Math.Max(page, 1);
        var offset = (page - 1) * limit;
        var (items, total) = await _audit.ListAuditAsync(orgId, limit, offset, action, ct);
        return Ok(new { items, total, limit, offset });
    }
}
