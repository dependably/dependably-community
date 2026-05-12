using Dapper;
using Prometheus;
using Dependably.Infrastructure;

namespace Dependably.Protocol;

/// <summary>
/// Enforces allowlist mode: when enabled for an org, any proxied PURL not in the
/// allowlist table returns 403 before any upstream fetch occurs.
/// Wildcard entries (no @version suffix) allow all versions.
/// </summary>
public sealed class AllowlistService
{
    private readonly IMetadataStore _db;
    private readonly AuditRepository _audit;

    private static readonly Counter AllowlistBlocks = Metrics.CreateCounter(
        "dependably_allowlist_blocks_total",
        "PURLs blocked by allowlist mode",
        new CounterConfiguration { LabelNames = ["org", "ecosystem"] });

    public AllowlistService(IMetadataStore db, AuditRepository audit)
    {
        _db = db;
        _audit = audit;
    }

    /// <summary>
    /// Returns true if the PURL is permitted (either allowlist mode is off, or PURL is listed).
    /// Returns false and records an audit event if blocked.
    /// </summary>
    public async Task<bool> IsAllowedAsync(
        string orgId, string ecosystem, string purl, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        // Wildcard match: check for pkg:ecosystem/name (no @version)
        var atIdx = purl.LastIndexOf('@');
        var purlWithoutVersion = atIdx > 0 ? purl[..atIdx] : purl;

        var match = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*) FROM allowlist
            WHERE org_id = @orgId AND ecosystem = @ecosystem
              AND (purl_pattern = @purl OR purl_pattern = @purlWithoutVersion)
            """,
            new { orgId, ecosystem, purl, purlWithoutVersion });

        if (match > 0)
            return true;

        AllowlistBlocks.WithLabels(orgId, ecosystem).Inc();
        await _audit.LogAsync("allowlist_blocked", orgId: orgId, ecosystem: ecosystem, purl: purl, ct: ct);
        return false;
    }

    /// <summary>
    /// Detects and records a dependency confusion conflict when a hosted package
    /// shadows a proxy package with the same name.
    /// </summary>
    public async Task RecordConflictIfNeededAsync(
        string orgId, string ecosystem, string hostedPurl, string upstreamPurl,
        CancellationToken ct = default)
    {
        await _audit.LogAsync(
            "conflict_resolved",
            orgId: orgId,
            ecosystem: ecosystem,
            purl: hostedPurl,
            detail: $"{{\"hosted\":\"{hostedPurl}\",\"upstream\":\"{upstreamPurl}\"}}",
            ct: ct);
    }
}
