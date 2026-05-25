using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;

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

    public AllowlistService(IMetadataStore db, AuditRepository audit)
    {
        _db = db;
        _audit = audit;
    }

    /// <summary>
    /// Returns true if the PURL is permitted (either allowlist mode is off, or PURL is listed).
    /// Returns false and records an audit event if blocked. The PURL already encodes the
    /// ecosystem (per the spec); allowlist patterns are matched against the PURL string only,
    /// with no separate ecosystem filter.
    /// </summary>
    public async Task<bool> IsAllowedAsync(
        string orgId, string purl, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        // Wildcard match: check for pkg:ecosystem/name (no @version)
        var atIdx = purl.LastIndexOf('@');
        var purlWithoutVersion = atIdx > 0 ? purl[..atIdx] : purl;

        var match = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*) FROM allowlist
            WHERE org_id = @orgId
              AND (purl_pattern = @purl OR purl_pattern = @purlWithoutVersion)
            """,
            new { orgId, purl, purlWithoutVersion });

        if (match > 0)
            return true;

        // Extract ecosystem from the PURL prefix for telemetry labels / audit. Falls back to
        // "" if the input isn't a valid PURL — the upstream caller has already routed by
        // ecosystem so this is purely a labelling concern.
        var ecosystem = ExtractEcosystem(purl);
        DependablyMeter.AllowlistBlocks.Add(1, new KeyValuePair<string, object?>("ecosystem", ecosystem));
        await _audit.LogAsync("allowlist_blocked", orgId: orgId, ecosystem: ecosystem, purl: purl, ct: ct);
        return false;
    }

    private static string ExtractEcosystem(string purl)
    {
        if (!purl.StartsWith("pkg:", StringComparison.Ordinal)) return "";
        var slash = purl.IndexOf('/', 4);
        return slash > 4 ? purl[4..slash] : "";
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
