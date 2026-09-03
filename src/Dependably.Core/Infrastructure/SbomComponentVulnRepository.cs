using Dapper;
using Dependably.Protocol;

namespace Dependably.Infrastructure;

/// <summary>
/// Scan-result persistence for <c>sbom_components</c>/<c>sbom_component_vulns</c> — the SBOM
/// inventory's own link to the global <c>vulnerabilities</c> table, kept separate from
/// <c>package_version_vulns</c> so a registry policy surface never counts application inventory
/// (see the <c>SbomComponentVuln</c> model doc comment). Shared by the upload-triggered
/// <c>SbomScanWorker</c> (Management) and the nightly restart/missed-upload safety net in
/// <see cref="VulnerabilityScanService"/> (Core).
/// </summary>
public sealed class SbomComponentVulnRepository
{
    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public SbomComponentVulnRepository(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    /// <summary>
    /// Links a component to a vulnerability. Idempotent upsert — an already-linked pair has its
    /// <c>checked_at</c> refreshed rather than a duplicate row inserted. <c>first_seen_at</c> is
    /// set only on the first insert: the conflict clause deliberately omits it, so a re-scan
    /// that hits the existing pair leaves the original first-observation instant untouched.
    /// </summary>
    public async Task LinkComponentVulnAsync(string componentId, string vulnId, CancellationToken ct = default)
    {
        string id = Guid.NewGuid().ToString("N");
        string now = _time.GetUtcNow().ToUtcIso();
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by component PK, org-scoped via the sbom_components FK. Every caller
        // resolves componentId from an org-scoped read before reaching this method.
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_component_vulns (id, component_id, vuln_id, checked_at, first_seen_at)
            VALUES (@id, @componentId, @vulnId, @now, @now)
            ON CONFLICT(component_id, vuln_id) DO UPDATE SET checked_at = excluded.checked_at
            """,
            new { id, componentId, vulnId, now });
    }

    /// <summary>
    /// Stamps <c>vuln_checked_at</c> on the <c>sbom_components</c> row. NULL is the scan work
    /// queue (<c>idx_sbom_components_scan</c>) — call this only for a component whose batch the
    /// advisory source actually answered (<c>OsvBatchQueryResult.Reached</c>); never for one in a
    /// deferred batch.
    /// </summary>
    public async Task MarkComponentCheckedAsync(string componentId, CancellationToken ct = default)
    {
        string now = _time.GetUtcNow().ToUtcIso();
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by component PK; caller resolves componentId from an org-scoped read.
        await conn.ExecuteAsync(
            "UPDATE sbom_components SET vuln_checked_at = @now WHERE id = @id",
            new { now, id = componentId });
    }

    // Head of the version-scoped scan query. The scannable condition itself is spliced from
    // SbomScannableComponents.BuildPredicate so this reader and the nightly pass cannot drift apart.
    private const string ScannableForVersionHeadSql =
        """
        SELECT sc.id AS Id, sc.purl AS Purl, sc.ecosystem AS Ecosystem, sc.purl_name AS PurlName
        FROM sbom_components sc
        WHERE sc.org_id = @orgId
          AND sc.project_version_id = @projectVersionId
          AND
        """;

    /// <summary>
    /// Every scannable component of one project version, org-scoped, per
    /// <see cref="SbomScannableComponents"/>. The set the upload-triggered <c>SbomScanWorker</c>
    /// (re)covers on each enqueue, regardless of each row's current <c>vuln_checked_at</c> — a
    /// rescan always covers the whole version it was handed, not just the rows that happen to be
    /// stale. A component with no parseable purl, no ecosystem, or an ecosystem OSV publishes no
    /// feed for is inventory/licence data only and is never queried; the policy evaluator reads
    /// those rows as unscannable rather than unscanned.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "The spliced fragment is SbomScannableComponents.BuildPredicate's own SQL, "
                        + "whose only variable part is DapperInClause.Expand's parenthesized, "
                        + "individually-parameterized (@sbomNoFeed0, @sbomNoFeed1, …) list — a "
                        + "code-owned ecosystem constant set, never user text. The table alias is a "
                        + "compile-time literal supplied by this call site.")]
    public async Task<IReadOnlyList<ScannableSbomComponent>> GetScannableComponentsForVersionAsync(
        string orgId, string projectVersionId, CancellationToken ct = default)
    {
        var (predicateSql, parameters) = SbomScannableComponents.BuildPredicate("sc");
        parameters.Add("orgId", orgId);
        parameters.Add("projectVersionId", projectVersionId);

        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<ScannableSbomComponent>(
            ScannableForVersionHeadSql + " " + predicateSql + " ORDER BY sc.id",
            parameters);
        return rows.ToList();
    }
}

/// <summary>
/// One component queued for an OSV lookup: its id, verbatim purl, and the parsed
/// ecosystem/name pair <see cref="VulnerabilityRepository.UpsertVulnerabilityAsync"/> needs to
/// stamp a hit against the global <c>vulnerabilities</c> table.
/// </summary>
public sealed record ScannableSbomComponent(string Id, string Purl, string Ecosystem, string? PurlName);
