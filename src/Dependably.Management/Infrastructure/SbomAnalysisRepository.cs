using System.Diagnostics.CodeAnalysis;
using Dapper;
using Dependably.Infrastructure.Sbom;

namespace Dependably.Infrastructure;

/// <summary>
/// Read side of the project-version analysis surface, plus the manual-triage upsert.
///
/// <para>Every method here loads one project version's facts and nothing else: the components, the
/// advisories linked to them, the VEX/reachability analysis rows, and the materialized policy
/// findings. The merge — matching an analysis row's <c>vuln_key</c> to an advisory through its
/// aliases, deriving the effective priority, applying the filters, sorting and paging — happens in
/// <see cref="Dependably.Api.SbomAnalysisProjection"/>, in memory, because none of it is
/// expressible in SQL: <c>vulnerabilities.aliases</c> is an unindexed JSON array, and the priority
/// bucket is derived from four columns across three tables at read time by design.</para>
///
/// <para>The load is bounded by the ingest path, which refuses an SBOM carrying more than
/// <see cref="MaxComponentsPerVersion"/> components, and the rows selected are narrow. Filtering in
/// SQL first would not help: the rollup is version-wide by contract, so the unfiltered set has to
/// be read regardless.</para>
/// </summary>
public sealed class SbomAnalysisRepository
{
    /// <summary>
    /// Upper bound on the component set a single version can hold, mirroring the ingest cap. Read
    /// paths apply it as a LIMIT so a row set that somehow grew past the cap truncates instead of
    /// materializing without a ceiling.
    /// </summary>
    public const int MaxComponentsPerVersion = 50_000;

    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public SbomAnalysisRepository(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    /// <summary>
    /// Resolves <paramref name="versionId"/> — or the literal <c>latest</c> — to a version of
    /// <paramref name="projectId"/> inside <paramref name="orgId"/>. Null when the project, the
    /// version, or the pairing does not exist in this tenant, which is what makes the caller's
    /// cross-org answer a 404 rather than a 403.
    /// </summary>
    public async Task<AnalysisVersionRef?> ResolveVersionAsync(
        string orgId, string projectId, string versionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        if (string.Equals(versionId, LatestVersionAlias, StringComparison.OrdinalIgnoreCase))
        {
            return await conn.QuerySingleOrDefaultAsync<AnalysisVersionRef>(new CommandDefinition(
                """
                SELECT pv.project_id    AS ProjectId,
                       p.name           AS ProjectName,
                       pv.id            AS VersionId,
                       pv.version       AS VersionLabel,
                       pv.is_latest     AS IsLatest,
                       pv.policy_status AS PolicyStatus,
                       pv.created_at    AS CreatedAt
                FROM project_versions pv
                JOIN projects p ON p.id = pv.project_id AND p.org_id = pv.org_id
                WHERE pv.org_id = @orgId AND pv.project_id = @projectId AND pv.is_latest = 1
                """,
                new { orgId, projectId }, cancellationToken: ct));
        }

        return await conn.QuerySingleOrDefaultAsync<AnalysisVersionRef>(new CommandDefinition(
            """
            SELECT pv.project_id    AS ProjectId,
                   p.name           AS ProjectName,
                   pv.id            AS VersionId,
                   pv.version       AS VersionLabel,
                   pv.is_latest     AS IsLatest,
                   pv.policy_status AS PolicyStatus,
                   pv.created_at    AS CreatedAt
            FROM project_versions pv
            JOIN projects p ON p.id = pv.project_id AND p.org_id = pv.org_id
            WHERE pv.org_id = @orgId AND pv.project_id = @projectId AND pv.id = @versionId
            """,
            new { orgId, projectId, versionId }, cancellationToken: ct));
    }

    /// <summary>The route segment that stands in for "whichever version carries is_latest".</summary>
    public const string LatestVersionAlias = "latest";

    /// <summary>Every component of one version, ordered so an unsorted read is still deterministic.</summary>
    public async Task<IReadOnlyList<AnalysisComponentRow>> ListComponentsAsync(
        string orgId, string projectVersionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<AnalysisComponentRow>(new CommandDefinition(
            """
            SELECT id               AS Id,
                   purl             AS Purl,
                   ecosystem        AS Ecosystem,
                   purl_name        AS PurlName,
                   version          AS Version,
                   name             AS Name,
                   component_type   AS ComponentType,
                   sbom_scope       AS SbomScope,
                   dependency_scope AS DependencyScope,
                   dependency_kind  AS DependencyKind,
                   dependency_path  AS DependencyPath,
                   license_spdx     AS LicenseSpdx,
                   description        AS Description,
                   component_author   AS ComponentAuthor,
                   copyright          AS Copyright,
                   component_group    AS ComponentGroup,
                   website_url        AS WebsiteUrl,
                   vcs_url            AS VcsUrl,
                   issue_tracker_url  AS IssueTrackerUrl,
                   distribution_url   AS DistributionUrl,
                   component_hashes   AS ComponentHashes,
                   vuln_checked_at  AS VulnCheckedAt
            FROM sbom_components
            WHERE org_id = @orgId AND project_version_id = @projectVersionId
            ORDER BY name, version, id
            LIMIT @limit
            """,
            new { orgId, projectVersionId, limit = MaxComponentsPerVersion }, cancellationToken: ct));
        return rows.ToList();
    }

    /// <summary>
    /// Every advisory linked to this version's components, with the threat-feed columns the
    /// priority derivation reads. <c>vulnerabilities</c> is the shared instance-global advisory
    /// store reached through an FK; the tenant filter sits on <c>sbom_components</c>, which is the
    /// only row in the join that carries one.
    /// </summary>
    public async Task<IReadOnlyList<AnalysisAdvisoryRow>> ListAdvisoriesAsync(
        string orgId, string projectVersionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<AnalysisAdvisoryRow>(new CommandDefinition(
            """
            SELECT c.id                    AS ComponentId,
                   v.id                    AS VulnId,
                   v.osv_id                AS OsvId,
                   v.aliases               AS Aliases,
                   v.severity              AS Severity,
                   v.cvss_score            AS CvssScore,
                   v.nvd_score             AS NvdScore,
                   v.is_kev                AS IsKev,
                   v.kev_known_ransomware  AS IsKevRansomware,
                   v.epss_score            AS EpssScore,
                   v.epss_percentile       AS EpssPercentile,
                   v.ssvc_exploitation     AS SsvcExploitation,
                   v.osv_id LIKE 'MAL-%'   AS IsMalicious
            FROM sbom_component_vulns scv
            JOIN sbom_components c ON c.id = scv.component_id
            JOIN vulnerabilities v ON v.id = scv.vuln_id
            WHERE c.org_id = @orgId AND c.project_version_id = @projectVersionId
            ORDER BY c.id, v.osv_id
            """,
            new { orgId, projectVersionId }, cancellationToken: ct));
        return rows.ToList();
    }

    /// <summary>Every VEX/reachability statement recorded against this version.</summary>
    public async Task<IReadOnlyList<AnalysisVexRow>> ListAnalysisAsync(
        string orgId, string projectVersionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<AnalysisVexRow>(new CommandDefinition(
            """
            SELECT purl_key          AS PurlKey,
                   vuln_key          AS VulnKey,
                   vex_state         AS VexState,
                   vex_justification AS VexJustification,
                   vex_response      AS VexResponse,
                   vex_detail        AS VexDetail,
                   vex_source        AS VexSource,
                   reachability      AS Reachability,
                   confidence        AS Confidence,
                   sarif_suppressed  AS SarifSuppressed,
                   security_severity AS SecuritySeverity,
                   severity_origin   AS SeverityOrigin,
                   updated_by        AS UpdatedBy,
                   updated_at        AS UpdatedAt
            FROM project_vuln_analysis
            WHERE org_id = @orgId AND project_version_id = @projectVersionId
            ORDER BY purl_key, vuln_key
            """,
            new { orgId, projectVersionId }, cancellationToken: ct));
        return rows.ToList();
    }

    /// <summary>
    /// One VEX/reachability row by its natural key, or null when nobody has written it.
    /// <paramref name="vulnKey"/> is matched case-insensitively (<c>UPPER()</c> on both sides,
    /// portable across SQLite and Postgres) rather than by canonicalizing the stored value — the
    /// same rule <see cref="SbomVulnKeyComparer"/> applies in memory — so a caller citing a stored
    /// row by any case still finds it without the column ever being rewritten to a case a GHSA id's
    /// conventionally-lowercase suffix does not use.
    ///
    /// <para>The match orders by <c>vuln_key</c> and takes one row, the same rule
    /// <see cref="UpsertManualTriageAsync"/> resolves its conflict key by, so the two agree on
    /// which spelling is the tenant's for a pair that already holds more than one — a database
    /// where case-variant rows exist reads deterministically instead of failing the request.</para>
    /// </summary>
    public async Task<AnalysisVexRow?> GetAnalysisRowAsync(
        string orgId, string projectVersionId, string purlKey, string vulnKey, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QueryFirstOrDefaultAsync<AnalysisVexRow>(new CommandDefinition(
            """
            SELECT purl_key          AS PurlKey,
                   vuln_key          AS VulnKey,
                   vex_state         AS VexState,
                   vex_justification AS VexJustification,
                   vex_response      AS VexResponse,
                   vex_detail        AS VexDetail,
                   vex_source        AS VexSource,
                   reachability      AS Reachability,
                   confidence        AS Confidence,
                   sarif_suppressed  AS SarifSuppressed,
                   security_severity AS SecuritySeverity,
                   severity_origin   AS SeverityOrigin,
                   updated_by        AS UpdatedBy,
                   updated_at        AS UpdatedAt
            FROM project_vuln_analysis
            WHERE org_id = @orgId AND project_version_id = @projectVersionId
              AND purl_key = @purlKey AND UPPER(vuln_key) = UPPER(@vulnKey)
            ORDER BY vuln_key
            LIMIT 1
            """,
            new { orgId, projectVersionId, purlKey, vulnKey }, cancellationToken: ct));
    }

    /// <summary>Every materialized policy finding for this version.</summary>
    public async Task<IReadOnlyList<AnalysisFindingRow>> ListPolicyFindingsAsync(
        string orgId, string projectVersionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<AnalysisFindingRow>(new CommandDefinition(
            """
            SELECT component_id AS ComponentId,
                   arm          AS Arm,
                   vuln_key     AS VulnKey,
                   license_spdx AS LicenseSpdx,
                   detail       AS Detail
            FROM sbom_policy_findings
            WHERE org_id = @orgId AND project_version_id = @projectVersionId
            ORDER BY component_id, arm, id
            """,
            new { orgId, projectVersionId }, cancellationToken: ct));
        return rows.ToList();
    }

    /// <summary>
    /// Every registry fact this tenant's own catalogue holds about one project version's
    /// components, keyed by <c>sbom_components.id</c>.
    ///
    /// <para>Two statements — the hosted catalogue and the tenant's own proxy-cache bindings —
    /// merged here. Never a per-row lookup and never a stored flag: a materialized link column
    /// goes stale in both directions the moment a package is published, blocked or deleted.</para>
    ///
    /// <para>Both statements are driven <em>from</em> <c>sbom_components</c> and join the registry
    /// on <c>(ecosystem, name)</c> equality, so <c>packages</c>'s
    /// <c>UNIQUE(org_id, ecosystem, purl_name)</c> and <c>cache_artifact</c>'s
    /// <c>UNIQUE(ecosystem, name, version, filename)</c> prefix both serve the lookup. The earlier
    /// shape matched a bound list of <c>ecosystem || '/' || purl_name</c> keys, which no composite
    /// index can answer: the hosted read degraded to an org-bounded scan and the cached read
    /// evaluated the concatenation over every artefact the tenant had ever pulled, once per page.
    /// Driving from the component rows also removes the key list altogether, which is what lets the
    /// answer cover the whole version rather than one page — the blind-spot rollup and the
    /// <c>registry</c> filter both need every component, and a 50 000-key <c>IN</c> list is not a
    /// query.</para>
    ///
    /// <para>The version-level arms match <c>version</c> by string equality, which is exact for the
    /// ecosystems whose purl carries the version verbatim (npm, PyPI, Maven, Cargo, Go) and can
    /// miss for the ones that do not — NuGet stores the normalized spelling, RPM's registry version
    /// carries a release and an epoch the SBOM's plain <c>version</c> does not. A miss is never
    /// silent: the coordinate-level arm still reports the condition, and the caller renders it as
    /// "another version of this package", not as a clean row.</para>
    /// </summary>
    public async Task<IReadOnlyDictionary<string, ComponentRegistryFacts>> ListRegistryFactsAsync(
        string orgId, string projectVersionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var hosted = await conn.QueryAsync<RegistryFactRow>(new CommandDefinition(
            HostedFactsSql, new { orgId, projectVersionId, limit = MaxComponentsPerVersion },
            cancellationToken: ct));
        var cached = await conn.QueryAsync<RegistryFactRow>(new CommandDefinition(
            CachedFactsSql, new { orgId, projectVersionId, limit = MaxComponentsPerVersion },
            cancellationToken: ct));

        var facts = new Dictionary<string, ComponentRegistryFacts>(StringComparer.Ordinal);
        foreach (var row in hosted)
        {
            facts[row.ComponentId] = Merge(facts.GetValueOrDefault(row.ComponentId), row, hostedPlane: true);
        }

        foreach (var row in cached)
        {
            facts[row.ComponentId] = Merge(facts.GetValueOrDefault(row.ComponentId), row, hostedPlane: false);
        }

        return facts;
    }

    /// <summary>
    /// Folds one plane's row into whatever the other plane already said. Every condition is a
    /// union: a coordinate blocked on the proxy plane and clean on the hosted one is blocked, and
    /// the newest upstream version either plane knows is the one reported.
    /// </summary>
    private static ComponentRegistryFacts Merge(
        ComponentRegistryFacts? existing, RegistryFactRow row, bool hostedPlane) => new(
            Hosted: (existing?.Hosted ?? false) || hostedPlane,
            Cached: (existing?.Cached ?? false) || !hostedPlane,
            UpstreamLatestVersion: row.UpstreamLatestVersion ?? existing?.UpstreamLatestVersion,
            BlockedThisVersion: (existing?.BlockedThisVersion ?? false) || row.BlockedThisVersion,
            BlockedAnyVersion: (existing?.BlockedAnyVersion ?? false) || row.BlockedAnyVersion,
            DeprecatedThisVersion: (existing?.DeprecatedThisVersion ?? false) || row.DeprecatedThisVersion,
            DeprecatedAnyVersion: (existing?.DeprecatedAnyVersion ?? false) || row.DeprecatedAnyVersion,
            HasInstallScriptThisVersion: (existing?.HasInstallScriptThisVersion ?? false) || row.HasInstallScriptThisVersion,
            // Presentation metadata is carried by the packages row, which only the hosted
            // statement selects, so the cached statement contributes nulls here and must not
            // erase what the other pass found — the same first-non-null fold
            // UpstreamLatestVersion already uses.
            Description: row.Description ?? existing?.Description,
            Author: row.Author ?? existing?.Author,
            Homepage: row.Homepage ?? existing?.Homepage,
            RepositoryUrl: row.RepositoryUrl ?? existing?.RepositoryUrl);

    /// <summary>
    /// Hosted-plane facts. <c>packages</c> is the name-level row every hosted publish creates, and
    /// the row a proxy first-fetch creates too, which is why <c>upstream_latest_version</c> is read
    /// here for both planes — <c>DeprecationRefreshService</c> writes it on that one row.
    /// </summary>
    // plane-ok: this is the hosted half of a deliberate two-statement read; the proxy plane is
    // resolved by CachedFactsSql below and merged by ListRegistryFactsAsync. Unioning them into
    // one statement would make each plane's per-tenant filter — packages.org_id on one side, the
    // tenant_artifact_access binding on the other — harder to read than the pair.
    private const string HostedFactsSql =
        """
        SELECT c.id AS ComponentId,
               p.upstream_latest_version AS UpstreamLatestVersion,
               p.description    AS Description,
               p.author         AS Author,
               p.homepage       AS Homepage,
               p.repository_url AS RepositoryUrl,
               CASE WHEN EXISTS (
                   SELECT 1 FROM package_versions pv
                   WHERE pv.package_id = p.id AND pv.manual_block_state = 'blocked'
                     AND pv.version = c.version) THEN 1 ELSE 0 END AS BlockedThisVersion,
               CASE WHEN EXISTS (
                   SELECT 1 FROM package_versions pv
                   WHERE pv.package_id = p.id AND pv.manual_block_state = 'blocked') THEN 1 ELSE 0 END AS BlockedAnyVersion,
               CASE WHEN EXISTS (
                   SELECT 1 FROM package_versions pv
                   WHERE pv.package_id = p.id AND pv.deprecated IS NOT NULL
                     AND pv.version = c.version) THEN 1 ELSE 0 END AS DeprecatedThisVersion,
               CASE WHEN EXISTS (
                   SELECT 1 FROM package_versions pv
                   WHERE pv.package_id = p.id AND pv.deprecated IS NOT NULL) THEN 1 ELSE 0 END AS DeprecatedAnyVersion,
               CASE WHEN EXISTS (
                   SELECT 1 FROM package_versions pv
                   WHERE pv.package_id = p.id AND pv.has_install_script = 1
                     AND pv.version = c.version) THEN 1 ELSE 0 END AS HasInstallScriptThisVersion
        FROM sbom_components c
        JOIN packages p ON p.org_id = c.org_id AND p.ecosystem = c.ecosystem AND p.purl_name = c.purl_name
        WHERE c.org_id = @orgId AND c.project_version_id = @projectVersionId
        LIMIT @limit
        """;

    /// <summary>
    /// Proxy-plane facts. <c>cache_artifact</c> is instance-global, so the tenant filter sits on the
    /// <c>tenant_artifact_access</c> binding — a coordinate another tenant cached is not this
    /// tenant's and must not light up its link, and the block state read is that binding's own
    /// per-tenant <c>manual_block_state</c>, not a global one.
    /// </summary>
    // xtenant: cache_artifact is the global proxy catalogue; the org filter is on the
    // tenant_artifact_access binding joined below, and on sbom_components driving the read.
    private const string CachedFactsSql =
        """
        SELECT c.id AS ComponentId,
               CAST(NULL AS TEXT) AS UpstreamLatestVersion,
               CASE WHEN EXISTS (
                   SELECT 1 FROM cache_artifact ca
                   JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id AND taa.org_id = c.org_id
                   WHERE ca.ecosystem = c.ecosystem AND ca.name = c.purl_name
                     AND taa.manual_block_state = 'blocked' AND ca.version = c.version) THEN 1 ELSE 0 END AS BlockedThisVersion,
               CASE WHEN EXISTS (
                   SELECT 1 FROM cache_artifact ca
                   JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id AND taa.org_id = c.org_id
                   WHERE ca.ecosystem = c.ecosystem AND ca.name = c.purl_name
                     AND taa.manual_block_state = 'blocked') THEN 1 ELSE 0 END AS BlockedAnyVersion,
               CASE WHEN EXISTS (
                   SELECT 1 FROM cache_artifact ca
                   JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id AND taa.org_id = c.org_id
                   WHERE ca.ecosystem = c.ecosystem AND ca.name = c.purl_name
                     AND ca.deprecated IS NOT NULL AND ca.version = c.version) THEN 1 ELSE 0 END AS DeprecatedThisVersion,
               CASE WHEN EXISTS (
                   SELECT 1 FROM cache_artifact ca
                   JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id AND taa.org_id = c.org_id
                   WHERE ca.ecosystem = c.ecosystem AND ca.name = c.purl_name
                     AND ca.deprecated IS NOT NULL) THEN 1 ELSE 0 END AS DeprecatedAnyVersion,
               CASE WHEN EXISTS (
                   SELECT 1 FROM cache_artifact ca
                   JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id AND taa.org_id = c.org_id
                   WHERE ca.ecosystem = c.ecosystem AND ca.name = c.purl_name
                     AND ca.has_install_script = 1 AND ca.version = c.version) THEN 1 ELSE 0 END AS HasInstallScriptThisVersion
        FROM sbom_components c
        WHERE c.org_id = @orgId AND c.project_version_id = @projectVersionId
          AND EXISTS (
              SELECT 1 FROM cache_artifact ca
              JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id AND taa.org_id = c.org_id
              WHERE ca.ecosystem = c.ecosystem AND ca.name = c.purl_name)
        LIMIT @limit
        """;

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class RegistryFactRow
    {
        public string ComponentId { get; set; } = "";
        public string? UpstreamLatestVersion { get; set; }
        public string? Description { get; set; }
        public string? Author { get; set; }
        public string? Homepage { get; set; }
        public string? RepositoryUrl { get; set; }
        public bool BlockedThisVersion { get; set; }
        public bool BlockedAnyVersion { get; set; }
        public bool DeprecatedThisVersion { get; set; }
        public bool DeprecatedAnyVersion { get; set; }
        public bool HasInstallScriptThisVersion { get; set; }
    }

    /// <summary>
    /// Display labels for the user ids stamped on manual triage rows, so the provenance line reads
    /// "set by someone@example.test" rather than an opaque id. Scoped to the tenant, so an id that
    /// belongs to another org resolves to nothing and the raw value is rendered instead.
    /// </summary>
    public async Task<IReadOnlyDictionary<string, string>> ListActorLabelsAsync(
        string orgId, IReadOnlyCollection<string> userIds, CancellationToken ct = default)
    {
        if (userIds.Count == 0)
        {
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }

        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string Id, string Email)>(new CommandDefinition(
            """
            SELECT id AS Id, email AS Email
            FROM users
            WHERE tenant_id = @orgId AND id IN @userIds
            """,
            new { orgId, userIds }, cancellationToken: ct));

        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (id, email) in rows)
        {
            map[id] = email;
        }

        return map;
    }

    /// <summary>Uploaded document receipts for one version, newest doc type order held stable.</summary>
    public async Task<IReadOnlyList<ProjectDocumentRow>> ListDocumentsAsync(
        string orgId, string projectVersionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<ProjectDocumentRow>(new CommandDefinition(
            """
            SELECT id           AS Id,
                   doc_type     AS DocType,
                   format       AS Format,
                   spec_version AS SpecVersion,
                   tool_name    AS ToolName,
                   tool_version AS ToolVersion,
                   sha256       AS Sha256,
                   size_bytes   AS SizeBytes,
                   uploaded_by  AS UploadedBy,
                   uploaded_at  AS UploadedAt
            FROM project_documents
            WHERE org_id = @orgId AND project_version_id = @projectVersionId
            ORDER BY doc_type
            """,
            new { orgId, projectVersionId }, cancellationToken: ct));
        return rows.ToList();
    }

    /// <summary>
    /// Applies one manual triage decision, then returns the row as stored.
    ///
    /// <para>Each VEX field is written through a parameterized <c>CASE WHEN @xSet = 1</c> branch
    /// rather than <c>COALESCE</c>, because null is a legitimate VALUE for all four of them — an
    /// operator clearing a stale justification means exactly that, and COALESCE would silently
    /// preserve the old one. The UPDATE therefore touches only the fields the caller actually
    /// addressed; the INSERT arm lands the supplied values with nulls for the rest.</para>
    ///
    /// <para><c>vex_source</c> becomes <c>manual</c> on both arms: whatever a document last said
    /// about this pair, an operator has now overruled it, and the provenance line has to say so.
    /// The SARIF-owned columns are never touched here.</para>
    ///
    /// <para>The INSERT resolves the spelling the tenant's own row already holds before it writes
    /// <c>vuln_key</c> — the rule <see cref="SbomVulnKeyComparer"/> documents, shared with the two
    /// ingest writers. An API client composes the advisory id itself, and a triage citing
    /// <c>cve-2023-32681</c> for an advisory a document recorded as <c>CVE-2023-32681</c> would
    /// otherwise miss the byte-for-byte conflict target and land a second row for one advisory on
    /// one component, which every reader here still considers a match.</para>
    /// </summary>
    public async Task<AnalysisVexRow?> UpsertManualTriageAsync(
        ManualTriageWrite write, CancellationToken ct = default)
    {
        string now = _time.GetUtcNow().ToUtcIso();
        await using var conn = await _db.OpenAsync(ct);

        var parameters = new
        {
            id = Guid.NewGuid().ToString("N"),
            orgId = write.OrgId,
            projectVersionId = write.ProjectVersionId,
            purlKey = write.PurlKey,
            vulnKey = write.VulnKey,
            vexState = write.VexState.Value,
            vexStateSet = write.VexState.IsPresent ? 1 : 0,
            vexJustification = write.VexJustification.Value,
            vexJustificationSet = write.VexJustification.IsPresent ? 1 : 0,
            vexResponse = write.VexResponse.Value,
            vexResponseSet = write.VexResponse.IsPresent ? 1 : 0,
            vexDetail = write.VexDetail.Value,
            vexDetailSet = write.VexDetail.IsPresent ? 1 : 0,
            updatedBy = write.ActorId,
            updatedAt = now,
        };

        await conn.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO project_vuln_analysis (
                id, org_id, project_version_id, purl_key, vuln_key,
                vex_state, vex_justification, vex_response, vex_detail, vex_source,
                updated_by, updated_at)
            SELECT @id, @orgId, @projectVersionId, @purlKey,
                   COALESCE((
                       SELECT stored.vuln_key
                       FROM project_vuln_analysis stored
                       WHERE stored.org_id = @orgId
                         AND stored.project_version_id = @projectVersionId
                         AND stored.purl_key = @purlKey
                         AND UPPER(stored.vuln_key) = UPPER(@vulnKey)
                       ORDER BY stored.vuln_key
                       LIMIT 1), @vulnKey),
                   @vexState, @vexJustification, @vexResponse, @vexDetail, 'manual',
                   @updatedBy, @updatedAt
            WHERE true
            ON CONFLICT (project_version_id, purl_key, vuln_key) DO UPDATE SET
                vex_state         = CASE WHEN @vexStateSet = 1 THEN @vexState ELSE project_vuln_analysis.vex_state END,
                vex_justification = CASE WHEN @vexJustificationSet = 1 THEN @vexJustification ELSE project_vuln_analysis.vex_justification END,
                vex_response      = CASE WHEN @vexResponseSet = 1 THEN @vexResponse ELSE project_vuln_analysis.vex_response END,
                vex_detail        = CASE WHEN @vexDetailSet = 1 THEN @vexDetail ELSE project_vuln_analysis.vex_detail END,
                vex_source        = 'manual',
                updated_by        = @updatedBy,
                updated_at        = @updatedAt
            WHERE project_vuln_analysis.org_id = @orgId
            """,
            parameters, cancellationToken: ct));

        return await GetAnalysisRowAsync(write.OrgId, write.ProjectVersionId, write.PurlKey, write.VulnKey, ct);
    }
}

/// <summary>
/// Identity of one resolved project version, including the labels the filename derivation needs.
/// Declared with settable properties rather than as a positional record so Dapper materializes it
/// column-by-column: constructor matching binds by CLR type, and SQLite hands back an INTEGER for
/// <see cref="IsLatest"/>, which no bool-typed constructor parameter matches.
/// </summary>
public sealed class AnalysisVersionRef
{
    public string ProjectId { get; set; } = "";
    public string ProjectName { get; set; } = "";
    public string VersionId { get; set; } = "";
    public string VersionLabel { get; set; } = "";
    public bool IsLatest { get; set; }
    public string? PolicyStatus { get; set; }
    /// <summary>
    /// Nullable on purpose: it is the comparison point the "inherited triage" signal reads
    /// (<see cref="Dependably.Api.SbomAnalysisProjection.IsInherited"/>), and a caller that
    /// forgot to select it must get null rather than a CLR default. A non-nullable
    /// <c>DateTimeOffset</c> here previously left an unselected column at 0001-01-01 — not
    /// missing, just silently wrong — which made every statement compare as "not inherited"
    /// without ever surfacing that no real comparison point existed.
    /// </summary>
    public DateTimeOffset? CreatedAt { get; set; }
}

/// <summary>
/// What this tenant's own registry knows about one SBOM component's coordinate, merged across the
/// hosted and proxy planes.
///
/// <para>Each condition is reported at two granularities on purpose. <c>ThisVersion</c> means the
/// exact version the application ships carries the condition; <c>AnyVersion</c> means the
/// coordinate carries it on some version. The pair is what keeps a version-string mismatch from
/// reading as a clean row: where the SBOM's spelling of a version and the registry's normalized
/// one disagree, the coordinate-level answer still surfaces the condition, labelled as belonging
/// to another version rather than to this one.</para>
/// </summary>
/// <param name="HasInstallScriptThisVersion">
/// True when this tenant's own registry (hosted or proxy plane) has recorded that the exact
/// coordinate this component names ships an install/lifecycle script. Read via a runtime join keyed
/// on <c>(ecosystem, purl_name, version)</c> — the same coordinate <see cref="BlockedThisVersion"/>
/// and <see cref="DeprecatedThisVersion"/> already join on — rather than a new column, because
/// <c>sbom_components</c> itself carries no install-script signal. Like every other
/// <c>ThisVersion</c> field here, this is necessarily best-effort: most SBOM components name
/// third-party dependencies this tenant never uploaded or proxied, so a false reading for those
/// means "unknown to this registry", not "verified clean".
/// </param>
public sealed record ComponentRegistryFacts(
    bool Hosted,
    bool Cached,
    string? UpstreamLatestVersion,
    bool BlockedThisVersion,
    bool BlockedAnyVersion,
    bool DeprecatedThisVersion,
    bool DeprecatedAnyVersion,
    bool HasInstallScriptThisVersion = false,
    string? Description = null,
    string? Author = null,
    string? Homepage = null,
    string? RepositoryUrl = null)
{
    /// <summary>True when either plane serves this coordinate for this tenant.</summary>
    public bool Present => Hosted || Cached;
}

/// <summary>One <c>sbom_components</c> row, as the analysis read needs it.</summary>
public sealed class AnalysisComponentRow
{
    public string Id { get; set; } = "";
    public string? Purl { get; set; }
    public string? Ecosystem { get; set; }
    public string? PurlName { get; set; }
    public string? Version { get; set; }
    public string Name { get; set; } = "";
    public string? ComponentType { get; set; }
    public string? SbomScope { get; set; }
    public string DependencyScope { get; set; } = "unknown";
    public string? DependencyKind { get; set; }
    public string? DependencyPath { get; set; }
    public string? LicenseSpdx { get; set; }
    public string? Description { get; set; }
    public string? ComponentAuthor { get; set; }
    public string? Copyright { get; set; }
    public string? ComponentGroup { get; set; }
    public string? WebsiteUrl { get; set; }
    public string? VcsUrl { get; set; }
    public string? IssueTrackerUrl { get; set; }
    public string? DistributionUrl { get; set; }
    public string? ComponentHashes { get; set; }
    public DateTimeOffset? VulnCheckedAt { get; set; }
}

/// <summary>
/// One advisory linked to a component, with the threat-feed and enrichment-overlay columns
/// priority reads. <see cref="NvdScore"/>, <see cref="IsKevRansomware"/>, <see cref="EpssPercentile"/>,
/// and <see cref="SsvcExploitation"/> are populated only when the operator's optional
/// VulnerabilityTracker connection is configured and has enriched this advisory; a default
/// deployment reads them as permanently null/NULL, which every arm that consumes them treats as
/// "unknown", never "low".
/// </summary>
public sealed class AnalysisAdvisoryRow
{
    public string ComponentId { get; set; } = "";
    public string VulnId { get; set; } = "";
    public string OsvId { get; set; } = "";
    /// <summary>JSON array of alias ids; unindexed, matched in memory.</summary>
    public string? Aliases { get; set; }
    public string? Severity { get; set; }
    public double? CvssScore { get; set; }
    /// <summary>CVSS score from the optional NVD enrichment overlay, or null when unconfigured/unscored.</summary>
    public double? NvdScore { get; set; }
    public bool IsKev { get; set; }
    /// <summary>Tri-state: see <see cref="VulnFacts.IsKevRansomware"/> for the null/false distinction.</summary>
    public bool? IsKevRansomware { get; set; }
    public double? EpssScore { get; set; }
    public double? EpssPercentile { get; set; }
    /// <summary>CISA Vulnrichment SSVC exploitation state — "none"/"poc"/"active" — or null.</summary>
    public string? SsvcExploitation { get; set; }
    /// <summary>True when <see cref="OsvId"/> is recorded under the <c>MAL-</c> prefix.</summary>
    public bool IsMalicious { get; set; }
}

/// <summary>One <c>project_vuln_analysis</c> row: the VEX arm and the reachability arm side by side.</summary>
public sealed class AnalysisVexRow
{
    public string PurlKey { get; set; } = "";
    public string VulnKey { get; set; } = "";
    public string? VexState { get; set; }
    public string? VexJustification { get; set; }
    public string? VexResponse { get; set; }
    public string? VexDetail { get; set; }
    public string? VexSource { get; set; }
    public string? Reachability { get; set; }
    public string? Confidence { get; set; }
    public bool SarifSuppressed { get; set; }
    public double? SecuritySeverity { get; set; }
    public string? SeverityOrigin { get; set; }
    public string? UpdatedBy { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>One materialized policy violation, as the advisory panel renders it.</summary>
public sealed class AnalysisFindingRow
{
    public string ComponentId { get; set; } = "";
    public string Arm { get; set; } = "";
    public string? VulnKey { get; set; }
    public string? LicenseSpdx { get; set; }
    public string? Detail { get; set; }
}

/// <summary>One uploaded document receipt.</summary>
public sealed class ProjectDocumentRow
{
    public string Id { get; set; } = "";
    public string DocType { get; set; } = "";
    public string Format { get; set; } = "";
    public string? SpecVersion { get; set; }
    public string? ToolName { get; set; }
    public string? ToolVersion { get; set; }
    public string Sha256 { get; set; } = "";
    public long SizeBytes { get; set; }
    public string? UploadedBy { get; set; }
    public DateTimeOffset UploadedAt { get; set; }
}

/// <summary>
/// One manual triage decision. The four VEX fields are tri-state — absent means leave unchanged,
/// present-and-null means clear — which is why they travel as <see cref="Dependably.Api.Optional{T}"/>
/// all the way to the SQL rather than collapsing to a nullable at the controller boundary.
/// </summary>
public sealed record ManualTriageWrite(
    string OrgId,
    string ProjectVersionId,
    string PurlKey,
    string VulnKey,
    Dependably.Api.Optional<string?> VexState,
    Dependably.Api.Optional<string?> VexJustification,
    Dependably.Api.Optional<string?> VexResponse,
    Dependably.Api.Optional<string?> VexDetail,
    string? ActorId);
