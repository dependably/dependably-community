using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure.Sbom;
using Dependably.Protocol;

namespace Dependably.Infrastructure;

/// <summary>
/// Dapper reads/writes backing <see cref="Protocol.SbomPolicyEvaluationService"/>. Loads the facts
/// <see cref="SbomPolicyEvaluator"/> needs for one project version (components, their linked
/// advisories, and the VEX statements that apply to them, pre-resolved so the evaluator never sees
/// a suppressed advisory) and persists the resulting findings + rollup. Every query is reached
/// through <c>sbom_components.org_id</c> or <c>project_versions.org_id</c> — <c>sbom_component_vulns</c>
/// carries no <c>org_id</c> of its own, always reached via its parent <c>sbom_components</c> row.
/// </summary>
public sealed class SbomPolicyRepository
{
    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public SbomPolicyRepository(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    /// <summary>
    /// Loads every component of a project version with its facts ready for
    /// <see cref="SbomPolicyEvaluator.Evaluate"/>: linked advisories annotated with the VEX state
    /// (if any) that applies to that exact (component purl, advisory) pair. Matching is on the
    /// version-less purl key against <c>project_vuln_analysis.purl_key</c> — derived by
    /// <see cref="SbomPurlKey.ForComponent"/>, the same function the ingest writer keys its rows
    /// with, never re-derived locally — and against either the
    /// advisory's own id or any of its aliases — a VEX statement legitimately cites a GHSA id for
    /// an advisory this instance only ever fetched by its CVE id, or vice versa.
    /// </summary>
    public async Task<IReadOnlyList<SbomComponentEvaluationInput>> LoadEvaluationContextAsync(
        string orgId, string projectVersionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        var components = (await conn.QueryAsync<ComponentRow>(
            """
            SELECT id AS Id, ecosystem AS Ecosystem, purl_name AS PurlName, purl AS Purl,
                   license_spdx AS LicenseSpdx, sbom_scope AS SbomScope,
                   vuln_checked_at AS VulnCheckedAt,
                   dependency_scope AS DependencyScope, dependency_kind AS DependencyKind
            FROM sbom_components
            WHERE org_id = @orgId AND project_version_id = @projectVersionId
            """,
            new { orgId, projectVersionId })).ToList();

        // The threat-feed/enrichment columns beyond IsKev/EpssScore/CvssScore are read here so the
        // per-vuln VulnFacts this method builds carries the full unified vocabulary — including
        // kev_known_ransomware's true tri-state — even though SbomPolicyEvaluator does not yet
        // consult any of them.
        var vulnLinks = (await conn.QueryAsync<VulnLinkRow>(
            """
            SELECT scv.component_id AS ComponentId, v.osv_id AS OsvId, v.aliases AS Aliases,
                   v.is_kev AS IsKev, v.epss_score AS EpssScore, v.cvss_score AS CvssScore,
                   v.kev_known_ransomware AS KevKnownRansomware, v.kev_due_date AS KevDueDate,
                   v.epss_percentile AS EpssPercentile, v.nvd_score AS NvdScore,
                   v.ssvc_exploitation AS SsvcExploitation, v.ssvc_automatable AS SsvcAutomatable,
                   v.ssvc_technical_impact AS SsvcTechnicalImpact
            FROM sbom_component_vulns scv
            JOIN sbom_components sc ON sc.id = scv.component_id
            JOIN vulnerabilities v ON v.id = scv.vuln_id
            WHERE sc.org_id = @orgId AND sc.project_version_id = @projectVersionId
            """,
            new { orgId, projectVersionId })).ToList();

        var vexRows = (await conn.QueryAsync<VexRow>(
            """
            SELECT purl_key AS PurlKey, vuln_key AS VulnKey, vex_state AS VexState
            FROM project_vuln_analysis
            WHERE org_id = @orgId AND project_version_id = @projectVersionId
            """,
            new { orgId, projectVersionId })).ToList();

        // Keyed with SbomVulnKeyComparer, the same case-insensitive rule the analysis projection
        // and the CycloneDX export use, so a VEX statement citing an advisory in any case resolves
        // identically wherever vuln_key is matched — without rewriting the stored spelling.
        var vexByKey = new Dictionary<(string PurlKey, string VulnKey), string?>(SbomVulnKeyComparer.Instance);
        foreach (var v in vexRows)
        {
            vexByKey[(v.PurlKey, v.VulnKey)] = v.VexState;
        }

        var linksByComponent = vulnLinks
            .GroupBy(l => l.ComponentId)
            .ToDictionary(g => g.Key, g => g.ToList());

        var results = new List<SbomComponentEvaluationInput>(components.Count);
        foreach (var component in components)
        {
            string? purlKey = SbomPurlKey.ForComponent(component.Ecosystem, component.PurlName, component.Purl);
            var vulns = new List<SbomComponentVulnFact>();

            if (purlKey is not null && linksByComponent.TryGetValue(component.Id, out var links))
            {
                foreach (var link in links)
                {
                    string? vexState = ResolveVexState(vexByKey, purlKey, link.OsvId, link.Aliases);
                    vulns.Add(new SbomComponentVulnFact(
                        VulnKey: link.OsvId,
                        Vuln: new VulnFacts(
                            Cvss: link.CvssScore,
                            NvdScore: link.NvdScore,
                            IsMalicious: link.OsvId.StartsWith("MAL-", StringComparison.Ordinal),
                            IsKev: link.IsKev,
                            IsKevRansomware: link.KevKnownRansomware,
                            KevDueDate: link.KevDueDate,
                            Epss: link.EpssScore,
                            EpssPercentile: link.EpssPercentile,
                            SsvcExploitation: link.SsvcExploitation,
                            SsvcAutomatable: link.SsvcAutomatable,
                            SsvcTechnicalImpact: link.SsvcTechnicalImpact,
                            // Unlike the gate-arm aggregate (BuildAggregateVulnFacts), this plane
                            // does not apply the operator's staleness-horizon cutoff to the raw
                            // NVD/SSVC columns above — nothing here consults them yet, so there is
                            // no freshness question to answer. Revisit once a consumer reads them.
                            HasStaleEnrichment: false,
                            // Always false on this plane, deliberately — not merely unwired. Unlike
                            // the gate-arm aggregate (which reads package_version_vulns, the actual
                            // version-precise link the value is scoped to), this SBOM plane's link
                            // table is sbom_component_vulns: a component/vuln pair with no FK back
                            // to a package_versions/cache_artifact row, so there is no version-
                            // precise link here to read the signal off. Fabricating one from the
                            // shared vulnerabilities row would reintroduce the exact cross-version
                            // collapse VulnFacts.MalStillLive's own doc explains is unsafe. Revisit
                            // only if sbom_components ever gains a registry-version FK.
                            MalStillLive: false),
                        VexState: vexState));
                }
            }

            results.Add(new SbomComponentEvaluationInput(
                component.Id,
                component.Purl,
                component.LicenseSpdx,
                new SbomComponentFacts(
                    component.Id,
                    component.Ecosystem,
                    component.SbomScope,
                    component.VulnCheckedAt,
                    vulns,
                    component.DependencyScope,
                    component.DependencyKind)));
        }

        return results;
    }

    private static string? ResolveVexState(
        Dictionary<(string PurlKey, string VulnKey), string?> vexByKey,
        string purlKey, string osvId, string? aliasesJson)
    {
        if (vexByKey.TryGetValue((purlKey, osvId), out string? state))
        {
            return state;
        }

        foreach (string alias in ExtractAliases(aliasesJson))
        {
            if (vexByKey.TryGetValue((purlKey, alias), out state))
            {
                return state;
            }
        }

        return null;
    }

    private static IEnumerable<string> ExtractAliases(string? aliasesJson)
    {
        if (string.IsNullOrWhiteSpace(aliasesJson))
        {
            yield break;
        }

        List<string>? aliases = null;
        try
        {
            aliases = JsonSerializer.Deserialize<List<string>>(aliasesJson);
        }
        catch (JsonException)
        {
            // Malformed alias JSON on a legacy row — treat as no aliases rather than throw.
        }

        if (aliases is null)
        {
            yield break;
        }

        foreach (string alias in aliases)
        {
            yield return alias;
        }
    }

    /// <summary>
    /// Replaces every finding row for a project version in one transaction: the previous
    /// evaluation's findings are wholesale-deleted and the new set is inserted. This is what
    /// makes re-evaluation idempotent — the findings table always reflects exactly the latest
    /// evaluation, never an accumulation of stale rows from earlier passes.
    /// </summary>
    public async Task ReplaceFindingsAsync(
        string orgId, string projectVersionId,
        IReadOnlyList<(string ComponentId, SbomPolicyFindingResult Finding)> findings,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);

        await conn.ExecuteAsync(
            "DELETE FROM sbom_policy_findings WHERE org_id = @orgId AND project_version_id = @projectVersionId",
            new { orgId, projectVersionId }, tx);

        if (findings.Count > 0)
        {
            string now = _time.GetUtcNow().ToUtcIso();
            var rows = findings.Select(f => new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId,
                projectVersionId,
                componentId = f.ComponentId,
                arm = f.Finding.Arm,
                vulnKey = f.Finding.VulnKey,
                licenseSpdx = f.Finding.LicenseSpdx,
                detail = f.Finding.Detail,
                now,
            });

            await conn.ExecuteAsync(
                """
                INSERT INTO sbom_policy_findings
                    (id, org_id, project_version_id, component_id, arm, vuln_key, license_spdx, detail, created_at)
                VALUES
                    (@id, @orgId, @projectVersionId, @componentId, @arm, @vulnKey, @licenseSpdx, @detail, @now)
                """,
                rows, tx);
        }

        await tx.CommitAsync(ct);
    }

    /// <summary>
    /// Stamps the per-version policy rollup. <c>null</c> is never written here — that state means
    /// "never evaluated" and only exists before this method's first call for a version.
    /// </summary>
    public async Task SetPolicyStatusAsync(
        string orgId, string projectVersionId, string status, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE project_versions SET policy_status = @status WHERE org_id = @orgId AND id = @projectVersionId",
            new { orgId, projectVersionId, status });
    }

    /// <summary>Project name + version label, for the alert title. Null on a cross-org id (BOLA guard).</summary>
    public async Task<(string ProjectName, string VersionLabel)?> GetVersionLabelAsync(
        string orgId, string projectVersionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<VersionLabelRow>(
            """
            SELECT p.name AS ProjectName, pv.version AS VersionLabel
            FROM project_versions pv
            JOIN projects p ON p.id = pv.project_id
            WHERE pv.org_id = @orgId AND pv.id = @projectVersionId
            """,
            new { orgId, projectVersionId });

        return row is null ? null : (row.ProjectName, row.VersionLabel);
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class ComponentRow
    {
        public string Id { get; set; } = "";
        public string? Ecosystem { get; set; }
        public string? PurlName { get; set; }
        public string? Purl { get; set; }
        public string? LicenseSpdx { get; set; }
        public string? SbomScope { get; set; }
        public DateTimeOffset? VulnCheckedAt { get; set; }
        public string? DependencyScope { get; set; }
        public string? DependencyKind { get; set; }
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class VulnLinkRow
    {
        public string ComponentId { get; set; } = "";
        public string OsvId { get; set; } = "";
        public string? Aliases { get; set; }
        public bool IsKev { get; set; }
        public double? EpssScore { get; set; }
        public double? CvssScore { get; set; }
        public bool? KevKnownRansomware { get; set; }
        public string? KevDueDate { get; set; }
        public double? EpssPercentile { get; set; }
        public double? NvdScore { get; set; }
        public string? SsvcExploitation { get; set; }
        public string? SsvcAutomatable { get; set; }
        public string? SsvcTechnicalImpact { get; set; }
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class VexRow
    {
        public string PurlKey { get; set; } = "";
        public string VulnKey { get; set; } = "";
        public string? VexState { get; set; }
    }

    private sealed class VersionLabelRow
    {
        public string ProjectName { get; set; } = "";
        public string VersionLabel { get; set; } = "";
    }
}

/// <summary>
/// One component's evaluator-ready facts, plus the fields the licence arm needs and the verbatim
/// <see cref="Purl"/> the scannability test reads (a row with no purl can never be answered by an
/// advisory query, so its NULL <c>vuln_checked_at</c> is not an open question).
/// </summary>
public sealed record SbomComponentEvaluationInput(
    string ComponentId, string? Purl, string? LicenseSpdx, SbomComponentFacts Facts);
