using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Dapper;
using Dependably.Infrastructure.Sbom;
using Dependably.Infrastructure.VulnTracker;
using Dependably.Protocol;

namespace Dependably.Infrastructure;

/// <summary>
/// Renders a project version's component inventory, vulnerability disclosure and effective VEX
/// state as fresh CycloneDX 1.6 JSON, and resolves an uploaded document's original blob coordinate
/// for verbatim download. Built directly against <c>System.Text.Json</c> — CONTRACT D2 forbids a
/// new NuGet dependency on the CycloneDX serializer, so a re-render is a re-render: it is not
/// byte-identical to whatever was originally uploaded, only spec-valid CycloneDX 1.6 covering the
/// same components, licences, dependency graph and vulnerability analysis the database holds.
///
/// Every query here is written directly against the schema rather than through another agent's
/// repository, per the fleet contract's "repositories are not shared" rule — a little query
/// duplication in exchange for a mergeable worktree.
/// </summary>
public sealed class SbomExportService
{
    /// <summary>
    /// Declares which version of each project an aggregate document selected. Emitted in
    /// <c>metadata.properties</c> because a document that does not say what it chose is read as
    /// exhaustive — and this one is not: it carries each project's <c>is_latest</c> version, which
    /// is the same selection the collection's own rollup counts describe.
    /// </summary>
    public const string LatestPerProjectSelection = "latest-per-project";

    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;
    private readonly ProjectRepository _projects;
    private readonly InstanceVulnTrackerConfig _tracker;

    public SbomExportService(
        IMetadataStore db, TimeProvider time, ProjectRepository projects, InstanceVulnTrackerConfig tracker)
    {
        _db = db;
        _time = time;
        _projects = projects;
        _tracker = tracker;
    }

    /// <summary>
    /// Whether the operator's optional vulnerability-tracker connection is enabled and dialable —
    /// the single fact every SSVC/NVD-derived per-vulnerability signal in an exported document
    /// shares, so a consumer can tell "absent because the feature is off" from "the source said
    /// nothing" without the per-vulnerability signal itself carrying that distinction.
    /// </summary>
    private async Task<bool> IsTrackerConfiguredAsync(CancellationToken ct)
        => (await _tracker.ResolveAsync(ct)).IsActive;

    /// <summary>
    /// Renders CycloneDX 1.6 JSON for <paramref name="variant"/> (<c>inventory</c> or <c>vdr</c>),
    /// or <c>null</c> when the project or version does not resolve for this org.
    /// </summary>
    public async Task<string?> BuildSbomDocumentAsync(
        string orgId, string projectId, string versionId, string variant, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        var resolved = await ResolveProjectVersionAsync(conn, orgId, projectId, versionId, ct);
        if (resolved is null)
        {
            return null;
        }

        var components = await LoadComponentsAsync(conn, orgId, resolved.ProjectVersionId, ct);
        var installScriptFacts = await LoadInstallScriptFactsAsync(conn, orgId, resolved.ProjectVersionId, ct);
        bool trackerConfigured = await IsTrackerConfiguredAsync(ct);

        string rootRef = $"{resolved.ProjectName}@{resolved.VersionLabel}";

        var doc = new JsonObject
        {
            ["bomFormat"] = "CycloneDX",
            ["specVersion"] = "1.6",
            ["serialNumber"] = $"urn:uuid:{Guid.NewGuid()}",
            ["version"] = 1,
            ["metadata"] = new JsonObject
            {
                ["timestamp"] = _time.GetUtcNow().ToUtcIso(),
                ["component"] = new JsonObject
                {
                    ["type"] = resolved.Classifier,
                    ["bom-ref"] = rootRef,
                    ["name"] = resolved.ProjectName,
                    ["version"] = resolved.VersionLabel,
                },
                ["properties"] = BuildCoverageProperties(components, trackerConfigured),
            },
            ["components"] = BuildComponentsArray(components, installScriptByComponentId: installScriptFacts),
            ["dependencies"] = BuildDependenciesArray(rootRef, components),
        };

        if (variant == "vdr")
        {
            var vulnRows = await LoadComponentVulnsAsync(conn, orgId, resolved.ProjectVersionId, ct);
            var analysisRows = await LoadAnalysisAsync(conn, orgId, resolved.ProjectVersionId, ct);
            var affectedApps = await CountAffectedApplicationsAsync(
                conn, orgId, vulnRows.Select(v => v.OsvId).Distinct(StringComparer.Ordinal).ToList(), ct);
            doc["vulnerabilities"] = BuildVulnerabilitiesArray(vulnRows, analysisRows, installScriptFacts, affectedApps);
        }

        return doc.ToJsonString();
    }

    /// <summary>
    /// Renders one CycloneDX 1.6 document covering every project beneath a collection, or
    /// <c>null</c> when the id is not a collection this org holds.
    ///
    /// <para><b>Shape.</b> Each project is a top-level <c>components[]</c> entry of its own
    /// classifier type, carrying its libraries in a nested <c>components[]</c>. A flat merge was
    /// rejected: it loses which project each library came from — the only thing this document adds
    /// over the per-project exports — and it produces an INVALID document, because bom-refs are
    /// derived from the purl and the same library in two projects would collide on a ref the spec
    /// requires to be unique. Every ref here is therefore namespaced by project id, while the
    /// <c>purl</c> field stays the bare purl a consumer matches on.</para>
    ///
    /// <para><b>Selection.</b> Each project contributes its <c>is_latest</c> version and nothing
    /// else, which is what the collection's own rollup counts describe — an export whose contents
    /// disagreed with the numbers rendered beside its button would be worse than no export. The
    /// rule is stated in <c>metadata.properties</c> rather than left implicit, and a project with
    /// no version at all is still listed, as an empty entry, so the document never reads as
    /// exhaustive when it is not. Several concurrently-live versions per project is a real shape
    /// this deliberately does not model yet; it needs a per-version label, not a second
    /// <c>is_latest</c>-like flag, and nothing has asked for it.</para>
    ///
    /// <para><b>No deduplication.</b> A library shipped by three projects appears three times, once
    /// under each. VEX analysis is per-project — the same advisory can be not-affected in one and
    /// live in another — so a single merged entry would need one analysis block holding two
    /// contradictory truths. Reducing on purl downstream is trivial; recovering provenance from a
    /// pre-deduplicated document is not.</para>
    ///
    /// <para>The walk is not transactional, so a concurrent upload can land in the middle of it and
    /// produce a mixed snapshot — the same property the rollup counts have.</para>
    /// </summary>
    public async Task<string?> BuildCollectionSbomDocumentAsync(
        string orgId, string collectionId, string variant, CancellationToken ct)
    {
        var subtree = await _projects.ListSubtreeProjectsAsync(orgId, collectionId, ct);
        if (subtree is null)
        {
            return null;
        }

        var collection = await _projects.GetAsync(orgId, collectionId, ct);
        if (collection is null)
        {
            return null;
        }

        await using var conn = await _db.OpenAsync(ct);

        string rootRef = $"collection:{collection.Id}";
        var projectEntries = new JsonArray();
        var dependencies = new JsonArray();
        var rootDependsOn = new JsonArray();
        var vulnerabilities = new JsonArray();
        int withoutSbom = 0;
        var coverage = new CoverageAccumulator();
        bool trackerConfigured = await IsTrackerConfiguredAsync(ct);

        foreach (var project in subtree)
        {
            string projectRef = $"{rootRef}/project:{project.ProjectId}";
            rootDependsOn.Add(projectRef);

            var entry = new JsonObject
            {
                ["type"] = project.Classifier,
                ["bom-ref"] = projectRef,
                ["name"] = project.Name,
            };
            if (project.VersionLabel is not null)
            {
                entry["version"] = project.VersionLabel;
            }

            if (project.ProjectVersionId is null)
            {
                // Listed, marked, and empty. Dropping it would make the document claim the folder
                // holds only the projects someone has uploaded for.
                withoutSbom++;
                entry["properties"] = new JsonArray(
                    new JsonObject { ["name"] = "dependably:noSbom", ["value"] = "true" });
                projectEntries.Add(entry);
                dependencies.Add(new JsonObject { ["ref"] = projectRef, ["dependsOn"] = new JsonArray() });
                continue;
            }

            await AppendProjectAsync(
                conn,
                new ProjectExport(orgId, project.ProjectVersionId, projectRef, variant),
                entry,
                new CollectionBuffers(projectEntries, dependencies, vulnerabilities),
                coverage,
                ct);
        }

        dependencies.Insert(0, new JsonObject { ["ref"] = rootRef, ["dependsOn"] = rootDependsOn });

        var metadataProperties = new JsonArray(
            new JsonObject { ["name"] = "dependably:aggregate", ["value"] = "collection" },
            new JsonObject { ["name"] = "dependably:selection", ["value"] = LatestPerProjectSelection },
            new JsonObject { ["name"] = "dependably:projectCount", ["value"] = subtree.Count.ToString(CultureInfo.InvariantCulture) },
            new JsonObject { ["name"] = "dependably:projectsWithoutSbom", ["value"] = withoutSbom.ToString(CultureInfo.InvariantCulture) });
        // DeepClone: a JsonNode can only ever have one parent, and coverage.ToProperties() returns
        // an array whose own entries are already parented to it — appending the nodes themselves
        // (rather than clones) throws the moment the second entry is added.
        foreach (var prop in coverage.ToProperties(trackerConfigured))
        {
            metadataProperties.Add(prop!.DeepClone());
        }

        var doc = new JsonObject
        {
            ["bomFormat"] = "CycloneDX",
            ["specVersion"] = "1.6",
            ["serialNumber"] = $"urn:uuid:{Guid.NewGuid()}",
            ["version"] = 1,
            ["metadata"] = new JsonObject
            {
                ["timestamp"] = _time.GetUtcNow().ToUtcIso(),
                // No version: a collection has none, and CycloneDX permits omitting it. Inventing
                // one would be the document asserting something the model does not hold.
                ["component"] = new JsonObject
                {
                    ["type"] = "application",
                    ["bom-ref"] = rootRef,
                    ["name"] = collection.Name,
                },
                ["properties"] = metadataProperties,
            },
            ["components"] = projectEntries,
            ["dependencies"] = dependencies,
        };

        if (variant == "vdr")
        {
            doc["vulnerabilities"] = vulnerabilities;
        }

        return doc.ToJsonString();
    }

    /// <summary>
    /// Renders a vulnerabilities-only CycloneDX 1.6 VEX document of the current effective
    /// analysis state — both upload-sourced and manually triaged rows — or <c>null</c> when the
    /// project or version does not resolve for this org.
    /// </summary>
    public async Task<string?> BuildVexDocumentAsync(
        string orgId, string projectId, string versionId, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        var resolved = await ResolveProjectVersionAsync(conn, orgId, projectId, versionId, ct);
        if (resolved is null)
        {
            return null;
        }

        var analysisRows = await LoadAnalysisAsync(conn, orgId, resolved.ProjectVersionId, ct);
        // A row a SARIF-only merge wrote (reachability/confidence, no VEX opinion) has nothing
        // to say in a VEX document — only rows carrying an actual analysis state are exported.
        var withState = analysisRows.Where(a => a.VexState is not null).ToList();

        var components = await LoadComponentsAsync(conn, orgId, resolved.ProjectVersionId, ct);
        bool trackerConfigured = await IsTrackerConfiguredAsync(ct);

        // A standalone VEX document is keyed by (purl_key, vuln_key), not by sbom_components.id, so
        // dependency-graph position and install-script presence — both component facts — are
        // recovered here the same way BuildVulnerabilitiesArray recovers an analysis row for a
        // component: by computing each component's own purl_key with the identical
        // SbomPurlKey.ForComponent rule the ingest writers used to key project_vuln_analysis.
        var componentByPurlKey = new Dictionary<string, ComponentRow>(StringComparer.Ordinal);
        foreach (var c in components)
        {
            string? key = SbomPurlKey.ForComponent(c.Ecosystem, c.PurlName, c.Purl);
            if (key is not null)
            {
                componentByPurlKey[key] = c;
            }
        }

        var installScriptFacts = await LoadInstallScriptFactsAsync(conn, orgId, resolved.ProjectVersionId, ct);

        var vulns = new JsonArray();
        if (withState.Count > 0)
        {
            var osvIds = withState.Select(a => a.VulnKey).Distinct(StringComparer.Ordinal).ToList();
            var (osvIdsClause, osvIdsParameters) = DapperInClause.Expand("osv", osvIds);
            // rawsql: osvIdsClause is a parameterized IN (@osv0, @osv1, …) list built in C#, not user text.
            // xtenant: vulnerabilities is the global OSV advisory cache, not a tenant table —
            // resolved by advisory id only, for best-effort source/rating/enrichment lookup.
            var known = (await conn.QueryAsync<VulnLookupRow>(new CommandDefinition(
                """
                SELECT osv_id AS OsvId, severity AS Severity, cvss_score AS CvssScore,
                       nvd_score AS NvdScore, nvd_checked_at AS NvdCheckedAt, nvd_asserted_at AS NvdAssertedAt,
                       is_kev AS IsKev, kev_known_ransomware AS IsKevRansomware,
                       kev_due_date AS KevDueDate, kev_date_added AS KevDateAdded,
                       kev_required_action AS KevRequiredAction, kev_cwes AS KevCwes, kev_notes AS KevNotes,
                       epss_score AS EpssScore, epss_percentile AS EpssPercentile,
                       ssvc_exploitation AS SsvcExploitation, ssvc_automatable AS SsvcAutomatable,
                       ssvc_technical_impact AS SsvcTechnicalImpact,
                       ssvc_checked_at AS SsvcCheckedAt, ssvc_asserted_at AS SsvcAssertedAt,
                       osv_id LIKE 'MAL-%' AS IsMalicious
                FROM vulnerabilities WHERE osv_id IN
                """ + " " + osvIdsClause,
                osvIdsParameters, cancellationToken: ct)))
                .ToDictionary(v => v.OsvId, StringComparer.Ordinal);
            var affectedApps = await CountAffectedApplicationsAsync(conn, orgId, osvIds, ct);

            foreach (var a in withState)
            {
                known.TryGetValue(a.VulnKey, out var lookup);
                componentByPurlKey.TryGetValue(a.PurlKey, out var component);
                var entry = new JsonObject
                {
                    ["bom-ref"] = $"vuln-{a.VulnKey}-{a.PurlKey}",
                    ["id"] = a.VulnKey,
                    ["source"] = BuildSource(a.VulnKey),
                };
                var ratings = BuildRatings(lookup?.Severity, lookup?.CvssScore);
                if (ratings is not null)
                {
                    entry["ratings"] = ratings;
                }

                entry["analysis"] = BuildAnalysis(a);
                entry["affects"] = new JsonArray(new JsonObject { ["ref"] = a.PurlKey });
                entry["properties"] = BuildVulnProperties(
                    new VulnSignalFacts(
                        lookup?.CvssScore,
                        lookup?.NvdScore,
                        lookup?.NvdCheckedAt,
                        lookup?.NvdAssertedAt,
                        lookup?.IsKev ?? false,
                        lookup?.IsKevRansomware,
                        lookup?.KevDueDate,
                        lookup?.KevDateAdded,
                        lookup?.KevRequiredAction,
                        lookup?.KevCwes,
                        lookup?.KevNotes,
                        lookup?.EpssScore,
                        lookup?.EpssPercentile,
                        lookup?.SsvcExploitation,
                        lookup?.SsvcAutomatable,
                        lookup?.SsvcTechnicalImpact,
                        lookup?.SsvcCheckedAt,
                        lookup?.SsvcAssertedAt,
                        component?.DependencyKind,
                        component?.DependencyScope,
                        component is not null && installScriptFacts.GetValueOrDefault(component.Id),
                        affectedApps.GetValueOrDefault(a.VulnKey),
                        lookup?.IsMalicious ?? false),
                    a.VexState,
                    a.Reachability);
                vulns.Add(entry);
            }
        }

        var doc = new JsonObject
        {
            ["bomFormat"] = "CycloneDX",
            ["specVersion"] = "1.6",
            ["serialNumber"] = $"urn:uuid:{Guid.NewGuid()}",
            ["version"] = 1,
            ["metadata"] = new JsonObject
            {
                ["timestamp"] = _time.GetUtcNow().ToUtcIso(),
                ["properties"] = BuildCoverageProperties(components, trackerConfigured),
            },
            ["vulnerabilities"] = vulns,
        };

        return doc.ToJsonString();
    }

    /// <summary>
    /// Resolves the blob coordinate and derived filename for an uploaded document's verbatim
    /// original, or <c>null</c> when the document does not exist for this org.
    /// </summary>
    public async Task<ProjectDocumentOriginal?> ResolveOriginalAsync(
        string orgId, string documentId, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<OriginalRow>(new CommandDefinition(
            """
            SELECT pd.blob_key AS BlobKey, pd.sha256 AS Sha256, pd.format AS Format,
                   pd.doc_type AS DocType, p.name AS ProjectName, pv.version AS VersionLabel
            FROM project_documents pd
            JOIN project_versions pv ON pv.id = pd.project_version_id
            JOIN projects p ON p.id = pv.project_id
            WHERE pd.id = @documentId AND pd.org_id = @orgId
            """,
            new { documentId, orgId }, cancellationToken: ct));

        return row is null
            ? null
            : new ProjectDocumentOriginal
            {
                BlobKey = row.BlobKey,
                Sha256 = row.Sha256,
                Format = row.Format,
                DocType = row.DocType,
                FileName = ProjectDocumentNaming.FileName(row.ProjectName, row.VersionLabel, row.DocType),
            };
    }

    // ── Project/version resolution ──────────────────────────────────────────

    private sealed record ResolvedVersion(
        string ProjectVersionId, string ProjectName, string VersionLabel, string Classifier);

    // {versionId} accepts the literal "latest", resolved with a one-line query per the fleet
    // contract — B0's helper is not imported here.
    private static async Task<ResolvedVersion?> ResolveProjectVersionAsync(
        System.Data.IDbConnection conn, string orgId, string projectId, string versionId, CancellationToken ct)
    {
        var project = await conn.QuerySingleOrDefaultAsync<ProjectRow>(new CommandDefinition(
            "SELECT name AS Name, classifier AS Classifier FROM projects WHERE id = @projectId AND org_id = @orgId",
            new { projectId, orgId }, cancellationToken: ct));
        if (project is null)
        {
            return null;
        }

        string versionSql = versionId == "latest"
            ? """
              SELECT id AS Id, version AS Version FROM project_versions
              WHERE project_id = @projectId AND org_id = @orgId AND is_latest = 1
              """
            : """
              SELECT id AS Id, version AS Version FROM project_versions
              WHERE id = @versionId AND project_id = @projectId AND org_id = @orgId
              """;

        var version = await conn.QuerySingleOrDefaultAsync<VersionRow>(new CommandDefinition(
            versionSql, new { projectId, orgId, versionId }, cancellationToken: ct));

        return version is null
            ? null
            : new ResolvedVersion(version.Id, project.Name, version.Version, project.Classifier);
    }

    private static async Task<List<ComponentRow>> LoadComponentsAsync(
        System.Data.Common.DbConnection conn, string orgId, string projectVersionId, CancellationToken ct)
        => (await conn.QueryAsync<ComponentRow>(new CommandDefinition(
            """
            SELECT id AS Id, purl AS Purl, name AS Name, version AS Version,
                   ecosystem AS Ecosystem, purl_name AS PurlName,
                   component_type AS ComponentType, sbom_scope AS SbomScope,
                   dependency_kind AS DependencyKind, dependency_scope AS DependencyScope,
                   dependency_path AS DependencyPath, license_spdx AS LicenseSpdx,
                   vuln_checked_at AS VulnCheckedAt
            FROM sbom_components
            WHERE project_version_id = @pvId AND org_id = @orgId
            ORDER BY name, version
            """,
            new { pvId = projectVersionId, orgId }, cancellationToken: ct))).AsList();

    private static async Task<List<ComponentVulnRow>> LoadComponentVulnsAsync(
        System.Data.Common.DbConnection conn, string orgId, string projectVersionId, CancellationToken ct)
        => (await conn.QueryAsync<ComponentVulnRow>(new CommandDefinition(
            """
            SELECT sc.id AS ComponentId, sc.purl AS ComponentPurl,
                   sc.ecosystem AS Ecosystem, sc.purl_name AS PurlName,
                   sc.dependency_kind AS DependencyKind, sc.dependency_scope AS DependencyScope,
                   v.osv_id AS OsvId, v.aliases AS Aliases, v.severity AS Severity,
                   v.cvss_score AS CvssScore, v.nvd_score AS NvdScore,
                   v.nvd_checked_at AS NvdCheckedAt, v.nvd_asserted_at AS NvdAssertedAt,
                   v.is_kev AS IsKev, v.kev_known_ransomware AS IsKevRansomware,
                   v.kev_due_date AS KevDueDate, v.kev_date_added AS KevDateAdded,
                   v.kev_required_action AS KevRequiredAction, v.kev_cwes AS KevCwes, v.kev_notes AS KevNotes,
                   v.epss_score AS EpssScore, v.epss_percentile AS EpssPercentile,
                   v.ssvc_exploitation AS SsvcExploitation, v.ssvc_automatable AS SsvcAutomatable,
                   v.ssvc_technical_impact AS SsvcTechnicalImpact,
                   v.ssvc_checked_at AS SsvcCheckedAt, v.ssvc_asserted_at AS SsvcAssertedAt,
                   v.osv_id LIKE 'MAL-%' AS IsMalicious
            FROM sbom_component_vulns scv
            JOIN sbom_components sc ON sc.id = scv.component_id
            JOIN vulnerabilities v ON v.id = scv.vuln_id
            WHERE sc.project_version_id = @pvId AND sc.org_id = @orgId
            ORDER BY sc.name, v.osv_id
            """,
            new { pvId = projectVersionId, orgId }, cancellationToken: ct))).AsList();

    private static async Task<List<AnalysisRow>> LoadAnalysisAsync(
        System.Data.IDbConnection conn, string orgId, string projectVersionId, CancellationToken ct)
    {
        var rows = await conn.QueryAsync<AnalysisRow>(new CommandDefinition(
            """
            SELECT purl_key AS PurlKey, vuln_key AS VulnKey, vex_state AS VexState,
                   vex_justification AS VexJustification, vex_response AS VexResponse,
                   vex_detail AS VexDetail, reachability AS Reachability
            FROM project_vuln_analysis
            WHERE project_version_id = @projectVersionId AND org_id = @orgId
            """,
            new { projectVersionId, orgId }, cancellationToken: ct));
        return rows.AsList();
    }

    /// <summary>
    /// One project version's registry-catalogue install-script cross-link, keyed by
    /// <c>sbom_components.id</c> — the boolean-only twin of
    /// <c>SbomAnalysisRepository.ListRegistryFactsAsync</c>'s <c>HasInstallScriptThisVersion</c>
    /// arm, written directly here rather than shared per the fleet contract's "repositories are not
    /// shared" rule. A miss (absent from the returned map) means "unknown to this registry", never
    /// "verified clean" — <see cref="DependablyExportProperties.InstallScript"/> is emitted only on
    /// a positive match for exactly that reason.
    /// </summary>
    private static async Task<Dictionary<string, bool>> LoadInstallScriptFactsAsync(
        System.Data.Common.DbConnection conn, string orgId, string projectVersionId, CancellationToken ct)
    {
        // plane-ok: this is the hosted half of a deliberate two-statement read; the proxy plane is
        // resolved by the cached-plane query immediately below and merged into one map.
        var hosted = await conn.QueryAsync<InstallScriptRow>(new CommandDefinition(
            """
            SELECT c.id AS ComponentId,
                   CASE WHEN EXISTS (
                       SELECT 1 FROM package_versions pv
                       WHERE pv.package_id = p.id AND pv.has_install_script = 1
                         AND pv.version = c.version) THEN 1 ELSE 0 END AS HasInstallScript
            FROM sbom_components c
            JOIN packages p ON p.org_id = c.org_id AND p.ecosystem = c.ecosystem AND p.purl_name = c.purl_name
            WHERE c.org_id = @orgId AND c.project_version_id = @projectVersionId
            """,
            new { orgId, projectVersionId }, cancellationToken: ct));

        // xtenant: cache_artifact is the global proxy catalogue; the org filter is on the
        // tenant_artifact_access binding joined below, and on sbom_components driving the read.
        var cached = await conn.QueryAsync<InstallScriptRow>(new CommandDefinition(
            """
            SELECT c.id AS ComponentId,
                   CASE WHEN EXISTS (
                       SELECT 1 FROM cache_artifact ca
                       JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id AND taa.org_id = c.org_id
                       WHERE ca.ecosystem = c.ecosystem AND ca.name = c.purl_name
                         AND ca.has_install_script = 1 AND ca.version = c.version) THEN 1 ELSE 0 END AS HasInstallScript
            FROM sbom_components c
            WHERE c.org_id = @orgId AND c.project_version_id = @projectVersionId
            """,
            new { orgId, projectVersionId }, cancellationToken: ct));

        var result = new Dictionary<string, bool>(StringComparer.Ordinal);
        foreach (var row in hosted)
        {
            result[row.ComponentId] = result.GetValueOrDefault(row.ComponentId) || row.HasInstallScript;
        }

        foreach (var row in cached)
        {
            result[row.ComponentId] = result.GetValueOrDefault(row.ComponentId) || row.HasInstallScript;
        }

        return result;
    }

    /// <summary>
    /// How many of this tenant's applications ship each of <paramref name="osvIds"/> on their
    /// latest version — the same query shape as
    /// <c>SbomBlastRadiusRepository.CountProjectsByAdvisoryAsync</c>, written directly here per the
    /// fleet contract. <b>Scoped to <c>is_latest = 1</c></b>, matching that repository's own
    /// documented reasoning: an older release is not something an operator can remediate today, and
    /// only <c>is_latest</c> versions get their advisory links refreshed nightly, so counting a
    /// superseded version would mix a current answer with a stale one under one number.
    /// </summary>
    private static async Task<Dictionary<string, int>> CountAffectedApplicationsAsync(
        System.Data.Common.DbConnection conn, string orgId, IReadOnlyList<string> osvIds, CancellationToken ct)
    {
        if (osvIds.Count == 0)
        {
            return new Dictionary<string, int>(StringComparer.Ordinal);
        }

        var (keysClause, parameters) = DapperInClause.Expand("osv", osvIds);
        parameters.Add("orgId", orgId);
        // rawsql: keysClause is a parameterized IN (@osv0, @osv1, …) list built in C#, not user text.
        var rows = await conn.QueryAsync<AffectedApplicationsRow>(new CommandDefinition(
            """
            SELECT v.osv_id AS OsvId, COUNT(DISTINCT pv.project_id) AS Count
            FROM sbom_component_vulns scv
            JOIN vulnerabilities v ON v.id = scv.vuln_id
            JOIN sbom_components c ON c.id = scv.component_id
            JOIN project_versions pv ON pv.id = c.project_version_id AND pv.org_id = c.org_id
            WHERE c.org_id = @orgId AND pv.is_latest = 1 AND v.osv_id IN
            """ + " " + keysClause + " GROUP BY v.osv_id",
            parameters, cancellationToken: ct));
        return rows.ToDictionary(r => r.OsvId, r => r.Count, StringComparer.Ordinal);
    }

    // ── Document/graph rendering ─────────────────────────────────────────────

    private static JsonArray BuildComponentsArray(
        IReadOnlyList<ComponentRow> components, string? refPrefix = null,
        IReadOnlyDictionary<string, bool>? installScriptByComponentId = null)
    {
        var arr = new JsonArray();
        foreach (var c in components)
        {
            var obj = new JsonObject
            {
                ["type"] = c.ComponentType ?? "library",
                ["bom-ref"] = RefOf(c, refPrefix),
                ["name"] = c.Name,
            };
            if (c.Version is not null)
            {
                obj["version"] = c.Version;
            }

            if (c.Purl is not null)
            {
                obj["purl"] = c.Purl;
            }

            // CONTRACT D1: component scope is written ONLY from sbom_scope (raw CycloneDX
            // scope, display-only) — never from dependency_scope, the SARIF-owned dev/prod
            // signal CycloneDX has no vocabulary for. Conflating them here is exactly what the
            // producer split exists to prevent.
            if (c.SbomScope is not null)
            {
                obj["scope"] = c.SbomScope;
            }

            if (c.LicenseSpdx is not null)
            {
                obj["licenses"] = new JsonArray(new JsonObject { ["expression"] = c.LicenseSpdx });
            }

            var properties = new JsonArray();
            if (c.DependencyKind is not null)
            {
                properties.Add(Prop(DependablyExportProperties.DependencyKind, c.DependencyKind));
            }

            if (c.DependencyScope is not null)
            {
                properties.Add(Prop(DependablyExportProperties.DependencyScope, c.DependencyScope));
            }

            // Positive-only: a miss (no dictionary, or a false/absent entry) means "unknown to
            // this registry", never "verified clean" — see DependablyExportProperties.InstallScript.
            if (installScriptByComponentId is not null && installScriptByComponentId.GetValueOrDefault(c.Id))
            {
                properties.Add(Prop(DependablyExportProperties.InstallScript, DependablyExportProperties.TrueValue));
            }

            if (properties.Count > 0)
            {
                obj["properties"] = properties;
            }

            arr.Add(obj);
        }

        return arr;
    }

    /// <summary>
    /// Reconstructs a closed <c>dependencies[]</c> adjacency graph from each component's own
    /// <see cref="ComponentRow.DependencyPath"/> — the JSON array of purls from the dependency
    /// root to the component itself (inclusive of its own ref). Consecutive elements of one
    /// component's path are direct edges; the root is the implicit ancestor of every path's first
    /// element. A component with no stored path is treated as a direct child of the root. Every
    /// ref that is ever named — root, every component, and any ancestor a path mentions without
    /// itself being an uploaded component — gets its own <c>dependencies[]</c> entry, so the graph
    /// has no dangling edges.
    /// </summary>
    private static JsonArray BuildDependenciesArray(
        string rootRef, IReadOnlyList<ComponentRow> components, string? refPrefix = null)
    {
        var order = new List<string> { rootRef };
        var childrenOf = new Dictionary<string, List<string>>(StringComparer.Ordinal) { [rootRef] = [] };

        void EnsureNode(string r)
        {
            if (!childrenOf.ContainsKey(r))
            {
                childrenOf[r] = [];
                order.Add(r);
            }
        }

        void AddEdge(string parent, string child)
        {
            EnsureNode(parent);
            EnsureNode(child);
            if (!childrenOf[parent].Contains(child))
            {
                childrenOf[parent].Add(child);
            }
        }

        // Path elements are stored as bare purls, so an aggregate has to namespace them the same
        // way the component bom-refs are — otherwise the graph names refs no component declares,
        // and two projects sharing a transitive dependency merge into one node.
        string Namespaced(string bareRef) => refPrefix is null ? bareRef : $"{refPrefix}/{bareRef}";

        foreach (var c in components)
        {
            string selfRef = RefOf(c, refPrefix);
            EnsureNode(selfRef);

            var path = ParseStringArray(c.DependencyPath);
            if (path.Count == 0)
            {
                AddEdge(rootRef, selfRef);
                continue;
            }

            AddEdge(rootRef, Namespaced(path[0]));
            for (int i = 0; i < path.Count - 1; i++)
            {
                AddEdge(Namespaced(path[i]), Namespaced(path[i + 1]));
            }
        }

        var arr = new JsonArray();
        foreach (string r in order)
        {
            var dependsOn = new JsonArray();
            foreach (string child in childrenOf[r])
            {
                dependsOn.Add(JsonValue.Create(child));
            }

            arr.Add(new JsonObject { ["ref"] = r, ["dependsOn"] = dependsOn });
        }

        return arr;
    }

    private static JsonArray BuildVulnerabilitiesArray(
        IReadOnlyList<ComponentVulnRow> vulnRows, IReadOnlyList<AnalysisRow> analysisRows,
        IReadOnlyDictionary<string, bool> installScriptByComponentId,
        IReadOnlyDictionary<string, int> affectedAppsByOsvId,
        string? refPrefix = null)
    {
        // Keyed with the same SbomVulnKeyComparer SbomPolicyRepository.ResolveVexState uses — one
        // comparison rule for vuln_key so an analysis block suppressed in the analysis view is
        // suppressed in the exported document too, never the reverse — without rewriting the
        // stored spelling of an advisory id.
        var analysisByKey = analysisRows.ToDictionary(
            a => (a.PurlKey, a.VulnKey), SbomVulnKeyComparer.Instance);

        var arr = new JsonArray();
        foreach (var v in vulnRows)
        {
            // The analysis rows are keyed by SbomPurlKey on the way in; re-deriving the key any
            // other way here drops the suppressing analysis block off exactly the scoped,
            // mixed-case and underscored coordinates canonicalization exists for.
            string? purlKey = SbomPurlKey.ForComponent(v.Ecosystem, v.PurlName, v.ComponentPurl);
            var analysis = purlKey is null
                ? null
                : FindAnalysis(analysisByKey, purlKey, v.OsvId, v.Aliases);

            var entry = new JsonObject
            {
                ["bom-ref"] = $"vuln-{v.OsvId}-{v.ComponentId}",
                ["id"] = v.OsvId,
                ["source"] = BuildSource(v.OsvId),
            };

            var ratings = BuildRatings(v.Severity, v.CvssScore);
            if (ratings is not null)
            {
                entry["ratings"] = ratings;
            }

            var analysisObj = BuildAnalysis(analysis);
            if (analysisObj is not null)
            {
                entry["analysis"] = analysisObj;
            }

            // Points at the component's bom-ref, which in an aggregate is the namespaced one —
            // an un-prefixed affects ref would resolve to whichever project's copy came first.
            entry["affects"] = new JsonArray(new JsonObject
            {
                ["ref"] = refPrefix is null ? v.ComponentPurl : $"{refPrefix}/{v.ComponentPurl}",
            });

            entry["properties"] = BuildVulnProperties(
                new VulnSignalFacts(
                    v.CvssScore,
                    v.NvdScore,
                    v.NvdCheckedAt,
                    v.NvdAssertedAt,
                    v.IsKev,
                    v.IsKevRansomware,
                    v.KevDueDate,
                    v.KevDateAdded,
                    v.KevRequiredAction,
                    v.KevCwes,
                    v.KevNotes,
                    v.EpssScore,
                    v.EpssPercentile,
                    v.SsvcExploitation,
                    v.SsvcAutomatable,
                    v.SsvcTechnicalImpact,
                    v.SsvcCheckedAt,
                    v.SsvcAssertedAt,
                    v.DependencyKind,
                    v.DependencyScope,
                    installScriptByComponentId.GetValueOrDefault(v.ComponentId),
                    affectedAppsByOsvId.GetValueOrDefault(v.OsvId),
                    v.IsMalicious),
                analysis?.VexState,
                analysis?.Reachability);

            arr.Add(entry);
        }

        return arr;
    }

    // ── Signal-property assembly, shared by every producer ───────────────────

    /// <summary>
    /// Every input <see cref="EffectivePriority.Derive"/> and the per-vulnerability property
    /// vocabulary need for one (component, advisory) pair, gathered from whichever producer's own
    /// row shapes so <see cref="BuildVulnProperties"/> has exactly one implementation shared by the
    /// VDR, collection, and standalone-VEX producers — the thing the fixture set that pairs them
    /// pins.
    /// </summary>
    private readonly record struct VulnSignalFacts(
        double? Cvss,
        double? NvdScore,
        string? NvdCheckedAt,
        string? NvdAssertedAt,
        bool IsKev,
        bool? IsKevRansomware,
        string? KevDueDate,
        string? KevDateAdded,
        string? KevRequiredAction,
        string? KevCwes,
        string? KevNotes,
        double? Epss,
        double? EpssPercentile,
        string? SsvcExploitation,
        string? SsvcAutomatable,
        string? SsvcTechnicalImpact,
        string? SsvcCheckedAt,
        string? SsvcAssertedAt,
        string? DependencyKind,
        string? DependencyScope,
        bool HasInstallScript,
        int AffectedApplications,
        bool IsMalicious);

    /// <summary>
    /// Builds the <c>properties[]</c> array for one vulnerability entry: the derived priority
    /// bucket (computed fresh here, per <see cref="EffectivePriority"/>'s never-materialize
    /// invariant) plus every exploitation/decision-support signal the platform holds for it.
    /// Fail-closed throughout: an absent signal is emitted as an explicit "unknown"/omitted
    /// property, never a value a consumer could mistake for verified-benign.
    /// </summary>
    private static JsonArray BuildVulnProperties(VulnSignalFacts f, string? vexState, string? reachability)
    {
        // HasStaleEnrichment is unused by Derive's rule text (see EffectivePriority's own doc
        // comment), so it stays at VulnFacts' unknown default here — the same posture
        // SbomAnalysisProjection.BuildAdvisory takes for the live analysis surface.
        var vulnFacts = VulnFacts.None with
        {
            Cvss = f.Cvss,
            NvdScore = f.NvdScore,
            IsKev = f.IsKev,
            IsKevRansomware = f.IsKevRansomware,
            IsMalicious = f.IsMalicious,
            Epss = f.Epss,
            EpssPercentile = f.EpssPercentile,
            SsvcExploitation = f.SsvcExploitation,
        };
        var verdict = EffectivePriority.Derive(PriorityFacts.ForProjectsPlane(
            vulnFacts, vexState, reachability, f.DependencyKind, f.DependencyScope, f.HasInstallScript));

        var props = new JsonArray
        {
            Prop(DependablyExportProperties.Priority, verdict.Bucket),
            Prop(DependablyExportProperties.Unscored, BoolValue(verdict.Unscored)),
            Prop(DependablyExportProperties.Kev, BoolValue(f.IsKev)),
            Prop(DependablyExportProperties.KevRansomware, TriStateValue(f.IsKevRansomware)),
            Prop(DependablyExportProperties.SsvcExploitation, f.SsvcExploitation ?? DependablyExportProperties.UnknownValue),
            Prop(DependablyExportProperties.AffectedApplications, f.AffectedApplications.ToString(CultureInfo.InvariantCulture)),
        };

        if (f.KevDueDate is not null)
        {
            props.Add(Prop(DependablyExportProperties.CisaKevDueDate, f.KevDueDate));
        }

        if (f.KevDateAdded is not null)
        {
            props.Add(Prop(DependablyExportProperties.CisaKevDateAdded, f.KevDateAdded));
        }

        if (f.KevRequiredAction is not null)
        {
            props.Add(Prop(DependablyExportProperties.CisaKevRequiredAction, f.KevRequiredAction));
        }

        if (f.KevCwes is not null)
        {
            props.Add(Prop(DependablyExportProperties.CisaKevCwes, f.KevCwes));
        }

        if (f.KevNotes is not null)
        {
            props.Add(Prop(DependablyExportProperties.CisaKevNotes, f.KevNotes));
        }

        if (f.EpssPercentile is not null)
        {
            props.Add(Prop(DependablyExportProperties.EpssPercentile, f.EpssPercentile.Value.ToString(CultureInfo.InvariantCulture)));
        }

        if (f.SsvcAutomatable is not null)
        {
            props.Add(Prop(DependablyExportProperties.SsvcAutomatable, f.SsvcAutomatable));
        }

        if (f.SsvcTechnicalImpact is not null)
        {
            props.Add(Prop(DependablyExportProperties.SsvcTechnicalImpact, f.SsvcTechnicalImpact));
        }

        if (f.NvdScore is not null)
        {
            props.Add(Prop(DependablyExportProperties.NvdScore, f.NvdScore.Value.ToString(CultureInfo.InvariantCulture)));
        }

        // Raw freshness timestamps, never a computed stale/fresh boolean — the operator's staleness
        // horizon is a policy judgment this export surface does not own; the consumer compares the
        // timestamp to its own cutoff. A stale reading is exported as-is (never suppressed just
        // because it is old), the same "stale input is not absent input" posture ARCH-block-gate
        // states for the gate itself. Omitted only when there is no signal at all to date.
        string? nvdCheckedAt = EffectiveFreshness(f.NvdCheckedAt, f.NvdAssertedAt);
        if (nvdCheckedAt is not null)
        {
            props.Add(Prop(DependablyExportProperties.NvdCheckedAt, nvdCheckedAt));
        }

        string? ssvcCheckedAt = EffectiveFreshness(f.SsvcCheckedAt, f.SsvcAssertedAt);
        if (ssvcCheckedAt is not null)
        {
            props.Add(Prop(DependablyExportProperties.SsvcCheckedAt, ssvcCheckedAt));
        }

        return props;
    }

    /// <summary>
    /// <c>COALESCE(assertedAt, checkedAt)</c> — the same left-operand shape
    /// <c>VulnerabilityRepository</c>'s own gate-signal freshness queries evaluate against the
    /// operator's staleness cutoff, mirrored here (not reused — this file writes its own queries
    /// per the fleet contract) because the export boundary needs the same "as-of" preference
    /// without needing the cutoff comparison itself. Null when <paramref name="checkedAt"/> is
    /// null: no signal was ever checked, which is a different, unambiguous absence, not a
    /// staleness question <paramref name="assertedAt"/> alone could answer.
    /// </summary>
    private static string? EffectiveFreshness(string? checkedAt, string? assertedAt) =>
        checkedAt is null ? null : (assertedAt ?? checkedAt);

    private static JsonObject Prop(string name, string value) => new() { ["name"] = name, ["value"] = value };

    private static string BoolValue(bool value) =>
        value ? DependablyExportProperties.TrueValue : DependablyExportProperties.FalseValue;

    private static string TriStateValue(bool? value) =>
        value is null ? DependablyExportProperties.UnknownValue : BoolValue(value.Value);

    // ── Document-level coverage/freshness metadata ───────────────────────────

    /// <summary>
    /// Buckets one document's components into scanned/unscanned/unscannable using the same
    /// classification <c>SbomPolicyEvaluationService.CountCoverage</c> applies on the analysis
    /// surface, and finds the latest scan stamp among the scanned set. A C# loop over the
    /// already-loaded component rows, not a query — scannability is a code-level classification
    /// (<see cref="SbomScannableComponents"/>), and every caller here already holds the full
    /// component list for the document it is building.
    /// </summary>
    private static (int Scanned, int Unscanned, int Unscannable, DateTimeOffset? LastScanAt) SummarizeCoverage(
        IReadOnlyList<ComponentRow> components)
    {
        int scanned = 0, unscanned = 0, unscannable = 0;
        DateTimeOffset? lastScanAt = null;

        foreach (var c in components)
        {
            if (!SbomScannableComponents.IsScannable(c.Ecosystem, c.Purl))
            {
                unscannable++;
                continue;
            }

            if (c.VulnCheckedAt is null)
            {
                unscanned++;
                continue;
            }

            scanned++;
            if (lastScanAt is null || c.VulnCheckedAt > lastScanAt)
            {
                lastScanAt = c.VulnCheckedAt;
            }
        }

        return (scanned, unscanned, unscannable, lastScanAt);
    }

    private static JsonArray BuildCoverageProperties(IReadOnlyList<ComponentRow> components, bool trackerConfigured)
    {
        var (scanned, unscanned, unscannable, lastScanAt) = SummarizeCoverage(components);
        return CoverageProperties(scanned, unscanned, unscannable, lastScanAt, trackerConfigured);
    }

    private static JsonArray CoverageProperties(
        int scanned, int unscanned, int unscannable, DateTimeOffset? lastScanAt, bool trackerConfigured)
    {
        var arr = new JsonArray
        {
            Prop(DependablyExportProperties.ScannedCount, scanned.ToString(CultureInfo.InvariantCulture)),
            Prop(DependablyExportProperties.UnscannedCount, unscanned.ToString(CultureInfo.InvariantCulture)),
            Prop(DependablyExportProperties.UnscannableCount, unscannable.ToString(CultureInfo.InvariantCulture)),
            Prop(DependablyExportProperties.TrackerConfigured, BoolValue(trackerConfigured)),
        };
        string? lastScanAtIso = lastScanAt.ToUtcIsoOrNull();
        if (lastScanAtIso is not null)
        {
            arr.Add(Prop(DependablyExportProperties.LastScanAt, lastScanAtIso));
        }

        return arr;
    }

    /// <summary>
    /// Accumulates <see cref="SummarizeCoverage"/> across every project in a collection subtree, so
    /// the aggregate document states one scanned/unscanned/unscannable/last-scan-at answer for the
    /// whole document rather than per-project figures the reader would have to sum themselves.
    /// </summary>
    private sealed class CoverageAccumulator
    {
        private int _scanned;
        private int _unscanned;
        private int _unscannable;
        private DateTimeOffset? _lastScanAt;

        public void Add(IReadOnlyList<ComponentRow> components)
        {
            var (scanned, unscanned, unscannable, lastScanAt) = SummarizeCoverage(components);
            _scanned += scanned;
            _unscanned += unscanned;
            _unscannable += unscannable;
            if (lastScanAt is not null && (_lastScanAt is null || lastScanAt > _lastScanAt))
            {
                _lastScanAt = lastScanAt;
            }
        }

        public JsonArray ToProperties(bool trackerConfigured) =>
            CoverageProperties(_scanned, _unscanned, _unscannable, _lastScanAt, trackerConfigured);
    }

    private static AnalysisRow? FindAnalysis(
        Dictionary<(string PurlKey, string VulnKey), AnalysisRow> byKey,
        string purlKey, string osvId, string? aliasesJson)
    {
        if (byKey.TryGetValue((purlKey, osvId), out var direct))
        {
            return direct;
        }

        // The alias fallback matches the design's documented posture: vulnerabilities.aliases has
        // no index, so a VEX/SARIF statement citing an alias id is resolved in memory, scoped to
        // this version's small analysis set — never a SQL join over the alias column.
        foreach (string alias in ParseStringArray(aliasesJson))
        {
            if (byKey.TryGetValue((purlKey, alias), out var byAlias))
            {
                return byAlias;
            }
        }

        return null;
    }

    /// <summary>
    /// Loads one project version's components (and, for a VDR, its advisories) and appends them to
    /// the document being assembled. Split out of the subtree walk so that walk stays a walk.
    /// </summary>
    /// <summary>One subtree project's export coordinates.</summary>
    private readonly record struct ProjectExport(
        string OrgId, string ProjectVersionId, string ProjectRef, string Variant);

    /// <summary>The three arrays the collection document is assembled into.</summary>
    private readonly record struct CollectionBuffers(
        JsonArray Projects, JsonArray Dependencies, JsonArray Vulnerabilities);

    private static async Task AppendProjectAsync(
        DbConnection conn, ProjectExport export, JsonObject entry, CollectionBuffers buffers,
        CoverageAccumulator coverage, CancellationToken ct)
    {
        var (orgId, projectVersionId, projectRef, variant) = export;

        var components = await LoadComponentsAsync(conn, orgId, projectVersionId, ct);
        var installScriptFacts = await LoadInstallScriptFactsAsync(conn, orgId, projectVersionId, ct);
        coverage.Add(components);
        entry["components"] = BuildComponentsArray(components, projectRef, installScriptFacts);
        buffers.Projects.Add(entry);

        foreach (var node in BuildDependenciesArray(projectRef, components, projectRef))
        {
            buffers.Dependencies.Add(node!.DeepClone());
        }

        if (variant != "vdr")
        {
            return;
        }

        var vulnRows = await LoadComponentVulnsAsync(conn, orgId, projectVersionId, ct);
        // Loaded per project and never shared: a purl-keyed lookup spanning the subtree would
        // bleed one project's VEX suppression onto another project's finding.
        var analysisRows = await LoadAnalysisAsync(conn, orgId, projectVersionId, ct);
        var affectedApps = await CountAffectedApplicationsAsync(
            conn, orgId, vulnRows.Select(v => v.OsvId).Distinct(StringComparer.Ordinal).ToList(), ct);
        foreach (var vuln in BuildVulnerabilitiesArray(vulnRows, analysisRows, installScriptFacts, affectedApps, projectRef))
        {
            buffers.Vulnerabilities.Add(vuln!.DeepClone());
        }
    }

    // Null is not an empty analysis object — it is the signal to omit the CycloneDX "analysis"
    // key entirely. An empty JsonObject would emit `"analysis": {}`, a different document.
    [SuppressMessage("Major Code Smell", "S1168:Empty arrays and collections should be returned instead of null",
        Justification = "null means 'omit this CycloneDX key'; an empty node emits a different document.")]
    private static JsonObject? BuildAnalysis(AnalysisRow? a)
    {
        if (a?.VexState is null)
        {
            return null;
        }

        var obj = new JsonObject { ["state"] = a.VexState };
        if (a.VexJustification is not null)
        {
            obj["justification"] = a.VexJustification;
        }

        if (a.VexResponse is not null)
        {
            obj["response"] = new JsonArray(JsonValue.Create(a.VexResponse));
        }

        if (a.VexDetail is not null)
        {
            obj["detail"] = a.VexDetail;
        }

        return obj;
    }

    // Null is not an empty ratings array — it is the signal to omit the CycloneDX "ratings" key.
    // Both call sites test for null before assigning; `[]` would emit `"ratings": []`, which
    // asserts "rated, with no ratings" rather than "unrated".
    [SuppressMessage("Major Code Smell", "S1168:Empty arrays and collections should be returned instead of null",
        Justification = "null means 'omit this CycloneDX key'; an empty node emits a different document.")]
    private static JsonArray? BuildRatings(string? severity, double? cvssScore)
    {
        if (severity is null && cvssScore is null)
        {
            return null;
        }

        var rating = new JsonObject();
        if (cvssScore is not null)
        {
            rating["score"] = cvssScore.Value;
        }

        if (severity is not null)
        {
            rating["severity"] = severity.ToLowerInvariant();
        }

        return new JsonArray(rating);
    }

    private static JsonObject BuildSource(string vulnId) => vulnId switch
    {
        _ when vulnId.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase) => new JsonObject
        {
            ["name"] = "NVD",
            ["url"] = $"https://nvd.nist.gov/vuln/detail/{vulnId}",
        },
        _ when vulnId.StartsWith("GHSA-", StringComparison.OrdinalIgnoreCase) => new JsonObject
        {
            ["name"] = "GitHub Advisories",
            ["url"] = $"https://github.com/advisories/{vulnId}",
        },
        _ => new JsonObject { ["name"] = "OSV" },
    };

    /// <summary>
    /// A component's bom-ref. <paramref name="prefix"/> is null for a single-project document,
    /// where the bare purl is unique; an aggregate document passes the project's own ref, because
    /// the SAME library in two projects would otherwise collide on a ref CycloneDX requires to be
    /// unique across the document. The <c>purl</c> FIELD is never prefixed — that is the value a
    /// consumer matches on.
    /// </summary>
    private static string RefOf(ComponentRow c, string? prefix = null)
    {
        string bare = c.Purl ?? (c.Version is null ? c.Name : $"{c.Name}@{c.Version}");
        return prefix is null ? bare : $"{prefix}/{bare}";
    }

    private static List<string> ParseStringArray(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<List<string>>(json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    // ── Row projections ──────────────────────────────────────────────────────

    private sealed class ProjectRow
    {
        public string Name { get; set; } = "";
        public string Classifier { get; set; } = "";
    }

    private sealed class VersionRow
    {
        public string Id { get; set; } = "";
        public string Version { get; set; } = "";
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class ComponentRow
    {
        public string Id { get; set; } = "";
        public string? Purl { get; set; }
        public string Name { get; set; } = "";
        public string? Version { get; set; }
        public string? Ecosystem { get; set; }
        public string? PurlName { get; set; }
        public string? ComponentType { get; set; }
        public string? SbomScope { get; set; }
        public string? DependencyKind { get; set; }
        public string? DependencyScope { get; set; }
        public string? DependencyPath { get; set; }
        public string? LicenseSpdx { get; set; }
        public DateTimeOffset? VulnCheckedAt { get; set; }
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class ComponentVulnRow
    {
        public string ComponentId { get; set; } = "";
        public string ComponentPurl { get; set; } = "";
        public string? Ecosystem { get; set; }
        public string? PurlName { get; set; }
        public string? DependencyKind { get; set; }
        public string? DependencyScope { get; set; }
        public string OsvId { get; set; } = "";
        public string? Aliases { get; set; }
        public string? Severity { get; set; }
        public double? CvssScore { get; set; }
        public double? NvdScore { get; set; }
        public string? NvdCheckedAt { get; set; }
        public string? NvdAssertedAt { get; set; }
        public bool IsKev { get; set; }
        public bool? IsKevRansomware { get; set; }
        public string? KevDueDate { get; set; }
        public string? KevDateAdded { get; set; }
        public string? KevRequiredAction { get; set; }
        public string? KevCwes { get; set; }
        public string? KevNotes { get; set; }
        public double? EpssScore { get; set; }
        public double? EpssPercentile { get; set; }
        public string? SsvcExploitation { get; set; }
        public string? SsvcAutomatable { get; set; }
        public string? SsvcTechnicalImpact { get; set; }
        public string? SsvcCheckedAt { get; set; }
        public string? SsvcAssertedAt { get; set; }
        public bool IsMalicious { get; set; }
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class AnalysisRow
    {
        public string PurlKey { get; set; } = "";
        public string VulnKey { get; set; } = "";
        public string? VexState { get; set; }
        public string? VexJustification { get; set; }
        public string? VexResponse { get; set; }
        public string? VexDetail { get; set; }
        public string? Reachability { get; set; }
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class VulnLookupRow
    {
        public string OsvId { get; set; } = "";
        public string? Severity { get; set; }
        public double? CvssScore { get; set; }
        public double? NvdScore { get; set; }
        public string? NvdCheckedAt { get; set; }
        public string? NvdAssertedAt { get; set; }
        public bool IsKev { get; set; }
        public bool? IsKevRansomware { get; set; }
        public string? KevDueDate { get; set; }
        public string? KevDateAdded { get; set; }
        public string? KevRequiredAction { get; set; }
        public string? KevCwes { get; set; }
        public string? KevNotes { get; set; }
        public double? EpssScore { get; set; }
        public double? EpssPercentile { get; set; }
        public string? SsvcExploitation { get; set; }
        public string? SsvcAutomatable { get; set; }
        public string? SsvcTechnicalImpact { get; set; }
        public string? SsvcCheckedAt { get; set; }
        public string? SsvcAssertedAt { get; set; }
        public bool IsMalicious { get; set; }
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class InstallScriptRow
    {
        public string ComponentId { get; set; } = "";
        public bool HasInstallScript { get; set; }
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class AffectedApplicationsRow
    {
        public string OsvId { get; set; } = "";
        public int Count { get; set; }
    }

    private sealed class OriginalRow
    {
        public string BlobKey { get; set; } = "";
        public string Sha256 { get; set; } = "";
        public string Format { get; set; } = "";
        public string DocType { get; set; } = "";
        public string ProjectName { get; set; } = "";
        public string VersionLabel { get; set; } = "";
    }
}

/// <summary>Blob coordinate and derived display name for an uploaded document's original bytes.</summary>
public sealed class ProjectDocumentOriginal
{
    public string BlobKey { get; init; } = "";
    public string Sha256 { get; init; } = "";
    public string Format { get; init; } = "";
    public string DocType { get; init; } = "";
    public string FileName { get; init; } = "";
}
