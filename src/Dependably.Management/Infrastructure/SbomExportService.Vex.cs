using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Nodes;
using Dapper;
using Dependably.Infrastructure.Sbom;

namespace Dependably.Infrastructure;

/// <summary>
/// The VEX half of <see cref="SbomExportService"/>: a vulnerabilities-only CycloneDX document of
/// one project version's current effective analysis state, upload-sourced and manually triaged
/// rows alike.
///
/// <para>Separated from the SBOM/VDR renderers by file only — one partial class, one
/// lifetime.</para>
///
/// <para>A standalone VEX document is keyed by (purl_key, vuln_key), not by
/// <c>sbom_components.id</c>, which is why the component facts each entry carries are recovered
/// through <see cref="SbomPurlKey.ForComponent"/> — the identical rule the ingest writers keyed
/// <c>project_vuln_analysis</c> with, never re-derived locally.</para>
/// </summary>
public sealed partial class SbomExportService
{
    /// <summary>
    /// Renders a vulnerabilities-only CycloneDX VEX document, under the caller's chosen
    /// <paramref name="specVersion"/> (<c>1.6</c> or <c>1.7</c>), of the current effective
    /// analysis state — both upload-sourced and manually triaged rows — or <c>null</c> when the
    /// project or version does not resolve for this org.
    /// </summary>
    [SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "The spliced fragment is DapperInClause.Expand's own parenthesized, "
                        + "individually-parameterized (@osv0, @osv1, …) list built from advisory ids "
                        + "this method already read out of the database, not user text — see "
                        + "DapperInClause's doc comment for why Dapper's own IN @list auto-expansion "
                        + "cannot be used (it binds a Postgres connection's enumerable as one native "
                        + "array parameter, valid only after = ANY(...), never after IN).")]
    public async Task<string?> BuildVexDocumentAsync(
        string orgId, string projectId, string versionId, string specVersion, CancellationToken ct)
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
        string orgSlug = await LoadOrgSlugAsync(conn, orgId, ct);
        var vexTool = await LoadDocumentToolAsync(conn, orgId, resolved.ProjectVersionId, "vex", ct);

        // A standalone VEX document is keyed by (purl_key, vuln_key), not by sbom_components.id, so
        // dependency-graph position and install-script presence — both component facts — are
        // recovered here the same way BuildVulnerabilitiesArray recovers an analysis row for a
        // component: by computing each component's own purl_key with the identical
        // SbomPurlKey.ForComponent rule the ingest writers used to key project_vuln_analysis.
        var componentByPurlKey = IndexComponentsByPurlKey(components);

        var installScriptFacts = await LoadInstallScriptFactsAsync(conn, orgId, resolved.ProjectVersionId, ct);

        var known = await LoadVexAdvisoryLookupAsync(conn, withState, ct);
        var vulns = BuildVexVulnerabilitiesArray(
            withState, known, componentByPurlKey, installScriptFacts,
            await CountAffectedApplicationsAsync(
                conn, orgId, withState.Select(a => a.VulnKey).Distinct(StringComparer.Ordinal).ToList(), ct));

        // Resolved before the content fingerprint (below), for the same reason the SBOM renderer
        // resolves it early — see SbomExportService.Revision.cs' "signature identity" decision
        // and BuildSbomDocumentAsync. A VEX export makes the SAME ["authors"] = org-slug claim a
        // signed SBOM export does, so it owes a reader the same "signed, or not — and here is
        // why" statement; leaving it off would let a consumer who has only ever seen a signed
        // SBOM read a bare VEX export as unsigned-because-refused rather than
        // unsigned-because-this-document-type-was-never-signed-in-the-first-place.
        var (resolvedSigningKey, signatureState, orgHasActiveKey) = await _signer.ResolveAsync(orgId, ct);
        using var signingKey = resolvedSigningKey;

        var vulnFingerprintFacts = VexVulnFingerprintFacts(withState, known, componentByPurlKey, installScriptFacts).ToList();
        string contentFingerprint = ComputeVexContentFingerprint(
            new ProvenanceIdentity(
                OrgSlug: orgSlug,
                OriginalToolName: vexTool?.ToolName,
                OriginalToolVersion: vexTool?.ToolVersion),
            vulnFingerprintFacts,
            orgHasActiveKey);

        // D6a: derived from the data the fingerprint just hashed (the analysis rows this document
        // renders, plus each one's resolved component, when it has one), never from the render
        // clock — see SbomExportService.Revision.cs' DeriveChangedAt.
        string derivedChangedAtIso = DeriveChangedAt(
            resolved.CreatedAt,
            withState.Select(a => (DateTimeOffset?)a.UpdatedAt),
            withState
                .Select(a => componentByPurlKey.GetValueOrDefault(a.PurlKey))
                .Where(c => c is not null)
                .Select(c => (DateTimeOffset?)c!.CreatedAt)).ToUtcIso();

        var revision = await ResolveRevisionAsync(
            conn,
            new RevisionKey(
                OrgId: orgId,
                ProjectVersionId: resolved.ProjectVersionId,
                DocKind: DocKindVex,
                Format: SbomExportOptions.Default.Format,
                ScopeFilter: ScopeFilterValue(SbomComponentFilter.All)),
            contentFingerprint, derivedChangedAtIso, ct);

        var properties = BuildCoverageProperties(
            components, trackerConfigured, SbomComponentFilter.All, filteredOutCount: 0,
            documentCarriesInventory: false);
        AddSignatureStateProperty(properties, signatureState);

        var doc = new JsonObject
        {
            ["bomFormat"] = "CycloneDX",
            ["specVersion"] = specVersion,
            ["serialNumber"] = revision.SerialNumber,
            ["version"] = revision.Revision,
            ["metadata"] = new JsonObject
            {
                ["timestamp"] = revision.ChangedAtIso,
                // D1/D5/D7/D8: the same provenance claims a per-project SBOM export carries — see
                // BuildAuthorsMetadata/BuildToolsMetadata/BuildLifecyclesMetadata.
                ["authors"] = BuildAuthorsMetadata(orgSlug),
                ["tools"] = BuildToolsMetadata(vexTool?.ToolName, vexTool?.ToolVersion),
                ["lifecycles"] = BuildLifecyclesMetadata(),
                // A VEX document carries no component filter of its own — always "all"/"0". It
                // also asserts no components[] array of its own at all, so it can never
                // truthfully claim dependably:full-inventory-rendered regardless of how many
                // components `components` holds for the underlying project version —
                // documentCarriesInventory: false says so explicitly rather than defaulting to
                // the affirmative claim (see BuildCoverageProperties' own doc comment for why
                // this parameter has no default at all).
                ["properties"] = properties,
            },
            ["vulnerabilities"] = vulns,
        };

        // Last: everything above is what gets signed.
        if (signingKey is not null)
        {
            Sbom.SbomAuthorSigner.Attach(doc, signingKey);
        }

        return doc.ToJsonString();
    }

    /// <summary>
    /// The advisory rows for every OSV id <paramref name="withState"/> cites — a separate query
    /// method so the revision fingerprint (<see cref="VexVulnFingerprintFacts"/>) and the rendered
    /// <c>vulnerabilities[]</c> array (<see cref="BuildVexVulnerabilitiesArray"/>) both read the
    /// SAME resolved lookup rather than querying it twice and risking the two disagree. Empty when
    /// no row carries an analysis state — the query is skipped in that case rather than issuing
    /// one whose result nothing reads.
    /// </summary>
    [SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "The spliced fragment is DapperInClause.Expand's own parenthesized, "
                        + "individually-parameterized (@osv0, @osv1, …) list built from advisory ids "
                        + "this method already read out of the database, not user text — see "
                        + "DapperInClause's doc comment for why Dapper's own IN @list auto-expansion "
                        + "cannot be used (it binds a Postgres connection's enumerable as one native "
                        + "array parameter, valid only after = ANY(...), never after IN).")]
    private static async Task<Dictionary<string, VulnLookupRow>> LoadVexAdvisoryLookupAsync(
        DbConnection conn, IReadOnlyList<AnalysisRow> withState, CancellationToken ct)
    {
        if (withState.Count == 0)
        {
            return new Dictionary<string, VulnLookupRow>(StringComparer.Ordinal);
        }

        var osvIds = withState.Select(a => a.VulnKey).Distinct(StringComparer.Ordinal).ToList();
        var (osvIdsClause, osvIdsParameters) = DapperInClause.Expand("osv", osvIds);
        // rawsql: osvIdsClause is a parameterized IN (@osv0, @osv1, …) list built in C#, not user text.
        // xtenant: vulnerabilities is the global OSV advisory cache, not a tenant table —
        // resolved by advisory id only, for best-effort source/rating/enrichment lookup.
        return (await conn.QueryAsync<VulnLookupRow>(new CommandDefinition(
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
    }

    /// <summary>The VEX document's <c>vulnerabilities</c> array, built from already-loaded rows.</summary>
    private static JsonArray BuildVexVulnerabilitiesArray(
        IReadOnlyList<AnalysisRow> withState,
        IReadOnlyDictionary<string, VulnLookupRow> known,
        IReadOnlyDictionary<string, ComponentRow> componentByPurlKey,
        IReadOnlyDictionary<string, bool> installScriptFacts,
        IReadOnlyDictionary<string, int> affectedApps)
    {
        var vulns = new JsonArray();
        foreach (var a in withState)
        {
            vulns.Add(BuildVexEntry(a, known, componentByPurlKey, installScriptFacts, affectedApps));
        }

        return vulns;
    }

    /// <summary>One VEX entry: the advisory's identity, ratings, analysis state and signal properties.</summary>
    private static JsonObject BuildVexEntry(
        AnalysisRow a,
        IReadOnlyDictionary<string, VulnLookupRow> known,
        IReadOnlyDictionary<string, ComponentRow> componentByPurlKey,
        IReadOnlyDictionary<string, bool> installScriptFacts,
        IReadOnlyDictionary<string, int> affectedApps)
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
        return entry;
    }

    /// <summary>
    /// Components keyed by their own <see cref="SbomPurlKey.ForComponent"/> value — the identical
    /// rule the ingest writers used to key <c>project_vuln_analysis</c>, which is what lets a
    /// standalone VEX document (keyed by purl_key, not by sbom_components.id) recover each
    /// advisory's component facts. A component with no derivable key is not indexable and is
    /// skipped.
    /// </summary>
    private static Dictionary<string, ComponentRow> IndexComponentsByPurlKey(
        IReadOnlyList<ComponentRow> components)
    {
        var byKey = new Dictionary<string, ComponentRow>(StringComparer.Ordinal);
        foreach (var c in components)
        {
            string? key = SbomPurlKey.ForComponent(c.Ecosystem, c.PurlName, c.Purl);
            if (key is not null)
            {
                byKey[key] = c;
            }
        }

        return byKey;
    }

    /// <summary>
    /// How many of this tenant's applications ship each of <paramref name="osvIds"/> on a version
    /// they still run — the same query shape as
    /// <c>SbomBlastRadiusRepository.CountProjectsByAdvisoryAsync</c>, written directly here per the
    /// fleet contract. <b>Scoped to <see cref="ProjectLifecycle.InServiceFilter"/></b>, matching
    /// that repository verbatim and for the same reason. The two agreeing is not cosmetic: this
    /// number is exported inside a VEX document an operator hands to a customer, so a wider or
    /// narrower count here than the UI shows is a published contradiction of the tenant's own
    /// dashboard.
    /// </summary>
    [SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "The spliced fragment is DapperInClause.Expand's own parenthesized, "
                        + "individually-parameterized (@osv0, @osv1, …) list built from advisory ids "
                        + "this method already read out of the database, not user text — see "
                        + "DapperInClause's doc comment for why Dapper's own IN @list auto-expansion "
                        + "cannot be used (it binds a Postgres connection's enumerable as one native "
                        + "array parameter, valid only after = ANY(...), never after IN).")]
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
            JOIN projects p ON p.id = pv.project_id AND p.org_id = pv.org_id
            WHERE c.org_id = @orgId
              AND p.is_active = 1 AND (pv.is_latest = 1 OR pv.is_active = 1)
              AND v.osv_id IN
            """ + " " + keysClause + " GROUP BY v.osv_id",
            parameters, cancellationToken: ct));
        return rows.ToDictionary(r => r.OsvId, r => r.Count, StringComparer.Ordinal);
    }

    // ── Document/graph rendering ─────────────────────────────────────────────
}
