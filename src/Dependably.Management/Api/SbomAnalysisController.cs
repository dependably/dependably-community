using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// The read surface for one project version's SBOM analysis, plus the manual VEX triage write.
///
/// <list type="bullet">
///   <item><c>GET  /api/v1/projects/{projectId}/versions/{versionId}/analysis</c> — the component
///   table: server-side filtered, sorted and paged, with the effective-priority bucket derived per
///   advisory and a version-wide rollup header.</item>
///   <item><c>PUT  /api/v1/projects/{projectId}/versions/{versionId}/analysis</c> — one manual
///   triage decision, written as <c>vex_source='manual'</c>, returning the refreshed row.</item>
///   <item><c>GET  /api/v1/projects/{projectId}/versions/{versionId}/documents</c> — the receipts
///   list of documents uploaded against the version.</item>
/// </list>
///
/// <para><b>The server owns the security judgement.</b> Priority bucketing, the prod/dev predicate,
/// the suppression rule and the violations filter are all decided here and shipped as values. A UI
/// that re-derived any of them would drift from the rollup counts the moment either side changed,
/// and two disagreeing risk pictures on one page is worse than one.</para>
///
/// <para><c>{versionId}</c> also accepts the literal <c>latest</c>, resolved through
/// <c>is_latest</c> so a bookmark keeps pointing at the current release.</para>
///
/// <para>Cross-org reads answer 404, not 403: every lookup is org-filtered, so a project id
/// belonging to another tenant simply resolves to nothing and cannot be probed for existence.</para>
/// </summary>
[ApiController]
[Authorize]
public sealed class SbomAnalysisController : OrgScopedControllerBase
{
    private readonly SbomAnalysisRepository _analysis;
    private readonly OrgAccessGuard _guard;
    private readonly ProblemResults _problems;
    private readonly AuditRepository _audit;
    private readonly ISbomPolicyReevaluator _reevaluator;

    public SbomAnalysisController(
        SbomAnalysisRepository analysis,
        OrgAccessGuard guard,
        ProblemResults problems,
        AuditRepository audit,
        ISbomPolicyReevaluator reevaluator)
    {
        _analysis = analysis;
        _guard = guard;
        _problems = problems;
        _audit = audit;
        _reevaluator = reevaluator;
    }

    /// <summary>
    /// GET /api/v1/projects/{projectId}/versions/{versionId}/analysis — the paged component table
    /// plus the version-wide rollup and the orphan analysis rows.
    /// </summary>
    // Read-only: accepts a PAT/service token carrying read:packages.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/projects/{projectId}/versions/{versionId}/analysis")]
    public async Task<IActionResult> Analysis(
        string projectId, string versionId,
        [FromQuery] ProjectAnalysisFilterRequest filter,
        CancellationToken ct = default)
    {
        var denied = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (denied is not null)
        {
            return denied;
        }

        var invalid = ValidateProjectAnalysisFilterRequest(filter);
        if (invalid is not null)
        {
            return invalid;
        }

        string orgId = CurrentTenantId();
        var version = await _analysis.ResolveVersionAsync(orgId, projectId, versionId, ct);
        if (version is null)
        {
            return _problems.NotFoundActionKey("error.sbom.versionNotFound");
        }

        var components = await _analysis.ListComponentsAsync(orgId, version.VersionId, ct);
        var advisories = await _analysis.ListAdvisoriesAsync(orgId, version.VersionId, ct);
        var statements = await _analysis.ListAnalysisAsync(orgId, version.VersionId, ct);
        var findings = await _analysis.ListPolicyFindingsAsync(orgId, version.VersionId, ct);
        // Version-wide, not page-scoped: the blind-spot rollup counts every component, and the
        // registry filter has to narrow the set before a page is cut from it.
        var registryFacts = await _analysis.ListRegistryFactsAsync(orgId, version.VersionId, ct);

        var query = ToQuery(filter);
        var page = SbomAnalysisProjection.Build(
            new AnalysisRows(components, advisories, statements, findings),
            registryFacts, version.PolicyStatus, query, version.CreatedAt);

        var actorLabels = await ResolveActorLabelsAsync(orgId, page, ct);

        return Ok(new
        {
            rollup = RollupPayload(page.Rollup),
            items = page.Items.Select(item => ItemPayload(item, actorLabels)),
            orphanAnalysis = page.Orphans.Select(orphan => OrphanPayload(orphan, actorLabels)),
            page = query.Page,
            limit = query.Limit,
            total = page.Total,
        });
    }

    /// <summary>
    /// PUT /api/v1/projects/{projectId}/versions/{versionId}/analysis — record one manual VEX
    /// decision and return the refreshed analysis row.
    /// </summary>
    // Writes tenant policy state: tenant:configure, and a JWT session or a token carrying it.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpPut("api/v1/projects/{projectId}/versions/{versionId}/analysis")]
    public async Task<IActionResult> Triage(
        string projectId, string versionId,
        [FromBody] UpdateProjectVulnAnalysisRequest req,
        CancellationToken ct = default)
    {
        var denied = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (denied is not null)
        {
            return denied;
        }

        string orgId = CurrentTenantId();
        var version = await _analysis.ResolveVersionAsync(orgId, projectId, versionId, ct);
        if (version is null)
        {
            return _problems.NotFoundActionKey("error.sbom.versionNotFound");
        }

        // Canonicalized before it addresses anything, so the row this read resolves and the row
        // the write lands on are the same row every other reader of the column derives.
        string? purlKey = req.PurlKey is { Length: > 0 } supplied ? CanonicalPurlKey(supplied) : null;
        var existing = purlKey is not null && req.VulnKey is { Length: > 0 } vulnKey
            ? await _analysis.GetAnalysisRowAsync(orgId, version.VersionId, purlKey, vulnKey, ct)
            : null;

        var invalid = ValidateUpdateProjectVulnAnalysisRequest(req, existing);
        if (invalid is not null)
        {
            return invalid;
        }

        string? actorId = GetUserId();
        var refreshed = await _analysis.UpsertManualTriageAsync(
            new ManualTriageWrite(
                orgId, version.VersionId, purlKey!, req.VulnKey!,
                req.VexState, req.VexJustification, req.VexResponse, req.VexDetail, actorId),
            ct);

        // A triage decision changes what the policy arms see. The evaluator owns the recomputation;
        // this is only the trigger, and its default binding is a no-op so a decision is never lost
        // to an absent evaluator.
        await _reevaluator.ReevaluateAsync(orgId, version.VersionId, ct);

        await _audit.LogAsync(
            "sbom.analysis.triage",
            orgId: orgId,
            actorId: actorId,
            actorKind: CurrentActorKind(),
            detail: JsonSerializer.Serialize(new
            {
                project_id = version.ProjectId,
                project_version_id = version.VersionId,
                purl_key = purlKey,
                vuln_key = req.VulnKey,
                vex_state = req.VexState.IsPresent ? req.VexState.Value : null,
                vex_justification = req.VexJustification.IsPresent ? req.VexJustification.Value : null,
                vex_response = req.VexResponse.IsPresent ? req.VexResponse.Value : null,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(),
            ct: ct);

        if (refreshed is null)
        {
            return _problems.NotFoundActionKey("error.sbom.analysisRowNotFound");
        }

        var labels = await _analysis.ListActorLabelsAsync(
            orgId, refreshed.UpdatedBy is null ? [] : new[] { refreshed.UpdatedBy }, ct);
        return Ok(TriageRowPayload(refreshed, labels));
    }

    /// <summary>
    /// GET /api/v1/projects/{projectId}/versions/{versionId}/documents — the uploaded originals for
    /// this version, one per document type.
    /// </summary>
    // Read-only: accepts a PAT/service token carrying read:packages.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/projects/{projectId}/versions/{versionId}/documents")]
    public async Task<IActionResult> Documents(string projectId, string versionId, CancellationToken ct = default)
    {
        var denied = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (denied is not null)
        {
            return denied;
        }

        string orgId = CurrentTenantId();
        var version = await _analysis.ResolveVersionAsync(orgId, projectId, versionId, ct);
        if (version is null)
        {
            return _problems.NotFoundActionKey("error.sbom.versionNotFound");
        }

        var documents = await _analysis.ListDocumentsAsync(orgId, version.VersionId, ct);
        return Ok(new
        {
            items = documents.Select(d => new
            {
                id = d.Id,
                docType = d.DocType,
                format = d.Format,
                specVersion = d.SpecVersion,
                toolName = d.ToolName,
                toolVersion = d.ToolVersion,
                sha256 = d.Sha256,
                sizeBytes = d.SizeBytes,
                uploadedAt = d.UploadedAt,
                uploadedBy = d.UploadedBy,
                // Derived, never stored: the upload carries no filename, and a stored one would
                // outlive the project rename that invalidated it. The download surface derives the
                // Content-Disposition name through this same helper so the two never disagree.
                fileName = ProjectDocumentNaming.FileName(version.ProjectName, version.VersionLabel, d.DocType),
            }),
        });
    }

    // ── Validation ───────────────────────────────────────────────────────────

    /// <summary>
    /// Clamps the paging numbers and rejects an unrecognised <em>filter</em> value. Rejecting
    /// rather than defaulting is the point for a filter: a mistyped <c>sev=hgih</c> that silently
    /// returned every row would read as "nothing matched that severity" and understate the
    /// version's risk.
    ///
    /// <para><c>sort</c> and <c>dir</c> are deliberately the other way round, matching
    /// <see cref="ProjectsController"/>: an unrecognised value falls back to the default rather
    /// than 422ing. A sort cannot understate risk — it orders the same rows — and these arrive
    /// from bookmarks and shared links as often as from the UI, so a renamed column would
    /// otherwise turn a saved URL into a permanent error page rather than a differently ordered
    /// table. The projection's allowlist is what makes the fallback safe.</para>
    /// </summary>
    [NonAction]
    private IActionResult? ValidateProjectAnalysisFilterRequest(ProjectAnalysisFilterRequest filter)
    {
        filter.Page = Math.Max(1, filter.Page);
        filter.Limit = Math.Clamp(filter.Limit, 1, SbomAnalysisProjection.MaxPageSize);
        filter.Q = NullIfBlank(filter.Q);
        filter.Sort = NullIfBlank(filter.Sort);
        filter.Dir = NullIfBlank(filter.Dir);
        filter.Scope = NullIfBlank(filter.Scope);
        filter.Sev = NullIfBlank(filter.Sev);
        filter.Reach = NullIfBlank(filter.Reach);
        filter.Registry = NullIfBlank(filter.Registry);

        if (filter.Sort is not null && !SbomAnalysisProjection.SortKeys.Contains(filter.Sort))
        {
            filter.Sort = SbomAnalysisProjection.DefaultSort;
        }

        if (filter.Dir is not null && !SortDirections.Contains(filter.Dir))
        {
            filter.Dir = null;
        }

        (string Field, string? Value, IReadOnlySet<string> Allowed, string Key)[] enumerated =
        [
            ("scope", filter.Scope, SbomAnalysisProjection.ScopeFilters, "error.sbom.scopeInvalid"),
            ("sev", filter.Sev, SbomAnalysisProjection.SeverityBuckets, "error.sbom.severityInvalid"),
            ("reach", filter.Reach, SbomAnalysisProjection.ReachabilityFilters, "error.sbom.reachInvalid"),
            ("registry", filter.Registry, RegistryPresence.Filters, "error.sbom.registryInvalid"),
        ];

        foreach (var (field, value, allowed, key) in enumerated)
        {
            if (value is not null && !allowed.Contains(value))
            {
                return _problems.ValidationErrorActionKey(field, key);
            }
        }

        return null;
    }

    /// <summary>The two sort directions, as a set so the filter check is one uniform loop.</summary>
    private static readonly IReadOnlySet<string> SortDirections =
        new HashSet<string>(StringComparer.Ordinal) { "asc", "desc" };

    /// <summary>
    /// Checks the triage body against the CycloneDX vocabulary. The justification rule is enforced
    /// against the state the row will actually hold after the patch, not against the field the
    /// caller happened to send, so a partial write cannot leave a justification attached to a state
    /// CycloneDX does not define one for.
    /// </summary>
    [NonAction]
    private IActionResult? ValidateUpdateProjectVulnAnalysisRequest(
        UpdateProjectVulnAnalysisRequest req, AnalysisVexRow? existing)
    {
        if (string.IsNullOrWhiteSpace(req.PurlKey))
        {
            return _problems.ValidationErrorActionKey("purlKey", "error.sbom.purlKeyRequired");
        }

        if (string.IsNullOrWhiteSpace(req.VulnKey))
        {
            return _problems.ValidationErrorActionKey("vulnKey", "error.sbom.vulnKeyRequired");
        }

        if (!req.VexState.IsPresent && !req.VexJustification.IsPresent
            && !req.VexResponse.IsPresent && !req.VexDetail.IsPresent)
        {
            return _problems.ValidationErrorActionKey("vexState", "error.sbom.triageEmpty");
        }

        // A present-but-empty string is a fourth Optional<T> state distinct from absent (leave
        // unchanged) and explicit null (clear the field): it is neither, so it is rejected here
        // rather than silently collapsing into either — an empty string never satisfies a closed
        // vocabulary, matched by the non-null pattern below (it does not require a positive
        // length), so it 422s the same way an unrecognised value like "hgih" already does instead
        // of reaching the schema CHECK and surfacing as an unlocalized 500.
        if (req.VexState.IsPresent && req.VexState.Value is { } state
            && !VexVocabulary.States.Contains(state))
        {
            return _problems.ValidationErrorActionKey("vexState", "error.sbom.vexStateInvalid");
        }

        if (req.VexResponse.IsPresent && req.VexResponse.Value is { } response
            && !VexVocabulary.Responses.Contains(response))
        {
            return _problems.ValidationErrorActionKey("vexResponse", "error.sbom.vexResponseInvalid");
        }

        if (req.VexDetail.IsPresent && req.VexDetail.Value is { Length: > VexVocabulary.MaxDetailLength })
        {
            return _problems.ValidationErrorActionKey("vexDetail", "error.sbom.vexDetailTooLong");
        }

        if (!req.VexJustification.IsPresent || req.VexJustification.Value is not { } justification)
        {
            return null;
        }

        if (!VexVocabulary.Justifications.Contains(justification))
        {
            return _problems.ValidationErrorActionKey("vexJustification", "error.sbom.vexJustificationInvalid");
        }

        string? effectiveState = req.VexState.IsPresent ? req.VexState.Value : existing?.VexState;
        return string.Equals(effectiveState, VexVocabulary.NotAffected, StringComparison.Ordinal)
            ? null
            : _problems.ValidationErrorActionKey("vexJustification", "error.sbom.justificationRequiresNotAffected");
    }

    // ── Payload shaping ──────────────────────────────────────────────────────

    private static AnalysisQuery ToQuery(ProjectAnalysisFilterRequest filter) => new(
        Page: filter.Page,
        Limit: filter.Limit,
        Sort: filter.Sort ?? "priority",
        Dir: filter.Dir ?? "desc",
        Q: filter.Q,
        Scope: string.Equals(filter.Scope, "all", StringComparison.Ordinal) ? null : filter.Scope,
        Sev: filter.Sev,
        Reach: filter.Reach,
        Registry: string.Equals(filter.Registry, "all", StringComparison.Ordinal) ? null : filter.Registry,
        ViolationsOnly: filter.Violations,
        IncludeSuppressed: filter.Suppressed);

    private static object RollupPayload(AnalysisRollup rollup) => new
    {
        componentTotal = rollup.ComponentTotal,
        prodCount = rollup.ProdCount,
        devCount = rollup.DevCount,
        unknownScopeCount = rollup.UnknownScopeCount,
        unscannableCount = rollup.UnscannableCount,
        scopeSuppressedCount = rollup.ScopeSuppressedCount,
        registryCounts = new
        {
            inRegistry = rollup.RegistryCounts.InRegistry,
            notInRegistry = rollup.RegistryCounts.NotInRegistry,
            unknown = rollup.RegistryCounts.Unknown,
        },
        severityCounts = new
        {
            critical = rollup.SeverityCounts["critical"],
            high = rollup.SeverityCounts["high"],
            medium = rollup.SeverityCounts["medium"],
            low = rollup.SeverityCounts["low"],
            unscored = rollup.SeverityCounts[SbomAnalysisProjection.UnscoredBucket],
        },
        priorityCounts = new
        {
            act = rollup.PriorityCounts[Infrastructure.EffectivePriority.Act],
            attend = rollup.PriorityCounts[Infrastructure.EffectivePriority.Attend],
            track = rollup.PriorityCounts[Infrastructure.EffectivePriority.Track],
            suppressed = rollup.PriorityCounts[Infrastructure.EffectivePriority.Suppressed],
        },
        licenseCounts = new
        {
            total = rollup.LicenseCounts.Total,
            declared = rollup.LicenseCounts.Declared,
            undeclared = rollup.LicenseCounts.Undeclared,
            byIdentifier = rollup.LicenseCounts.ByIdentifier,
        },
        policyStatus = rollup.PolicyStatus,
        violationCount = rollup.ViolationCount,
        lastScanAt = rollup.LastScanAt,
    };

    private static object ItemPayload(
        AnalysisComponentView item,
        IReadOnlyDictionary<string, string> actorLabels)
    {
        bool present = item.Registry.InRegistry;
        return new
        {
            componentId = item.ComponentId,
            purl = item.Purl,
            purlKey = item.PurlKey,
            name = item.Name,
            version = item.Version,
            ecosystem = item.Ecosystem,
            componentType = item.ComponentType,
            sbomScope = item.SbomScope,
            dependencyScope = item.DependencyScope,
            isProd = item.IsProd,
            dependencyKind = item.DependencyKind,
            dependencyPath = item.DependencyPath,
            licenseSpdx = item.LicenseSpdx,
            // The component's own presentation metadata. Every field is display-only, but the
            // panel that renders them is gated on the payload carrying at least one, so omitting
            // them here does not degrade the panel — it removes it, silently and completely.
            description = item.Description,
            author = item.Author,
            copyright = item.Copyright,
            group = item.Group,
            websiteUrl = item.WebsiteUrl,
            vcsUrl = item.VcsUrl,
            issueTrackerUrl = item.IssueTrackerUrl,
            distributionUrl = item.DistributionUrl,
            hashes = item.Hashes,
            versionRange = item.VersionRange,
            isExternal = item.IsExternal,
            metadataSource = item.MetadataSource,
            inRegistry = present,
            registryLink = present ? RegistryLink(item.Ecosystem!, item.PurlName!) : null,
            registry = RegistryPayload(item.Registry),
            policyViolations = item.PolicyViolations.Select(ViolationPayload),
            advisories = item.Advisories.Select(a => AdvisoryPayload(a, actorLabels)),
        };
    }

    private static object AdvisoryPayload(
        AnalysisAdvisoryView advisory, IReadOnlyDictionary<string, string> actorLabels) => new
        {
            vulnKey = advisory.VulnKey,
            osvId = advisory.OsvId,
            aliases = advisory.Aliases,
            severity = advisory.Severity,
            cvss = advisory.Cvss,
            isKev = advisory.IsKev,
            epss = advisory.Epss,
            effectivePriority = advisory.EffectivePriority,
            unscored = advisory.Unscored,
            severityBucket = advisory.SeverityBucket,
            vexState = advisory.VexState,
            vexJustification = advisory.VexJustification,
            vexResponse = advisory.VexResponse,
            vexDetail = advisory.VexDetail,
            vexSource = advisory.VexSource,
            vexUpdatedBy = Label(advisory.VexUpdatedBy, actorLabels),
            vexUpdatedAt = advisory.VexUpdatedAt,
            reachability = advisory.Reachability,
            confidence = advisory.Confidence,
            sarifSuppressed = advisory.SarifSuppressed,
            securitySeverity = advisory.SecuritySeverity,
            severityOrigin = advisory.SeverityOrigin,
            inherited = advisory.Inherited,
            policyViolations = advisory.PolicyViolations.Select(ViolationPayload),
        };

    private static object OrphanPayload(
        AnalysisOrphanView orphan, IReadOnlyDictionary<string, string> actorLabels) => new
        {
            purlKey = orphan.PurlKey,
            vulnKey = orphan.VulnKey,
            vexState = orphan.VexState,
            vexJustification = orphan.VexJustification,
            vexResponse = orphan.VexResponse,
            vexDetail = orphan.VexDetail,
            vexSource = orphan.VexSource,
            vexUpdatedBy = Label(orphan.VexUpdatedBy, actorLabels),
            vexUpdatedAt = orphan.VexUpdatedAt,
            reachability = orphan.Reachability,
            confidence = orphan.Confidence,
            sarifSuppressed = orphan.SarifSuppressed,
            securitySeverity = orphan.SecuritySeverity,
            severityOrigin = orphan.SeverityOrigin,
            inherited = orphan.Inherited,
        };

    private static object TriageRowPayload(
        AnalysisVexRow row, IReadOnlyDictionary<string, string> actorLabels) => new
        {
            purlKey = row.PurlKey,
            vulnKey = row.VulnKey,
            vexState = row.VexState,
            vexJustification = row.VexJustification,
            vexResponse = row.VexResponse,
            vexDetail = row.VexDetail,
            vexSource = row.VexSource,
            vexUpdatedBy = Label(row.UpdatedBy, actorLabels),
            vexUpdatedAt = row.UpdatedAt,
            reachability = row.Reachability,
            confidence = row.Confidence,
            sarifSuppressed = row.SarifSuppressed,
            securitySeverity = row.SecuritySeverity,
            severityOrigin = row.SeverityOrigin,
        };

    /// <summary>
    /// The registry cross-link facts as the component row renders them. <c>presence</c> carries the
    /// third state explicitly (<c>unknown</c> — no coordinate to ask about) rather than collapsing
    /// it into <c>absent</c>, and <c>outdated</c> is deliberately nullable: null means this
    /// ecosystem has no native version ordering here, and the UI shows the known upstream version
    /// as a fact instead of claiming the application is current.
    /// </summary>
    private static object RegistryPayload(ComponentRegistryView registry) => new
    {
        presence = registry.Presence,
        hosted = registry.Hosted,
        cached = registry.Cached,
        blocked = registry.Blocked,
        deprecated = registry.Deprecated,
        latestVersion = registry.LatestVersion,
        outdated = registry.Outdated,
    };

    private static object ViolationPayload(AnalysisPolicyViolationView violation) => new
    {
        arm = violation.Arm,
        detail = violation.Detail,
        vulnKey = violation.VulnKey,
        licenseSpdx = violation.LicenseSpdx,
    };

    /// <summary>
    /// Relative SPA path to the registry's own page for this coordinate. Each name segment is
    /// escaped on its own so a scoped npm name keeps the separator the route matcher splits on.
    /// </summary>
    private static string RegistryLink(string ecosystem, string purlName)
    {
        string name = string.Join('/', purlName.Split('/').Select(Uri.EscapeDataString));
        return $"/package/{Uri.EscapeDataString(ecosystem)}/{name}";
    }

    private static string? Label(string? actorId, IReadOnlyDictionary<string, string> labels) =>
        actorId is null ? null : labels.TryGetValue(actorId, out string? label) ? label : actorId;

    private async Task<IReadOnlyDictionary<string, string>> ResolveActorLabelsAsync(
        string orgId, AnalysisPage page, CancellationToken ct)
    {
        var ids = page.Items
            .SelectMany(i => i.Advisories)
            .Select(a => a.VexUpdatedBy)
            .Concat(page.Orphans.Select(o => o.VexUpdatedBy))
            .Where(id => id is { Length: > 0 })
            .Select(id => id!)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        return await _analysis.ListActorLabelsAsync(orgId, ids, ct);
    }

    /// <summary>
    /// Which kind of actor is writing. A CI/CD token carries no users row, so it is a service actor
    /// and the audit row must say so rather than filing the write under a user id that resolves to
    /// nothing.
    /// </summary>
    private string CurrentActorKind() =>
        User.Identities.Any(i => i.AuthenticationType == TokenAuthenticationDefaults.Scheme)
        && string.Equals(CurrentRole(), "ci", StringComparison.Ordinal)
            ? ActorKinds.Service
            : ActorKinds.User;

    /// <summary>
    /// The stored spelling of an incoming <c>purl_key</c>. Every writer and every reader of the
    /// column derives it through <see cref="SbomPurlKey"/> — <c>%40</c> decoded, then folded for
    /// its ecosystem — so a caller spelling a purl its own way (a mixed-case NuGet id, an
    /// underscored PyPI name, a scoped npm name) is folded here before it addresses a row.
    /// Storing it verbatim writes a row the policy evaluator's canonical derivation never finds:
    /// the endpoint answers 200, the editor shows the decision saved, and the suppression never
    /// applies, so the finding survives and its alert re-fires.
    ///
    /// <para>A key that is not purl-shaped is kept exactly as written. An analysis row that
    /// matched no component legitimately carries a SARIF rule id in this column, and folding
    /// that would break the only key it has.</para>
    /// </summary>
    private static string CanonicalPurlKey(string purlKey) =>
        SbomPurlKey.TryParse(purlKey)?.Key ?? purlKey;

    private static string? NullIfBlank(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
