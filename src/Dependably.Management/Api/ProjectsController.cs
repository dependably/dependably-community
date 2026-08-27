using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// The projects plane's management surface: the application/collection tree teams upload SBOM, VEX
/// and SARIF documents about.
///
/// Reads gate on <see cref="Capabilities.ReadPackages"/> — the same capability that serves the rest
/// of the inventory surfaces — and mutations on <see cref="Capabilities.TenantConfigure"/>, because
/// creating and deleting a project changes what the tenant tracks rather than what it serves.
/// Everything is org-scoped through <see cref="OrgAccessGuard.AuthorizeCapAsync"/> and the
/// repository's own <c>org_id</c> filters, and a row belonging to another tenant is reported as
/// absent (404) rather than refused (403) so ids stay unenumerable.
///
/// A <c>{versionId}</c> path segment also accepts the literal <c>latest</c>, resolved server-side
/// through the <c>is_latest</c> flag. "Latest" is never a version label compared as a number.
///
/// Deleting a project or a version cascades in the database. The blob keys of the documents that
/// cascade away are enumerated BEFORE the rows go, because the metadata row is the blob's only
/// reference; the bytes are removed after the delete commits, so a failed delete never strands a
/// row pointing at bytes that are already gone.
/// </summary>
[ApiController]
[Authorize]
public sealed class ProjectsController : OrgScopedControllerBase
{
    /// <summary>Ceiling on the list page size, matching the other inventory list surfaces.</summary>
    private const int MaxPageSize = 200;

    /// <summary>Ceiling on a project name, and on the free-text search over names.</summary>
    private const int MaxNameLength = 200;

    /// <summary>Ceiling on a project description.</summary>
    private const int MaxDescriptionLength = 2000;

    /// <summary>
    /// Ceiling on the unpaged collections listing. Collections are a filing structure a person
    /// maintains by hand, so this is a runaway guard rather than a paging boundary — a truncated
    /// page would silently hide relocation targets, which is why it sits far above any real tree.
    /// </summary>
    private const int MaxCollections = 1000;

    private readonly ProjectRepository _projects;
    private readonly OrgAccessGuard _guard;
    private readonly AuditRepository _audit;
    private readonly SbomIngestRepository _ingest;
    private readonly ProblemResults _problems;
    private readonly ITenantStorageResolver _storage;
    private readonly ILogger<ProjectsController> _logger;

    public ProjectsController(
        ProjectRepository projects,
        OrgAccessGuard guard,
        AuditRepository audit,
        SbomIngestRepository ingest,
        ProblemResults problems,
        ITenantStorageResolver storage,
        ILogger<ProjectsController> logger)
    {
        _projects = projects;
        _guard = guard;
        _audit = audit;
        _ingest = ingest;
        _problems = problems;
        _storage = storage;
        _logger = logger;
    }

    /// <summary>
    /// GET /api/v1/projects?limit=50&amp;offset=0&amp;q=api
    /// One page of the org's projects and collections, each carrying the rollup of its latest
    /// version. <c>q</c> is a case-insensitive substring match on the name. <c>sort</c> accepts
    /// <c>name</c>, <c>latest</c> or <c>policy</c> with <c>dir=asc|desc</c>; anything else falls
    /// back to the default rather than erroring, so a stale bookmark still renders. Sorting is
    /// server-side because the result is paged — a client-side sort would order one page against
    /// itself while the pager counts the whole set. Unfiltered, the page
    /// (and <c>total</c>) holds root-level projects only, matching the grouped/indented tree the
    /// UI renders; a search matches at any depth and returns the flat set of matches, which the
    /// caller groups under their parent.
    /// </summary>
    // Read-only: accepts a PAT/service token carrying read:packages.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/projects")]
    public async Task<IActionResult> List(
        [FromQuery] int limit = 50,
        [FromQuery] int offset = 0,
        [FromQuery] string? q = null,
        [FromQuery] string? sort = null,
        [FromQuery] string? dir = null,
        CancellationToken ct = default)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        limit = Math.Clamp(limit, 1, MaxPageSize);
        offset = Math.Max(offset, 0);

        string? search = string.IsNullOrWhiteSpace(q) ? null : q.Trim();
        if (search is { Length: > MaxNameLength })
        {
            search = search[..MaxNameLength];
        }

        // Visible validation decision on sort/dir: an unrecognised value falls back to the default
        // rather than 422ing, because these arrive from bookmarks and shared links as often as from
        // the UI, and a renamed column should not turn a saved URL into an error page. The
        // repository's allowlist is what makes the fallback safe.
        string sortKey = sort is not null && ProjectRepository.ListSortKeys.Contains(sort)
            ? sort
            : ProjectRepository.DefaultListSort;
        string sortDir = string.Equals(dir, "desc", StringComparison.OrdinalIgnoreCase) ? "desc" : "asc";

        var (items, total) = await _projects.ListAsync(
            CurrentTenantId(), search, limit, offset, sortKey, sortDir, ct);

        return Ok(new
        {
            total,
            limit,
            offset,
            // Echoed so a caller can see which sort actually applied when its own was not accepted.
            sort = sortKey,
            dir = sortDir,
            items = items.Select(r => new
            {
                id = r.Id,
                name = r.Name,
                kind = r.Kind,
                classifier = r.Classifier,
                parentId = r.ParentId,
                parentName = r.ParentName,
                latestVersion = r.LatestVersion,
                componentCount = r.ComponentCount,
                severityCounts = SeverityPayload(r.SeverityCounts),
                policyStatus = r.PolicyStatus,
                lastUploadAt = r.LastUploadAt,
                // Collections only — null on a project row, which summarizes only itself.
                subtreeProjectCount = r.SubtreeProjectCount,
                subtreeUnevaluatedProjectCount = r.SubtreeUnevaluatedProjectCount,
            }),
        });
    }

    /// <summary>
    /// GET /api/v1/projects/collections
    /// Every collection the org holds, flat and unpaged, each carrying its own <c>parentId</c>.
    /// This backs the relocation picker, which offers the root plus every collection as a target
    /// and renders each as a full path — a use that needs the whole set, not one page of roots.
    ///
    /// The literal segment takes precedence over the <c>{projectId}</c> route below (ASP.NET
    /// matches literals ahead of parameters), and a project id is a GUID, so no real project is
    /// ever shadowed by this path.
    /// </summary>
    // Read-only: accepts a PAT/service token carrying read:packages.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/projects/collections")]
    public async Task<IActionResult> ListCollections(CancellationToken ct = default)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        var rows = await _projects.ListCollectionsAsync(CurrentTenantId(), MaxCollections, ct);

        return Ok(new
        {
            total = rows.Count,
            limit = MaxCollections,
            items = rows.Select(r => new { id = r.Id, name = r.Name, parentId = r.ParentId }),
        });
    }

    /// <summary>
    /// GET /api/v1/projects/{projectId}
    /// One project with its versions and, for a collection, its direct children. <c>ancestors</c>
    /// is the root-first chain of containing collections (empty at the root), which is what the
    /// breadcrumb climbs — the caller never has to walk <c>parentId</c> a request at a time.
    ///
    /// <c>rollup</c> is present only for a collection, and sums its whole subtree rather than its
    /// direct children: a folder of folders would otherwise report zeros while the projects two
    /// levels down carry every component and finding. It is null for a plain project, whose own
    /// versions are already in the payload. Each child row carries the same rollup its own list
    /// row would, so the numbers read identically at every level.
    /// </summary>
    // Read-only: accepts a PAT/service token carrying read:packages.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/projects/{projectId}")]
    public async Task<IActionResult> Get(string projectId, CancellationToken ct = default)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string orgId = CurrentTenantId();
        var project = await _projects.GetAsync(orgId, projectId, ct);
        if (project is null)
        {
            return NotFound();
        }

        var versions = await _projects.ListVersionsAsync(orgId, projectId, ct);
        var children = await _projects.ListChildrenAsync(orgId, projectId, ct);
        var ancestors = await _projects.ListAncestorsAsync(orgId, projectId, ct);
        // Null for a plain project — it summarizes its own versions, which are already here.
        var rollup = await _projects.GetSubtreeRollupAsync(orgId, projectId, ct);

        return Ok(new
        {
            id = project.Id,
            name = project.Name,
            kind = project.Kind,
            classifier = project.Classifier,
            description = project.Description,
            parentId = project.ParentId,
            ancestors = ancestors.Select(a => new { id = a.Id, name = a.Name }),
            createdAt = project.CreatedAt,
            rollup = rollup is null ? null : new
            {
                projectCount = rollup.ProjectCount,
                unevaluatedProjectCount = rollup.UnevaluatedProjectCount,
                componentCount = rollup.ComponentCount,
                severityCounts = SeverityPayload(rollup.SeverityCounts),
                policyStatus = rollup.PolicyStatus,
                lastUploadAt = rollup.LastUploadAt,
            },
            versions = versions.Select(VersionPayload),
            children = children.Select(c => new
            {
                id = c.Id,
                name = c.Name,
                kind = c.Kind,
                latestVersion = c.LatestVersion,
                policyStatus = c.PolicyStatus,
                componentCount = c.ComponentCount,
                severityCounts = SeverityPayload(c.SeverityCounts),
            }),
        });
    }

    /// <summary>
    /// POST /api/v1/projects
    /// Creates a project or a collection. <c>parentId</c>, when supplied, must name a collection in
    /// the same org — a project cannot contain another project.
    /// </summary>
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpPost("api/v1/projects")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    public async Task<IActionResult> Create(
        [FromBody] CreateProjectRequest req, CancellationToken ct = default)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string name = req.Name?.Trim() ?? "";
        if (name.Length == 0)
        {
            return _problems.ValidationErrorActionKey("name", "error.project.nameRequired");
        }

        if (name.Length > MaxNameLength)
        {
            return _problems.ValidationErrorActionKey("name", "error.project.nameTooLong", MaxNameLength);
        }

        string kind = string.IsNullOrWhiteSpace(req.Kind) ? ProjectKinds.Project : req.Kind.Trim();
        if (!ProjectKinds.IsKnown(kind))
        {
            return _problems.ValidationErrorActionKey(
                "kind", "error.common.mustBeOneOf", string.Join(", ", ProjectKinds.All));
        }

        string? classifier = string.IsNullOrWhiteSpace(req.Classifier) ? null : req.Classifier.Trim();
        if (classifier is not null && !ProjectClassifiers.IsKnown(classifier))
        {
            return _problems.ValidationErrorActionKey(
                "classifier", "error.common.mustBeOneOf", string.Join(", ", ProjectClassifiers.All));
        }

        string? description = string.IsNullOrWhiteSpace(req.Description) ? null : req.Description.Trim();
        if (description is { Length: > MaxDescriptionLength })
        {
            return _problems.ValidationErrorActionKey(
                "description", "error.project.descriptionTooLong", MaxDescriptionLength);
        }

        string? parentId = string.IsNullOrWhiteSpace(req.ParentId) ? null : req.ParentId.Trim();
        string orgId = CurrentTenantId();

        // A name already taken in the same parent scope is a conflict, not a second row: the two
        // partial unique indexes would refuse the insert anyway, and answering 409 up front says
        // which of the caller's two fields is the problem.
        if (await _projects.GetByNameAsync(orgId, parentId, name, ct) is not null)
        {
            return _problems.ConflictActionKey("error.project.nameTaken");
        }

        Project created;
        try
        {
            created = await _projects.CreateAsync(
                orgId, new NewProject(name, kind, classifier, description, parentId), GetUserId(), ct);
        }
        catch (ProjectResolutionException ex)
        {
            return ProblemForResolution(ex);
        }

        string detail = JsonSerializer.Serialize(
            new { projectId = created.Id, name = created.Name, kind = created.Kind },
            Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail);
        var actor = await ResolveActorAsync(orgId, ct);
        await _audit.LogAsync(
            "project.created", orgId, actor.Id, actor.Kind, null, null, detail,
            sourceIp: HttpContext.GetNormalizedRemoteIp(), actorLabel: actor.Label, ct: ct);

        return Created($"/api/v1/projects/{created.Id}", new
        {
            id = created.Id,
            name = created.Name,
            kind = created.Kind,
            classifier = created.Classifier,
            description = created.Description,
            parentId = created.ParentId,
            createdAt = created.CreatedAt,
        });
    }

    /// <summary>
    /// PATCH /api/v1/projects/{projectId}
    /// Renames, re-describes, re-classifies and/or relocates a project or collection.
    ///
    /// Every field is leave-unchanged-on-absent, the same posture the proxy-settings endpoint
    /// takes: a surface that edits only the name must not blank the description just because its
    /// form never rendered one. <c>description</c>, <c>classifier</c> and <c>parentId</c> are
    /// <see cref="Optional{T}"/> rather than plain nullables because null is a legitimate VALUE
    /// for all three — <c>parentId: null</c> is precisely how a caller moves a project back to the
    /// root, which a plain nullable could not tell apart from not mentioning the field at all.
    ///
    /// <c>kind</c> is deliberately not editable. Flipping a project to a collection would strand
    /// its versions (collections hold none) and flipping a collection to a project would strand its
    /// children (a project contains none); either is a data migration, not a field edit.
    /// </summary>
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpPatch("api/v1/projects/{projectId}")]
    // input-validation-ok: every field of `req` is validated in ResolveEdit below — name presence
    // and length, classifier against the known set, description length — and its refusal is
    // returned before anything is written. The decision is one call away rather than inline so the
    // action stays readable, not because it is absent.
    public async Task<IActionResult> Update(
        string projectId, [FromBody] UpdateProjectRequest req, CancellationToken ct = default)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string orgId = CurrentTenantId();
        var current = await _projects.GetAsync(orgId, projectId, ct);
        if (current is null)
        {
            return NotFound();
        }

        var invalid = ResolveEdit(req, current, out var edit);
        if (invalid is not null)
        {
            return invalid;
        }

        Project? updated;
        try
        {
            updated = await _projects.UpdateAsync(
                orgId, projectId, edit.Name, edit.Classifier, edit.Description, edit.ParentId, ct);
        }
        catch (ProjectResolutionException ex)
        {
            return ProblemForResolution(ex);
        }

        if (updated is null)
        {
            return NotFound();
        }

        var actor = await ResolveActorAsync(orgId, ct);
        await _audit.LogAsync(
            "project.updated", orgId, actor.Id, actor.Kind, null, null, UpdateAuditDetail(current, updated),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), actorLabel: actor.Label, ct: ct);

        return Ok(new
        {
            id = updated.Id,
            name = updated.Name,
            kind = updated.Kind,
            classifier = updated.Classifier,
            description = updated.Description,
            parentId = updated.ParentId,
            createdAt = updated.CreatedAt,
        });
    }

    /// <summary>The four editable columns, already folded to their final values.</summary>
    private readonly record struct ProjectEdit(
        string Name, string Classifier, string? Description, string? ParentId);

    /// <summary>
    /// Folds "leave unchanged" into the row's current value for each editable field and validates
    /// what the caller did send, so <see cref="ProjectRepository.UpdateAsync"/> always writes four
    /// resolved values. Returns the refusal to send, or null when <paramref name="edit"/> is good.
    /// </summary>
    private IActionResult? ResolveEdit(UpdateProjectRequest req, Project current, out ProjectEdit edit)
    {
        edit = default;

        string name = req.Name is null ? current.Name : req.Name.Trim();
        var invalid = ValidateName(name);
        if (invalid is not null)
        {
            return invalid;
        }

        invalid = ResolveClassifier(req, current, out string classifier);
        if (invalid is not null)
        {
            return invalid;
        }

        invalid = ResolveDescription(req, current, out string? description);
        if (invalid is not null)
        {
            return invalid;
        }

        edit = new ProjectEdit(name, classifier, description, ResolveParentId(req, current));
        return null;
    }

    private IActionResult? ValidateName(string name) =>
        name.Length switch
        {
            0 => _problems.ValidationErrorActionKey("name", "error.project.nameRequired"),
            > MaxNameLength =>
                _problems.ValidationErrorActionKey("name", "error.project.nameTooLong", MaxNameLength),
            _ => null,
        };

    /// <summary>An absent or blank classifier resolves to the default, never to null.</summary>
    private IActionResult? ResolveClassifier(UpdateProjectRequest req, Project current, out string classifier)
    {
        classifier = current.Classifier;
        if (!req.Classifier.IsPresent)
        {
            return null;
        }

        string? requested = string.IsNullOrWhiteSpace(req.Classifier.Value)
            ? null : req.Classifier.Value!.Trim();
        if (requested is not null && !ProjectClassifiers.IsKnown(requested))
        {
            return _problems.ValidationErrorActionKey(
                "classifier", "error.common.mustBeOneOf", string.Join(", ", ProjectClassifiers.All));
        }

        classifier = requested ?? ProjectClassifiers.Default;
        return null;
    }

    /// <summary>A blank description clears it, which is distinct from leaving it unchanged.</summary>
    private IActionResult? ResolveDescription(UpdateProjectRequest req, Project current, out string? description)
    {
        description = current.Description;
        if (!req.Description.IsPresent)
        {
            return null;
        }

        description = string.IsNullOrWhiteSpace(req.Description.Value)
            ? null : req.Description.Value!.Trim();
        return description is { Length: > MaxDescriptionLength }
            ? _problems.ValidationErrorActionKey(
                "description", "error.project.descriptionTooLong", MaxDescriptionLength)
            : null;
    }

    /// <summary>A blank parent id moves the project to the root; an absent one leaves it put.</summary>
    private static string? ResolveParentId(UpdateProjectRequest req, Project current)
        => !req.ParentId.IsPresent
            ? current.ParentId
            : string.IsNullOrWhiteSpace(req.ParentId.Value) ? null : req.ParentId.Value!.Trim();

    /// <summary>
    /// The audit detail for one update. A rename and a move each record where the project came
    /// from; a field that did not change records nothing, so the row says what actually happened.
    /// </summary>
    private static string UpdateAuditDetail(Project current, Project updated) =>
        JsonSerializer.Serialize(
            new
            {
                projectId = updated.Id,
                name = updated.Name,
                kind = updated.Kind,
                renamedFrom = string.Equals(current.Name, updated.Name, StringComparison.Ordinal)
                    ? null : current.Name,
                movedFrom = string.Equals(current.ParentId, updated.ParentId, StringComparison.Ordinal)
                    ? null : current.ParentId ?? "",
                parentId = updated.ParentId,
            },
            Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail);

    /// <summary>
    /// DELETE /api/v1/projects/{projectId}
    /// Removes the project and, by FK cascade, its subtree, versions, documents and derived rows.
    /// </summary>
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpDelete("api/v1/projects/{projectId}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Delete(string projectId, CancellationToken ct = default)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string orgId = CurrentTenantId();
        var project = await _projects.GetAsync(orgId, projectId, ct);
        if (project is null)
        {
            return NotFound();
        }

        var blobKeys = await _projects.ListDocumentBlobKeysForProjectAsync(orgId, projectId, ct);

        if (!await _projects.DeleteAsync(orgId, projectId, ct))
        {
            return NotFound();
        }

        await DeleteDocumentBlobsAsync(orgId, blobKeys, ct);

        string detail = JsonSerializer.Serialize(
            new { projectId = project.Id, name = project.Name, kind = project.Kind, documents = blobKeys.Count },
            Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail);
        var actor = await ResolveActorAsync(orgId, ct);
        await _audit.LogAsync(
            "project.deleted", orgId, actor.Id, actor.Kind, null, null, detail,
            sourceIp: HttpContext.GetNormalizedRemoteIp(), actorLabel: actor.Label, ct: ct);

        return NoContent();
    }

    /// <summary>
    /// DELETE /api/v1/projects/{projectId}/versions/{versionId}
    /// Removes one version and its documents. <c>{versionId}</c> also accepts <c>latest</c>.
    /// </summary>
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpDelete("api/v1/projects/{projectId}/versions/{versionId}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> DeleteVersion(
        string projectId, string versionId, CancellationToken ct = default)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string orgId = CurrentTenantId();
        string? resolvedId = await _projects.ResolveVersionIdAsync(orgId, projectId, versionId, ct);
        if (resolvedId is null)
        {
            return NotFound();
        }

        var version = await _projects.GetVersionAsync(orgId, projectId, resolvedId, ct);
        if (version is null)
        {
            return NotFound();
        }

        var blobKeys = await _projects.ListDocumentBlobKeysForVersionAsync(orgId, resolvedId, ct);

        if (!await _projects.DeleteVersionAsync(orgId, projectId, resolvedId, ct))
        {
            return NotFound();
        }

        await DeleteDocumentBlobsAsync(orgId, blobKeys, ct);

        string detail = JsonSerializer.Serialize(
            new { projectId, projectVersionId = resolvedId, version = version.Version, documents = blobKeys.Count },
            Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail);
        var actor = await ResolveActorAsync(orgId, ct);
        await _audit.LogAsync(
            "project.version_deleted", orgId, actor.Id, actor.Kind, null, null, detail,
            sourceIp: HttpContext.GetNormalizedRemoteIp(), actorLabel: actor.Label, ct: ct);

        return NoContent();
    }

    /// <summary>
    /// POST /api/v1/projects/{projectId}/versions/{versionId}/promote-latest
    /// Makes this version the project's latest, clearing the flag from whichever version held it.
    /// Promoting the version that is already latest is a no-op that still answers 200.
    /// </summary>
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpPost("api/v1/projects/{projectId}/versions/{versionId}/promote-latest")]
    public async Task<IActionResult> PromoteLatest(
        string projectId, string versionId, CancellationToken ct = default)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string orgId = CurrentTenantId();
        string? resolvedId = await _projects.ResolveVersionIdAsync(orgId, projectId, versionId, ct);
        if (resolvedId is null || !await _projects.PromoteLatestAsync(orgId, projectId, resolvedId, ct))
        {
            return NotFound();
        }

        var versions = await _projects.ListVersionsAsync(orgId, projectId, ct);
        var promoted = versions.FirstOrDefault(v => string.Equals(v.Id, resolvedId, StringComparison.Ordinal));
        if (promoted is null)
        {
            return NotFound();
        }

        string detail = JsonSerializer.Serialize(
            new { projectId, projectVersionId = resolvedId, version = promoted.Version },
            Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail);
        var actor = await ResolveActorAsync(orgId, ct);
        await _audit.LogAsync(
            "project.version_promoted", orgId, actor.Id, actor.Kind, null, null, detail,
            sourceIp: HttpContext.GetNormalizedRemoteIp(), actorLabel: actor.Label, ct: ct);

        return Ok(VersionPayload(promoted));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────

    /// <summary>The audit attribution of whoever is driving this request.</summary>
    private readonly record struct AuditActor(string? Id, string? Kind, string? Label);

    /// <summary>
    /// Resolves the audit attribution of the caller. Every mutation here authenticates on either
    /// the session scheme or the API-token scheme, and for a service token the subject is the
    /// token's own id rather than a users row — so hardcoding the user discriminator files the
    /// write under an id the users join cannot resolve, and the row reads as anonymous, which is
    /// exactly what an operator asking who deleted a project must not see.
    ///
    /// <para>The label comes back populated for a service actor only. A user's display name is an
    /// email, and the membership-removal and retention scrubs both clear a fixed column list, so
    /// denormalizing one here would leave personal data at rest beyond either sweep.</para>
    /// </summary>
    private async Task<AuditActor> ResolveActorAsync(string orgId, CancellationToken ct)
    {
        string? actorId = GetUserId();
        if (actorId is null)
        {
            return new AuditActor(null, null, null);
        }

        (string kind, string? label) = await _ingest.ResolveActorAsync(orgId, actorId, ct);
        return new AuditActor(actorId, kind, label);
    }

    private static object VersionPayload(ProjectVersionSummary v) => new
    {
        id = v.Id,
        version = v.Version,
        isLatest = v.IsLatest,
        policyStatus = v.PolicyStatus,
        componentCount = v.ComponentCount,
        createdAt = v.CreatedAt,
    };

    private static object SeverityPayload(SeverityCounts counts) => new
    {
        critical = counts.Critical,
        high = counts.High,
        medium = counts.Medium,
        low = counts.Low,
        unscored = counts.Unscored,
        kevCount = counts.KevCount,
    };

    // The rows are already gone when this runs, so a failed blob delete cannot roll the delete
    // back — it leaves an unreferenced blob, which is precisely the shape
    // OrphanBlobReconcilerService reclaims. Log and carry on rather than answering 500 for a
    // delete that did succeed.
    private async Task DeleteDocumentBlobsAsync(
        string orgId, IReadOnlyList<string> blobKeys, CancellationToken ct)
    {
        if (blobKeys.Count == 0)
        {
            return;
        }

        try
        {
            var registry = await _storage.GetRegistryAsync(orgId, ct);
            foreach (string key in blobKeys)
            {
                await registry.DeleteAsync(BlobKeys.StoreKey(key), ct);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                "Document blob cleanup failed after project delete for org {OrgId}; " +
                "{BlobCount} blob(s) left for the orphan reconciler. {ExceptionType}: {ExceptionMessage}",
                orgId, blobKeys.Count, ex.GetType().Name, ex.Message);
        }
    }

    private IActionResult ProblemForResolution(ProjectResolutionException ex) => ex.Reason switch
    {
        ProjectResolutionReason.ParentNotACollection =>
            _problems.ValidationErrorActionKey("parentId", "error.project.parentNotACollection"),
        ProjectResolutionReason.CollectionTarget =>
            _problems.ConflictActionKey("error.project.isCollection"),
        ProjectResolutionReason.ParentIsSelf =>
            _problems.ValidationErrorActionKey("parentId", "error.project.parentIsSelf"),
        ProjectResolutionReason.ParentIsDescendant =>
            _problems.ValidationErrorActionKey("parentId", "error.project.parentIsDescendant"),
        ProjectResolutionReason.NameTaken =>
            _problems.ConflictActionKey("error.project.nameTaken"),
        _ => _problems.ValidationErrorActionKey("parentId", "error.project.parentNotFound"),
    };
}

/// <summary>
/// Body of <c>POST /api/v1/projects</c>. Every field is validated inline in
/// <see cref="ProjectsController.Create"/>; MVC binds with
/// <c>JsonUnmappedMemberHandling.Disallow</c>, so a field not listed here is a 400.
/// </summary>
/// <param name="Name">Required. Unique within the parent scope.</param>
/// <param name="Kind"><c>project</c> (default) or <c>collection</c>.</param>
/// <param name="Classifier">CycloneDX <c>component.type</c>; defaults to <c>application</c>.</param>
/// <param name="Description">Free text.</param>
/// <param name="ParentId">The containing collection, or absent for a root-level project.</param>
public sealed record CreateProjectRequest(
    string? Name,
    string? Kind = null,
    string? Classifier = null,
    string? Description = null,
    string? ParentId = null);

/// <summary>
/// Body of <c>PATCH /api/v1/projects/{projectId}</c>. Every field is optional and absent means
/// leave unchanged; MVC binds with <c>JsonUnmappedMemberHandling.Disallow</c>, so a field not
/// listed here — <c>kind</c> included — is a 400 rather than a silently ignored key.
/// </summary>
/// Declared as init-only properties rather than constructor parameters, the same shape
/// <c>UpdateRetentionRequest</c> uses and for the same reason: the OpenAPI exporter serializes a
/// parameter's default value into the schema, and a custom struct's <c>default</c> throws there —
/// 500ing <c>/openapi/management.json</c> for the whole document, not just this route.
public sealed record UpdateProjectRequest
{
    /// <summary>The new name. Absent (or null) leaves it alone; a blank name is a 422.</summary>
    public string? Name { get; init; }

    /// <summary>CycloneDX <c>component.type</c>. Explicit null resets it to the default.</summary>
    public Optional<string> Classifier { get; init; }

    /// <summary>Free text. Explicit null (or blank) clears it.</summary>
    public Optional<string> Description { get; init; }

    /// <summary>
    /// The containing collection. Explicit null moves the project to the root — which is why this
    /// is <see cref="Optional{T}"/> and not a plain nullable.
    /// </summary>
    public Optional<string> ParentId { get; init; }
}
