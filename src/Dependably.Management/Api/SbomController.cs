using System.Security.Claims;
using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Infrastructure.Sbom;
using Dependably.Protocol;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// Where a project version is, and whether the caller may have one created for it. Bound from
/// the query string so a CI job can push a document with
/// <c>curl --data-binary @bom.json</c> and no multipart ceremony.
/// </summary>
public sealed record SbomUploadQuery
{
    /// <summary>The project the document describes. Required.</summary>
    public string? ProjectName { get; init; }

    /// <summary>The version label, opaque and never parsed for an ordering. Required.</summary>
    public string? ProjectVersion { get; init; }

    /// <summary>Creates the project and version when they do not exist; otherwise a miss is a 404.</summary>
    public bool AutoCreate { get; init; }

    /// <summary>
    /// The collection to file the project under, by id. Unlike <see cref="ParentName"/> this names
    /// exactly one row at any depth, so it is the only way to target a nested folder — and it is
    /// never auto-created. Mutually exclusive with <see cref="ParentName"/>.
    /// </summary>
    public string? ParentId { get; init; }

    /// <summary>
    /// The collection to file a newly created project under, by name. Resolved in the ROOT scope
    /// only, so it cannot address a nested folder and a name shared by a root folder and a nested
    /// one resolves to the root. Kept for the Dependency-Track-compatible CI surface; callers that
    /// know the id should send <see cref="ParentId"/>.
    /// </summary>
    public string? ParentName { get; init; }

    /// <summary>The parent collection's version, for a versioned collection.</summary>
    public string? ParentVersion { get; init; }

    /// <summary>Promotes this version to the project's latest, inside the resolution transaction.</summary>
    public bool IsLatest { get; init; }
}

/// <summary>The target of a VEX or SARIF upload. Neither kind may create a project version.</summary>
public sealed record ProjectTargetQuery
{
    /// <summary>The project the document describes. Required.</summary>
    public string? ProjectName { get; init; }

    /// <summary>The version label. Required.</summary>
    public string? ProjectVersion { get; init; }

    /// <summary>
    /// The containing collection, by id — the only way to address a project nested in a folder,
    /// since the project name alone is unique per parent scope rather than per org.
    /// </summary>
    public string? ParentId { get; init; }
}

/// <summary>Injected dependencies, bundled so the controller constructor stays within S107.</summary>
public sealed record SbomControllerServices(
    OrgAccessGuard Guard,
    ProjectRepository Projects,
    SbomIngestRepository Ingest,
    SbomMergeService Merge,
    SbomDocumentStore Documents,
    ProjectDocumentRepository DocumentRows,
    Dependably.Infrastructure.SbomScanWorker ScanQueue,
    AuditRepository Audit,
    ProblemResults Problems,
    TimeProvider Time,
    SbomOptions Options,
    string StagingPath,
    ILogger<SbomController> Logger);

/// <summary>
/// The three document-upload surfaces for the projects plane:
/// <c>PUT /api/v1/sbom</c>, <c>PUT /api/v1/vex</c> and <c>PUT /api/v1/sarif</c>, each taking a
/// raw JSON body and naming its target in the query string.
///
/// <para><b>One endpoint per document kind, deliberately.</b> A CycloneDX document carrying both
/// <c>components</c> and <c>vulnerabilities</c> is genuinely ambiguous — it is an inventory with
/// a vulnerability disclosure report attached, or it is a VEX — and no amount of sniffing
/// resolves what the uploader meant. The caller declares intent by choosing a route. The one
/// discrimination made by content is CycloneDX-VEX versus OpenVEX inside the VEX route, because
/// those two are unambiguous and asking a caller to pick between them would be a route per
/// file format rather than per meaning.</para>
///
/// <para><b>Every upload is a merge, not an event.</b> The state of a version is defined as
/// "the latest SBOM, then the latest VEX, then the latest SARIF, applied in that order", so a
/// re-uploaded document is re-merged rather than appended: uploading a new SBOM re-applies the
/// version's already-stored VEX and SARIF against the inventory it just wrote, so those rows stay
/// bound across an inventory change. The order is fixed across kinds, not free-standing —
/// <c>PUT /vex</c> and <c>PUT /sarif</c> resolve their target version read-only and answer 404
/// against one that does not exist yet, because only an SBOM upload creates a version. A CI
/// pipeline that fans its three PUTs out in parallel is therefore order-sensitive on the wire even
/// though ingest itself is a merge: the SBOM PUT has to land, and complete, before the VEX or
/// SARIF PUT for the same project version — sequencing the SBOM first, or awaiting it before
/// issuing the other two, is what keeps that fan-out from 404ing. That also makes re-uploading
/// free — a document byte-identical to the one already held for its kind is a 200 that does no
/// work.</para>
///
/// <para><b>Merge includes retraction.</b> "The latest document wins" is only true if a statement
/// the latest document dropped stops applying, which is how a VEX producer withdraws one. Each
/// ingest request therefore ends with a single sweep over the union of everything it asserted,
/// clearing the upload-sourced analysis rows outside it — one sweep per request, not one per
/// apply, because an SBOM upload applies its own embedded statements and then re-applies the
/// stored VEX, and a per-apply sweep would have the second retract the first. Manually triaged
/// rows are never swept. The sweep is skipped for an arm whose stored document could not be
/// re-read, so a missing blob costs a stale fact rather than every fact that document carried.</para>
///
/// <para><b>The document row is written last.</b> It is what the dedup arm reads, so its presence
/// has to mean "this exact document has been fully applied" rather than "these bytes arrived" —
/// see <see cref="Infrastructure.Sbom.SbomDocumentStore"/> for why the bytes still go first.</para>
///
/// <para><b>Resource controls.</b> The configured cap is checked against <c>Content-Length</c>
/// before a byte is read and again against the running count while streaming, so neither a
/// declared-oversize body nor a chunked one gets to spend disk. The body streams to a staging
/// file under the operator-configured staging root and is deleted on every exit path; nothing
/// larger than one buffer is ever held in managed memory before the parse.</para>
/// </summary>
[ApiController]
// Documents are pushed by CI far more often than by a person, so both credentials are accepted:
// a JWT session from the upload dialog and an API token from a pipeline. sbom:upload is its own
// capability rather than a reuse of import:*/tenant:configure, which together would let a build
// token rewrite tenant configuration.
[Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
public sealed class SbomController : ControllerBase
{
    // The framework's backstop, far above any configured cap. The cap that actually governs is
    // Sbom:MaxUploadBytes, enforced here so the refusal is a localized problem detail rather
    // than the pipeline's opaque 413.
    private const long RequestCeilingBytes = 256L * 1024 * 1024;

    private readonly SbomControllerServices _svc;

    public SbomController(SbomControllerServices svc)
    {
        _svc = svc;
        // PROXY_STAGING_PATH is operator-configured; no caller-supplied value reaches the path.
        _stagingPath = string.IsNullOrWhiteSpace(svc.StagingPath) ? Path.GetTempPath() : svc.StagingPath;
    }

    private readonly string _stagingPath;

    /// <summary>
    /// PUT /api/v1/sbom — ingest a CycloneDX 1.4–1.7 inventory for one project version, replacing
    /// whatever inventory that version held and re-applying its stored VEX and SARIF afterwards.
    /// </summary>
    [HttpPut("api/v1/sbom")]
    [RequestSizeLimit(RequestCeilingBytes)]
    [EnableRateLimiting("sbom-upload")]
    [RequireCapability(Capabilities.SbomUpload)]
    public async Task<IActionResult> PutSbom([FromQuery] SbomUploadQuery query, CancellationToken ct)
    {
        var (error, orgId, actorId) = await AuthorizeAsync(ct);
        if (error is not null)
        {
            return error;
        }

        var invalid = ValidateTarget(query.ProjectName, query.ProjectVersion);
        if (invalid is not null)
        {
            return invalid;
        }

        var (stagingError, staged) = await StageAsync(ct);
        if (stagingError is not null)
        {
            return stagingError;
        }

        try
        {
            return await IngestSbomAsync(orgId!, actorId, query, staged!, ct);
        }
        catch (SbomParseException ex)
        {
            return ParseProblem(ex);
        }
        finally
        {
            RequestBodyStager.TryDelete(staged?.Path);
        }
    }

    /// <summary>
    /// PUT /api/v1/vex — ingest a CycloneDX VEX or an OpenVEX document, binding its statements
    /// to the version's analysis rows. The project version must already exist: a VEX describes
    /// components, and only an SBOM can say what they are.
    /// </summary>
    [HttpPut("api/v1/vex")]
    [RequestSizeLimit(RequestCeilingBytes)]
    [EnableRateLimiting("sbom-upload")]
    [RequireCapability(Capabilities.SbomUpload)]
    public async Task<IActionResult> PutVex([FromQuery] ProjectTargetQuery query, CancellationToken ct)
    {
        var (error, orgId, actorId) = await AuthorizeAsync(ct);
        if (error is not null)
        {
            return error;
        }

        var invalid = ValidateTarget(query.ProjectName, query.ProjectVersion);
        if (invalid is not null)
        {
            return invalid;
        }

        var (stagingError, staged) = await StageAsync(ct);
        if (stagingError is not null)
        {
            return stagingError;
        }

        try
        {
            return await IngestVexAsync(orgId!, actorId, query, staged!, ct);
        }
        catch (SbomParseException ex)
        {
            return ParseProblem(ex);
        }
        finally
        {
            RequestBodyStager.TryDelete(staged?.Path);
        }
    }

    /// <summary>
    /// PUT /api/v1/sarif — ingest a SARIF 2.1.0 log, writing reachability facts to the version's
    /// analysis rows and the dev/prod signal onto its components. The project version must already
    /// exist: a SARIF result names a component, and only an SBOM can say what they are.
    /// </summary>
    [HttpPut("api/v1/sarif")]
    [RequestSizeLimit(RequestCeilingBytes)]
    [EnableRateLimiting("sbom-upload")]
    [RequireCapability(Capabilities.SbomUpload)]
    public async Task<IActionResult> PutSarif([FromQuery] ProjectTargetQuery query, CancellationToken ct)
    {
        var (error, orgId, actorId) = await AuthorizeAsync(ct);
        if (error is not null)
        {
            return error;
        }

        var invalid = ValidateTarget(query.ProjectName, query.ProjectVersion);
        if (invalid is not null)
        {
            return invalid;
        }

        var (stagingError, staged) = await StageAsync(ct);
        if (stagingError is not null)
        {
            return stagingError;
        }

        try
        {
            return await IngestSarifAsync(orgId!, actorId, query, staged!, ct);
        }
        catch (SbomParseException ex)
        {
            return ParseProblem(ex);
        }
        finally
        {
            RequestBodyStager.TryDelete(staged?.Path);
        }
    }

    // ── Per-kind ingest ──────────────────────────────────────────────────────────────────────

    private async Task<IActionResult> IngestSbomAsync(
        string orgId, string? actorId, SbomUploadQuery query, RequestBodyStager.StagedBody staged, CancellationToken ct)
    {
        var duplicate = await TryDedupAsync(
            orgId, query.ProjectName!, query.ProjectVersion!, "sbom", query.ParentId, staged, ct);
        if (duplicate is not null)
        {
            // The dedup short-circuit skips the merge, but not a promotion the caller explicitly
            // asked for: `isLatest=true` on a byte-identical re-upload is a CI job re-running a
            // build it has already pushed and now wants pinned as the release, and honouring it is
            // what makes the no-op genuinely equivalent to the full ingest path rather than a
            // request whose isLatest flag silently dropped on the floor. A promotion of the
            // version that is already latest is itself a no-op, same as the dedicated
            // promote-latest endpoint.
            if (query.IsLatest)
            {
                await _svc.Projects.PromoteLatestAsync(
                    orgId, duplicate.Version.ProjectId, duplicate.Version.ProjectVersionId, ct);
            }

            int held = await _svc.Ingest.CountComponentsAsync(orgId, duplicate.Version.ProjectVersionId, ct);
            return Ok(new
            {
                documentId = duplicate.DocumentId,
                project = new { id = duplicate.Version.ProjectId, name = duplicate.Version.ProjectName },
                projectVersion = new
                {
                    id = duplicate.Version.ProjectVersionId,
                    version = duplicate.Version.VersionLabel,
                },
                components = new { total = held, added = 0, removed = 0, unchanged = held },
                embeddedVexStatements = 0,
                scanQueued = false,
            });
        }

        using var json = await ReadJsonAsync(staged.Path, ct);
        var document = CycloneDxParser.Parse(json.RootElement);

        var (resolveError, resolved, projectCreated) = await ResolveAsync(orgId, query, document, actorId, ct);
        if (resolveError is not null)
        {
            return resolveError;
        }

        var target = resolved!;
        var now = _svc.Time.GetUtcNow();
        var documentWrite = new SbomDocumentWrite(
            orgId, target.ProjectId, target.ProjectVersionId, "sbom", "cyclonedx-json",
            document.SpecVersion, document.ToolName, document.ToolVersion,
            staged.Sha256, staged.Size, staged.Path, actorId, now);
        string blobKey = await _svc.Documents.StageBlobAsync(documentWrite, ct);

        var counts = await _svc.Merge.MergeComponentsAsync(orgId, target.ProjectVersionId, document, now, ct);
        var embedded = await _svc.Merge.ApplyCycloneDxStatementsAsync(
            orgId, target.ProjectVersionId, document.Statements, actorId, now, ct);
        var reapplied = await ReapplyStoredFactsAsync(orgId, target.ProjectVersionId, ct);
        await RetractAfterSbomAsync(orgId, target.ProjectVersionId, embedded, reapplied, now, ct);

        // Last, and only now: the document row is what the dedup arm reads, so it must not exist
        // until everything above has actually landed.
        string documentId = await _svc.Documents.CommitRowAsync(documentWrite, blobKey, ct);

        await RecordUploadAsync(orgId, actorId, target, "sbom", projectCreated, ct);
        return Ok(new
        {
            documentId,
            project = new { id = target.ProjectId, name = target.ProjectName },
            projectVersion = new { id = target.ProjectVersionId, version = target.VersionLabel },
            components = new
            {
                total = counts.Total,
                added = counts.Added,
                removed = counts.Removed,
                unchanged = counts.Unchanged,
            },
            embeddedVexStatements = embedded.Counts.Total,
            scanQueued = _svc.ScanQueue.TryEnqueue(orgId, target.ProjectVersionId),
        });
    }

    private async Task<IActionResult> IngestVexAsync(
        string orgId, string? actorId, ProjectTargetQuery query, RequestBodyStager.StagedBody staged, CancellationToken ct)
    {
        var duplicate = await TryDedupAsync(
            orgId, query.ProjectName!, query.ProjectVersion!, "vex", query.ParentId, staged, ct);
        if (duplicate is not null)
        {
            return VexResponse(duplicate.DocumentId, AsTarget(orgId, duplicate.Version), new SbomBindingCounts(0, 0, 0), scanQueued: false);
        }

        using var json = await ReadJsonAsync(staged.Path, ct);
        bool openVex = OpenVexParser.IsOpenVex(json.RootElement);
        if (!openVex && !CycloneDxParser.IsCycloneDx(json.RootElement))
        {
            throw new SbomParseException(SbomParseFailure.WrongDocumentKind);
        }

        var (locateError, located) = await LocateAsync(
            orgId, query.ProjectName!, query.ProjectVersion!, query.ParentId, ct);
        if (locateError is not null)
        {
            return locateError;
        }

        var target = located!;
        var now = _svc.Time.GetUtcNow();
        var write = openVex
            ? BuildVexWrite(orgId, target, staged, OpenVexParser.Parse(json.RootElement), actorId, now)
            : BuildVexWrite(orgId, target, staged, CycloneDxParser.Parse(json.RootElement), actorId, now);

        string blobKey = await _svc.Documents.StageBlobAsync(write.Document, ct);
        var application = openVex
            ? await _svc.Merge.ApplyOpenVexStatementsAsync(
                orgId, target.ProjectVersionId, write.OpenVex!.Statements, actorId, now, ct)
            : await _svc.Merge.ApplyCycloneDxStatementsAsync(
                orgId, target.ProjectVersionId, write.CycloneDx!.Statements, actorId, now, ct);

        // Latest-wins: a statement this document dropped is a statement the producer withdrew.
        // The uploaded VEX is the authoritative analysis for the version, so it also supersedes
        // whatever the stored SBOM's embedded vulnerabilities[] asserted — the next SBOM upload
        // re-asserts those, and the interim state errs toward not suppressing.
        await _svc.Merge.RetractUnassertedVexAsync(
            orgId, target.ProjectVersionId, application.Asserted, now, ct);

        string documentId = await _svc.Documents.CommitRowAsync(write.Document, blobKey, ct);

        await RecordUploadAsync(orgId, actorId, target, "vex", projectCreated: false, ct);
        // A VEX or SARIF upload changes policy inputs for the version, so it re-enters the scan
        // queue the same way an SBOM upload does.
        return VexResponse(documentId, target, application.Counts,
            _svc.ScanQueue.TryEnqueue(target.OrgId, target.ProjectVersionId));
    }

    private async Task<IActionResult> IngestSarifAsync(
        string orgId, string? actorId, ProjectTargetQuery query, RequestBodyStager.StagedBody staged, CancellationToken ct)
    {
        var duplicate = await TryDedupAsync(
            orgId, query.ProjectName!, query.ProjectVersion!, "sarif", query.ParentId, staged, ct);
        if (duplicate is not null)
        {
            return SarifResponse(duplicate.DocumentId, AsTarget(orgId, duplicate.Version), new SbomBindingCounts(0, 0, 0), scanQueued: false);
        }

        using var json = await ReadJsonAsync(staged.Path, ct);
        var document = SarifParser.Parse(json.RootElement);

        var (locateError, located) = await LocateAsync(
            orgId, query.ProjectName!, query.ProjectVersion!, query.ParentId, ct);
        if (locateError is not null)
        {
            return locateError;
        }

        var target = located!;
        var now = _svc.Time.GetUtcNow();
        var documentWrite = new SbomDocumentWrite(
            orgId, target.ProjectId, target.ProjectVersionId, "sarif", "sarif-json",
            document.Version, document.ToolName, document.ToolVersion,
            staged.Sha256, staged.Size, staged.Path, actorId, now);
        string blobKey = await _svc.Documents.StageBlobAsync(documentWrite, ct);

        var application = await _svc.Merge.ApplySarifAsync(
            orgId, target.ProjectVersionId, document, actorId, now, ct);
        await _svc.Merge.RetractUnassertedSarifAsync(
            orgId, target.ProjectVersionId, application, now, ct);

        string documentId = await _svc.Documents.CommitRowAsync(documentWrite, blobKey, ct);

        await RecordUploadAsync(orgId, actorId, target, "sarif", projectCreated: false, ct);
        return SarifResponse(documentId, target, application.Counts,
            _svc.ScanQueue.TryEnqueue(target.OrgId, target.ProjectVersionId));
    }

    // ── Shared pipeline steps ────────────────────────────────────────────────────────────────

    private async Task<(IActionResult? Error, string? OrgId, string? ActorId)> AuthorizeAsync(CancellationToken ct)
    {
        var deny = await _svc.Guard.AuthorizeCapAsync(User, HttpContext, Capabilities.SbomUpload, ct);
        if (deny is not null)
        {
            return (deny, null, null);
        }

        var ctx = (TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!;
        string? actorId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? User.FindFirst("sub")?.Value;
        return (null, ctx.TenantId, actorId);
    }

    // Both required query fields are checked here rather than by DataAnnotations because the
    // refusal has to be a localized problem detail, which the automatic ModelState 400 is not.
    private IActionResult? ValidateTarget(string? projectName, string? projectVersion)
    {
        return string.IsNullOrWhiteSpace(projectName)
            ? _svc.Problems.ValidationErrorActionKey("projectName", "error.sbom.projectNameRequired")
            : string.IsNullOrWhiteSpace(projectVersion)
                ? _svc.Problems.ValidationErrorActionKey("projectVersion", "error.sbom.projectVersionRequired")
                : null;
    }

    private async Task<(IActionResult? Error, RequestBodyStager.StagedBody? Document)> StageAsync(CancellationToken ct)
    {
        long cap = _svc.Options.MaxUploadBytes;
        if (Request.ContentLength is long declared && declared > cap)
        {
            return (TooLarge(cap), null);
        }

        try
        {
            var staged = await RequestBodyStager.StageAsync(
                Request.Body, _stagingPath, cap, withMavenDigests: false, ct);
            return (null, staged);
        }
        catch (InvalidDataException)
        {
            // LimitedReadStream aborts the copy the byte after the cap, so a chunked body with
            // no declared length costs the cap and not one byte more.
            return (TooLarge(cap), null);
        }
    }

    private IActionResult TooLarge(long cap) =>
        _svc.Problems.PayloadTooLargeActionKey("error.sbom.tooLarge", cap);

    /// <summary>What a dedup hit resolved to, so the no-op response can name it.</summary>
    private sealed record DedupHit(string DocumentId, ProjectVersionRef Version);

    // The digest is compared before the document is parsed and before the project is resolved,
    // because a CI job re-running an unchanged build should cost a hash and two indexed reads.
    // The lookup is deliberately the read-only one: a re-upload of an unchanged document must
    // not be what creates a project.
    private async Task<DedupHit?> TryDedupAsync(
        string orgId, string projectName, string projectVersion, string docType,
        string? parentId, RequestBodyStager.StagedBody staged, CancellationToken ct)
    {
        var candidates = await _svc.Ingest.ResolveVersionCandidatesAsync(
            orgId, projectName, projectVersion, parentId, ct);
        // Exactly one, or nothing. An ambiguous name is not a dedup hit: short-circuiting on a
        // guess would report someone else's project as already holding these bytes. The upload
        // path answers the ambiguity properly a few lines later.
        if (candidates.Count != 1)
        {
            return null;
        }

        var version = candidates[0];

        var current = await _svc.DocumentRows.GetAsync(orgId, version.ProjectVersionId, docType, ct);
        // Identical bytes are only a no-op if the projection that applied them is the one running
        // now. A build that widened what ingest extracts writes different rows for the same
        // document, so a hash-only match would report "already applied" about rows this build
        // would not have produced — and nothing would ever correct them, because the next upload
        // of an unchanged document takes this same branch. The stored revision is the tiebreak.
        return current is not null
            && string.Equals(current.Sha256, staged.Sha256, StringComparison.Ordinal)
            && current.IngestVersion == SbomIngestVersion.Current
            ? new DedupHit(current.Id, version)
            : null;
    }

    /// <summary>The target of an upload once the project and version are known.</summary>
    private sealed record UploadTarget(
        string OrgId, string ProjectId, string ProjectName, string ProjectVersionId, string VersionLabel);

    private async Task<(IActionResult? Error, UploadTarget? Value, bool ProjectCreated)> ResolveAsync(
        string orgId, SbomUploadQuery query, CycloneDxDocument document, string? actorId, CancellationToken ct)
    {
        try
        {
            var resolution = await _svc.Projects.ResolveOrCreateAsync(
                orgId,
                new ProjectVersionRequest(
                    query.ProjectName!,
                    query.ProjectVersion!,
                    query.AutoCreate,
                    query.ParentId,
                    query.ParentName,
                    query.ParentVersion,
                    query.IsLatest,
                    document.Root?.Type),
                actorId,
                ct);
            return (
                null,
                new UploadTarget(
                    orgId, resolution.ProjectId, resolution.ProjectName,
                    resolution.ProjectVersionId, resolution.VersionLabel),
                resolution.ProjectCreated);
        }
        catch (ProjectResolutionException ex)
        {
            return (ResolutionProblem(ex.Reason), null, false);
        }
    }

    // VEX and SARIF resolve read-only: neither can seed an inventory, so an unknown project or
    // version is a 404 rather than a silent creation that would then have nothing in it.
    private async Task<(IActionResult? Error, UploadTarget? Value)> LocateAsync(
        string orgId, string projectName, string projectVersion, string? parentId, CancellationToken ct)
    {
        var candidates = await _svc.Ingest.ResolveVersionCandidatesAsync(
            orgId, projectName, projectVersion, parentId, ct);
        if (candidates.Count == 0)
        {
            return (_svc.Problems.NotFoundActionKey("error.sbom.projectNotFound", projectName, projectVersion), null);
        }

        // Two folders may each hold a project of this name, so the name alone no longer identifies
        // one. Say so and name the field that resolves it, rather than picking one and attaching
        // the caller's document to whichever row sorted first.
        if (candidates.Count > 1)
        {
            return (_svc.Problems.ConflictActionKeyFormat(
                "error.sbom.ambiguousProject", projectName, candidates.Count), null);
        }

        var version = candidates[0];

        return string.Equals(version.ProjectKind, "collection", StringComparison.Ordinal)
            ? (_svc.Problems.ConflictActionKey("error.sbom.collectionTarget"), null)
            : (null, new UploadTarget(
                orgId, version.ProjectId, version.ProjectName, version.ProjectVersionId, version.VersionLabel));
    }

    private IActionResult ResolutionProblem(ProjectResolutionReason reason) => reason switch
    {
        ProjectResolutionReason.CollectionTarget => _svc.Problems.ConflictActionKey("error.sbom.collectionTarget"),
        ProjectResolutionReason.ParentNotACollection => _svc.Problems.ConflictActionKey("error.sbom.parentNotACollection"),
        ProjectResolutionReason.ParentNotFound => _svc.Problems.NotFoundActionKey("error.sbom.parentNotFound"),
        _ => _svc.Problems.NotFoundActionKey("error.sbom.projectNotFound"),
    };

    private IActionResult ParseProblem(SbomParseException ex) => ex.Failure switch
    {
        SbomParseFailure.UnsupportedSpecVersion => _svc.Problems.ValidationErrorActionKey(
            "specVersion", "error.sbom.unsupportedSpecVersion", ex.Diagnostic ?? string.Empty),
        SbomParseFailure.TooManyComponents => _svc.Problems.ValidationErrorActionKey(
            "components", "error.sbom.tooManyComponents", ex.Diagnostic ?? string.Empty),
        SbomParseFailure.TooManyStatements => _svc.Problems.ValidationErrorActionKey(
            "statements", "error.sbom.tooManyStatements", ex.Diagnostic ?? string.Empty),
        SbomParseFailure.TooManyResults => _svc.Problems.ValidationErrorActionKey(
            "results", "error.sbom.tooManyResults", ex.Diagnostic ?? string.Empty),
        SbomParseFailure.WrongDocumentKind => _svc.Problems.ValidationErrorActionKey(
            "body", "error.sbom.wrongDocumentKind"),
        _ => _svc.Problems.ValidationErrorActionKey("body", "error.sbom.malformed"),
    };

    private static async Task<JsonDocument> ReadJsonAsync(string tempPath, CancellationToken ct)
    {
        // tempPath is "sbom-stage-{server-guid}.tmp" under the operator-configured staging root.
        await using var file = new FileStream(
            tempPath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 81920, useAsync: true);
        try
        {
            return await JsonDocument.ParseAsync(file, cancellationToken: ct);
        }
        catch (JsonException)
        {
            throw new SbomParseException(SbomParseFailure.Malformed);
        }
    }

    /// <summary>The document row plus whichever parse produced it, for the VEX branch.</summary>
    private sealed record VexWrite(
        SbomDocumentWrite Document, CycloneDxDocument? CycloneDx, OpenVexDocument? OpenVex);

    private static VexWrite BuildVexWrite(
        string orgId, UploadTarget target, RequestBodyStager.StagedBody staged,
        CycloneDxDocument document, string? actorId, DateTimeOffset now) =>
        new(
            new SbomDocumentWrite(
                orgId, target.ProjectId, target.ProjectVersionId, "vex", "cyclonedx-json",
                document.SpecVersion, document.ToolName, document.ToolVersion,
                staged.Sha256, staged.Size, staged.Path, actorId, now),
            document,
            null);

    private static VexWrite BuildVexWrite(
        string orgId, UploadTarget target, RequestBodyStager.StagedBody staged,
        OpenVexDocument document, string? actorId, DateTimeOffset now) =>
        new(
            new SbomDocumentWrite(
                orgId, target.ProjectId, target.ProjectVersionId, "vex", "openvex-json",
                null, document.ToolName, null,
                staged.Sha256, staged.Size, staged.Path, actorId, now),
            null,
            document);

    /// <summary>
    /// What re-applying this version's stored VEX and SARIF asserted, and whether that re-apply
    /// was complete. Completeness is what gates retraction: a document whose blob is missing or
    /// whose bytes no longer parse asserted nothing this pass, and sweeping against an empty set
    /// would retract every fact it had contributed — turning a transient read failure into
    /// permanent data loss.
    /// </summary>
    private sealed record ReappliedFacts
    {
        public HashSet<AnalysisRowKey> Vex { get; } = [];

        public SbomSarifApplication? Sarif { get; set; }

        public bool VexComplete { get; set; } = true;

        public bool SarifComplete { get; set; } = true;
    }

    // The merge is defined over the latest document of each kind, so a new SBOM re-runs the
    // stored VEX and SARIF against the inventory it just wrote. Without this a component that
    // reappears in a re-uploaded SBOM would come back with no dev/prod signal and no
    // reachability, silently reading as unclassified production.
    private async Task<ReappliedFacts> ReapplyStoredFactsAsync(
        string orgId, string projectVersionId, CancellationToken ct)
    {
        var reapplied = new ReappliedFacts();
        var stored = await _svc.DocumentRows.ListAsync(orgId, projectVersionId, ct);
        foreach (var row in stored)
        {
            if (row.DocType is not ("vex" or "sarif"))
            {
                continue;
            }

            await using var bytes = await _svc.Documents.OpenAsync(orgId, row.BlobKey, ct);
            if (bytes is null)
            {
                _svc.Logger.LogWarning(
                    "Stored {DocType} document {DocumentId} could not be re-applied: its blob is missing.",
                    row.DocType, row.Id);
                MarkIncomplete(reapplied, row.DocType);
                continue;
            }

            try
            {
                // The stored document's own uploader and timestamp travel with the re-apply, not
                // the SBOM uploader's: a document nobody touched this request must not have its
                // provenance restamped to whoever happened to re-upload the SBOM, or the triage
                // editor's "set by {user}" line starts lying the moment any SBOM is re-uploaded.
                using var json = await JsonDocument.ParseAsync(bytes, cancellationToken: ct);
                await ReapplyOneAsync(
                    new ReapplyTarget(orgId, projectVersionId, row.UploadedBy, row.UploadedAt),
                    row.DocType, json.RootElement, reapplied, ct);
            }
            catch (JsonException ex)
            {
                _svc.Logger.LogWarning(
                    "Stored {DocType} document {DocumentId} could not be re-applied: {ExceptionType}: {Message}",
                    row.DocType, row.Id, ex.GetType().Name, ex.Message);
                MarkIncomplete(reapplied, row.DocType);
            }
            catch (SbomParseException ex)
            {
                _svc.Logger.LogWarning(
                    "Stored {DocType} document {DocumentId} could not be re-applied: {ExceptionType}: {Failure}",
                    row.DocType, row.Id, ex.GetType().Name, ex.Failure);
                MarkIncomplete(reapplied, row.DocType);
            }
        }

        return reapplied;
    }

    private static void MarkIncomplete(ReappliedFacts reapplied, string docType)
    {
        if (docType == "sarif")
        {
            reapplied.SarifComplete = false;
            return;
        }

        reapplied.VexComplete = false;
    }

    /// <summary>
    /// The version being re-applied to, plus the STORED document's own provenance. The uploader and
    /// timestamp travel with the document rather than with whoever triggered the re-apply — see the
    /// call site.
    /// </summary>
    private readonly record struct ReapplyTarget(
        string OrgId, string ProjectVersionId, string? ActorId, DateTimeOffset Now);

    private async Task ReapplyOneAsync(
        ReapplyTarget target, string docType, JsonElement root, ReappliedFacts reapplied,
        CancellationToken ct)
    {
        var (orgId, projectVersionId, actorId, now) = target;

        if (docType == "sarif")
        {
            reapplied.Sarif = await _svc.Merge.ApplySarifAsync(
                orgId, projectVersionId, SarifParser.Parse(root), actorId, now, ct);
            return;
        }

        var application = OpenVexParser.IsOpenVex(root)
            ? await _svc.Merge.ApplyOpenVexStatementsAsync(
                orgId, projectVersionId, OpenVexParser.Parse(root).Statements, actorId, now, ct)
            : await _svc.Merge.ApplyCycloneDxStatementsAsync(
                orgId, projectVersionId, CycloneDxParser.Parse(root).Statements, actorId, now, ct);
        reapplied.Vex.UnionWith(application.Asserted);
    }

    // One sweep per request, over the union of everything this request asserted. An SBOM upload
    // re-derives both arms — its own embedded statements plus the stored VEX and SARIF — so both
    // are swept; sweeping after each individual apply would instead have the stored VEX retract
    // the embedded statements the same request had just written.
    private async Task RetractAfterSbomAsync(
        string orgId,
        string projectVersionId,
        SbomVexApplication embedded,
        ReappliedFacts reapplied,
        DateTimeOffset now,
        CancellationToken ct)
    {
        if (reapplied.VexComplete)
        {
            var assertedVex = new HashSet<AnalysisRowKey>(embedded.Asserted);
            assertedVex.UnionWith(reapplied.Vex);
            await _svc.Merge.RetractUnassertedVexAsync(orgId, projectVersionId, assertedVex, now, ct);
        }

        if (reapplied is { SarifComplete: true, Sarif: not null })
        {
            await _svc.Merge.RetractUnassertedSarifAsync(orgId, projectVersionId, reapplied.Sarif, now, ct);
        }
    }

    private static UploadTarget AsTarget(string orgId, ProjectVersionRef version) =>
        new(orgId, version.ProjectId, version.ProjectName, version.ProjectVersionId, version.VersionLabel);

    // statements and results are the same three numbers under two names, because a VEX statement
    // and a SARIF result answer the same question about the same analysis row. They stay
    // separately named so a client binding one response shape cannot silently read the other.
    private IActionResult VexResponse(string documentId, UploadTarget target, SbomBindingCounts counts, bool scanQueued) =>
        Ok(new
        {
            documentId,
            project = new { id = target.ProjectId, name = target.ProjectName },
            projectVersion = new { id = target.ProjectVersionId, version = target.VersionLabel },
            statements = new { total = counts.Total, applied = counts.Applied, unmatched = counts.Unmatched },
            scanQueued,
        });

    private IActionResult SarifResponse(string documentId, UploadTarget target, SbomBindingCounts counts, bool scanQueued) =>
        Ok(new
        {
            documentId,
            project = new { id = target.ProjectId, name = target.ProjectName },
            projectVersion = new { id = target.ProjectVersionId, version = target.VersionLabel },
            results = new { total = counts.Total, applied = counts.Applied, unmatched = counts.Unmatched },
            scanQueued,
        });

    private async Task RecordUploadAsync(
        string orgId, string? actorId, UploadTarget target, string docType, bool projectCreated, CancellationToken ct)
    {
        DependablyMeter.SbomUploads.Add(1);

        (string? kind, string? label) = actorId is null
            ? (null, null)
            : await _svc.Ingest.ResolveActorAsync(orgId, actorId, ct);
        string detail = JsonSerializer.Serialize(
            new
            {
                doc_type = docType,
                project_id = target.ProjectId,
                project_name = target.ProjectName,
                project_version_id = target.ProjectVersionId,
                version = target.VersionLabel,
            },
            Infrastructure.Audit.Events.EventJsonOptions.Detail);

        await _svc.Audit.LogActivityAsync(
            orgId, "sbom", purl: null, eventType: "sbom_uploaded",
            actorId: actorId, actorKind: kind, detail: detail,
            sourceIp: HttpContext.GetNormalizedRemoteIp(), actorLabel: label, ct: ct);

        if (projectCreated)
        {
            // One name for one event: ProjectsController writes the same creation as
            // project.created, and a consumer filtering on either spelling silently missed the
            // rows written by the other surface.
            await _svc.Audit.LogAsync(
                "project.created", orgId: orgId, actorId: actorId, actorKind: kind,
                detail: detail, sourceIp: HttpContext.GetNormalizedRemoteIp(), actorLabel: label, ct: ct);
        }
    }
}
