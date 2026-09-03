using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Normalized CycloneDX 1.7 re-renders and verbatim original-document download — two distinct
/// actions per the design: <c>export/sbom</c> and <c>export/vex</c> rebuild a fresh document from
/// the database, while <c>sbom-documents/{id}/original</c> streams back the exact bytes a caller
/// uploaded. All three are reads: <c>read:packages</c>, no activity/audit row (matching the
/// existing audit-export posture), org-scoped with the standard 404-not-403 BOLA shape.
///   GET /api/v1/projects/{projectId}/export/sbom?variant=inventory|vdr        (collections)
///   GET /api/v1/projects/{projectId}/versions/{versionId}/export/sbom?variant=inventory|vdr
///   GET /api/v1/projects/{projectId}/versions/{versionId}/export/vex
///   GET /api/v1/sbom-documents/{documentId}/original
/// </summary>
[ApiController]
[Authorize]
public sealed class SbomExportController : OrgScopedControllerBase
{
    private static readonly HashSet<string> ValidVariants = new(StringComparer.Ordinal) { "inventory", "vdr" };

    private const string CycloneDxContentType = "application/vnd.cyclonedx+json; version=1.7";

    private readonly SbomExportService _export;
    private readonly OrgAccessGuard _guard;
    private readonly ProblemResults _problems;
    private readonly SbomDocumentStore _documents;

    public SbomExportController(
        SbomExportService export, OrgAccessGuard guard, ProblemResults problems, SbomDocumentStore documents)
    {
        _export = export;
        _guard = guard;
        _problems = problems;
        _documents = documents;
    }

    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/projects/{projectId}/versions/{versionId}/export/sbom")]
    public async Task<IActionResult> ExportSbom(
        string projectId, string versionId, [FromQuery] string variant = "inventory", CancellationToken ct = default)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        // Visible validation decision on the variant query param: a closed, enum-shaped
        // vocabulary rather than an open string, so an unrecognised value 422s instead of
        // silently falling through to a default.
        if (!ValidVariants.Contains(variant))
        {
            return _problems.ValidationErrorActionKey("variant", "error.sbom.export.invalidVariant");
        }

        string orgId = CurrentTenantId();
        string? json = await _export.BuildSbomDocumentAsync(orgId, projectId, versionId, variant, ct);
        return json is null ? NotFound() : Content(json, CycloneDxContentType);
    }

    /// <summary>
    /// GET /api/v1/projects/{projectId}/export/sbom?variant=inventory|vdr
    /// One document covering every project beneath a collection, each contributing its
    /// <c>is_latest</c> version — the same selection the collection's rollup counts describe, and
    /// stated in the document's own <c>metadata.properties</c> rather than left to be inferred.
    ///
    /// Collections only. A plain project is 404 here rather than being quietly redirected to its
    /// latest version: it already has a version-scoped export, and answering a different question
    /// from the one asked is how a caller ends up shipping the wrong document.
    ///
    /// There is deliberately no collection-scoped <c>export/vex</c>. A VEX document is a
    /// per-project triage communication, and the <c>vdr</c> variant already carries the effective
    /// analysis state for everything in the subtree.
    /// </summary>
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/projects/{projectId}/export/sbom")]
    public async Task<IActionResult> ExportCollectionSbom(
        string projectId, [FromQuery] string variant = "inventory", CancellationToken ct = default)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        if (!ValidVariants.Contains(variant))
        {
            return _problems.ValidationErrorActionKey("variant", "error.sbom.export.invalidVariant");
        }

        string orgId = CurrentTenantId();
        string? json = await _export.BuildCollectionSbomDocumentAsync(orgId, projectId, variant, ct);
        return json is null ? NotFound() : Content(json, CycloneDxContentType);
    }

    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/projects/{projectId}/versions/{versionId}/export/vex")]
    public async Task<IActionResult> ExportVex(string projectId, string versionId, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string orgId = CurrentTenantId();
        string? json = await _export.BuildVexDocumentAsync(orgId, projectId, versionId, ct);
        return json is null ? NotFound() : Content(json, CycloneDxContentType);
    }

    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/sbom-documents/{documentId}/original")]
    public async Task<IActionResult> DownloadOriginal(string documentId, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string orgId = CurrentTenantId();
        var original = await _export.ResolveOriginalAsync(orgId, documentId, ct);
        if (original is null)
        {
            return NotFound();
        }

        // CONTRACT D4: the full 64-char sha256, strong (quoted) — not the protocol plane's
        // 16-char truncated form (CargoController.ComputeETagFromBytes). The document row already
        // stores the canonical digest of the exact bytes this endpoint serves, so the byte-identity
        // contract wants the whole thing, not a shortened fingerprint of it.
        string etag = $"\"{original.Sha256}\"";
        if (Request.Headers.IfNoneMatch.FirstOrDefault() == etag)
        {
            Response.Headers.ETag = etag;
            return StatusCode(StatusCodes.Status304NotModified);
        }

        // Resolved through the same ITenantStorageResolver the write path uses
        // (SbomDocumentStore.StageBlobAsync/CommitRowAsync), so the read path applies the
        // resolver's tenant status/provisioning gates and lands on the same store the bytes
        // were written to.
        var stream = await _documents.OpenAsync(orgId, original.BlobKey, ct);
        if (stream is null)
        {
            return NotFound();
        }

        Response.Headers.ETag = etag;
        // Streamed via FileStreamResult (not buffered into a byte[]) — documents run up to
        // Sbom:MaxUploadBytes (50 MB by default).
        return File(stream, ContentTypeFor(original.Format), original.FileName);
    }

    private static string ContentTypeFor(string format) => format switch
    {
        "cyclonedx-json" => CycloneDxContentType,
        "sarif-json" => "application/sarif+json",
        _ => "application/json",
    };
}
