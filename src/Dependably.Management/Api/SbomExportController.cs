using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Normalized CycloneDX re-renders and verbatim original-document download — two distinct
/// actions per the design: <c>export/sbom</c> and <c>export/vex</c> rebuild a fresh document from
/// the database, while <c>sbom-documents/{id}/original</c> streams back the exact bytes a caller
/// uploaded. All three require only <c>read:packages</c> and write no activity/audit row (matching
/// the existing audit-export posture), org-scoped with the standard 404-not-403 BOLA shape — but
/// <c>export/sbom</c> and <c>export/vex</c> are NOT read-only at the database: resolving D6/D9
/// revision identity (<c>SbomExportService.Revision.cs</c>) mints a row in
/// <c>sbom_export_revisions</c> on a project version's first export and conditionally advances its
/// revision counter on every export after that. A <c>read:packages</c> principal therefore mints a
/// serial and can advance a counter merely by calling a read-scoped endpoint — a real behavioural
/// change from the pre-D6/D9 shape (a fresh, unstored UUID on every call), and one that is safe
/// under concurrent callers only because that resolution path itself is atomic (see
/// <c>ResolveRevisionAsync</c>'s optimistic-concurrency bump).
/// <c>export/sbom</c> and <c>export/vex</c> accept the export-option query parameters resolved by
/// <see cref="TryBuildOptions"/>; every parameter is optional and absent/default values reproduce
/// today's behaviour exactly. <c>scope</c> validates against <see cref="SbomAnalysisProjection.ScopeFilters"/>
/// directly — the same <c>all|prod|dev</c> vocabulary the component table's own filter reads, not
/// a second declaration of it, so the two surfaces cannot drift on what "prod" means.
///   GET /api/v1/projects/{projectId}/export/sbom?variant=inventory|vdr&amp;format=cyclonedx-json&amp;specVersion=1.6|1.7&amp;scope=all|prod|dev        (collections)
///   GET /api/v1/projects/{projectId}/versions/{versionId}/export/sbom?variant=inventory|vdr&amp;format=cyclonedx-json&amp;specVersion=1.6|1.7&amp;scope=all|prod|dev
///   GET /api/v1/projects/{projectId}/versions/{versionId}/export/vex?specVersion=1.6|1.7
///   GET /api/v1/sbom-documents/{documentId}/original
/// </summary>
[ApiController]
[Authorize]
public sealed class SbomExportController : OrgScopedControllerBase
{
    private static readonly HashSet<string> ValidVariants = new(StringComparer.Ordinal) { "inventory", "vdr" };
    private static readonly HashSet<string> ValidFormats = new(StringComparer.Ordinal) { "cyclonedx-json" };
    private static readonly HashSet<string> ValidSpecVersions = new(StringComparer.Ordinal) { "1.6", "1.7" };

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
        string projectId, string versionId,
        [FromQuery] string variant = "inventory",
        [FromQuery] string format = "cyclonedx-json",
        [FromQuery] string specVersion = "1.7",
        [FromQuery] string scope = "all",
        CancellationToken ct = default)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        var validationError = TryBuildOptions(variant, format, specVersion, scope, out var options);
        if (validationError is not null)
        {
            return validationError;
        }

        string orgId = CurrentTenantId();
        string? json = await _export.BuildSbomDocumentAsync(orgId, projectId, versionId, options, ct);
        return json is null ? NotFound() : Content(json, CycloneDxContentTypeFor(specVersion));
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
        string projectId,
        [FromQuery] string variant = "inventory",
        [FromQuery] string format = "cyclonedx-json",
        [FromQuery] string specVersion = "1.7",
        [FromQuery] string scope = "all",
        CancellationToken ct = default)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        var validationError = TryBuildOptions(variant, format, specVersion, scope, out var options);
        if (validationError is not null)
        {
            return validationError;
        }

        string orgId = CurrentTenantId();
        string? json = await _export.BuildCollectionSbomDocumentAsync(orgId, projectId, options, ct);
        return json is null ? NotFound() : Content(json, CycloneDxContentTypeFor(specVersion));
    }

    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/projects/{projectId}/versions/{versionId}/export/vex")]
    public async Task<IActionResult> ExportVex(
        string projectId, string versionId, [FromQuery] string specVersion = "1.7", CancellationToken ct = default)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        if (!ValidSpecVersions.Contains(specVersion))
        {
            return _problems.ValidationErrorActionKey("specVersion", "error.sbom.export.invalidSpecVersion");
        }

        string orgId = CurrentTenantId();
        string? json = await _export.BuildVexDocumentAsync(orgId, projectId, versionId, specVersion, ct);
        return json is null ? NotFound() : Content(json, CycloneDxContentTypeFor(specVersion));
    }

    /// <summary>
    /// Validates the four export query parameters against their closed vocabularies — an
    /// unrecognised value 422s instead of silently falling through to a default — and folds them
    /// into one <see cref="SbomExportOptions"/>, constructed with named arguments per that type's
    /// own contract. Returns the 422 <see cref="IActionResult"/> on the first failing parameter,
    /// or <c>null</c> when every parameter is valid. <paramref name="scope"/> is checked against
    /// <see cref="SbomAnalysisProjection.ScopeFilters"/> itself, not a copy of its values.
    /// </summary>
    private IActionResult? TryBuildOptions(
        string variant, string format, string specVersion, string scope, out SbomExportOptions options)
    {
        options = SbomExportOptions.Default;

        if (!ValidVariants.Contains(variant))
        {
            return _problems.ValidationErrorActionKey("variant", "error.sbom.export.invalidVariant");
        }

        if (!ValidFormats.Contains(format))
        {
            return _problems.ValidationErrorActionKey("format", "error.sbom.export.invalidFormat");
        }

        if (!ValidSpecVersions.Contains(specVersion))
        {
            return _problems.ValidationErrorActionKey("specVersion", "error.sbom.export.invalidSpecVersion");
        }

        if (!SbomAnalysisProjection.ScopeFilters.Contains(scope))
        {
            // Reuses the analysis endpoint's own invalid-scope key rather than minting a
            // near-duplicate — same vocabulary, same message, the same reason the two surfaces
            // share SbomAnalysisProjection.ScopeFilters instead of each declaring their own.
            return _problems.ValidationErrorActionKey("scope", "error.sbom.scopeInvalid");
        }

        options = new SbomExportOptions(
            Variant: variant,
            Format: format,
            SpecVersion: specVersion,
            Filter: scope switch
            {
                "prod" => SbomComponentFilter.Prod,
                "dev" => SbomComponentFilter.Dev,
                _ => SbomComponentFilter.All,
            });
        return null;
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

    /// <summary>
    /// The CycloneDX media type for <paramref name="specVersion"/> — used by every export/sbom and
    /// export/vex response, whose spec version is the caller's own query-param choice.
    /// </summary>
    private static string CycloneDxContentTypeFor(string specVersion) =>
        $"application/vnd.cyclonedx+json; version={specVersion}";

    /// <summary>
    /// The content type for a verbatim original download, keyed on the stored document's own
    /// <c>format</c> — deliberately NOT the request's export-option spec version, which this
    /// endpoint does not take and does not apply to a byte-identical original.
    /// </summary>
    private static string ContentTypeFor(string format) => format switch
    {
        "cyclonedx-json" => CycloneDxContentTypeFor("1.7"),
        "sarif-json" => "application/sarif+json",
        _ => "application/json",
    };
}
