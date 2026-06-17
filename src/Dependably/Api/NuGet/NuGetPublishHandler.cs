using System.IO.Compression;
using System.Xml.Linq;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Infrastructure.Publish;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NuGet.Versioning;

namespace Dependably.Api.NuGetProtocol;

/// <summary>
/// Handles NuGet package publish (PUT /nuget/publish), symbol push (PUT /nuget/symbols),
/// version unlist (DELETE /nuget/publish/{id}/{version}), and symbol download
/// (GET /nuget/symbols/{id}/{version}/{file}).
/// </summary>
public sealed class NuGetPublishHandler(
    OrgRepository orgs,
    PackageRepository packages,
    TokenRepository tokens,
    IBlobStore blobs,
    IMetadataStore db,
    PublishGate publishGate,
    IPackagePublishService publish,
    ClaimResolver claimResolver,
    LicenseRepository licenses,
    RenderedResponseCache<NuGetRegistrationKey> cache,
    ILogger<NuGetPublishHandler> logger,
    string stagingPath)
{
    // Known Microsoft nuspec namespaces
    private static readonly HashSet<string> KnownNuspecNamespaces = [
        "http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd",
        "http://schemas.microsoft.com/packaging/2011/08/nuspec.xsd",
        "http://schemas.microsoft.com/packaging/2011/10/nuspec.xsd",
        "http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd",
        "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"
    ];

    // Maximum NuGet package id length per the NuGet.org spec.
    private const int MaxNuGetIdLength = 100;

    public Task<IActionResult> PushAsync(HttpContext httpContext, string orgId, CancellationToken ct)
        => PushPackageAsync(httpContext, orgId, isSymbol: false, ct);

    public Task<IActionResult> PushSymbolsAsync(HttpContext httpContext, string orgId, CancellationToken ct)
        => PushPackageAsync(httpContext, orgId, isSymbol: true, ct);

    private async Task<IActionResult> PushPackageAsync(
        HttpContext httpContext, string orgId, bool isSymbol, CancellationToken ct)
    {
        var (token, authError) = await ResolveNuGetPushTokenAsync(httpContext, orgId, ct);
        if (authError is not null)
        {
            return authError;
        }

        var (stagedPath, sizeBytes, readError) = await StageNupkgBodyAsync(httpContext, ct);
        if (readError is not null)
        {
            return readError;
        }

        try
        {
            var (parseResult, nuspecId, nuspecVersion) = ParseNupkgFromFile(stagedPath!, isSymbol);
            if (!parseResult.IsValid)
            {
                return new UnprocessableEntityObjectResult(
                    new ProblemDetails { Detail = parseResult.Message, Status = StatusCodes.Status422UnprocessableEntity });
            }

            var settings = await orgs.GetSettingsAsync(orgId, ct);
            long limit = await orgs.GetUploadLimitAsync(settings, "nuget", ct);
            var pushCtx = new NuGetPushContext(orgId, token!, settings, limit);
            return await PublishNuspecAsync(httpContext, pushCtx,
                new NuGetStagedNupkg(nuspecId!, nuspecVersion!, isSymbol, stagedPath!, sizeBytes), ct);
        }
        finally
        {
            DeleteStagingFile(stagedPath);
        }
    }

    public async Task<IActionResult> UnlistAsync(
        HttpContext httpContext, string orgId, string id, string version, CancellationToken ct)
    {
        // [Authorize] + [RequireCapability(YankNuget)] enforce auth + capability on the action.
        // Resolve the token here only for the cross-tenant guard.
        string? apiKey = httpContext.Request.Headers["X-NuGet-ApiKey"].FirstOrDefault();
        TokenRecord? token = null;
        if (apiKey is not null)
        {
            token = await tokens.ResolveAsync(apiKey, ct);
        }

        if (token is null || token.OrgId != orgId)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        var pkg = await packages.GetByPurlNameAsync(orgId, "nuget", id.ToLowerInvariant(), ct);
        if (pkg is null)
        {
            return new NotFoundResult();
        }

        var pkgVersion = await packages.GetVersionAsync(pkg.Id, version, ct);
        if (pkgVersion is null)
        {
            return new NotFoundResult();
        }

        await using var conn = await db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE package_versions SET yanked = 1 WHERE id = @id",
            new { id = pkgVersion.Id });

        // Evict all four registration cache entries (semver1/2 × local/proxy) so the
        // unlisted version disappears from registration index responses immediately.
        string normalizedPurl = id.ToLowerInvariant();
        cache.Evict(new NuGetRegistrationKey(orgId, normalizedPurl, SemVer2: false));
        cache.Evict(new NuGetRegistrationKey(orgId, normalizedPurl, SemVer2: true));
        cache.Evict(new NuGetRegistrationKey(orgId, normalizedPurl, SemVer2: false) { IsProxy = true });
        cache.Evict(new NuGetRegistrationKey(orgId, normalizedPurl, SemVer2: true) { IsProxy = true });

        return new NoContentResult();
    }

    public async Task<IActionResult> GetSymbolsAsync(
        HttpContext httpContext, string orgId, string id, string version, string file, CancellationToken ct)
    {
        var settings = await orgs.GetSettingsAsync(orgId, ct);
        // Org-scoped resolve: cross-org tokens are coerced to null so AnonymousPull governs.
        var token = await httpContext.Request.ResolveTokenAsync(tokens, orgId, ct);
        if (!settings!.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        var pkg = await packages.GetByPurlNameAsync(orgId, "nuget", id.ToLowerInvariant(), ct);
        if (pkg is null)
        {
            return new NotFoundResult();
        }

        var versions = await packages.GetVersionsAsync(pkg.Id, ct);
        string normalizedSymbolVersion = NuGetVersion.TryParse(version, out var snv)
            ? snv.ToNormalizedString() : version;
        var match = versions.FirstOrDefault(v => v.Version == normalizedSymbolVersion && v.BlobKey.EndsWith(".snupkg"));
        if (match is null)
        {
            return new NotFoundResult();
        }

        // Privately-uploaded symbols require a token regardless of AnonymousPull, mirroring the
        // .nupkg path (ServeHostedVersionAsync). Symbols are always uploaded-origin (there is no
        // proxy path for .snupkg), and their PDBs/debug info are at least as sensitive as the
        // package itself, so anonymous read must not leak them even when AnonymousPull is on.
        if (match.Origin == "uploaded" && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        var stream = await blobs.GetAsync(BlobKeys.StoreKey(match.BlobKey), ct);
        return stream is null
            ? new NotFoundResult()
            : new FileStreamResult(stream, "application/octet-stream") { FileDownloadName = file };
    }

    /// <summary>
    /// Cross-tenant guard + token resolution for NuGet push. [Authorize] +
    /// [RequireCapability] on the action method already enforce auth + capability;
    /// this method's only remaining job is to assert the resolved token's tenant
    /// matches the request's tenant and to surface the WWW-Authenticate header on
    /// rejection. Returns the resolved token on success or an IActionResult on
    /// rejection.
    /// </summary>
    private async Task<(TokenRecord? token, IActionResult? error)> ResolveNuGetPushTokenAsync(
        HttpContext httpContext, string orgId, CancellationToken ct)
    {
        string? apiKey = httpContext.Request.Headers["X-NuGet-ApiKey"].FirstOrDefault();
        TokenRecord? token = null;
        if (apiKey is not null)
        {
            token = await tokens.ResolveAsync(apiKey, ct);
        }

        if (token is null || token.OrgId != orgId)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return (null, new UnauthorizedResult());
        }
        return (token, null);
    }

    /// <summary>
    /// Streams the multipart body's first file to a staging temp file under
    /// PROXY_STAGING_PATH. Returns (stagingPath, sizeBytes, null) on success or
    /// (null, 0, error) on shape mismatch. The caller is responsible for deleting
    /// the staging file via <see cref="DeleteStagingFile"/>.
    /// </summary>
    private async Task<(string? stagingPath, long sizeBytes, IActionResult? error)> StageNupkgBodyAsync(
        HttpContext httpContext, CancellationToken ct)
    {
        if (!httpContext.Request.HasFormContentType)
        {
            return (null, 0, new BadRequestObjectResult("Expected multipart/form-data."));
        }

        var form = await httpContext.Request.ReadFormAsync(ct);
        var file = form.Files.Count > 0 ? form.Files[0] : null;
        if (file is null)
        {
            return (null, 0, new UnprocessableEntityObjectResult(
                new ProblemDetails { Detail = "No file in request.", Status = StatusCodes.Status422UnprocessableEntity }));
        }

        // deepcode ignore PT: staging file name is "publish-stage-{server-guid}" under the operator-configured staging root — no user input reaches the path.
        string tempPath = System.IO.Path.Combine(stagingPath, $"publish-stage-{Guid.NewGuid():N}.tmp");
        bool succeeded = false;
        try
        {
            await using (var fileStream = new FileStream(
                tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                bufferSize: 81920, useAsync: true))
            await using (var src = file.OpenReadStream())
            {
                await src.CopyToAsync(fileStream, ct);
            }
            long sizeBytes = new FileInfo(tempPath).Length;
            succeeded = true;
            return (tempPath, sizeBytes, null);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to stage NuGet push body: {ExceptionType}", ex.GetType().Name);
            return (null, 0, new ObjectResult(
                new ProblemDetails { Detail = "Failed to stage upload.", Status = StatusCodes.Status500InternalServerError })
            { StatusCode = StatusCodes.Status500InternalServerError });
        }
        finally
        {
            if (!succeeded)
            {
                DeleteStagingFile(tempPath);
            }
        }
    }

    private void DeleteStagingFile(string? path)
    {
        if (path is null) { return; }
        try
        {
            if (System.IO.File.Exists(path))
            {
                // deepcode ignore PT: path is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
                System.IO.File.Delete(path);
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to delete staging temp file {TempPath}: {ExceptionType}",
                path, ex.GetType().Name);
        }
    }

    /// <summary>
    /// Path-safety + size + claim-gate validation, build the PublishRequest, dispatch to
    /// PackagePublishService, and emit the licence rows on success. The final mile of the
    /// push flow lives here so PushPackageAsync stays a thin orchestrator.
    /// </summary>
    private async Task<IActionResult> PublishNuspecAsync(
        HttpContext httpContext, NuGetPushContext ctx, NuGetStagedNupkg nupkg, CancellationToken ct)
    {
        string nuspecId = nupkg.NuspecId;
        string nuspecVersion = nupkg.NuspecVersion;
        bool isSymbol = nupkg.IsSymbol;
        string stagedPath = nupkg.StagedPath;
        long sizeBytes = nupkg.SizeBytes;

        string normalizedVersion = PurlNormalizer.NormalizeNuGetVersionString(nuspecVersion);
        string purlName = nuspecId.ToLowerInvariant();
        string filename = $"{purlName}.{normalizedVersion.ToLowerInvariant()}.{(isSymbol ? "snupkg" : "nupkg")}";

        if (ValidateNuspecCoordinates(nuspecId, nuspecVersion, filename) is { } pathError)
        {
            return pathError;
        }

        if (await publishGate.CheckAsync(ctx.OrgId, "nuget", purlName, ct) is { } claimReject)
        {
            return claimReject;
        }

        if (sizeBytes > ctx.Limit)
        {
            return new ObjectResult(
                new ProblemDetails { Detail = "Upload exceeds NuGet size limit.", Status = StatusCodes.Status413PayloadTooLarge })
            { StatusCode = StatusCodes.Status413PayloadTooLarge };
        }

        var claim = await claimResolver.ResolveAsync(ctx.OrgId, "nuget", purlName, ct);
        var artifact = new NuspecArtifact(nuspecId, purlName, normalizedVersion, filename, stagedPath, sizeBytes, claim.State);
        var publishResult = await publish.StoreAndRecordAsync(
            BuildNuspecPublishRequest(httpContext, ctx, artifact), ct);

        if (publishResult is PublishResult.Rejected rej)
        {
            return rej.Code == "version_exists"
                ? new ConflictObjectResult(
                    new ProblemDetails { Detail = $"Version {normalizedVersion} already exists.", Status = StatusCodes.Status409Conflict })
                : new ObjectResult(new ProblemDetails { Detail = rej.Message, Status = rej.HttpStatus })
                { StatusCode = rej.HttpStatus };
        }

        string versionId = ((PublishResult.Accepted)publishResult).VersionId;
        await EmitNuspecLicensesAsync(versionId, stagedPath, ct);

        // Evict all four registration cache entries (semver1/2 × local/proxy) so the
        // newly-pushed version appears immediately on the next registration index request.
        cache.Evict(new NuGetRegistrationKey(ctx.OrgId, purlName, SemVer2: false));
        cache.Evict(new NuGetRegistrationKey(ctx.OrgId, purlName, SemVer2: true));
        cache.Evict(new NuGetRegistrationKey(ctx.OrgId, purlName, SemVer2: false) { IsProxy = true });
        cache.Evict(new NuGetRegistrationKey(ctx.OrgId, purlName, SemVer2: true) { IsProxy = true });

        return new StatusCodeResult(StatusCodes.Status201Created);
    }

    /// <summary>
    /// Three path-safety guards in one place. Returns the 422 result on the first failure
    /// or null when all three checks pass. Filename is rebuilt from the normalised id +
    /// version + extension so the safety check covers the actual stored path.
    /// </summary>
    private static UnprocessableEntityObjectResult? ValidateNuspecCoordinates(
        string nuspecId, string nuspecVersion, string filename)
    {
        foreach (var (value, kind) in new[] { (nuspecId, "id"), (nuspecVersion, "version"), (filename, "filename") })
        {
            var check = PathSafeValidator.Validate(value, kind);
            if (!check.IsValid)
            {
                return new UnprocessableEntityObjectResult(
                    new ProblemDetails { Detail = check.Message, Status = StatusCodes.Status422UnprocessableEntity });
            }
        }
        return null;
    }

    private static PublishRequest BuildNuspecPublishRequest(
        HttpContext httpContext, NuGetPushContext ctx, NuspecArtifact artifact)
        => new()
        {
            OrgId = ctx.OrgId,
            Ecosystem = "nuget",
            Name = artifact.NuspecId,
            PurlName = artifact.PurlName,
            Version = artifact.NormalizedVersion,
            Filename = artifact.Filename,
            Purl = PurlNormalizer.NuGet(artifact.NuspecId, artifact.NormalizedVersion),
            ArtifactStagingPath = artifact.StagingPath,
            ArtifactSizeBytes = artifact.SizeBytes,
            Origin = "uploaded",
            SizeCap = ctx.Limit,
            ActorUserId = ctx.Token.UserId,
            ActorKind = ctx.Token.ActorKind,
            AuditAction = "push",
            AllowOverwrite = ctx.Settings?.AllowVersionOverwrite ?? false,
            ClaimState = artifact.ClaimState,
            SourceIp = httpContext.GetNormalizedRemoteIp(),
        };

    /// <summary>
    /// License rows from the .nuspec inside the .nupkg. Deprecation lives in registration
    /// metadata, not the nuspec — never available at push time, only on proxy fetches with
    /// a registration leaf. Reads from the staged temp file so the artifact is never
    /// materialized in managed memory on the push path.
    /// </summary>
    private async Task EmitNuspecLicensesAsync(string versionId, string stagedPath, CancellationToken ct)
    {
        // deepcode ignore PT: stagedPath is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
        await using var fs = new FileStream(
            stagedPath, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 81920, useAsync: true);
        var extracted = LicenseExtractor.FromNuspec(fs);
        if (extracted.Spdx.Count > 0)
        {
            await licenses.SetLicensesAsync(versionId, extracted.Spdx, "upstream", ct);
        }
    }

    /// <summary>
    /// Parses the .nupkg or .snupkg ZIP archive from a staging temp file, extracting the
    /// nuspec id and version. Streams from disk — never materializes the archive in a byte[].
    /// </summary>
    private static (ValidationResult, string? id, string? version) ParseNupkgFromFile(
        string stagedPath, bool isSymbol)
    {
        try
        {
            // deepcode ignore PT: stagedPath is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
            using var fileStream = new FileStream(
                stagedPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                bufferSize: 81920, useAsync: false);
            using var zip = new ZipArchive(fileStream, ZipArchiveMode.Read);

            if (isSymbol)
            {
                bool hasPdb = zip.Entries.Any(e => e.Name.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase));
                if (!hasPdb)
                {
                    return (ValidationResult.Fail("content", ".snupkg must contain at least one .pdb file"), null, null);
                }
            }

            var nuspecEntry = zip.Entries.FirstOrDefault(e =>
                e.Name.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase) &&
                !e.FullName.Contains('/'));

            if (nuspecEntry is null)
            {
                return (ValidationResult.Fail("content", "No .nuspec found at ZIP root"), null, null);
            }

            using var nuspecStream = new LimitedReadStream(
                nuspecEntry.Open(), ZipEntryLimits.MaxMetadataEntryBytes, "nuspec");
            var doc = XDocument.Load(nuspecStream);
            string ns = doc.Root?.Name.NamespaceName ?? "";

            if (!KnownNuspecNamespaces.Contains(ns))
            {
                return (ValidationResult.Fail("content", $"Unknown nuspec namespace: {ns}"), null, null);
            }

            XNamespace xns = ns;
            var metadata = doc.Root?.Element(xns + "metadata");
            string? id = metadata?.Element(xns + "id")?.Value?.Trim();
            string? version = metadata?.Element(xns + "version")?.Value?.Trim();
            string? description = metadata?.Element(xns + "description")?.Value?.Trim();
            string? authors = metadata?.Element(xns + "authors")?.Value?.Trim();

            if (string.IsNullOrEmpty(id) || id.Length > MaxNuGetIdLength)
            {
                return (ValidationResult.Fail("id", "id must be 1-100 characters"), null, null);
            }

            if (!NuGetIdValidator.IsValidId(id))
            {
                return (ValidationResult.Fail("id", "id contains invalid characters"), null, null);
            }

            if (!NuGetVersion.TryParse(version, out _))
            {
                return (ValidationResult.Fail("version", $"Invalid NuGet version: {version}"), null, null);
            }

            if (string.IsNullOrEmpty(description))
            {
                return (ValidationResult.Fail("description", "description is required"), null, null);
            }

            if (string.IsNullOrEmpty(authors))
            {
                return (ValidationResult.Fail("authors", "authors is required"), null, null);
            }

            return (ValidationResult.Ok(), id, version);
        }
        catch (Exception ex)
        {
            return (ValidationResult.Fail("content", $"Invalid ZIP/OPC: {ex.Message}"), null, null);
        }
    }

    // Publish-side context for NuGet push: tenant id, resolved token, the org's settings
    // row (nullable for fresh tenants), and the resolved size cap.
    private sealed record NuGetPushContext(
        string OrgId, TokenRecord Token, OrgSettings? Settings, long Limit);

    // Artifact-level coordinates resolved from the nuspec and used to build the PublishRequest.
    // Bundles the per-file inputs so BuildNuspecPublishRequest stays within the parameter limit.
    private sealed record NuspecArtifact(
        string NuspecId, string PurlName, string NormalizedVersion,
        string Filename, string StagingPath, long SizeBytes, string ClaimState);

    // Staged nupkg inputs from the parse step: raw nuspec id/version, symbol flag, staging
    // path and byte count. Bundles the five per-file values so PublishNuspecAsync stays within
    // the S107 parameter limit.
    private sealed record NuGetStagedNupkg(
        string NuspecId, string NuspecVersion, bool IsSymbol, string StagedPath, long SizeBytes);
}
