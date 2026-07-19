using System.Diagnostics.CodeAnalysis;
using System.IO.Compression;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit.Events;
using Dependably.Infrastructure.Caching;
using Dependably.Infrastructure.Edge;
using Dependably.Infrastructure.Publish;
using Dependably.Infrastructure.Webhooks;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api.NuGetProtocol;

/// <summary>
/// Handles NuGet package publish (PUT /nuget/publish), symbol push (PUT /nuget/symbols),
/// version unlist (DELETE /nuget/publish/{id}/{version}), and symbol download
/// (GET /nuget/symbols/{id}/{version}/{file}).
/// </summary>
// Full NuGet publish/symbol/unlist surface; the real remedy for the coupling is per-concern
// handler extraction, a separate architectural change.
[SuppressMessage("Major Code Smell", "S1200:Classes should not be coupled to too many other classes",
    Justification = "Full NuGet publish/symbol/unlist surface; coupling is inherent and the remedy is handler extraction, a separate change.")]
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
    NuGetSymbolIndexRepository symbolIndex,
    RenderedResponseCache<NuGetRegistrationKey> cache,
    ILogger<NuGetPublishHandler> logger,
    TimeProvider time,
    string stagingPath,
    AuditRepository audit,
    IPackageEventSink eventSink,
    EdgePublishGuard edgeGuard,
    IUploadLimitResolver uploadLimits)
{
    // Route-level hard ceiling for NuGet push requests (500 MiB); matches NuGetController's
    // [RequestSizeLimit]. Used as the fallback effective cap when no org/instance NuGet limit
    // is configured.
    private const long NuGetUploadSizeLimitBytes = 500L * 1024 * 1024;

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

        // Resolve the effective NuGet upload cap before reading any body bytes, falling back to
        // the route's hard ceiling when no org/instance limit is configured. The resolved cap
        // gates the staging write itself via LimitedReadStream below, so an oversize body is
        // rejected mid-stream instead of after the full artifact is already on disk.
        long effectiveCap = (await uploadLimits.ResolveAsync(orgId, "nuget", ct)) ?? NuGetUploadSizeLimitBytes;

        var (stagedPath, sizeBytes, readError) = await StageNupkgBodyAsync(httpContext, effectiveCap, ct);
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
        // Fail-closed on an edge node: unlist writes yanked=1 on an authoritative version row a
        // cache edge does not own, so it is refused here before any lookup.
        if (edgeGuard.UploadRejection() is { } edgeReject)
        {
            return edgeReject;
        }

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

        // Resolve against the same lowercased canonical form the version is stored under, so
        // unlisting a mixed-case prerelease (e.g. "1.0.0-Beta1") matches regardless of the
        // casing the client puts in the route.
        var pkgVersion = await packages.GetVersionAsync(pkg.Id, NuGetNormalization.NormalizeVersion(version), ct);
        if (pkgVersion is null)
        {
            return new NotFoundResult();
        }

        await using var conn = await db.OpenAsync(ct);
        // Stamp yanked_at so the unlist-age retention gate (purge_unlisted_after_days) can
        // measure time since this unlist rather than since the version was published.
        string yankedAt = time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
        // xtenant: keyed by the version PK resolved above via GetByPurlNameAsync(orgId, …) →
        // GetVersionAsync(pkg.Id, …); an unknown or cross-tenant coordinate already 404'd.
        await conn.ExecuteAsync(
            "UPDATE package_versions SET yanked = 1, yanked_at = @yankedAt WHERE id = @id",
            new { id = pkgVersion.Id, yankedAt });

        // Evict all four registration cache entries (semver1/2 × local/proxy) so the
        // unlisted version disappears from registration index responses immediately.
        string normalizedPurl = id.ToLowerInvariant();
        cache.Evict(new NuGetRegistrationKey(orgId, normalizedPurl, SemVer2: false));
        cache.Evict(new NuGetRegistrationKey(orgId, normalizedPurl, SemVer2: true));
        cache.Evict(new NuGetRegistrationKey(orgId, normalizedPurl, SemVer2: false) { IsProxy = true });
        cache.Evict(new NuGetRegistrationKey(orgId, normalizedPurl, SemVer2: true) { IsProxy = true });

        // Per-version operator action → activity (audit gap: unlist had no activity row before).
        string? actorId = token?.UserId;
        string? actorKind = token?.ActorKind;
        await audit.LogActivityAsync(orgId, "nuget", pkgVersion.Purl, "unlist",
            actorId, actorKind: actorKind, sourceIp: httpContext.GetNormalizedRemoteIp(), ct: ct);

        // Webhook dispatch: notify subscribers of the package.unlist event.
        var orgRecord = await orgs.GetByIdAsync(orgId, ct);
        string orgSlug = orgRecord?.Slug ?? orgId;
        string unlistPayload = new PackageEvents.Unlist("nuget", id, version, pkgVersion.Purl).ToJson();
        eventSink.Dispatch(new PackageEventEnvelope(
            EventType: PackageEvents.TypeUnlist,
            OrgId: orgId,
            OrgSlug: orgSlug,
            Ecosystem: "nuget",
            Name: id,
            Version: version,
            Purl: pkgVersion.Purl,
            ArtifactHash: pkgVersion.ChecksumSha256 is null ? null : "sha256:" + pkgVersion.ChecksumSha256,
            Actor: actorId,
            OccurredAt: time.GetUtcNow(),
            DataJson: unlistPayload));

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
        // Resolve against the same lowercased canonical form the version is stored under
        // (see PublishNuspecAsync) so a mixed-case route segment (e.g. "1.0.0-Beta1") still
        // matches the stored "1.0.0-beta1" row.
        string normalizedSymbolVersion = NuGetNormalization.NormalizeVersion(version);
        var match = versions.FirstOrDefault(v => v.Version == normalizedSymbolVersion && v.BlobKey.EndsWith(".snupkg"));
        if (match is null)
        {
            return new NotFoundResult();
        }

        var stream = await blobs.GetAsync(BlobKeys.StoreKey(match.BlobKey), ct);
        return stream is null
            ? new NotFoundResult()
            : new FileStreamResult(stream, "application/octet-stream") { FileDownloadName = file };
    }

    /// <summary>
    /// Simple Symbol Query Protocol (SSQP) read endpoint. A debugger requests
    /// <c>GET /nuget/symbols/{pdbName}/{key}/{pdbName}</c> where <paramref name="key"/> is the
    /// Portable-PDB debug-id (GUID + <c>ffffffff</c> age). Resolves the key through the per-org
    /// symbol index to the stored <c>.snupkg</c>, extracts the single PDB entry, and streams its
    /// raw bytes as <c>application/octet-stream</c>. Filename + key are matched case-insensitively
    /// (debuggers lowercase them). Honours the same AnonymousPull gate as the <c>.snupkg</c> read
    /// surface; an unindexed key returns 404, and a key belonging to another tenant is never served.
    /// </summary>
    public async Task<IActionResult> GetSymbolFileAsync(
        HttpContext httpContext, string orgId, string pdbName, string key, CancellationToken ct)
    {
        var settings = await orgs.GetSettingsAsync(orgId, ct);
        // Org-scoped resolve: cross-org tokens are coerced to null so AnonymousPull governs.
        var token = await httpContext.Request.ResolveTokenAsync(tokens, orgId, ct);
        if (!settings!.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        var row = await symbolIndex.ResolveAsync(orgId, pdbName, key, ct);
        if (row is null)
        {
            return new NotFoundResult();
        }

        var blobStream = await blobs.GetAsync(BlobKeys.StoreKey(row.SnupkgBlobKey), ct);
        if (blobStream is null)
        {
            return new NotFoundResult();
        }

        // ZipArchive needs a seekable stream to read the central directory. Every in-process blob
        // backend (local disk, in-memory) already returns one; only a genuinely non-seekable source
        // (e.g. a live network response stream) needs buffering first. Buffering the *compressed*
        // archive here carries no amplification risk on its own — the real decompression-bomb risk
        // is the entry's *decompressed* read, which LimitedReadStream caps below.
        var archiveSource = blobStream;
        if (!blobStream.CanSeek)
        {
            var buffered = new MemoryStream();
            await blobStream.CopyToAsync(buffered, ct);
            await blobStream.DisposeAsync();
            buffered.Position = 0;
            archiveSource = buffered;
        }

        ZipArchive zip;
        ZipArchiveEntry? entry;
        try
        {
            // leaveOpen:false — disposing the archive also disposes archiveSource (the buffer, or
            // the original seekable blob stream), so callers only need to track the archive.
            zip = new ZipArchive(archiveSource, ZipArchiveMode.Read, leaveOpen: false);
            entry = zip.GetEntry(row.EntryPath);
        }
        catch (InvalidDataException)
        {
            // The stored .snupkg is no longer a well-formed ZIP (corrupted at rest since indexing).
            await archiveSource.DisposeAsync();
            return new NotFoundResult();
        }

        if (entry is null)
        {
            zip.Dispose();
            return new NotFoundResult();
        }

        Stream entryStream;
        try
        {
            entryStream = new LimitedReadStream(entry.Open(), ZipEntryLimits.MaxPdbEntryBytes, "PDB entry");
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or NotSupportedException)
        {
            zip.Dispose();
            return new NotFoundResult();
        }

        // Stream the entry straight to the response instead of buffering the decompressed PDB
        // into a byte[] first. The archive must stay open for the lifetime of the streamed read,
        // so the response stream disposes both the entry stream and the owning archive together.
        var responseStream = new ZipEntryResponseStream(entryStream, zip);
        return new FileStreamResult(responseStream, "application/octet-stream")
        {
            FileDownloadName = pdbName,
        };
    }

    /// <summary>
    /// Wraps a ZIP entry's (already decompression-bomb-guarded) read stream together with the
    /// owning <see cref="ZipArchive"/> so both are disposed together once the streamed response
    /// finishes. The archive — and, when the blob source needed buffering to seek, its in-memory
    /// buffer, since <see cref="ZipArchive"/> disposes its underlying stream when opened with
    /// <c>leaveOpen: false</c> — must stay alive for the whole streamed read, not just until
    /// <see cref="GetSymbolFileAsync"/> returns.
    /// </summary>
    private sealed class ZipEntryResponseStream(Stream inner, IDisposable owner) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            inner.ReadAsync(buffer, offset, count, cancellationToken);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            inner.ReadAsync(buffer, cancellationToken);

        public override void Flush()
        {
            // Read-only stream: nothing to flush.
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
                owner.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    /// <summary>
    /// Extracts each Portable PDB from the staged <c>.snupkg</c> and records its SSQP key in the
    /// per-org symbol index. Re-reads the staged archive from disk (symbol-push path only) so the
    /// PDBs are parsed without materialising them in managed memory on the hot push path.
    /// Non-Portable / unreadable PDBs are skipped by the extractor.
    /// <paramref name="blobKey"/> is the key the publish service actually stored the
    /// <c>.snupkg</c> under, carried through from <see cref="PublishResult.Accepted"/>: hosted
    /// artifacts are content-addressed, so the key cannot be rebuilt from the coordinate alone.
    /// </summary>
    private async Task IndexSymbolPdbsAsync(
        string orgId, string versionId, string filename, string blobKey,
        string stagedPath, CancellationToken ct)
    {
        IReadOnlyList<PdbSymbol> symbols;
        // stagedPath is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
        using (var fs = new FileStream(
            stagedPath, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 81920, useAsync: false))
        {
            symbols = NuGetSymbolKey.ExtractPortablePdbs(fs);
        }

        if (symbols.Count == 0)
        {
            logger.LogInformation(
                "Symbol package {Filename} for org {OrgId} contained no indexable Portable PDBs.",
                filename, orgId);
            return;
        }

        await symbolIndex.IndexAsync(orgId, versionId, blobKey, symbols, ct);
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
    /// PROXY_STAGING_PATH via <see cref="FormFileStager"/>. The cap gates the copy itself, so an
    /// oversize body is rejected with a 413 during the copy, before the full artifact is ever
    /// fully written to disk. Returns (stagingPath, sizeBytes, null) on success or (null, 0,
    /// error) on shape mismatch or cap breach. The caller is responsible for deleting the
    /// staging file via <see cref="DeleteStagingFile"/>.
    /// </summary>
    private async Task<(string? stagingPath, long sizeBytes, IActionResult? error)> StageNupkgBodyAsync(
        HttpContext httpContext, long cap, CancellationToken ct)
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

        try
        {
            var staged = await FormFileStager.StageAsync(file, stagingPath, cap, ct);
            return (staged.Path, staged.Size, null);
        }
        catch (InvalidDataException)
        {
            return (null, 0, new ObjectResult(
                new ProblemDetails { Detail = "Upload exceeds NuGet size limit.", Status = StatusCodes.Status413PayloadTooLarge })
            { StatusCode = StatusCodes.Status413PayloadTooLarge });
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
    }

    private void DeleteStagingFile(string? path)
    {
        if (path is null) { return; }
        try
        {
            if (System.IO.File.Exists(path))
            {
                // path is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
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

        // Store the same lowercased canonical form every read path resolves against
        // (NuGetNormalization.NormalizeVersion). NuGet clients always lowercase the version
        // segment in flatcontainer/registration URLs, and GetVersionAsync compares against a
        // BINARY-collated version column — a case-preserving stored form (e.g. "1.0.0-Beta1")
        // would never match the lowercased lookup, making mixed-case prereleases undownloadable.
        string normalizedVersion = NuGetNormalization.NormalizeVersion(nuspecVersion);
        string purlName = nuspecId.ToLowerInvariant();
        string filename = $"{purlName}.{normalizedVersion}.{(isSymbol ? "snupkg" : "nupkg")}";

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

        // License rows come from the .nuspec inside the .nupkg. Extracted here (before the
        // publish call) so the hard-block gate inside StoreAndRecordAsync can evaluate it
        // before the version row is persisted; the same extraction is reused below to attach
        // the license rows on acceptance. Reads from the staged temp file so the artifact is
        // never materialized in managed memory on the push path.
        var extracted = ExtractNuspecLicense(stagedPath);
        var publishResult = await publish.StoreAndRecordAsync(
            BuildNuspecPublishRequest(httpContext, ctx, artifact, extracted.Spdx.Count > 0 ? extracted.Spdx : null), ct);

        if (publishResult is PublishResult.Rejected rej)
        {
            return rej.Code == "version_exists"
                ? new ConflictObjectResult(
                    new ProblemDetails { Detail = $"Version {normalizedVersion} already exists.", Status = StatusCodes.Status409Conflict })
                : new ObjectResult(new ProblemDetails { Detail = rej.Message, Status = rej.HttpStatus })
                { StatusCode = rej.HttpStatus };
        }

        var accepted = (PublishResult.Accepted)publishResult;
        string versionId = accepted.VersionId;
        if (extracted.Spdx.Count > 0)
        {
            await licenses.SetLicensesAsync(versionId, extracted.Spdx, "upstream", ct);
        }

        // Symbol packages: index each contained Portable PDB by its SSQP debug-id key so a
        // debugger can later fetch the single PDB via GET /nuget/symbols/{pdb}/{key}/{pdb}. The
        // version row is already committed at this point, so a failure here (corrupt PDB entry,
        // I/O error) must never fail the push or skip the cache eviction below — it is logged and
        // swallowed; the .snupkg itself is still stored and downloadable via GetSymbolsAsync, just
        // not resolvable by debug-id key until a future re-index.
        if (isSymbol)
        {
            try
            {
                await IndexSymbolPdbsAsync(ctx.OrgId, versionId, filename, accepted.BlobKey, stagedPath, ct);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex,
                    "Failed to index symbol package {Filename} for org {OrgId}: {ExceptionType}",
                    filename, ctx.OrgId, ex.GetType().Name);
            }
        }

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
        HttpContext httpContext, NuGetPushContext ctx, NuspecArtifact artifact, IReadOnlyList<string>? licenses)
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
            Licenses = licenses,
        };

    /// <summary>
    /// License rows from the .nuspec inside the .nupkg. Deprecation lives in registration
    /// metadata, not the nuspec — never available at push time, only on proxy fetches with
    /// a registration leaf. Reads from the staged temp file so the artifact is never
    /// materialized in managed memory on the push path.
    /// </summary>
    // stagedPath is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
    private static LicenseExtractor.ExtractedMetadata ExtractNuspecLicense(string stagedPath)
    {
        using var fs = new FileStream(
            stagedPath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 81920, useAsync: false);
        return LicenseExtractor.FromNuspec(fs);
    }

    /// <summary>
    /// Parses the .nupkg or .snupkg ZIP archive from a staging temp file, extracting the
    /// nuspec id and version. Streams from disk — never materializes the archive in a byte[].
    /// Delegates validation to <see cref="NuGetNupkgValidator.ParseFromStream"/> so the
    /// publish path and the import path share a single set of validation rules.
    /// </summary>
    private static (ValidationResult, string? id, string? version) ParseNupkgFromFile(
        string stagedPath, bool isSymbol)
    {
        // stagedPath is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
        using var fileStream = new FileStream(
            stagedPath, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 81920, useAsync: false);
        return NuGetNupkgValidator.ParseFromStream(fileStream, isSymbol);
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
