using System.Text;
using System.Text.Json.Nodes;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Infrastructure.Edge;
using Dependably.Infrastructure.Publish;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api.NpmProtocol;

/// <summary>
/// Handles npm publish (PUT /npm/{pkg}), deprecate (PUT without _attachments), and the
/// unpublish surface. Modern per-version unpublish is a three-step wire sequence — GET the
/// packument (reads its synthetic _rev), PUT the pruned packument to /npm/{pkg}/-rev/{rev}, then
/// DELETE /npm/{pkg}/-/{tarball}/-rev/{rev} — alongside the bare DELETE /npm/{pkg}/-rev/{rev}
/// version/whole-package path. Publish and deprecate route by the shape of the PUT body:
/// _attachments present = publish, absent = deprecate.
/// </summary>
public sealed class NpmPublishHandler(
    OrgRepository orgs,
    PackageRepository packages,
    TokenRepository tokens,
    AuditRepository audit,
    IBlobStore blobs,
    IPackagePublishService publish,
    ClaimResolver claimResolver,
    LicenseRepository licenses,
    IUploadLimitResolver uploadLimits,
    NpmDistTagRepository distTags,
    MetadataInvalidationCoordinator invalidation,
    EdgePublishGuard edgeGuard,
    string stagingPath)
{
    // Route-level hard ceiling for npm publish requests (500 MiB); per-tenant limits are
    // enforced by UploadSizeLimitMiddleware before any blob is written.
    private const long NpmPublishSizeLimitBytes = 500L * 1024 * 1024;

    // Ceiling for the pruned-packument body the unpublish rev-PUT accepts. Metadata-only (no
    // attachments) but grows with the version list, so it is bounded well above a large packument
    // and well below the publish ceiling.
    private const long PrunePackumentMaxBytes = 32L * 1024 * 1024;

    public Task<IActionResult> PublishAsync(
        HttpContext httpContext, string orgId, string package, CancellationToken ct)
    {
        // The npm CLI publishes a scoped package as a single %2F-encoded path segment
        // (PUT /npm/@scope%2Fname), which never matches the two-segment scoped route
        // [HttpPut("/npm/@{scope}/{package}")] — ASP.NET keeps %2F encoded — so it lands
        // here on the unscoped route. Decode (as every other unscoped npm route already
        // does) and split the leading @scope/ so the publish is validated as scoped
        // instead of failing name validation as a bogus plain name ("@scope/name").
        string decoded = NpmSharedHelpers.DecodeNpmName(package);
        if (decoded.StartsWith('@'))
        {
            int slash = decoded.IndexOf('/');
            if (slash > 1 && slash < decoded.Length - 1)
            {
                return PublishPackageAsync(httpContext, orgId, decoded[(slash + 1)..], decoded[..slash], ct);
            }
        }
        return PublishPackageAsync(httpContext, orgId, decoded, scope: null, ct);
    }

    public Task<IActionResult> PublishScopedAsync(
        HttpContext httpContext, string orgId, string scope, string package, CancellationToken ct)
        => PublishPackageAsync(httpContext, orgId, package, scope: "@" + scope, ct);

    public Task<IActionResult> UnpublishAsync(
        HttpContext httpContext, string orgId, string pkg, string rev, CancellationToken ct)
        => UnpublishImplAsync(httpContext, orgId, NpmSharedHelpers.DecodeNpmName(pkg), rev, ct);

    public Task<IActionResult> UnpublishScopedAsync(
        HttpContext httpContext, string orgId, string scope, string pkg, string rev, CancellationToken ct)
        => UnpublishImplAsync(httpContext, orgId, "@" + scope + "/" + pkg, rev, ct);

    public Task<IActionResult> UnpublishRevPutAsync(
        HttpContext httpContext, string orgId, string pkg, string rev, CancellationToken ct)
        => UnpublishRevPutImplAsync(httpContext, orgId, NpmSharedHelpers.DecodeNpmName(pkg), rev, ct);

    public Task<IActionResult> UnpublishRevPutScopedAsync(
        HttpContext httpContext, string orgId, string scope, string pkg, string rev, CancellationToken ct)
        => UnpublishRevPutImplAsync(httpContext, orgId, "@" + scope + "/" + pkg, rev, ct);

    public Task<IActionResult> DeleteTarballWithRevAsync(
        HttpContext httpContext, string orgId, string pkg, string file, string rev, CancellationToken ct)
        => DeleteTarballWithRevImplAsync(httpContext, orgId, NpmSharedHelpers.DecodeNpmName(pkg), file, rev, ct);

    public Task<IActionResult> DeleteTarballWithRevScopedAsync(
        HttpContext httpContext, string orgId, string scope, string pkg, string file, string rev, CancellationToken ct)
        => DeleteTarballWithRevImplAsync(httpContext, orgId, "@" + scope + "/" + pkg, file, rev, ct);

    private async Task<IActionResult> PublishPackageAsync(
        HttpContext httpContext, string orgId, string package, string? scope, CancellationToken ct)
    {
        // Fail-closed on an edge node: this PUT surface is both publish and deprecate. Publish
        // funnels through PackagePublishService (which also refuses on edge), but deprecate mutates
        // the deprecated column directly, so the whole surface is refused here at the choke point.
        if (edgeGuard.UploadRejection() is { } edgeReject)
        {
            return edgeReject;
        }

        // [Authorize] above already enforced auth + capability. We still resolve the token
        // for the cross-tenant guard (token.OrgId vs requested org) and to attribute the
        // audit row to the token owner (token.UserId).
        var token = await httpContext.Request.ResolveTokenAsync(tokens, ct);
        if (token is null || token.OrgId != orgId)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        // Resolve the effective npm upload limit before reading any body bytes. The resolved
        // limit gates both the body read (via LimitedReadStream) and the attachment pre-check
        // (declared length vs limit before base64 decode). Falls back to the 500 MB route
        // ceiling when no org/instance npm limit is configured, so the explicit cap always
        // applies regardless of whether the middleware set MaxRequestBodySize.
        long npmBodyCap = (await uploadLimits.ResolveAsync(orgId, "npm", ct)) ?? NpmPublishSizeLimitBytes;

        // Stream-parse the publish body: the raw body is spooled to a staging file, the base64
        // tarball under _attachments.{key}.data is base64-decoded incrementally straight to a
        // second staging file, and only a small redacted envelope DOM (name / versions /
        // dist-tags / _attachments with the data value elided) is materialised. The full tarball
        // and its base64 encoding never enter managed memory.
        var parsed = await NpmPublishBodyParser.ParseAsync(httpContext.Request.Body, npmBodyCap, stagingPath, ct);
        if (parsed.ErrorKind is not NpmPublishBodyParser.NpmParseErrorKind.None)
        {
            return MapParseError(parsed);
        }

        var body = parsed.Envelope;
        string? attachStagingPath = parsed.TarballPath;

        string fullName = scope is not null ? $"{scope}/{package}" : package;
        string plainName = scope is not null ? package : fullName;

        var nameError = ValidatePackageName(body, fullName, plainName);
        if (nameError is not null)
        {
            DeleteNpmStagingFile(attachStagingPath);
            return nameError;
        }

        // Detect the no-attachments shape: npm deprecate sends a packument PUT without the
        // _attachments key at all. Route to the deprecation handler. An empty or multi-entry
        // _attachments object is rejected as a 422 inside the parser, so a body that reaches here
        // with _attachments present has exactly one staged tarball.
        if (body?["_attachments"] is null)
        {
            DeleteNpmStagingFile(attachStagingPath);
            return await HandleDeprecateAsync(httpContext, orgId, body, fullName, token, ct);
        }

        string? attachmentKey = parsed.AttachmentKey;
        long stagingSize = parsed.TarballSize;

        try
        {
            return await PublishAttachmentAsync(
                httpContext, orgId, fullName, body, token, attachStagingPath!, attachmentKey!, stagingSize, ct);
        }
        finally
        {
            DeleteNpmStagingFile(attachStagingPath);
        }
    }

    // Validates the staged tarball against the packument body, builds the install manifest,
    // enforces the per-tenant size cap, then stores + records the version and persists its
    // dist-tags. Split out of PublishPackageAsync, which owns the staging-file lifetime
    // (stream-parse the body, delete the staged tarball in its finally) around this call.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Each argument is a distinct publish-coordinate/staging input threaded from PublishAsync's single caller.")]
    private async Task<IActionResult> PublishAttachmentAsync(
        HttpContext httpContext, string orgId, string fullName, JsonNode? body, TokenRecord token,
        string attachStagingPath, string attachmentKey, long stagingSize, CancellationToken ct)
    {
        var (innerName, innerVersion, tarballManifest, tarballError) =
            ValidateTarballAndExtractNameVersionFromFile(attachStagingPath);
        if (tarballError is not null)
        {
            return tarballError;
        }

        var versions = body?["versions"]?.AsObject();
        string? versionKey = versions?.First().Key;
        var matchError = ValidateBodyMatch(versionKey, innerName, innerVersion, fullName);
        if (matchError is not null)
        {
            return matchError;
        }

        // Install-relevant manifest subset from the tarball's package.json (the parse
        // above — artefact-authoritative, no extra tarball read) plus the publisher's
        // verbatim dist.integrity claim from the publish body. Persisted on the version
        // row so the packument can advertise bin/dependencies/engines/dist.integrity.
        var bodyVersion = versions?[versionKey!];
        string? manifestJson = NpmInstallManifest.BuildJson(tarballManifest, bodyVersion, fullName);
        string? declaredIntegrity = NpmInstallManifest.DeclaredIntegritySri(bodyVersion);

        string filename = attachmentKey.Split('/').Last(); // e.g. package-1.0.0.tgz

        // Per-tenant + per-ecosystem upload size cap. The publish service enforces it
        // again as a safety net but we keep this lookup here so the existing
        // UploadSizeLimitError shape (413 with the same body) is preserved verbatim.
        var sizeError = await CheckUploadSizeFromFileAsync(orgId, stagingSize, ct);
        if (sizeError is not null)
        {
            return sizeError;
        }

        var orgSettings = await orgs.GetSettingsAsync(orgId, ct);
        var claim = await claimResolver.ResolveAsync(orgId, "npm", fullName, ct);

        // License: read the tarball's package.json (canonical, matches the proxy first-fetch
        // path) before the publish call so the hard-block gate inside StoreAndRecordAsync can
        // evaluate it before the version row is persisted. Fall back to the packument when the
        // tarball lacks a parseable package/package.json — many publish clients don't include
        // license in the packument's version object. Deprecation only ever lives in the
        // packument (npm deprecate writes there). Reads from the staged temp file — the tarball
        // is never materialized in managed memory.
        var fromTarball = ExtractNpmTarballLicense(attachStagingPath);
        var fromPackument = LicenseExtractor.FromNpmPackumentVersion(bodyVersion);
        var spdx = fromTarball.Spdx.Count > 0 ? fromTarball.Spdx : fromPackument.Spdx;
        // Presentation metadata: the tarball's package.json is canonical; fall back to the
        // packument version object per field when the tarball omits one.
        string? homepage = fromTarball.Homepage ?? fromPackument.Homepage;
        string? repository = fromTarball.Repository ?? fromPackument.Repository;
        string? description = fromTarball.Description ?? fromPackument.Description;

        var request = BuildNpmPublishRequest(httpContext, new NpmPublishContext(
            orgId, fullName, versionKey!, filename, attachStagingPath, stagingSize,
            token.UserId, token.ActorKind, orgSettings?.AllowVersionOverwrite ?? false, claim.State,
            manifestJson, declaredIntegrity, spdx.Count > 0 ? spdx : null,
            homepage, repository, description)) with
        { ActorTokenId = token.Id };
        var result = await publish.StoreAndRecordAsync(request, ct);

        if (result is PublishResult.Rejected rej)
        {
            return MapPublishRejection(rej, versionKey!);
        }

        string versionId = ((PublishResult.Accepted)result).VersionId;
        if (spdx.Count > 0)
        {
            await licenses.SetLicensesAsync(versionId, spdx, "upstream", ct);
        }
        if (fromPackument.Deprecated is not null)
        {
            await packages.UpdateDeprecatedAsync(versionId, fromPackument.Deprecated, ct);
        }

        // Persist dist-tags from the packument. npm sends {"dist-tags":{"beta":"1.0.0-beta.1"}}
        // on `npm publish --tag beta`. When no dist-tags object is present, default to 'latest'.
        var pkg = await packages.GetByPurlNameAsync(orgId, "npm", fullName, ct);
        if (pkg is not null)
        {
            await PersistPublishDistTagsAsync(orgId, pkg.Id, body, versionKey!, ct);
        }

        // Invalidate the cached packument so the newly-published version appears immediately —
        // on this replica and, when a fan-out transport is configured, on its peers.
        invalidation.Invalidate(MetadataInvalidation.ForNpm(orgId, fullName));

        return new OkResult();
    }

    // Reads the dist-tags map from the publish body and persists each tag. When no
    // dist-tags object is in the body (or it is empty) the version is set as 'latest'
    // only when no 'latest' tag already exists — so a pre-release publish without an
    // explicit --tag does not silently take over 'latest'.
    private async Task PersistPublishDistTagsAsync(
        string orgId, string packageId, JsonNode? body, string version, CancellationToken ct)
    {
        var distTagsNode = body?["dist-tags"]?.AsObject();
        bool anySaved = false;
        if (distTagsNode is not null)
        {
            foreach (var (tag, tagVal) in distTagsNode)
            {
                string? tagVersion = tagVal?.GetValue<string>();
                if (tagVersion is null)
                {
                    continue;
                }
                await distTags.SetTagAsync(orgId, packageId, tag, tagVersion, ct);
                anySaved = true;
            }
        }

        // No explicit tags: seed 'latest' only when the package has no persisted 'latest' yet,
        // so a bare `npm publish` on a fresh package gets a 'latest' pointer without overwriting
        // a tag that was set by a previous publish with an explicit --tag.
        if (!anySaved)
        {
            var existing = await distTags.GetTagsAsync(orgId, packageId, ct);
            if (!existing.ContainsKey("latest"))
            {
                await distTags.SetTagAsync(orgId, packageId, "latest", version, ct);
            }
        }
    }

    // Bundles BuildNpmPublishRequest's tail-end coordinates into a single param to keep the
    // builder's signature within S107's threshold while preserving the ergonomic call shape.
    private sealed record NpmPublishContext(
        string OrgId, string FullName, string VersionKey, string Filename,
        string StagingPath, long StagingSize,
        string? ActorUserId, string? ActorKind, bool AllowOverwrite, string ClaimState,
        string? ManifestJson, string? DeclaredIntegritySri, IReadOnlyList<string>? Licenses,
        string? Homepage, string? Repository, string? Description);

    private static PublishRequest BuildNpmPublishRequest(HttpContext httpContext, NpmPublishContext ctx)
        => new()
        {
            OrgId = ctx.OrgId,
            Ecosystem = "npm",
            Name = ctx.FullName,
            PurlName = ctx.FullName,
            Version = ctx.VersionKey,
            Filename = ctx.Filename,
            Purl = PurlNormalizer.Npm(ctx.FullName, ctx.VersionKey),
            ArtifactStagingPath = ctx.StagingPath,
            ArtifactSizeBytes = ctx.StagingSize,
            // Already enforced by CheckUploadSizeFromFileAsync; service-side cap is defence in depth.
            SizeCap = long.MaxValue,
            Origin = "uploaded",
            ActorUserId = ctx.ActorUserId,
            ActorKind = ctx.ActorKind,
            AuditAction = "push",
            AllowOverwrite = ctx.AllowOverwrite,
            ClaimState = ctx.ClaimState,
            SourceIp = httpContext.GetNormalizedRemoteIp(),
            ManifestJson = ctx.ManifestJson,
            DeclaredIntegritySri = ctx.DeclaredIntegritySri,
            Licenses = ctx.Licenses,
            Homepage = ctx.Homepage,
            Repository = ctx.Repository,
            Description = ctx.Description,
        };

    // stagingPath is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
    private static LicenseExtractor.ExtractedMetadata ExtractNpmTarballLicense(string stagingPath)
    {
        using var fs = new FileStream(
            stagingPath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 81920, useAsync: false);
        return LicenseExtractor.FromNpmTarballPackageJson(fs);
    }

    // Handles the no-attachments PUT shape sent by `npm deprecate`. The body contains a
    // versions map where each version object may carry a `deprecated` string (empty string
    // means undeprecate). Updates the deprecated column for every version present in the
    // body; versions absent from the body are left unchanged.
    private async Task<IActionResult> HandleDeprecateAsync(
        HttpContext httpContext, string orgId, JsonNode? body, string fullName,
        TokenRecord token, CancellationToken ct)
    {
        var versionsNode = body?["versions"]?.AsObject();
        if (versionsNode is null || versionsNode.Count == 0)
        {
            return new UnprocessableEntityObjectResult(new ProblemDetails
            {
                Detail = "No versions found in body. Both _attachments and versions are missing.",
                Status = StatusCodes.Status422UnprocessableEntity
            });
        }

        var pkg = await packages.GetByPurlNameAsync(orgId, "npm", fullName, ct);
        if (pkg is null)
        {
            return new NotFoundResult();
        }

        foreach (var (versionKey, versionNode) in versionsNode)
        {
            var ver = await packages.GetVersionAsync(pkg.Id, versionKey, ct);
            if (ver is null)
            {
                continue;
            }

            // An empty string means "undeprecate" per npm protocol conventions.
            // Non-string values (e.g. booleans, numbers) in the deprecated field are
            // treated as absent — GetValue<string>() throws on mismatched kinds, so the
            // node kind is checked first.
            var deprecatedNode = versionNode?["deprecated"];
            if (deprecatedNode is not null
                && deprecatedNode.GetValueKind() != System.Text.Json.JsonValueKind.String)
            {
                continue;
            }

            string? deprecatedMsg = deprecatedNode?.GetValue<string>();
            string? stored = string.IsNullOrEmpty(deprecatedMsg) ? null : deprecatedMsg;
            await packages.UpdateDeprecatedAsync(ver.Id, stored, ct);
        }

        await audit.LogActivityAsync(orgId, "npm", fullName, "deprecate", token.UserId,
            actorKind: token.ActorKind, sourceIp: httpContext.GetNormalizedRemoteIp(), ct: ct);

        // Invalidate the cached packument so the deprecation change is visible immediately.
        invalidation.Invalidate(MetadataInvalidation.ForNpm(orgId, fullName));

        return new OkResult();
    }

    private static ObjectResult MapPublishRejection(PublishResult.Rejected rej, string versionKey) => rej.Code switch
    {
        "version_exists" => new ConflictObjectResult(new ProblemDetails { Detail = $"Version {versionKey} already exists.", Status = StatusCodes.Status409Conflict }),
        _ => new ObjectResult(new ProblemDetails { Detail = rej.Message, Status = rej.HttpStatus }) { StatusCode = rej.HttpStatus },
    };

    // Maps a streaming-parser failure to the exact HTTP result the pre-streaming handler produced:
    // a cap breach or an over-cap declared attachment length → 413; malformed JSON or a bad
    // _attachments shape → 422.
    private static ObjectResult MapParseError(NpmPublishBodyParser.NpmParseResult parsed)
    {
        string detail = parsed.ErrorDetail ?? "Invalid publish body.";
        return parsed.ErrorKind switch
        {
            NpmPublishBodyParser.NpmParseErrorKind.TooLarge => new ObjectResult(new ProblemDetails
            {
                Detail = detail,
                Status = StatusCodes.Status413PayloadTooLarge,
            })
            { StatusCode = StatusCodes.Status413PayloadTooLarge },
            _ => new UnprocessableEntityObjectResult(new ProblemDetails
            {
                Detail = detail,
                Status = StatusCodes.Status422UnprocessableEntity,
            }),
        };
    }

    private static UnprocessableEntityObjectResult? ValidatePackageName(JsonNode? body, string fullName, string plainName)
    {
        string bodyName = body?["name"]?.GetValue<string>() ?? "";
        return bodyName != fullName
            ? new UnprocessableEntityObjectResult(new ProblemDetails { Detail = "name in body does not match URL.", Status = StatusCodes.Status422UnprocessableEntity })
            : !NpmNameValidator.IsValidPlainName(plainName)
            ? new UnprocessableEntityObjectResult(new ProblemDetails { Detail = $"Invalid npm package name: {plainName}", Status = StatusCodes.Status422UnprocessableEntity })
            : null;
    }

    private async Task<IActionResult?> CheckUploadSizeFromFileAsync(string orgId, long sizeBytes, CancellationToken ct)
    {
        var settings = await orgs.GetSettingsAsync(orgId, ct);
        long limit = await orgs.GetUploadLimitAsync(settings, "npm", ct);
        return sizeBytes > limit
            ? new ObjectResult(new ProblemDetails { Detail = "Upload exceeds npm size limit.", Status = StatusCodes.Status413PayloadTooLarge })
            { StatusCode = StatusCodes.Status413PayloadTooLarge }
            : null;
    }

    private static (string? InnerName, string? InnerVersion, JsonObject? Manifest, IActionResult? Error)
        ValidateTarballAndExtractNameVersionFromFile(string fileStagingPath)
    {
        // Stream the staged tarball through the validator rather than reading the whole artifact
        // back into a byte[] — the gzip/tar decompression is already bounded by TarScanLimits.
        // fileStagingPath is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
        using var tarball = new System.IO.FileStream(
            fileStagingPath, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.Read,
            bufferSize: 81920, useAsync: false);
        var parsed = NpmTarballValidator.Validate(tarball);
        return parsed.Validation.IsValid
            ? (parsed.Name, parsed.Version, parsed.Manifest, null)
            : (null, null, null, new UnprocessableEntityObjectResult(new ProblemDetails { Detail = parsed.Validation.Message, Status = StatusCodes.Status422UnprocessableEntity }));
    }

    private static void DeleteNpmStagingFile(string? path)
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
        catch
        {
            // Best-effort cleanup; a leaked temp file under PROXY_STAGING_PATH is
            // operator-visible and can be purged on restart.
        }
    }

    private static UnprocessableEntityObjectResult? ValidateBodyMatch(
        string? versionKey, string? innerName, string? innerVersion, string fullName) =>
        versionKey is null
            ? new UnprocessableEntityObjectResult(new ProblemDetails { Detail = "versions object is empty.", Status = StatusCodes.Status422UnprocessableEntity })
            : innerName != fullName
                ? new UnprocessableEntityObjectResult(new ProblemDetails
                {
                    Detail = $"package.json name '{innerName}' does not match published name '{fullName}'.",
                    Status = StatusCodes.Status422UnprocessableEntity,
                })
                : innerVersion != versionKey
                    ? new UnprocessableEntityObjectResult(new ProblemDetails
                    {
                        Detail = $"package.json version '{innerVersion}' does not match declared version '{versionKey}'.",
                        Status = StatusCodes.Status422UnprocessableEntity,
                    })
                    : null;

    private async Task<IActionResult> UnpublishImplAsync(
        HttpContext httpContext, string orgId, string fullName, string rev, CancellationToken ct)
    {
        // Fail-closed on an edge node: unpublish deletes an authoritative artifact + DB rows a
        // cache edge does not own, so it is refused here before any lookup.
        if (edgeGuard.UploadRejection() is { } edgeReject)
        {
            return edgeReject;
        }

        var token = await httpContext.Request.ResolveTokenAsync(tokens, ct);
        if (token is null || token.OrgId != orgId)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        // rev encodes the version: npm sends "{version}-{rev}" or just the version.
        // Extract the version portion: the part before the first '-' following a digit,
        // but more reliably just strip the known pattern by checking for an existing version row.
        var pkg = await packages.GetByPurlNameAsync(orgId, "npm", fullName, ct);
        if (pkg is null)
        {
            return new NotFoundResult();
        }

        // Resolve version from the rev parameter. npm sends the version string directly as
        // the rev in modern clients; older clients may append "-N". Try the rev as-is first,
        // then strip a trailing dash-suffix if no match.
        var ver = await packages.GetVersionAsync(pkg.Id, rev, ct);
        if (ver is null)
        {
            // Try stripping the last "-N" rev suffix that some clients append.
            int dash = rev.LastIndexOf('-');
            if (dash > 0)
            {
                string candidate = rev[..dash];
                ver = await packages.GetVersionAsync(pkg.Id, candidate, ct);
            }
        }

        if (ver is null)
        {
            // Whole-package unpublish would need all versions to be listed in the body, so
            // we conservatively return 403 and direct the caller to the management API.
            return new ObjectResult(new ProblemDetails
            {
                Detail = "Whole-package unpublish is not supported via the npm protocol. " +
                         "Use the management API to delete individual versions.",
                Status = StatusCodes.Status403Forbidden
            })
            { StatusCode = StatusCodes.Status403Forbidden };
        }

        if (ver.Origin != "uploaded")
        {
            return OnlyUploadedVersionsForbidden();
        }

        await ApplyVersionRemovalsAsync(httpContext, orgId, pkg, fullName, new[] { ver }, token, ct);
        return new OkResult();
    }

    // Modern npm per-version unpublish PUTs the pruned packument back to /npm/{pkg}/-rev/{rev}
    // (the rev read from the packument's synthetic _rev). The body's "versions" map is the set
    // the client wants to KEEP; any stored uploaded version absent from it is the one being
    // unpublished, so this diffs stored-uploaded against the keep-set and removes the difference.
    private async Task<IActionResult> UnpublishRevPutImplAsync(
        HttpContext httpContext, string orgId, string fullName, string rev, CancellationToken ct)
    {
        if (edgeGuard.UploadRejection() is { } edgeReject)
        {
            return edgeReject;
        }

        var token = await httpContext.Request.ResolveTokenAsync(tokens, ct);
        if (token is null || token.OrgId != orgId)
        {
            return UnauthorizedBearer(httpContext);
        }

        // Fail loud on an unresolvable revision. A packument that advertises no _rev makes the
        // CLI PUT to /-rev/undefined; refuse it so the failure is visible instead of the version
        // appearing removed while it still lists.
        if (IsUnresolvableRev(rev))
        {
            return UnresolvableRevConflict(rev);
        }

        JsonObject? keepVersions;
        try
        {
            keepVersions = await ReadPackumentKeepVersionsAsync(httpContext.Request, ct);
        }
        catch (System.Text.Json.JsonException)
        {
            return new UnprocessableEntityObjectResult(new ProblemDetails
            {
                Detail = "Malformed packument body.",
                Status = StatusCodes.Status422UnprocessableEntity
            });
        }

        if (keepVersions is null || keepVersions.Count == 0)
        {
            // A prune that keeps zero versions is a whole-package unpublish, which npm sends as a
            // bare DELETE /-rev/{rev}. Refuse the empty-keep-set PUT rather than mass-delete on a
            // truncated or malformed body.
            return new UnprocessableEntityObjectResult(new ProblemDetails
            {
                Detail = "Packument body must list the versions to keep. " +
                         "Whole-package unpublish uses DELETE, not PUT.",
                Status = StatusCodes.Status422UnprocessableEntity
            });
        }

        var pkg = await packages.GetByPurlNameAsync(orgId, "npm", fullName, ct);
        if (pkg is null)
        {
            return new NotFoundResult();
        }

        // Only user-published (uploaded) versions can be unpublished; proxy-cached versions are
        // never advertised as removable, so a version absent from the keep-set that is not
        // uploaded is left untouched.
        var stored = await packages.GetVersionsAsync(pkg.Id, ct);
        var toPrune = stored
            .Where(v => v.Origin == "uploaded" && !keepVersions.ContainsKey(v.Version))
            .ToList();

        if (toPrune.Count > 0)
        {
            await ApplyVersionRemovalsAsync(httpContext, orgId, pkg, fullName, toPrune, token, ct);
        }

        // CouchDB-style ok envelope so the CLI treats the prune as applied.
        return new OkObjectResult(new JsonObject { ["ok"] = true, ["id"] = fullName, ["rev"] = rev });
    }

    // Final step of the modern unpublish flow: DELETE /npm/{pkg}/-/{file}/-rev/{rev}. The rev-PUT
    // above already pruned the version, so this is normally an idempotent confirmation — it still
    // removes the version defensively when a client skips the PUT step.
    private async Task<IActionResult> DeleteTarballWithRevImplAsync(
        HttpContext httpContext, string orgId, string fullName, string file, string rev, CancellationToken ct)
    {
        if (edgeGuard.UploadRejection() is { } edgeReject)
        {
            return edgeReject;
        }

        var token = await httpContext.Request.ResolveTokenAsync(tokens, ct);
        if (token is null || token.OrgId != orgId)
        {
            return UnauthorizedBearer(httpContext);
        }

        if (IsUnresolvableRev(rev))
        {
            return UnresolvableRevConflict(rev);
        }

        var pkg = await packages.GetByPurlNameAsync(orgId, "npm", fullName, ct);
        if (pkg is null)
        {
            // The rev-PUT prune already removed the version and its now-empty package — nothing
            // left for this final idempotent step.
            return new OkResult();
        }

        string plainName = fullName.Contains('/') ? fullName.Split('/').Last() : fullName;
        string? version = NpmSharedHelpers.ExtractVersionFromTarballFilename(plainName, file);
        if (version is null)
        {
            return new NotFoundResult();
        }

        var ver = await packages.GetVersionAsync(pkg.Id, version, ct);
        if (ver is null)
        {
            // Already pruned by the rev-PUT step — idempotent success.
            return new OkResult();
        }

        if (ver.Origin != "uploaded")
        {
            return OnlyUploadedVersionsForbidden();
        }

        await ApplyVersionRemovalsAsync(httpContext, orgId, pkg, fullName, new[] { ver }, token, ct);
        return new OkResult();
    }

    // Physically removes a set of uploaded versions: deletes each blob + version row and records
    // an audit row, then prunes dist-tags pointing at a removed version, re-anchoring 'latest' to
    // the highest remaining stable version when it was among the pruned tags, and dropping the
    // package row when no versions remain. Shared by the bare version-unpublish DELETE, the modern
    // rev-PUT prune, and the tarball DELETE-with-rev so all three leave identical residual state.
    private async Task ApplyVersionRemovalsAsync(
        HttpContext httpContext, string orgId, Package pkg, string fullName,
        IReadOnlyList<PackageVersion> toRemove, TokenRecord token, CancellationToken ct)
    {
        var removedTags = new HashSet<string>(StringComparer.Ordinal);
        foreach (var ver in toRemove)
        {
            await blobs.DeleteAsync(BlobKeys.StoreKey(ver.BlobKey), ct);
            await packages.DeleteVersionAsync(ver.Id, ct);
            foreach (string tag in await distTags.DeleteTagsForVersionAsync(orgId, pkg.Id, ver.Version, ct))
            {
                removedTags.Add(tag);
            }

            await audit.LogActivityAsync(orgId, "npm", ver.Purl, "delete", token.UserId,
                actorKind: token.ActorKind, sourceIp: httpContext.GetNormalizedRemoteIp(), ct: ct);
        }

        // Re-anchor 'latest' when it was among the removed tags and the package still has other
        // versions. The package row is deleted last so the remaining-version query stays valid.
        bool packageStillExists = !(await packages.DeletePackageIfEmptyAsync(pkg.Id, ct));
        if (packageStillExists && removedTags.Contains("latest"))
        {
            var remaining = await packages.GetVersionsAsync(pkg.Id, ct);
            var activeRemaining = remaining.Where(v => !v.Yanked).ToList();
            string? newLatest = NpmSharedHelpers.ComputeLazyLatest(activeRemaining);
            if (newLatest is not null)
            {
                await distTags.SetTagAsync(orgId, pkg.Id, "latest", newLatest, ct);
            }
        }

        // Invalidate the cached packument so the removed versions disappear immediately.
        invalidation.Invalidate(MetadataInvalidation.ForNpm(orgId, fullName));
    }

    // Reads the pruned packument PUT body and returns its "versions" map (the versions to keep),
    // bounded so a hostile body cannot exhaust memory. Returns null when the body carries no
    // versions object.
    private static async Task<JsonObject?> ReadPackumentKeepVersionsAsync(HttpRequest request, CancellationToken ct)
    {
        await using var limited = new LimitedReadStream(request.Body, PrunePackumentMaxBytes, "npm unpublish packument body");
        var node = await System.Text.Json.JsonSerializer.DeserializeAsync<JsonNode>(limited, cancellationToken: ct);
        return node?["versions"]?.AsObject();
    }

    // True when the packument revision the client echoed cannot be resolved — the degenerate
    // "undefined"/"null" the npm CLI sends when a packument advertised no _rev.
    private static bool IsUnresolvableRev(string rev) =>
        string.IsNullOrWhiteSpace(rev) || rev is "undefined" or "null";

    private static ObjectResult UnresolvableRevConflict(string rev) => new(new ProblemDetails
    {
        Detail = $"Packument revision could not be resolved (received '{rev}'). " +
                 "Retry the unpublish with an npm client that reads the packument _rev.",
        Status = StatusCodes.Status409Conflict
    })
    { StatusCode = StatusCodes.Status409Conflict };

    private static ObjectResult OnlyUploadedVersionsForbidden() => new(new ProblemDetails
    {
        Detail = "Only user-published versions can be unpublished via this endpoint.",
        Status = StatusCodes.Status403Forbidden
    })
    { StatusCode = StatusCodes.Status403Forbidden };

    private static UnauthorizedResult UnauthorizedBearer(HttpContext httpContext)
    {
        httpContext.Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
        return new UnauthorizedResult();
    }
}
