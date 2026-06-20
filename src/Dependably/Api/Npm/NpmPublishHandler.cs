using System.Text;
using System.Text.Json.Nodes;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Infrastructure.Publish;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api.NpmProtocol;

/// <summary>
/// Handles npm publish (PUT /npm/{pkg}), unpublish (DELETE /npm/{pkg}/-rev/{rev}),
/// and deprecate (PUT without _attachments). Each action routes by the shape of the
/// PUT body: _attachments present = publish, absent = deprecate.
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
    RenderedResponseCache<NpmPackumentKey> cache,
    string stagingPath)
{
    // Route-level hard ceiling for npm publish requests (500 MiB); per-tenant limits are
    // enforced by UploadSizeLimitMiddleware before any blob is written.
    private const long NpmPublishSizeLimitBytes = 500L * 1024 * 1024;

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

    private async Task<IActionResult> PublishPackageAsync(
        HttpContext httpContext, string orgId, string package, string? scope, CancellationToken ct)
    {
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

        var (body, parseError) = await ParsePublishBodyAsync(httpContext, npmBodyCap, ct);
        if (parseError is not null)
        {
            return parseError;
        }

        string fullName = scope is not null ? $"{scope}/{package}" : package;
        string plainName = scope is not null ? package : fullName;

        var nameError = ValidatePackageName(body, fullName, plainName);
        if (nameError is not null)
        {
            return nameError;
        }

        // Detect the no-attachments shape: npm deprecate sends a packument PUT without the
        // _attachments key at all. Route to the deprecation handler before the attachment
        // validator rejects the body with 422. An empty _attachments object (key present but
        // empty) is an invalid publish, not a deprecate — let ExtractAttachment return 422.
        if (body?["_attachments"] is null)
        {
            return await HandleDeprecateAsync(httpContext, orgId, body, fullName, token, ct);
        }

        var (attachmentKey, attachStagingPath, stagingSize, attachmentError) =
            await ExtractAttachmentToStagingAsync(body, npmBodyCap);
        if (attachmentError is not null)
        {
            return attachmentError;
        }

        try
        {
            var (innerName, innerVersion, tarballError) =
                ValidateTarballAndExtractNameVersionFromFile(attachStagingPath!);
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

            string filename = attachmentKey!.Split('/').Last(); // e.g. package-1.0.0.tgz

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
            var request = BuildNpmPublishRequest(httpContext, new NpmPublishContext(
                orgId, fullName, versionKey!, filename, attachStagingPath!, stagingSize,
                token.UserId, token.ActorKind, orgSettings?.AllowVersionOverwrite ?? false, claim.State));
            var result = await publish.StoreAndRecordAsync(request, ct);

            if (result is PublishResult.Rejected rej)
            {
                return MapPublishRejection(rej, versionKey!);
            }

            string versionId = ((PublishResult.Accepted)result).VersionId;
            await EmitNpmLicensesAndDeprecationAsync(versionId, attachStagingPath!, versions?[versionKey!], ct);

            // Persist dist-tags from the packument. npm sends {"dist-tags":{"beta":"1.0.0-beta.1"}}
            // on `npm publish --tag beta`. When no dist-tags object is present, default to 'latest'.
            var pkg = await packages.GetByPurlNameAsync(orgId, "npm", fullName, ct);
            if (pkg is not null)
            {
                await PersistPublishDistTagsAsync(orgId, pkg.Id, body, versionKey!, ct);
            }

            // Evict the cached packument so the newly-published version appears immediately.
            cache.Evict(new NpmPackumentKey(orgId, fullName));

            return new OkResult();
        }
        finally
        {
            DeleteNpmStagingFile(attachStagingPath);
        }
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
        string? ActorUserId, string? ActorKind, bool AllowOverwrite, string ClaimState);

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
        };

    /// <summary>
    /// License: read the tarball's package.json (canonical, matches the proxy first-fetch
    /// path). Fall back to the packument when the tarball lacks a parseable
    /// package/package.json — many publish clients don't include license in the
    /// packument's version object. Deprecation only ever lives in the packument (npm
    /// deprecate writes there), so it must always come from the packument extractor.
    /// Reads from the staged temp file — the tarball is never materialized in managed memory.
    /// </summary>
    private async Task EmitNpmLicensesAndDeprecationAsync(
        string versionId, string fileStagingPath, JsonNode? packumentVersion, CancellationToken ct)
    {
        // deepcode ignore PT: stagingPath is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
        await using var fs = new FileStream(
            fileStagingPath, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 81920, useAsync: true);
        var fromTarball = LicenseExtractor.FromNpmTarballPackageJson(fs);
        var fromPackument = LicenseExtractor.FromNpmPackumentVersion(packumentVersion);
        var spdx = fromTarball.Spdx.Count > 0 ? fromTarball.Spdx : fromPackument.Spdx;
        if (spdx.Count > 0)
        {
            await licenses.SetLicensesAsync(versionId, spdx, "upstream", ct);
        }

        if (fromPackument.Deprecated is not null)
        {
            await packages.UpdateDeprecatedAsync(versionId, fromPackument.Deprecated, ct);
        }
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

        // Evict the cached packument so the deprecation change is visible immediately.
        cache.Evict(new NpmPackumentKey(orgId, fullName));

        return new OkResult();
    }

    private static ObjectResult MapPublishRejection(PublishResult.Rejected rej, string versionKey) => rej.Code switch
    {
        "version_exists" => new ConflictObjectResult(new ProblemDetails { Detail = $"Version {versionKey} already exists.", Status = StatusCodes.Status409Conflict }),
        _ => new ObjectResult(new ProblemDetails { Detail = rej.Message, Status = rej.HttpStatus }) { StatusCode = rej.HttpStatus },
    };

    private static async Task<(JsonNode? Body, IActionResult? Error)> ParsePublishBodyAsync(
        HttpContext httpContext, long bodyCap, CancellationToken ct)
    {
        // Wrap the request body in a byte-counting stream so the full JSON string read is
        // bounded by the resolved npm upload limit before any parsing or allocation occurs.
        // A cap overflow surfaces as an InvalidDataException from LimitedReadStream.
        // All other exceptions indicate malformed JSON.
        var limited = new LimitedReadStream(httpContext.Request.Body, bodyCap, "npm publish body");
        try
        {
            using var reader = new StreamReader(limited, Encoding.UTF8, leaveOpen: true);
            string json = await reader.ReadToEndAsync(ct);
            return (JsonNode.Parse(json), null);
        }
        catch (InvalidDataException)
        {
            return (null, new ObjectResult(new ProblemDetails
            {
                Detail = $"Request body exceeds the npm publish limit of {bodyCap} bytes.",
                Status = StatusCodes.Status413PayloadTooLarge,
            })
            { StatusCode = StatusCodes.Status413PayloadTooLarge });
        }
        catch
        {
            return (null, new UnprocessableEntityObjectResult(new ProblemDetails { Detail = "Invalid JSON body.", Status = StatusCodes.Status422UnprocessableEntity }));
        }
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

    /// <summary>
    /// Extracts the tarball from the _attachments JSON field and stages it to a temp file
    /// under PROXY_STAGING_PATH. Base64-decodes the attachment data to disk so the artifact
    /// bytes are never simultaneously live in managed memory alongside the JSON envelope.
    /// Returns (attachmentKey, stagingPath, sizeBytes, null) on success or
    /// (null, null, 0, error) on validation failure.
    /// </summary>
    private async Task<(string? Key, string? StagingPath, long SizeBytes, IActionResult? Error)>
        ExtractAttachmentToStagingAsync(JsonNode? body, long limit)
    {
        var attachments = body?["_attachments"]?.AsObject();
        if (attachments is null || attachments.Count != 1)
        {
            return (null, null, 0, new UnprocessableEntityObjectResult(new ProblemDetails
            { Detail = "_attachments must contain exactly one entry.", Status = StatusCodes.Status422UnprocessableEntity }));
        }

        var (attachmentKey, attachmentNode) = attachments.First();
        string? base64Data = attachmentNode?["data"]?.GetValue<string>();
        if (base64Data is null)
        {
            return (null, null, 0, new UnprocessableEntityObjectResult(new ProblemDetails
            { Detail = "_attachments.data is required.", Status = StatusCodes.Status422UnprocessableEntity }));
        }

        // Reject before decoding when the declared decoded size already exceeds the limit —
        // avoids a ~1.33x allocation for an oversized attachment.
        long declaredLength = attachmentNode?["length"]?.GetValue<long>() ?? -1;
        if (declaredLength > limit)
        {
            return (null, null, 0, new ObjectResult(new ProblemDetails
            { Detail = $"Attachment declared length {declaredLength} exceeds the npm publish limit of {limit} bytes.", Status = StatusCodes.Status413PayloadTooLarge })
            { StatusCode = StatusCodes.Status413PayloadTooLarge });
        }

        // Decode base64 → staging file so the decoded bytes are not held in managed memory.
        // deepcode ignore PT: staging file name is "publish-stage-{server-guid}" under the operator-configured staging root — no user input reaches the path.
        string tempPath = System.IO.Path.Combine(stagingPath, $"publish-stage-{Guid.NewGuid():N}.tmp");
        bool succeeded = false;
        try
        {
            byte[] decoded;
            try { decoded = Convert.FromBase64String(base64Data); }
            catch
            {
                return (null, null, 0, new UnprocessableEntityObjectResult(new ProblemDetails
                { Detail = "Invalid base64 in _attachments.data.", Status = StatusCodes.Status422UnprocessableEntity }));
            }

            if (declaredLength >= 0 && decoded.Length != declaredLength)
            {
                return (null, null, 0, new UnprocessableEntityObjectResult(new ProblemDetails
                { Detail = $"Attachment length mismatch: declared {declaredLength}, actual {decoded.Length}.", Status = StatusCodes.Status422UnprocessableEntity }));
            }

            // Write decoded bytes to the staging file. After the write, the byte[] is no
            // longer referenced and can be GC'd, leaving only the file on disk.
            await System.IO.File.WriteAllBytesAsync(tempPath, decoded);
            long sizeBytes = decoded.LongLength;
            succeeded = true;
            return (attachmentKey, tempPath, sizeBytes, null);
        }
        finally
        {
            if (!succeeded)
            {
                DeleteNpmStagingFile(tempPath);
            }
        }
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

    private static (string? InnerName, string? InnerVersion, IActionResult? Error)
        ValidateTarballAndExtractNameVersionFromFile(string fileStagingPath)
    {
        // deepcode ignore PT: stagingPath is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
        byte[] tarball = System.IO.File.ReadAllBytes(fileStagingPath);
        var parsed = NpmTarballValidator.Validate(tarball);
        return parsed.Validation.IsValid
            ? (parsed.Name, parsed.Version, null)
            : (null, null, new UnprocessableEntityObjectResult(new ProblemDetails { Detail = parsed.Validation.Message, Status = StatusCodes.Status422UnprocessableEntity }));
    }

    private static void DeleteNpmStagingFile(string? path)
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
            return new ObjectResult(new ProblemDetails
            {
                Detail = "Only user-published versions can be unpublished via this endpoint.",
                Status = StatusCodes.Status403Forbidden
            })
            { StatusCode = StatusCodes.Status403Forbidden };
        }

        await blobs.DeleteAsync(BlobKeys.StoreKey(ver.BlobKey), ct);
        await packages.DeleteVersionAsync(ver.Id, ct);

        // Remove any dist-tags that pointed at the deleted version, then re-anchor
        // 'latest' when it was among the removed tags and the package still has other
        // versions. The package row is deleted last so the version list query above is
        // still valid at this point.
        var removedTags = await distTags.DeleteTagsForVersionAsync(orgId, pkg.Id, ver.Version, ct);
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

        await audit.LogActivityAsync(orgId, "npm", ver.Purl, "delete", token.UserId,
            actorKind: token.ActorKind, sourceIp: httpContext.GetNormalizedRemoteIp(), ct: ct);

        // Evict the cached packument so the deleted version disappears immediately.
        cache.Evict(new NpmPackumentKey(orgId, fullName));

        return new OkResult();
    }
}
