using System.Text.RegularExpressions;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Infrastructure.Publish;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api.PyPiProtocol;

/// <summary>
/// Handles POST /pypi/legacy/ — twine-compatible package upload (PEP 517/621). Orchestrates
/// form validation, path-safety checks, staging to disk, SHA-256 + MD5 verification,
/// file-type validation, publish dispatch, and license extraction.
/// </summary>
public sealed class PyPiPublishHandler(
    OrgRepository orgs,
    TokenRepository tokens,
    PublishGate publishGate,
    IPackagePublishService publish,
    ClaimResolver claimResolver,
    LicenseRepository licenses,
    RenderedResponseCache<PyPiSimpleIndexKey> cache,
    ILogger<PyPiPublishHandler> logger,
    string stagingPath)
{
    // PEP 508 name regex
    private static readonly Regex Pep508NameRegex =
        new(@"^[A-Za-z0-9]([A-Za-z0-9._\-]*[A-Za-z0-9])?$", RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    // PEP 440 version: permissive check — must start with a digit
    private static readonly Regex Pep440VersionRegex =
        new(@"^\d[\w\.\!\+\-]*$", RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private static readonly HashSet<string> ValidMetadataVersions =
        new(StringComparer.Ordinal) { "1.0", "1.1", "1.2", "2.0", "2.1", "2.2", "2.3", "2.4" };

    public async Task<IActionResult> UploadAsync(HttpContext httpContext, string orgId, CancellationToken ct)
    {
        var authError = await CheckUploadAuthAsync(httpContext, orgId, ct);
        if (authError is not null)
        {
            return authError;
        }

        var token = (await httpContext.Request.ResolveTokenAsync(tokens, ct))!;

        if (!httpContext.Request.HasFormContentType)
        {
            return new BadRequestObjectResult("Expected multipart/form-data.");
        }

        var form = await httpContext.Request.ReadFormAsync(ct);

        var (name, version, sha256Digest, file, formError) = ValidateUploadForm(form);
        if (formError is not null)
        {
            return formError;
        }

        var pathError = ValidatePathSafety(name!, version!, file!.FileName);
        if (pathError is not null)
        {
            return pathError;
        }

        var claimReject = await publishGate.CheckAsync(orgId, "pypi", name!.ToLowerInvariant(), ct);
        if (claimReject is not null)
        {
            return claimReject;
        }

        // Stage to disk: stream multipart file through HashingFileStream so SHA-256 is
        // computed inline, never materializing the full artifact as a byte[].
        var (stagedPath, sizeBytes, stageError) = await StagePyPiFileAsync(file!, ct);
        if (stageError is not null)
        {
            return stageError;
        }

        string? sourceIp = httpContext.GetNormalizedRemoteIp();

        try
        {
            var sizeError = await CheckPyPiUploadSizeAsync(orgId, sizeBytes, ct);
            if (sizeError is not null)
            {
                return sizeError;
            }

            var (actualSha256, hashErr) = await VerifyDigestsFromFileAsync(stagedPath!, sha256Digest!,
                form["md5_digest"].FirstOrDefault(), ct);
            if (hashErr is not null)
            {
                return hashErr;
            }

            var fileTypeError = ValidateFileTypeContentsFromFile(
                form["filetype"].FirstOrDefault() ?? "", stagedPath!, name!, file!.FileName);
            return fileTypeError is not null
                ? fileTypeError
                : await StoreAndRecordUploadAsync(
                    new PyPiUpload(name!, version!, file!.FileName, stagedPath!, sizeBytes, actualSha256!),
                    new ProxyTenantContext(orgId, token, sourceIp), ct);
        }
        finally
        {
            DeleteStagingFile(stagedPath);
        }
    }

    private async Task<IActionResult?> CheckUploadAuthAsync(HttpContext httpContext, string orgId, CancellationToken ct)
    {
        // [Authorize] + [RequireCapability(Capabilities.PublishPypi)] on the action method
        // already enforce auth + capability; this method's only remaining job is the
        // cross-tenant guard (token.OrgId vs requested orgId) and surfacing the
        // WWW-Authenticate header on rejection.
        var token = await httpContext.Request.ResolveTokenAsync(tokens, ct);
        if (token is null || token.OrgId != orgId)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }
        return null;
    }

    private static (string? Name, string? Version, string? Sha256, IFormFile? File, IActionResult? Error) ValidateUploadForm(IFormCollection form)
    {
        if (form[":action"].FirstOrDefault() != "file_upload")
        {
            return (null, null, null, null, new UnprocessableEntityObjectResult(
                new ProblemDetails
                {
                    Detail = ":action must be 'file_upload'",
                    Status = StatusCodes.Status422UnprocessableEntity
                }));
        }

        string? metadataVersion = form["metadata_version"].FirstOrDefault();
        if (!ValidMetadataVersions.Contains(metadataVersion ?? ""))
        {
            return (null, null, null, null, new UnprocessableEntityObjectResult(
                new ProblemDetails
                {
                    Detail = $"Invalid metadata_version: {metadataVersion}",
                    Status = StatusCodes.Status422UnprocessableEntity
                }));
        }

        string name = form["name"].FirstOrDefault() ?? "";
        string version = form["version"].FirstOrDefault() ?? "";
        string sha256Digest = form["sha256_digest"].FirstOrDefault() ?? "";

        if (!Pep508NameRegex.IsMatch(name))
        {
            return (null, null, null, null, new UnprocessableEntityObjectResult(
                new ProblemDetails
                {
                    Detail = $"Invalid package name: {name}",
                    Status = StatusCodes.Status422UnprocessableEntity
                }));
        }

        if (!Pep440VersionRegex.IsMatch(version))
        {
            return (null, null, null, null, new UnprocessableEntityObjectResult(
                new ProblemDetails
                {
                    Detail = $"Invalid version: {version}",
                    Status = StatusCodes.Status422UnprocessableEntity
                }));
        }

        if (string.IsNullOrEmpty(sha256Digest))
        {
            return (null, null, null, null, new UnprocessableEntityObjectResult(
                new ProblemDetails
                {
                    Detail = "sha256_digest is required",
                    Status = StatusCodes.Status422UnprocessableEntity
                }));
        }

        var file = form.Files.GetFile("content");
        if (file is null)
        {
            return (null, null, null, null, new UnprocessableEntityObjectResult(
                new ProblemDetails
                {
                    Detail = "File content is required",
                    Status = StatusCodes.Status422UnprocessableEntity
                }));
        }

        return (name, version, sha256Digest, file, null);
    }

    private static UnprocessableEntityObjectResult? ValidatePathSafety(string name, string version, string filename)
    {
        foreach (var (value, kind) in new[] { (name, "name"), (version, "version"), (filename, "filename") })
        {
            var check = PathSafeValidator.Validate(value, kind);
            if (!check.IsValid)
            {
                return new UnprocessableEntityObjectResult(new ProblemDetails { Detail = check.Message, Status = StatusCodes.Status422UnprocessableEntity });
            }
        }
        return null;
    }

    private async Task<IActionResult?> CheckPyPiUploadSizeAsync(string orgId, long size, CancellationToken ct)
    {
        var settings = await orgs.GetSettingsAsync(orgId, ct);
        long limit = await orgs.GetUploadLimitAsync(settings, "pypi", ct);
        return size > limit
            ? new ObjectResult(new ProblemDetails { Detail = "Upload exceeds size limit.", Status = StatusCodes.Status413PayloadTooLarge })
            { StatusCode = StatusCodes.Status413PayloadTooLarge }
            : null;
    }

    /// <summary>
    /// Streams the multipart file to a staging temp file under PROXY_STAGING_PATH via
    /// <see cref="HashingFileStream"/>, computing SHA-256 inline. Returns the staging
    /// path, byte count, and null on success; (null, 0, error) on failure.
    /// </summary>
    private async Task<(string? Path, long Size, IActionResult? Error)> StagePyPiFileAsync(
        IFormFile file, CancellationToken ct)
    {
        // deepcode ignore PT: staging file name is "publish-stage-{server-guid}" under the operator-configured staging root — no user input reaches the path.
        string tempPath = System.IO.Path.Combine(stagingPath, $"publish-stage-{Guid.NewGuid():N}.tmp");
        bool succeeded = false;
        try
        {
            var fileStream = new FileStream(
                tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                bufferSize: 81920, useAsync: true);
            await using (var staging = new HashingFileStream(fileStream, long.MaxValue))
            await using (var src = file.OpenReadStream())
            {
                await src.CopyToAsync(staging, ct);
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
            logger.LogWarning(ex, "Failed to stage PyPI push body: {ExceptionType}", ex.GetType().Name);
            return (null, 0, new ObjectResult(new ProblemDetails { Detail = "Failed to stage upload.", Status = StatusCodes.Status500InternalServerError })
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

    /// <summary>
    /// Verifies SHA-256 (required) and optional MD5 by streaming the staged file.
    /// Returns the actual sha256 hex on success; the error result on mismatch.
    /// </summary>
    private static async Task<(string? ActualSha256, IActionResult? Error)> VerifyDigestsFromFileAsync(
        string stagedPath, string sha256Digest, string? md5Digest, CancellationToken ct)
    {
        // deepcode ignore PT: stagedPath is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
        await using var fs = new FileStream(
            stagedPath, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 81920, useAsync: true);
        using var sha256Alg = System.Security.Cryptography.IncrementalHash.CreateHash(
            System.Security.Cryptography.HashAlgorithmName.SHA256);
        using var md5Alg = string.IsNullOrEmpty(md5Digest)
            ? null
            : System.Security.Cryptography.IncrementalHash.CreateHash(
                System.Security.Cryptography.HashAlgorithmName.MD5);
        byte[] buffer = new byte[81920];
        int read;
        while ((read = await fs.ReadAsync(buffer, ct)) > 0)
        {
            sha256Alg.AppendData(buffer, 0, read);
            md5Alg?.AppendData(buffer, 0, read);
        }
        string actualSha256 = Convert.ToHexString(sha256Alg.GetHashAndReset()).ToLowerInvariant();
        if (!string.Equals(actualSha256, sha256Digest, StringComparison.OrdinalIgnoreCase))
        {
            return (null, new UnprocessableEntityObjectResult(new ProblemDetails { Detail = "SHA-256 digest mismatch.", Status = StatusCodes.Status422UnprocessableEntity }));
        }
        if (md5Alg is not null)
        {
            string actualMd5 = Convert.ToHexString(md5Alg.GetHashAndReset()).ToLowerInvariant();
            if (!string.Equals(actualMd5, md5Digest, StringComparison.OrdinalIgnoreCase))
            {
                return (null, new UnprocessableEntityObjectResult(new ProblemDetails { Detail = "MD5 digest mismatch.", Status = StatusCodes.Status422UnprocessableEntity }));
            }
        }
        return (actualSha256, null);
    }

    private static UnprocessableEntityObjectResult? ValidateFileTypeContentsFromFile(
        string fileType, string stagedPath, string name, string filename)
    {
        var result = fileType switch
        {
            "bdist_wheel" => ValidateWheelFromFile(stagedPath),
            "bdist_egg" => ValidateEggFromFile(stagedPath),
            "sdist" => ValidateSdist(name, filename),
            _ => ValidationResult.Ok(),
        };
        return result.IsValid ? null : new UnprocessableEntityObjectResult(new ProblemDetails { Detail = result.Message, Status = StatusCodes.Status422UnprocessableEntity });
    }

    private async Task<IActionResult> StoreAndRecordUploadAsync(
        PyPiUpload upload, ProxyTenantContext tenant, CancellationToken ct)
    {
        string purlName = PurlNormalizer.PyPiName(upload.Name);
        string purl = PurlNormalizer.PyPi(upload.Name, upload.Version);

        var orgSettings = await orgs.GetSettingsAsync(tenant.OrgId, ct);
        var claim = await claimResolver.ResolveAsync(tenant.OrgId, "pypi", purlName, ct);
        var result = await publish.StoreAndRecordAsync(new PublishRequest
        {
            OrgId = tenant.OrgId,
            Ecosystem = "pypi",
            Name = upload.Name,
            PurlName = purlName,
            Version = upload.Version,
            Filename = upload.Filename,
            Purl = purl,
            ArtifactStagingPath = upload.StagingPath,
            ArtifactSizeBytes = upload.SizeBytes,
            Origin = "uploaded",
            SizeCap = long.MaxValue,        // size cap already enforced upstream by CheckPyPiUploadSizeAsync
            ActorUserId = tenant.Token?.UserId,
            ActorKind = tenant.Token?.ActorKind,
            AuditAction = "push",
            AllowOverwrite = orgSettings?.AllowVersionOverwrite ?? false,
            ClaimState = claim.State,
            SourceIp = tenant.SourceIp,
        }, ct);

        if (result is PublishResult.Rejected rej)
        {
            return MapPyPiPublishRejection(rej, upload.Version);
        }

        // Format-specific post-publish: license info comes from the wheel METADATA / sdist
        // PKG-INFO. Read from the staged file — the artifact is never held in a byte[].
        string versionId = ((PublishResult.Accepted)result).VersionId;
        // deepcode ignore PT: StagingPath is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
        await using var stagingFs = new FileStream(
            upload.StagingPath, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 81920, useAsync: true);
        var extracted = LicenseExtractor.FromPyPiPackageBytes(stagingFs, upload.Filename);
        if (extracted.Spdx.Count > 0)
        {
            await licenses.SetLicensesAsync(versionId, extracted.Spdx, "upstream", ct);
        }

        // Evict the cached simple index so the newly-published version appears immediately.
        // The formatter normalizes the name (PEP 503), so the raw upload name is passed.
        cache.Evict(new PyPiSimpleIndexKey(tenant.OrgId, upload.Name));

        return new OkResult();
    }

    private static IActionResult MapPyPiPublishRejection(PublishResult.Rejected rej, string version)
    {
        return rej.Code == "version_exists"
            ? new ConflictObjectResult(new ProblemDetails { Detail = $"Version {version} already exists.", Status = StatusCodes.Status409Conflict })
            : new ObjectResult(new ProblemDetails { Detail = rej.Message, Status = rej.HttpStatus }) { StatusCode = rej.HttpStatus };
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

    private static ValidationResult ValidateWheelFromFile(string stagedPath)
    {
        try
        {
            // deepcode ignore PT: stagedPath is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
            using var fileStream = new FileStream(
                stagedPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                bufferSize: 81920, useAsync: false);
            using var zip = new System.IO.Compression.ZipArchive(fileStream, System.IO.Compression.ZipArchiveMode.Read);
            bool hasMetadata = zip.Entries.Any(e =>
                e.FullName.EndsWith(".dist-info/METADATA", StringComparison.OrdinalIgnoreCase));
            return !hasMetadata ? ValidationResult.Fail("content", "Wheel is missing .dist-info/METADATA") : ValidationResult.Ok();
        }
        catch
        {
            return ValidationResult.Fail("content", "Wheel is not a valid ZIP file");
        }
    }

    private static ValidationResult ValidateEggFromFile(string stagedPath)
    {
        try
        {
            // deepcode ignore PT: stagedPath is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
            using var fileStream = new FileStream(
                stagedPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                bufferSize: 81920, useAsync: false);
            using var zip = new System.IO.Compression.ZipArchive(fileStream, System.IO.Compression.ZipArchiveMode.Read);
            bool hasMetadata = zip.Entries.Any(e =>
                e.FullName.EndsWith("EGG-INFO/PKG-INFO", StringComparison.OrdinalIgnoreCase));
            return !hasMetadata ? ValidationResult.Fail("content", "Egg is missing EGG-INFO/PKG-INFO") : ValidationResult.Ok();
        }
        catch
        {
            return ValidationResult.Fail("content", "Egg is not a valid ZIP file");
        }
    }

    private static ValidationResult ValidateSdist(string name, string filename)
    {
        if (!filename.EndsWith(".tar.gz") && !filename.EndsWith(".zip"))
        {
            return ValidationResult.Fail("filename", "sdist must end in .tar.gz or .zip");
        }

        // Basic check: filename should start with the package name. Normalize BOTH
        // sides the same way (PEP 503: lowercase, runs of [-_.] -> "-") before
        // comparing — PEP 625 sdist filenames use underscores
        // (e.g. python_library_checker-1.0.tar.gz) while the declared name normalizes
        // to hyphens, so a raw prefix check would spuriously 422 every modern sdist.
        string normalized = Regex.Replace(name, @"[-_.]+", "-", RegexOptions.None, PyPiConstants.RegexTimeout).ToLowerInvariant();
        string normalizedFilename = Regex.Replace(filename, @"[-_.]+", "-", RegexOptions.None, PyPiConstants.RegexTimeout).ToLowerInvariant();
        return !normalizedFilename.StartsWith(normalized, StringComparison.Ordinal)
            ? ValidationResult.Fail("filename", "Filename does not match declared package name")
            : ValidationResult.Ok();
    }
}
