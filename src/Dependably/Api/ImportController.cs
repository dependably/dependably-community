using System.Security.Claims;
using System.Security.Cryptography;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Publish;
using Dependably.Protocol;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Api;

/// <summary>
/// Admin upload surface. Two modes share the controller because they both turn user-supplied
/// bytes into <c>uploaded</c> package versions; only the input shape differs.
/// <list type="bullet">
///   <item><b>upload</b> (POST <c>/api/v1/admin/upload</c>): a multipart batch of N files.
///   Ecosystem is detected from each file's <em>contents</em> (magic bytes + required
///   manifest entries — <c>.nuspec</c>, <c>*.dist-info/METADATA</c>, <c>EGG-INFO/PKG-INFO</c>,
///   <c>package/package.json</c>, <c>PKG-INFO</c>/<c>pyproject.toml</c>) so a renamed file
///   can't lie. One bad file does not abort the batch; rejections are surfaced per-file.</item>
///   <item><b>manifest</b> (POST <c>/api/v1/admin/import/manifest</c>): a lockfile
///   (<c>package-lock.json</c>, <c>requirements.txt</c>, <c>Pipfile.lock</c>, <c>poetry.lock</c>,
///   or <c>packages.lock.json</c>) plus matching artefacts. All-or-nothing pre-validation —
///   manifest↔artefact correspondence must be complete and hashes must match before any blob
///   writes; any mismatch rejects the entire batch with a structured 422 report.</item>
/// </list>
/// Both modes emit per-file accept/reject audit rows tagged with a shared <c>batch_id</c> so
/// ops can reconstruct what came in on a given operation.
///
/// Resource controls:
/// <list type="bullet">
///   <item>Both routes carry [EnableRateLimiting("import")] — 5 requests/min per token (IP
///   fallback). Conservative by design: a bulk-import batch already contains N files and a
///   well-behaved operator never needs more than a handful of batch calls per minute.</item>
///   <item>The route [RequestSizeLimit] is capped at 1 GB total batch size.</item>
///   <item>Each artefact is streamed to a disk staging file under PROXY_STAGING_PATH before
///   its bytes enter managed memory. On the upload path files are processed one at a time
///   (staged, imported, temp file deleted). On the manifest path, staging and hash/detection
///   happen in a first pass over all files; the import loop then reads one file at a time
///   from disk, imports it, and deletes the temp file before the next file is read, so the
///   process never holds the entire multi-file batch in RAM simultaneously. A try/finally
///   over the manifest batch ensures all staged temp files are deleted on every exit path.</item>
///   <item>A per-file size cap is enforced from the per-tenant upload-limit chain (org
///   ecosystem limit → org global limit → instance default). Files exceeding the cap are
///   rejected individually (upload path) or abort the whole batch (manifest path) without
///   leaving orphaned disk state.</item>
/// </list>
/// </summary>
[ApiController]
// Admin import accepts both JWT (UI/admin) and API tokens (automation). An API token
// presented as Bearer is validated by the ApiToken scheme; the per-action
// [RequireCapability(ImportAll)] plus AuthorizeAdminAsync's tenant:configure check still
// gate it, so a publish/automation token must carry both capabilities to import. Mirrors
// the dual-scheme pattern on the publish endpoints (PyPi/NuGet/Rpm).
[Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
public sealed class ImportController : ControllerBase
{
    private readonly OrgAccessGuard _guard;
    private readonly OrgRepository _orgs;
    private readonly IPackagePublishService _publish;
    private readonly ClaimResolver _claimResolver;
    private readonly LicenseRepository _licenses;
    private readonly IUploadLimitResolver _limitResolver;
    private readonly string _stagingPath;
    private readonly IMemoryCache _cache;

    // Total batch ceiling: 1 GB. Individual file caps come from the per-tenant
    // upload-limit chain; this constant bounds the whole multipart envelope before
    // any bytes are read so a single oversized request never buffers unbounded data.
    private const long BatchSizeLimitBytes = 1L * 1024 * 1024 * 1024;

    public ImportController(ImportControllerServices svc)
    {
        _guard = svc.Guard;
        _orgs = svc.Orgs;
        _publish = svc.Publish;
        _claimResolver = svc.ClaimResolver;
        _licenses = svc.Licenses;
        _limitResolver = svc.LimitResolver;
        // deepcode ignore PT: PROXY_STAGING_PATH is operator-configured; user input never reaches the path.
        _stagingPath = string.IsNullOrWhiteSpace(svc.StagingPath)
            ? Path.GetTempPath()
            : svc.StagingPath;
        _cache = svc.Cache;
    }

    /// <summary>Per-batch context threaded through the upload + manifest paths.</summary>
    private sealed record ImportContext(string OrgId, string? ActorId, string BatchId);

    /// <summary>
    /// POST /api/v1/admin/upload — bulk-upload N artefacts of any supported ecosystem. The
    /// server reads magic bytes (gzipped tar vs ZIP) and peeks for the ecosystem's required
    /// manifest entry; the filename extension is informational only. A garbage file becomes
    /// a per-file rejection and the rest of the batch proceeds.
    /// </summary>
    [HttpPost("/api/v1/admin/upload")]
    [RequestSizeLimit(BatchSizeLimitBytes)]
    [RequestFormLimits(MultipartBodyLengthLimit = BatchSizeLimitBytes)]
    [EnableRateLimiting("import")]
    [RequireCapability(Capabilities.ImportAll)]
    public async Task<IActionResult> Upload([FromQuery] bool dryRun, CancellationToken ct)
    {
        var (Error, OrgId, ActorId) = await AuthorizeAdminAsync(ct);
        if (Error is not null)
        {
            return Error;
        }

        var (orgId, actorId) = (OrgId!, ActorId);

        if (!Request.HasFormContentType)
        {
            return BadRequest("Expected multipart/form-data.");
        }

        IFormCollection form;
        try
        {
            form = await Request.ReadFormAsync(ct);
        }
        catch (InvalidDataException)
        {
            return Problem(
                statusCode: StatusCodes.Status413PayloadTooLarge,
                title: "Payload Too Large",
                detail: "The multipart batch exceeds the 1 GB request size limit.");
        }
        var artefactFiles = form.Files.Where(f => f.Name != "sha256sums").ToList();
        if (artefactFiles.Count == 0)
        {
            return BadRequest("No files in request.");
        }

        // Optional sha256sums sidecar: when present, every artefact's actual digest must match
        // before any blob lands. Mismatch fails the WHOLE batch (tamper-evidence — partial
        // accepts defeat the purpose). Absence keeps the legacy behaviour unchanged.
        var sumsCheck = await ValidateSha256SumsSidecarAsync(form, artefactFiles, ct);
        if (sumsCheck is not null)
        {
            return sumsCheck;
        }

        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var importCtx = new ImportContext(orgId, actorId, Guid.NewGuid().ToString("N"));
        var outcomes = new List<object>(artefactFiles.Count);
        int accepted = 0;
        int rejected = 0;

        foreach (var file in artefactFiles)
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            // Resolve the org-global size cap before ecosystem is known so an oversized
            // file is rejected before any bytes enter managed memory. The publish pipeline
            // re-checks the per-ecosystem cap after detection; both layers are necessary.
            long preStageCap = await ResolveGlobalCapAsync(orgId, ct);
            var stageResult = await StageFileAsync(file, preStageCap, ct);
            if (stageResult.Error is not null)
            {
                outcomes.Add(Reject(file.FileName, stageResult.Error.Value.Code, stageResult.Error.Value.Message, dryRun: dryRun));
                rejected++;
                continue;
            }

            byte[] bytes = stageResult.Bytes!;
            object outcome = await ImportOneAsync(importCtx, file.FileName, bytes, settings, dryRun, ct);
            outcomes.Add(outcome);
            if (outcome is AcceptedOutcome)
            {
                accepted++;
            }
            else
            {
                rejected++;
            }
        }

        return Ok(new
        {
            batch_id = importCtx.BatchId,
            mode = dryRun ? "upload-bulk-dryrun" : "upload-bulk",
            dry_run = dryRun,
            accepted,
            rejected,
            outcomes
        });
    }

    /// <summary>
    /// Parses the optional <c>sha256sums</c> multipart part and verifies every artefact
    /// in the batch matches its declared digest. Returns null when the sidecar is absent
    /// (legacy path) or all files match; returns a 422 IActionResult on parse error or
    /// digest mismatch. Files NOT mentioned in the sidecar are rejected — if you sign a
    /// bundle, every artefact must be in the bundle.
    /// </summary>
    private async Task<IActionResult?> ValidateSha256SumsSidecarAsync(
        IFormCollection form, IReadOnlyList<IFormFile> artefactFiles, CancellationToken ct)
    {
        var sidecar = form.Files.GetFile("sha256sums");
        if (sidecar is null)
        {
            return null;
        }

        string sidecarText;
        using (var ms = new MemoryStream())
        {
            await sidecar.CopyToAsync(ms, ct);
            sidecarText = System.Text.Encoding.UTF8.GetString(ms.ToArray());
        }

        IReadOnlyDictionary<string, string> expected;
        try { expected = Sha256SumsParser.Parse(sidecarText); }
        catch (InvalidDataException ex)
        {
            return UnprocessableEntity(new
            {
                title = "sha256sums sidecar is malformed",
                detail = ex.Message,
            });
        }

        var mismatches = new List<object>();
        var unlisted = new List<string>();

        foreach (var file in artefactFiles)
        {
            if (!expected.TryGetValue(file.FileName, out string? declared))
            {
                unlisted.Add(file.FileName);
                continue;
            }
            using var ms = new MemoryStream();
            await file.CopyToAsync(ms, ct);
            string actual = Convert.ToHexString(SHA256.HashData(ms.ToArray())).ToLowerInvariant();
            if (!string.Equals(actual, declared, StringComparison.OrdinalIgnoreCase))
            {
                mismatches.Add(new { filename = file.FileName, expected = declared, actual });
            }
        }

        return mismatches.Count > 0 || unlisted.Count > 0
            ? UnprocessableEntity(new
            {
                title = "sha256sums verification failed",
                detail = "One or more artefacts did not match the sidecar; nothing was imported.",
                mismatches,
                unlisted_files = unlisted,
            })
            : (IActionResult?)null;
    }

    /// <summary>
    /// POST /api/v1/admin/import/manifest — manifest-driven import. Two multipart parts are
    /// expected: a <c>manifest</c> file (package-lock.json, requirements.txt, or
    /// packages.lock.json) and one or more <c>files</c> entries with the matching artefacts.
    /// All-or-nothing pre-validation: every manifest entry must have a matching artefact and
    /// every artefact must match a manifest entry; any mismatch rejects the entire batch
    /// before any blob writes.
    /// </summary>
    [HttpPost("/api/v1/admin/import/manifest")]
    [RequestSizeLimit(BatchSizeLimitBytes)]
    [RequestFormLimits(MultipartBodyLengthLimit = BatchSizeLimitBytes)]
    [EnableRateLimiting("import")]
    [RequireCapability(Capabilities.ImportAll)]
    public async Task<IActionResult> ImportManifest([FromQuery] bool dryRun, CancellationToken ct)
    {
        var (Error, OrgId, ActorId) = await AuthorizeAdminAsync(ct);
        if (Error is not null)
        {
            return Error;
        }

        var (orgId, actorId) = (OrgId!, ActorId);

        var (form, formError) = await ReadManifestFormAsync(ct);
        if (formError is not null)
        {
            return formError;
        }

        var (manifest, manifestError) = await ParseManifestPartAsync(form!, ct);
        if (manifestError is not null)
        {
            return manifestError;
        }

        long preStageCap = await ResolveGlobalCapAsync(orgId, ct);
        var artefactFiles = form!.Files.Where(f => f.Name is not "manifest" and not "sha256sums").ToList();

        List<LoadedArtefact>? loaded = null;
        try
        {
            var (staged, loadError) = await LoadArtefactsAsync(artefactFiles, preStageCap, ct);
            if (loadError is not null)
            {
                return loadError;
            }
            loaded = staged!;

            var validation = BuildManifestCoverage(manifest!.Entries, loaded);
            if (!validation.AllClear)
            {
                return UnprocessableEntity(new
                {
                    title = "Manifest validation failed",
                    detail = "Pre-validation found mismatches; nothing was imported.",
                    manifest_type = manifest.Type.ToString(),
                    manifest_digest = manifest.Digest,
                    manifest_entries_without_files = validation.ManifestEntriesWithoutFiles,
                    files_without_manifest_entries = validation.FilesWithoutManifestEntries,
                    unparseable_files = validation.Unparseable,
                    hash_mismatches = validation.HashMismatches,
                });
            }

            var settings = await _orgs.GetSettingsAsync(orgId, ct);
            var importCtx = new ImportContext(orgId, actorId, Guid.NewGuid().ToString("N"));
            var (outcomes, accepted, rejected) = await ImportLoadedArtefactsAsync(
                importCtx, loaded, settings, dryRun, ct);

            return Ok(new
            {
                batch_id = importCtx.BatchId,
                mode = dryRun ? "manifest-bulk-dryrun" : "manifest-bulk",
                dry_run = dryRun,
                manifest_type = manifest.Type.ToString(),
                manifest_digest = manifest.Digest,
                accepted,
                rejected,
                outcomes,
            });
        }
        finally
        {
            // Delete any staged temp files not yet consumed by the import loop. This covers
            // validation-failure early returns, exceptions, and cancellation. Files that were
            // already processed by ImportLoadedArtefactsAsync have their temp paths deleted
            // inline; the remaining entries (if any) are cleaned up here.
            if (loaded is not null)
            {
                foreach (var artefact in loaded.Where(a => a.TempPath is not null))
                {
                    DeleteTempFile(artefact.TempPath!);
                }
            }
        }
    }

    private async Task<(IFormCollection? form, IActionResult? error)> ReadManifestFormAsync(CancellationToken ct)
    {
        if (!Request.HasFormContentType)
        {
            return (null, BadRequest("Expected multipart/form-data."));
        }

        try
        {
            return (await Request.ReadFormAsync(ct), null);
        }
        catch (InvalidDataException)
        {
            return (null, Problem(
                statusCode: StatusCodes.Status413PayloadTooLarge,
                title: "Payload Too Large",
                detail: "The multipart batch exceeds the 1 GB request size limit."));
        }
    }

    private sealed record ManifestParseResult(
        ManifestParser.ManifestType Type, string Digest, IReadOnlyList<ManifestEntry> Entries);

    /// <summary>
    /// Reads the <c>manifest</c> multipart part, detects its type, parses it, and returns
    /// the parsed entries + sha256 digest. Returns one of three error cases as IActionResult:
    /// missing manifest part, unrecognised manifest type, or empty entry list.
    /// </summary>
    private async Task<(ManifestParseResult? manifest, IActionResult? error)> ParseManifestPartAsync(
        IFormCollection form, CancellationToken ct)
    {
        var manifestFile = form.Files.GetFile("manifest");
        if (manifestFile is null)
        {
            return (null, BadRequest("Expected a 'manifest' multipart part containing the lockfile."));
        }

        byte[] manifestBytes;
        using (var ms = new MemoryStream())
        {
            await manifestFile.CopyToAsync(ms, ct);
            manifestBytes = ms.ToArray();
        }
        string manifestText = System.Text.Encoding.UTF8.GetString(manifestBytes);
        var manifestType = ManifestParser.Detect(manifestFile.FileName, manifestText);
        if (manifestType == ManifestParser.ManifestType.Unknown)
        {
            return (null, BadRequest($"Unrecognised manifest type for '{manifestFile.FileName}'. " +
                                     "Expected package-lock.json, requirements.txt, or packages.lock.json."));
        }

        IReadOnlyList<ManifestEntry> expected;
        try { expected = ManifestParser.Parse(manifestType, manifestText); }
        catch (Exception ex) { return (null, BadRequest($"Failed to parse manifest: {ex.Message}")); }

        if (expected.Count == 0)
        {
            return (null, BadRequest("Manifest contains no package entries."));
        }

        string digest = Convert.ToHexString(SHA256.HashData(manifestBytes)).ToLowerInvariant();
        return (new ManifestParseResult(manifestType, digest, expected), null);
    }

    // Staging paths used in LoadArtefactsAsync, ImportLoadedArtefactsAsync, and DeleteTempFile
    // are never user-controlled: each path is "import-stage-{server-guid}.tmp" under the
    // operator-configured staging root (_stagingPath / PROXY_STAGING_PATH). The analyzer's
    // interprocedural taint from IFormFileCollection through LoadedArtefact.TempPath is a
    // false positive — the file name is constructed from a server-generated GUID, not from
    // any field or property of the uploaded file. Disable path-traversal warning for these methods.
#pragma warning disable SCS0018

    /// <summary>
    /// Stages each artefact to a disk temp file one at a time, computes its SHA-256, and
    /// runs ecosystem detection. Each file's bytes are in RAM only for the duration of its
    /// detection pass; the temp file is kept on disk so <see cref="ImportLoadedArtefactsAsync"/>
    /// can re-open it per-file during the import loop. The caller is responsible for
    /// deleting all staged temp paths via the <see cref="LoadedArtefact.TempPath"/> field
    /// regardless of outcome — a try/finally in <see cref="ImportManifest"/> covers this.
    /// Files that exceed <paramref name="perFileCap"/> are treated as unparseable
    /// (no temp path) so <see cref="BuildManifestCoverage"/> surfaces them in the
    /// unparseable bucket and the 422 includes the reason.
    /// </summary>
    private async Task<(List<LoadedArtefact>? loaded, IActionResult? error)> LoadArtefactsAsync(
        List<IFormFile> artefactFiles, long perFileCap, CancellationToken ct)
    {
        var loaded = new List<LoadedArtefact>(artefactFiles.Count);
        foreach (var file in artefactFiles)
        {
            var stageResult = await StageToDiskAsync(file, perFileCap, ct);
            if (stageResult.Error is not null)
            {
                // Treat oversized/error files as unparseable; no temp path to track.
                loaded.Add(new LoadedArtefact(
                    file.FileName, null, string.Empty,
                    null, null, null, null,
                    stageResult.Error.Value.Message));
                continue;
            }

            // Read bytes into RAM only long enough to hash and detect ecosystem; release
            // before the next file is staged. The temp file remains on disk for the import loop.
            string tempPath = stageResult.TempPath!;
            byte[] bytes = await System.IO.File.ReadAllBytesAsync(tempPath, ct);
            string sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            var (ok, err) = EcosystemDetector.Detect(file.FileName, bytes);
            // bytes goes out of scope here; GC can reclaim before the next iteration.
            loaded.Add(new LoadedArtefact(
                file.FileName, tempPath, sha,
                ok?.Ecosystem, ok?.Name, ok?.PurlName, ok?.Version,
                err?.Message));
        }
        return (loaded, null);
    }

    /// <summary>
    /// Streams a single multipart file to a temp file under PROXY_STAGING_PATH, enforcing
    /// <paramref name="sizeCap"/> during the write, then reads the staged bytes back into
    /// memory and deletes the temp file. On success returns the file's bytes. On failure
    /// (size cap exceeded or I/O error) returns an error code/message pair and ensures the
    /// temp file is cleaned up.
    /// </summary>
    private async Task<StagedFile> StageFileAsync(IFormFile file, long sizeCap, CancellationToken ct)
    {
        var diskResult = await StageToDiskAsync(file, sizeCap, ct);
        if (diskResult.Error is not null)
        {
            return new StagedFile(null, diskResult.Error);
        }
        string tempPath = diskResult.TempPath!;
        try
        {
            byte[] bytes = await System.IO.File.ReadAllBytesAsync(tempPath, ct);
            return new StagedFile(bytes, null);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new StagedFile(null,
                (Code: "staging_error",
                 Message: $"Failed to read staged file: {ex.GetType().Name}"));
        }
        finally
        {
            DeleteTempFile(tempPath);
        }
    }

    /// <summary>
    /// Streams a single multipart file to a temp file under PROXY_STAGING_PATH, enforcing
    /// <paramref name="sizeCap"/> during the write. On success returns the temp file path;
    /// the caller is responsible for deleting it. On failure (size cap exceeded or I/O error)
    /// returns an error and ensures the partial temp file is cleaned up.
    /// </summary>
    private async Task<StagedToDisk> StageToDiskAsync(IFormFile file, long sizeCap, CancellationToken ct)
    {
        // deepcode ignore PT: staging file name is "import-stage-{server-guid}" under the operator-configured staging root — no user input reaches the path.
        string tempPath = Path.Combine(_stagingPath, $"import-stage-{Guid.NewGuid():N}.tmp");
        bool succeeded = false;
        try
        {
            long written = 0;
            using (var fileStream = new FileStream(
                tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                bufferSize: 81920, useAsync: true))
            {
                byte[] buffer = new byte[81920];
                await using var src = file.OpenReadStream();
                int read;
                while ((read = await src.ReadAsync(buffer, ct)) > 0)
                {
                    written += read;
                    if (written > sizeCap)
                    {
                        // Abort: the file exceeds the size cap. The finally block cleans
                        // up the partial temp file.
                        return new StagedToDisk(null,
                            (Code: "size_limit_exceeded",
                             Message: $"File exceeds the upload size limit ({sizeCap} bytes)."));
                    }
                    await fileStream.WriteAsync(buffer.AsMemory(0, read), ct);
                }
            }
            succeeded = true;
            return new StagedToDisk(tempPath, null);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new StagedToDisk(null,
                (Code: "staging_error",
                 Message: $"Failed to stage file for processing: {ex.GetType().Name}"));
        }
        finally
        {
            if (!succeeded)
            {
                DeleteTempFile(tempPath);
            }
        }
    }

    private static void DeleteTempFile(string path)
    {
        try
        {
            if (System.IO.File.Exists(path))
            {
                // deepcode ignore PT: path is "import-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
                System.IO.File.Delete(path);
            }
        }
        catch
        {
            // Best-effort cleanup; a leaked temp file under PROXY_STAGING_PATH is
            // operator-visible and can be purged on restart.
        }
    }

    private sealed record StagedFile(byte[]? Bytes, (string Code, string Message)? Error);
    private sealed record StagedToDisk(string? TempPath, (string Code, string Message)? Error);

    private sealed record CoverageReport(
        IReadOnlyList<object> ManifestEntriesWithoutFiles,
        IReadOnlyList<object> FilesWithoutManifestEntries,
        IReadOnlyList<object> Unparseable,
        IReadOnlyList<object> HashMismatches)
    {
        public bool AllClear =>
            ManifestEntriesWithoutFiles.Count == 0
            && FilesWithoutManifestEntries.Count == 0
            && Unparseable.Count == 0
            && HashMismatches.Count == 0;
    }

    /// <summary>
    /// Cross-references the manifest's expected coordinates against the uploaded artefacts:
    /// builds the four mismatch lists (missing files, extra files, unparseable artefacts,
    /// hash mismatches) the controller surfaces in a 422 problem document on failure.
    /// </summary>
    private static CoverageReport BuildManifestCoverage(
        IReadOnlyList<ManifestEntry> expected, IReadOnlyList<LoadedArtefact> loaded)
    {
        var expectedByCoord = expected.ToDictionary(e => (e.Ecosystem, e.Name, e.Version), e => e);
        var actualByCoord = loaded
            .Where(l => l.ParseError is null)
            .GroupBy(l => (l.Ecosystem!, l.Name!, l.Version!))
            .ToDictionary(g => g.Key, g => g.First());

        var manifestEntriesWithoutFiles = expected
            .Where(e => !actualByCoord.ContainsKey((e.Ecosystem, e.Name, e.Version)))
            .Select(e => (object)new { ecosystem = e.Ecosystem, name = e.Name, version = e.Version })
            .ToList();

        var filesWithoutManifestEntries = loaded
            .Where(l => l.ParseError is null
                && !expectedByCoord.ContainsKey((l.Ecosystem!, l.Name!, l.Version!)))
            .Select(l => (object)new { filename = l.Filename, ecosystem = l.Ecosystem, name = l.Name, version = l.Version })
            .ToList();

        var unparseable = loaded
            .Where(l => l.ParseError is not null)
            .Select(l => (object)new { filename = l.Filename, error = l.ParseError })
            .ToList();

        var hashMismatches = loaded
            .Where(l => l.ParseError is null
                     && expectedByCoord.TryGetValue((l.Ecosystem!, l.Name!, l.Version!), out var entry)
                     && entry.Sha256 is not null
                     && !string.Equals(entry.Sha256, l.Sha256, StringComparison.OrdinalIgnoreCase))
            .Select(l => (object)new
            {
                filename = l.Filename,
                expected = expectedByCoord[(l.Ecosystem!, l.Name!, l.Version!)].Sha256,
                actual = l.Sha256,
            })
            .ToList();

        return new CoverageReport(
            manifestEntriesWithoutFiles, filesWithoutManifestEntries, unparseable, hashMismatches);
    }

    /// <summary>
    /// Iterates the pre-validated artefact list. For each entry: reads its bytes from the
    /// staged temp file, imports the artefact, then immediately deletes the temp file.
    /// Only one file's bytes are in RAM at a time. The caller's try/finally ensures any
    /// temp files not yet reached by the loop are cleaned up on exception or cancellation.
    /// </summary>
    private async Task<(List<object> outcomes, int accepted, int rejected)> ImportLoadedArtefactsAsync(
        ImportContext ctx, IReadOnlyList<LoadedArtefact> loaded, OrgSettings? settings,
        bool dryRun, CancellationToken cancellationToken)
    {
        var outcomes = new List<object>(loaded.Count);
        int accepted = 0;
        int rejected = 0;
        foreach (var artefact in loaded)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            // Every artefact reaching this loop passed BuildManifestCoverage pre-validation,
            // so it carries no parse error and its staged temp path is guaranteed non-null.
            // deepcode ignore PT: TempPath is "import-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
            byte[] bytes = await System.IO.File.ReadAllBytesAsync(artefact.TempPath!, cancellationToken);
            // Delete the temp file immediately after reading so memory is released and
            // disk space is freed before processing begins.
            DeleteTempFile(artefact.TempPath!);
            var detection = new EcosystemDetector.DetectionResult(
                artefact.Ecosystem!, artefact.Name!, artefact.PurlName!, artefact.Version!);
            object outcome = await ImportDetectedAsync(
                ctx, artefact.Filename, bytes, detection, settings, dryRun, cancellationToken);
            outcomes.Add(outcome);
            if (outcome is AcceptedOutcome)
            {
                accepted++;
            }
            else
            {
                rejected++;
            }
        }
        return (outcomes, accepted, rejected);
    }

#pragma warning restore SCS0018

    // TempPath is the disk-staged file path, null when staging failed (ParseError is set).
    // The import loop reads bytes from TempPath one file at a time and deletes it after use.
    private sealed record LoadedArtefact(
        string Filename, string? TempPath, string Sha256,
        string? Ecosystem, string? Name, string? PurlName, string? Version,
        string? ParseError);

    /// <summary>
    /// Per-file dispatch for the unified upload path. Detects ecosystem from content, resolves
    /// the per-ecosystem size cap, then defers the shared tail (path safety, claim gate, size,
    /// dedup, blob put, version row, audit) to <see cref="IPackagePublishService"/>.
    /// </summary>
    private async Task<object> ImportOneAsync(
        ImportContext ctx, string filename, byte[] bytes, OrgSettings? settings,
        bool dryRun, CancellationToken ct)
    {
        var (ok, err) = EcosystemDetector.Detect(filename, bytes);
        return ok is null
            ? Reject(filename, err!.Code, err.Message, dryRun: dryRun)
            : await ImportDetectedAsync(ctx, filename, bytes, ok, settings, dryRun, ct);
    }

    private async Task<object> ImportDetectedAsync(
        ImportContext ctx, string filename, byte[] bytes,
        EcosystemDetector.DetectionResult detection, OrgSettings? settings,
        bool dryRun, CancellationToken ct)
    {
        long sizeCap = SizeCapFor(detection.Ecosystem, settings);
        string purl = PurlFor(detection);
        var claim = await _claimResolver.ResolveAsync(ctx.OrgId, detection.Ecosystem, detection.PurlName, ct);
        var request = new PublishRequest
        {
            OrgId = ctx.OrgId,
            Ecosystem = detection.Ecosystem,
            Name = detection.Name,
            PurlName = detection.PurlName,
            Version = detection.Version,
            Filename = filename,
            Purl = purl,
            ArtifactBytes = bytes,
            Origin = "uploaded",
            SizeCap = sizeCap,
            ActorUserId = ctx.ActorId,
            ActorKind = ActorKinds.User,
            AuditAction = "import",
            AuditDetail = AuditDetailFor(ctx.BatchId, detection.Ecosystem),
            ClaimState = claim.State,
            SourceIp = HttpContext.GetNormalizedRemoteIp(),
        };
        var result = dryRun
            ? await _publish.ValidateAsync(request, ct)
            : await _publish.StoreAndRecordAsync(request, ct);

        if (!dryRun && result is PublishResult.Accepted accepted)
        {
            var extracted = ExtractLicense(detection.Ecosystem, bytes, filename);
            if (extracted.Spdx.Count > 0)
            {
                await _licenses.SetLicensesAsync(accepted.VersionId, extracted.Spdx, "uploaded", ct);
            }

            // Evict cached metadata so the imported version appears immediately.
            switch (detection.Ecosystem)
            {
                case "npm":
                    _cache.Remove($"metadata:{ctx.OrgId}:npm:{detection.PurlName}");
                    break;
                case "pypi":
                    _cache.Remove($"metadata:{ctx.OrgId}:pypi:{detection.PurlName}");
                    break;
                case "nuget":
                    string nugetId = detection.PurlName.ToLowerInvariant();
                    _cache.Remove($"metadata:{ctx.OrgId}:nuget:{nugetId}:sv1");
                    _cache.Remove($"metadata:{ctx.OrgId}:nuget:{nugetId}:sv2");
                    break;
            }
        }

        return OutcomeFromResult(filename, result, detection.Ecosystem, detection.PurlName, dryRun);
    }

    private static LicenseExtractor.ExtractedMetadata ExtractLicense(
        string ecosystem, byte[] bytes, string filename) => ecosystem switch
        {
            // Wrap in a MemoryStream so we use the unified Stream-shaped LicenseExtractor surface.
            "nuget" => LicenseExtractor.FromNuspec(new MemoryStream(bytes, writable: false)),
            "pypi" => LicenseExtractor.FromPyPiPackageBytes(new MemoryStream(bytes, writable: false), filename),
            "npm" => LicenseExtractor.FromNpmTarballPackageJson(new MemoryStream(bytes, writable: false)),
            _ => LicenseExtractor.ExtractedMetadata.Empty,
        };

    private static string PurlFor(EcosystemDetector.DetectionResult d) => d.Ecosystem switch
    {
        "npm" => PurlNormalizer.Npm(d.Name, d.Version),
        "pypi" => PurlNormalizer.PyPi(d.Name, d.Version),
        "nuget" => PurlNormalizer.NuGet(d.Name, d.Version),
        _ => throw new ArgumentOutOfRangeException(nameof(d), $"Unsupported ecosystem '{d.Ecosystem}'.")
    };

    private static long SizeCapFor(string ecosystem, OrgSettings? settings)
    {
        long fallback = settings?.MaxUploadBytes ?? long.MaxValue;
        return ecosystem switch
        {
            "npm" => settings?.MaxUploadBytesNpm ?? fallback,
            "pypi" => settings?.MaxUploadBytesPyPi ?? fallback,
            "nuget" => settings?.MaxUploadBytesNuGet ?? fallback,
            _ => fallback
        };
    }

    private async Task<long> ResolveGlobalCapAsync(string orgId, CancellationToken ct)
    {
        // Resolve the org-global (non-ecosystem-specific) cap as a pre-stage gate before
        // ecosystem is known. The per-ecosystem cap is re-applied inside ImportDetectedAsync
        // via the publish pipeline; this layer prevents oversized bytes from staging to disk.
        //
        // Use the "unknown" sentinel ecosystem so GetUploadLimitAsync skips the per-eco
        // instance key lookup and falls straight through to the org-global and instance
        // MAX_UPLOAD_BYTES values — the two limits that apply regardless of file type.
        long? resolved = await _limitResolver.ResolveAsync(orgId, "unknown", ct);
        // If no global limit is configured, use the batch ceiling as a per-file bound so
        // a single file is at most as large as the total batch request limit.
        return resolved ?? BatchSizeLimitBytes;
    }

    private static string AuditDetailFor(string batchId, string ecosystem) =>
        $"{{\"batch_id\":\"{batchId}\",\"import_mode\":\"upload\",\"ecosystem\":\"{ecosystem}\"}}";

    /// <summary>
    /// Translates a <see cref="PublishResult"/> into the outcome shape the upload API surfaces.
    /// <c>ecosystem</c> is attached to both accepted and rejected outcomes (claim-required
    /// path included) so the UI can render the per-file badge and the claim-and-upload flow
    /// has the bits it needs to re-submit. On a dry run, <c>status</c> reads as
    /// <c>would_accept</c> / <c>would_reject</c> so the operator can tell at a glance that
    /// nothing was written.
    /// </summary>
    private static object OutcomeFromResult(string filename, PublishResult result,
        string ecosystem, string name, bool dryRun) => result switch
        {
            PublishResult.Accepted a => new AcceptedOutcome(
                filename, dryRun ? "would_accept" : "accepted", ecosystem, a.VersionId, a.Purl, a.Sha256),
            PublishResult.Rejected r when r.Code == "claim_required" =>
                Reject(filename, r.Code, r.Message, ecosystem: ecosystem, name: name, dryRun: dryRun),
            PublishResult.Rejected r => Reject(filename, r.Code, r.Message, ecosystem: ecosystem, dryRun: dryRun),
            _ => Reject(filename, "unknown", "Unknown publish outcome.", dryRun: dryRun),
        };

    // ── shared helpers ────────────────────────────────────────────────────────

    private async Task<(IActionResult? Error, string? OrgId, string? ActorId)> AuthorizeAdminAsync(CancellationToken ct)
    {
        // The endpoint already carries [RequireCapability(Capabilities.ImportAll)] for the
        // protocol-level cap check; this guard call now provides the 404-on-cross-tenant
        // invariant. tenant:configure is the management-API gate (admin + owner). The dual
        // auth scheme means the principal here is either a JWT (UI) or an API token; both
        // carry sub + cap + scope, so the guard works the same for either.
        var deny = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (deny is not null)
        {
            return (deny, null, null);
        }

        var ctx = (TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!;
        string? actorId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                   ?? User.FindFirst("sub")?.Value;
        return (null, ctx.TenantId, actorId);
    }

    private static RejectedOutcome Reject(string filename, string code, string message,
        string? ecosystem = null, string? name = null, bool dryRun = false) =>
        new(filename, dryRun ? "would_reject" : "rejected", code, message, ecosystem, name);

    private sealed record AcceptedOutcome(
        string Filename, string Status, string Ecosystem, string VersionId, string Purl, string Sha256);
    private sealed record RejectedOutcome(
        string Filename, string Status, string Code, string Message,
        string? Ecosystem, string? Name);
}

public sealed record ImportControllerServices(
    OrgAccessGuard Guard,
    PublishGate PublishGate,
    OrgRepository Orgs,
    IPackagePublishService Publish,
    ClaimResolver ClaimResolver,
    LicenseRepository Licenses,
    IUploadLimitResolver LimitResolver,
    string StagingPath,
    IMemoryCache Cache);
