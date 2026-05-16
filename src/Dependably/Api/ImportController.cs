using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Publish;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;

namespace Dependably.Api;

/// <summary>
/// Admin upload surface. Two modes share the controller because they both turn user-supplied
/// bytes into <c>uploaded</c> package versions; only the input shape differs.
/// <list type="bullet">
///   <item><b>upload</b> (POST <c>/api/v1/admin/upload</c>): a multipart batch of N files.
///   Ecosystem is detected from each file's <em>contents</em> (magic bytes + required
///   manifest entries — <c>.nuspec</c>, <c>*.dist-info/METADATA</c>, <c>package/package.json</c>,
///   <c>PKG-INFO</c>/<c>pyproject.toml</c>) so a renamed file can't lie. One bad file does
///   not abort the batch; rejections are surfaced per-file.</item>
///   <item><b>manifest</b> (POST <c>/api/v1/admin/import/manifest</c>): a lockfile
///   (<c>package-lock.json</c>, <c>requirements.txt</c>, or <c>packages.lock.json</c>) plus
///   matching artefacts. All-or-nothing pre-validation — manifest↔artefact correspondence
///   must be complete and hashes must match before any blob writes; any mismatch rejects
///   the entire batch with a structured 422 report.</item>
/// </list>
/// Both modes emit per-file accept/reject audit rows tagged with a shared <c>batch_id</c> so
/// ops can reconstruct what came in on a given operation.
/// </summary>
[ApiController]
[Authorize]
public sealed class ImportController : ControllerBase
{
    private readonly OrgAccessGuard _guard;
    private readonly OrgRepository _orgs;
    private readonly IPackagePublishService _publish;
    private readonly ClaimResolver _claimResolver;
    private readonly LicenseRepository _licenses;

    public ImportController(ImportControllerServices svc)
    {
        _guard = svc.Guard;
        _orgs = svc.Orgs;
        _publish = svc.Publish;
        _claimResolver = svc.ClaimResolver;
        _licenses = svc.Licenses;
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
    [RequestSizeLimit(4L * 1024 * 1024 * 1024)]
    [RequireCapability(Capabilities.ImportAll)]
    public async Task<IActionResult> Upload([FromQuery] bool dryRun, CancellationToken ct)
    {
        var ctxResult = await AuthorizeAdminAsync(ct);
        if (ctxResult.Error is not null) return ctxResult.Error;
        var (orgId, actorId) = (ctxResult.OrgId!, ctxResult.ActorId);

        if (!Request.HasFormContentType) return BadRequest("Expected multipart/form-data.");
        var form = await Request.ReadFormAsync(ct);
        var artefactFiles = form.Files.Where(f => f.Name != "sha256sums").ToList();
        if (artefactFiles.Count == 0) return BadRequest("No files in request.");

        // Optional sha256sums sidecar: when present, every artefact's actual digest must match
        // before any blob lands. Mismatch fails the WHOLE batch (tamper-evidence — partial
        // accepts defeat the purpose). Absence keeps the legacy behaviour unchanged.
        var sumsCheck = await ValidateSha256SumsSidecarAsync(form, artefactFiles, ct);
        if (sumsCheck is not null) return sumsCheck;

        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var importCtx = new ImportContext(orgId, actorId, Guid.NewGuid().ToString("N"));
        var outcomes = new List<object>(artefactFiles.Count);
        var accepted = 0;
        var rejected = 0;

        foreach (var file in artefactFiles)
        {
            if (ct.IsCancellationRequested) break;
            var bytes = await ReadAllAsync(file, ct);
            var outcome = await ImportOneAsync(importCtx, file.FileName, bytes, settings, dryRun, ct);
            outcomes.Add(outcome);
            if (outcome is AcceptedOutcome) accepted++; else rejected++;
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
    /// #46: parses the optional <c>sha256sums</c> multipart part and verifies every artefact
    /// in the batch matches its declared digest. Returns null when the sidecar is absent
    /// (legacy path) or all files match; returns a 422 IActionResult on parse error or
    /// digest mismatch. Files NOT mentioned in the sidecar are rejected — if you sign a
    /// bundle, every artefact must be in the bundle.
    /// </summary>
    private async Task<IActionResult?> ValidateSha256SumsSidecarAsync(
        IFormCollection form, IReadOnlyList<IFormFile> artefactFiles, CancellationToken ct)
    {
        var sidecar = form.Files.GetFile("sha256sums");
        if (sidecar is null) return null;

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
            if (!expected.TryGetValue(file.FileName, out var declared))
            {
                unlisted.Add(file.FileName);
                continue;
            }
            using var ms = new MemoryStream();
            await file.CopyToAsync(ms, ct);
            var actual = Convert.ToHexString(SHA256.HashData(ms.ToArray())).ToLowerInvariant();
            if (!string.Equals(actual, declared, StringComparison.OrdinalIgnoreCase))
                mismatches.Add(new { filename = file.FileName, expected = declared, actual });
        }

        if (mismatches.Count > 0 || unlisted.Count > 0)
        {
            return UnprocessableEntity(new
            {
                title = "sha256sums verification failed",
                detail = "One or more artefacts did not match the sidecar; nothing was imported.",
                mismatches,
                unlisted_files = unlisted,
            });
        }
        return null;
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
    [RequestSizeLimit(4L * 1024 * 1024 * 1024)]
    [RequireCapability(Capabilities.ImportAll)]
    public async Task<IActionResult> ImportManifest([FromQuery] bool dryRun, CancellationToken ct)
    {
        var ctxResult = await AuthorizeAdminAsync(ct);
        if (ctxResult.Error is not null) return ctxResult.Error;
        var (orgId, actorId) = (ctxResult.OrgId!, ctxResult.ActorId);

        var (form, formError) = await ReadManifestFormAsync(ct);
        if (formError is not null) return formError;

        var (manifest, manifestError) = await ParseManifestPartAsync(form!, ct);
        if (manifestError is not null) return manifestError;

        var artefactFiles = form!.Files.Where(f => f.Name != "manifest" && f.Name != "sha256sums").ToList();
        var loaded = await LoadArtefactsAsync(artefactFiles, ct);

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

    private async Task<(IFormCollection? form, IActionResult? error)> ReadManifestFormAsync(CancellationToken ct)
    {
        if (!Request.HasFormContentType)
            return (null, BadRequest("Expected multipart/form-data."));
        return (await Request.ReadFormAsync(ct), null);
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
            return (null, BadRequest("Expected a 'manifest' multipart part containing the lockfile."));

        byte[] manifestBytes;
        using (var ms = new MemoryStream())
        {
            await manifestFile.CopyToAsync(ms, ct);
            manifestBytes = ms.ToArray();
        }
        var manifestText = System.Text.Encoding.UTF8.GetString(manifestBytes);
        var manifestType = ManifestParser.Detect(manifestFile.FileName, manifestText);
        if (manifestType == ManifestParser.ManifestType.Unknown)
            return (null, BadRequest($"Unrecognised manifest type for '{manifestFile.FileName}'. " +
                                     "Expected package-lock.json, requirements.txt, or packages.lock.json."));

        IReadOnlyList<ManifestEntry> expected;
        try { expected = ManifestParser.Parse(manifestType, manifestText); }
        catch (Exception ex) { return (null, BadRequest($"Failed to parse manifest: {ex.Message}")); }

        if (expected.Count == 0)
            return (null, BadRequest("Manifest contains no package entries."));

        var digest = Convert.ToHexString(SHA256.HashData(manifestBytes)).ToLowerInvariant();
        return (new ManifestParseResult(manifestType, digest, expected), null);
    }

    private static async Task<List<LoadedArtefact>> LoadArtefactsAsync(
        List<IFormFile> artefactFiles, CancellationToken ct)
    {
        var loaded = new List<LoadedArtefact>(artefactFiles.Count);
        foreach (var file in artefactFiles)
        {
            using var ms = new MemoryStream();
            await file.CopyToAsync(ms, ct);
            var bytes = ms.ToArray();
            var sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            var (ok, err) = EcosystemDetector.Detect(file.FileName, bytes);
            loaded.Add(new LoadedArtefact(
                file.FileName, bytes, sha,
                ok?.Ecosystem, ok?.Name, ok?.PurlName, ok?.Version,
                err?.Message));
        }
        return loaded;
    }

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

    private async Task<(List<object> outcomes, int accepted, int rejected)> ImportLoadedArtefactsAsync(
        ImportContext ctx, IReadOnlyList<LoadedArtefact> loaded, OrgSettings? settings,
        bool dryRun, CancellationToken cancellationToken)
    {
        var outcomes = new List<object>(loaded.Count);
        var accepted = 0;
        var rejected = 0;
        foreach (var artefact in loaded)
        {
            if (cancellationToken.IsCancellationRequested) break;
            // ParseError is null here because BuildManifestCoverage already pre-validated.
            var detection = new EcosystemDetector.DetectionResult(
                artefact.Ecosystem!, artefact.Name!, artefact.PurlName!, artefact.Version!);
            var outcome = await ImportDetectedAsync(
                ctx, artefact.Filename, artefact.Bytes, detection, settings, dryRun, cancellationToken);
            outcomes.Add(outcome);
            if (outcome is AcceptedOutcome) accepted++; else rejected++;
        }
        return (outcomes, accepted, rejected);
    }

    private sealed record LoadedArtefact(
        string Filename, byte[] Bytes, string Sha256,
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
        if (ok is null)
            return Reject(filename, err!.Code, err.Message, dryRun: dryRun);

        return await ImportDetectedAsync(ctx, filename, bytes, ok, settings, dryRun, ct);
    }

    private async Task<object> ImportDetectedAsync(
        ImportContext ctx, string filename, byte[] bytes,
        EcosystemDetector.DetectionResult detection, OrgSettings? settings,
        bool dryRun, CancellationToken ct)
    {
        var sizeCap = SizeCapFor(detection.Ecosystem, settings);
        var purl = PurlFor(detection);
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
                await _licenses.SetLicensesAsync(accepted.VersionId, extracted.Spdx, "uploaded", ct);
        }

        return OutcomeFromResult(filename, result, detection.Ecosystem, detection.PurlName, dryRun);
    }

    private static LicenseExtractor.ExtractedMetadata ExtractLicense(
        string ecosystem, byte[] bytes, string filename) => ecosystem switch
    {
        "nuget" => LicenseExtractor.FromNuspec(bytes),
        "pypi"  => LicenseExtractor.FromPyPiPackageBytes(bytes, filename),
        "npm"   => LicenseExtractor.FromNpmTarballPackageJson(bytes),
        _       => LicenseExtractor.ExtractedMetadata.Empty,
    };

    private static string PurlFor(EcosystemDetector.DetectionResult d) => d.Ecosystem switch
    {
        "npm"   => PurlNormalizer.Npm(d.Name, d.Version),
        "pypi"  => PurlNormalizer.PyPi(d.Name, d.Version),
        "nuget" => PurlNormalizer.NuGet(d.Name, d.Version),
        _ => throw new ArgumentOutOfRangeException(nameof(d), $"Unsupported ecosystem '{d.Ecosystem}'.")
    };

    private static long SizeCapFor(string ecosystem, OrgSettings? settings)
    {
        var fallback = settings?.MaxUploadBytes ?? long.MaxValue;
        return ecosystem switch
        {
            "npm"   => settings?.MaxUploadBytesNpm   ?? fallback,
            "pypi"  => settings?.MaxUploadBytesPyPi  ?? fallback,
            "nuget" => settings?.MaxUploadBytesNuGet ?? fallback,
            _ => fallback
        };
    }

    private static async Task<byte[]> ReadAllAsync(IFormFile file, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        await file.CopyToAsync(ms, ct);
        return ms.ToArray();
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
        // invariant. tenant:configure is the management-API gate (admin + owner).
        var deny = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (deny is not null) return (deny, null, null);
        var ctx = (TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!;
        var actorId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
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
    LicenseRepository Licenses);
