using System.Security.Cryptography;
using Dependably.Infrastructure.Audit;
using Dependably.Infrastructure.Audit.Events;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;

namespace Dependably.Infrastructure.Publish;

/// <summary>
/// Default <see cref="IPackagePublishService"/>. The single tail end of the publish flow:
/// path safety → claim gate → size cap → dedup check → blob put → version create → audit.
/// Replaces what used to be inlined in three protocol controllers and three import handlers.
/// </summary>
public sealed class PackagePublishService : IPackagePublishService
{
    private readonly PackageRepository _packages;
    private readonly IBlobStore _blobs;   // TieredBlobStorage.Registry — never the cache tier (#57)
    private readonly AuditRepository _audit;
    private readonly PublishGate _publishGate;
    private readonly IAuditEmitter _auditEmitter;
    private readonly VulnerabilityScanService _scanner;
    private readonly ILogger<PackagePublishService> _logger;

    public PackagePublishService(
        PackageRepository packages,
        TieredBlobStorage blobs,
        AuditRepository audit,
        PublishGate publishGate,
        IAuditEmitter auditEmitter,
        VulnerabilityScanService scanner,
        ILogger<PackagePublishService> logger)
    {
        _packages = packages;
        // Published artefacts always land on the registry tier. In split-tier deployments
        // the cache tier is recoverable / cheap; the registry tier is durable / backed up.
        _blobs = blobs.Registry;
        _audit = audit;
        _publishGate = publishGate;
        _auditEmitter = auditEmitter;
        _scanner = scanner;
        _logger = logger;
    }

    public async Task<PublishResult> StoreAndRecordAsync(PublishRequest request, CancellationToken ct = default)
    {
        // 1. Path safety on the components that land verbatim in path positions. Name is
        //    intentionally not validated here: npm scoped names ("@scope/name") legitimately
        //    contain a slash, and per-ecosystem callers do their own format validation
        //    (PEP 508, NuGet id charset, npm name regex) before reaching the service.
        foreach (var (value, kind) in new[]
        {
            (request.Version, "version"),
            (request.Filename, "filename")
        })
        {
            var safe = PathSafeValidator.Validate(value, kind);
            if (!safe.IsValid)
                return new PublishResult.Rejected(422, "path_unsafe", safe.Message ?? "Unsafe value.");
        }
        // PurlName / Name still need a traversal guard — without it, a malformed caller
        // could persist "../etc" as a name. Reject only the dangerous shape, not the slash.
        if (request.Name.Contains("..") || request.PurlName.Contains("..")
            || request.Name.Contains('\0') || request.PurlName.Contains('\0'))
            return new PublishResult.Rejected(422, "path_unsafe", "Name must not contain '..' or null bytes.");

        // 2. Size cap. Callers know per-tenant + per-ecosystem cap; we enforce as a final
        //    safety net so no single path can write a too-large blob even if a caller forgets.
        if (request.ArtifactBytes.LongLength > request.SizeCap)
            return new PublishResult.Rejected(413, "size_limit_exceeded",
                $"File exceeds the {request.Ecosystem} upload size limit ({request.SizeCap} bytes).");

        // 3. Claim gate. The PublishGate is no-op when CLAIM_ENFORCEMENT=off and when an
        //    explicit local_only/mixed claim already exists. Errors come back as 409 from
        //    the gate; we translate them into the service's structured Rejected shape.
        var claimReject = await _publishGate.CheckAsync(request.OrgId, request.Ecosystem, request.PurlName, ct);
        if (claimReject is not null)
            return new PublishResult.Rejected(409, "claim_required",
                $"Name '{request.PurlName}' is unclaimed; create a 'local_only' or 'mixed' claim first.");

        // 4. Dedup vs overwrite (#45). When AllowOverwrite is false (default) a duplicate
        //    coordinate rejects with 409. When true, the existing row's artefact is replaced
        //    in place and a package.replace audit event records both old and new hashes.
        var blobKey = BlobKeys.Hosted(request.OrgId, request.Ecosystem, request.PurlName, request.Version, request.Filename);
        var pkg = await _packages.GetOrCreateAsync(request.OrgId, request.Ecosystem, request.Name, request.PurlName, isProxy: false, ct);
        var existing = await _packages.GetVersionAsync(pkg.Id, request.Version, ct);
        if (existing is not null && !request.AllowOverwrite)
            return new PublishResult.Rejected(409, "version_exists",
                $"Tarball parsed as {request.PurlName}@{request.Version}; that version already exists. " +
                "Delete it first or enable allow_version_overwrite.");

        // 5. Hash + blob put. SHA-256 is recomputed inside the trust boundary even when
        //    callers passed the bytes pre-hashed — cheap, and it removes "did the caller
        //    hash it correctly?" from the trust surface.
        var sha256 = Convert.ToHexString(SHA256.HashData(request.ArtifactBytes)).ToLowerInvariant();
        await _blobs.PutAsync(blobKey, new MemoryStream(request.ArtifactBytes), ct);

        PackageVersion newVersion;
        if (existing is not null)
        {
            // Overwrite path: keep the same id so dependent rows (vulns, licenses) follow.
            // vuln_checked_at is reset by the repository so the next scan re-checks the new
            // bytes — the prior scan applied to a hash that's no longer in the blob store.
            await _packages.UpdateVersionForOverwriteAsync(existing.Id, blobKey,
                request.ArtifactBytes.LongLength, sha256, request.Origin, ct);
            newVersion = (await _packages.GetVersionAsync(pkg.Id, request.Version, ct))!;
        }
        else
        {
            newVersion = await _packages.CreateVersionAsync(
                new NewPackageVersion(pkg.Id, request.Version, request.Purl, blobKey,
                    request.ArtifactBytes.LongLength, sha256, Origin: request.Origin), ct);
        }

        // Parity with proxy first-fetch (see NpmController/PyPiController/NuGetController
        // post-RecordOrLookupProxyVersionAsync): scan the new bytes synchronously so the
        // Unscanned banner clears before the publisher's request returns. Custom names OSV
        // doesn't know about resolve to zero advisories → status "clean", same path as a
        // public package with no known issues. Failures are swallowed so a transient OSV
        // outage cannot fail an otherwise valid publish; the scheduled pass retries later.
        try
        {
            await _scanner.ScanVersionAsync(request.Purl, newVersion.Id, request.Ecosystem,
                request.PurlName, request.OrgId, request.ActorUserId, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Post-publish vuln scan failed for {Purl}; scheduled pass will retry.", request.Purl);
        }

        // 6. Audit. Imports are per-version operator events and belong in `activity` only —
        //    `audit_log` is the tenant-level config/security sink. Never dual-write (5f6e1f0).
        //    `push` still dual-writes pending the separate sweep called out in that commit.
        //    Typed audit_event emission below is independent and runs for both.
        if (request.AuditAction != "import")
        {
            await _audit.LogAsync(request.AuditAction, request.OrgId, request.ActorUserId,
                request.Ecosystem, request.Purl, detail: request.AuditDetail, ct: ct);
        }
        await _audit.LogActivityAsync(request.OrgId, request.Ecosystem, request.Purl,
            request.AuditAction, request.ActorUserId, detail: request.AuditDetail, ct: ct);

        // Typed event into audit_event. Action mapping: 'push' → package.publish,
        // 'import' → package.import (carries batch_id + import_mode in the detail).
        var actorType = request.ActorUserId is null ? "system" : "user";
        if (request.AuditAction == "import")
        {
            // Pull batch_id + import_mode out of the caller-supplied detail JSON. Best
            // effort: if absent, fall back to neutral defaults rather than dropping the event.
            var (batchId, importMode) = ExtractBatchInfo(request.AuditDetail);
            var payload = new PackageEvents.Import(
                request.Ecosystem, request.PurlName, request.Version, request.Filename,
                "sha256:" + sha256, request.ArtifactBytes.LongLength, request.Origin,
                batchId, importMode, request.ClaimState).ToJson();
            await _auditEmitter.EmitAsync(PackageEvents.TypeImport,
                request.OrgId, actorType, request.ActorUserId, "accepted", payload, ct);
        }
        else
        {
            var payload = new PackageEvents.Publish(
                request.Ecosystem, request.PurlName, request.Version, request.Filename,
                "sha256:" + sha256, request.ArtifactBytes.LongLength, request.Origin,
                request.ClaimState).ToJson();
            await _auditEmitter.EmitAsync(PackageEvents.TypePublish,
                request.OrgId, actorType, request.ActorUserId, "accepted", payload, ct);
        }

        if (existing is not null)
        {
            var priorHash = "sha256:" + (existing.ChecksumSha256 ?? "");
            var newHash = "sha256:" + sha256;
            var replaceDetail = System.Text.Json.JsonSerializer.Serialize(new
            {
                prior_artifact_hash = priorHash,
                artifact_hash = newHash,
                origin = request.Origin,
            });
            await _audit.LogAsync("package.replace", request.OrgId, request.ActorUserId,
                request.Ecosystem, request.Purl, detail: replaceDetail, ct: ct);

            var replacePayload = new PackageEvents.Replace(
                request.Ecosystem, request.PurlName, request.Version, request.Filename,
                newHash, priorHash, request.ArtifactBytes.LongLength, request.Origin,
                request.ClaimState).ToJson();
            await _auditEmitter.EmitAsync(PackageEvents.TypeReplace,
                request.OrgId, actorType, request.ActorUserId, "accepted", replacePayload, ct);
        }

        return new PublishResult.Accepted(newVersion.Id, request.Purl, sha256);
    }

    /// <summary>
    /// Dry-run companion to <see cref="StoreAndRecordAsync"/> (#46). Runs the same
    /// validation chain — path safety, size cap, claim gate, dedup — but stops short of
    /// any write: no blob put, no version row, no audit emission. Uses
    /// <see cref="PackageRepository.GetByPurlNameAsync"/> in place of
    /// <c>GetOrCreateAsync</c> so the package row is not created as a side effect.
    /// On Accepted, <c>VersionId</c> is the empty string and <c>Sha256</c> is the
    /// computed digest of the candidate bytes.
    /// </summary>
    public async Task<PublishResult> ValidateAsync(PublishRequest request, CancellationToken ct = default)
    {
        // 1. Path safety — same rules as the live path. See StoreAndRecordAsync for the
        //    rationale on Name being excluded from the strict validator.
        foreach (var (value, kind) in new[]
        {
            (request.Version, "version"),
            (request.Filename, "filename")
        })
        {
            var safe = PathSafeValidator.Validate(value, kind);
            if (!safe.IsValid)
                return new PublishResult.Rejected(422, "path_unsafe", safe.Message ?? "Unsafe value.");
        }
        if (request.Name.Contains("..") || request.PurlName.Contains("..")
            || request.Name.Contains('\0') || request.PurlName.Contains('\0'))
            return new PublishResult.Rejected(422, "path_unsafe", "Name must not contain '..' or null bytes.");

        // 2. Size cap.
        if (request.ArtifactBytes.LongLength > request.SizeCap)
            return new PublishResult.Rejected(413, "size_limit_exceeded",
                $"File exceeds the {request.Ecosystem} upload size limit ({request.SizeCap} bytes).");

        // 3. Claim gate.
        var claimReject = await _publishGate.CheckAsync(request.OrgId, request.Ecosystem, request.PurlName, ct);
        if (claimReject is not null)
            return new PublishResult.Rejected(409, "claim_required",
                $"Name '{request.PurlName}' is unclaimed; create a 'local_only' or 'mixed' claim first.");

        // 4. Dedup — non-mutating lookup. If the package row doesn't exist yet, the
        //    version can't either, so dedup passes implicitly.
        var pkg = await _packages.GetByPurlNameAsync(request.OrgId, request.Ecosystem, request.PurlName, ct);
        if (pkg is not null)
        {
            var existing = await _packages.GetVersionAsync(pkg.Id, request.Version, ct);
            if (existing is not null && !request.AllowOverwrite)
                return new PublishResult.Rejected(409, "version_exists",
                    $"Tarball parsed as {request.PurlName}@{request.Version}; that version already exists. " +
                    "Delete it first or enable allow_version_overwrite.");
        }

        var sha256 = Convert.ToHexString(SHA256.HashData(request.ArtifactBytes)).ToLowerInvariant();
        return new PublishResult.Accepted(VersionId: "", request.Purl, sha256);
    }

    /// <summary>
    /// Best-effort lift of batch_id + import_mode out of the caller-supplied detail JSON.
    /// Returns neutral fallbacks when the JSON is absent or malformed — we'd rather emit
    /// the event with placeholders than drop it.
    /// </summary>
    private static (string BatchId, string ImportMode) ExtractBatchInfo(string? detail)
    {
        if (string.IsNullOrEmpty(detail)) return ("", "single");
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(detail);
            var root = doc.RootElement;
            var batchId = root.TryGetProperty("batch_id", out var b) && b.ValueKind == System.Text.Json.JsonValueKind.String
                ? b.GetString() ?? "" : "";
            var mode = root.TryGetProperty("import_mode", out var m) && m.ValueKind == System.Text.Json.JsonValueKind.String
                ? m.GetString() ?? "single" : "single";
            return (batchId, mode);
        }
        catch
        {
            return ("", "single");
        }
    }
}
