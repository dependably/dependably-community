using System.Net.Http;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;

namespace Dependably.Storage;

/// <summary>
/// Orchestrates the post-bytes half of the proxy cache-miss flow shared by the three
/// ecosystem controllers (PyPI, npm, NuGet). Each ecosystem still owns its own upstream
/// URL shape and the per-format extractors; once those produce the raw artefact bytes,
/// every controller does the same dance:
///
/// <list type="number">
///   <item>SHA-256 the bytes (trust-boundary recompute even if the caller passed a hash).</item>
///   <item>Blob put under <see cref="BlobKeys.Proxy"/> if not already present.</item>
///   <item>Best-effort <see cref="CacheAccessRecorder"/> tick (per-tenant first/last access).</item>
///   <item>Record the version row via <see cref="ProxyVersionRecorder"/> (handles the
///         unique-constraint race when two concurrent first-fetches collide).</item>
///   <item>Synchronous OSV scan so the block gate can fire on the very first fetch.</item>
///   <item><see cref="BlockGateService"/> evaluate; on Blocked the caller returns 403.</item>
/// </list>
///
/// This service is the single home for that sequence. Each controller's proxy method
/// shrinks to: build the upstream URL → fetch → call <see cref="RecordAndScanAsync"/>.
/// </summary>
public sealed class ProxyFetchService
{
    private readonly IBlobStore _blobs;
    private readonly CacheAccessRecorder _cacheRecorder;
    private readonly ProxyVersionRecorder _proxyVersions;
    private readonly VulnerabilityScanService _scanner;
    private readonly BlockGateService _blockGate;
    private readonly PackageRepository _packages;

    public ProxyFetchService(
        IBlobStore blobs,
        CacheAccessRecorder cacheRecorder,
        ProxyVersionRecorder proxyVersions,
        VulnerabilityScanService scanner,
        BlockGateService blockGate,
        PackageRepository packages)
    {
        // Currently uses the default IBlobStore registration (registry tier). The cache-tier
        // routing for proxy artefacts is tracked separately (#57); the existing controllers
        // wrote here too, so this preserves their behaviour exactly.
        _blobs = blobs;
        _cacheRecorder = cacheRecorder;
        _proxyVersions = proxyVersions;
        _scanner = scanner;
        _blockGate = blockGate;
        _packages = packages;
    }

    /// <summary>
    /// Hashes + caches the raw bytes, records the proxy version, scans it, and runs the
    /// block gate. Returns the outcome plus the bytes so the caller can serve them. Bytes
    /// are returned unchanged on Allowed; the caller writes the HTTP response.
    /// </summary>
    public async Task<ProxyFetchResult> RecordAndScanAsync(
        ProxyFetchRequest request, CancellationToken ct = default)
    {
        var sha256 = ChecksumVerifier.ComputeSha256Hex(request.Bytes);
        var blobKey = BlobKeys.Proxy(sha256);
        if (!await _blobs.ExistsAsync(blobKey, ct))
            await _blobs.PutAsync(blobKey, new MemoryStream(request.Bytes), ct);

        // #48 cache_artifact + tenant_artifact_access. Best-effort: a recorder failure
        // shouldn't fail the proxy fetch, so the caller may pass null to opt out and the
        // controller can skip this entirely.
        if (request.CacheAccess is { } access)
        {
            await _cacheRecorder.RecordAccessAsync(access with { Sha256 = sha256, BlobKey = blobKey, SizeBytes = request.Bytes.Length }, ct);
        }

        var scanVersionId = await _proxyVersions.RecordAsync(
            new ProxyVersionRequest(
                OrgId: request.OrgId, Ecosystem: request.Ecosystem,
                PackageName: request.PackageName, PurlName: request.PurlName,
                Version: request.Version, Purl: request.Purl,
                Sha256: sha256, File: request.File, Bytes: request.Bytes,
                UserId: request.UserId, SourceIp: request.SourceIp),
            request.ExtractLicenses, ct);

        if (scanVersionId is null)
        {
            // Race recovery in ProxyVersionRecorder returned null — the parent package row
            // was deleted between the unique-constraint catch and the lookup. Rare; treat
            // as "served but unrecorded" so the bytes still flow to the client.
            return new ProxyFetchResult(BlockDecision.Allowed, sha256, blobKey, VersionId: null);
        }

        // Synchronous scan so the block gate can act on the very first fetch.
        await _scanner.ScanVersionAsync(request.Purl, scanVersionId, request.Ecosystem,
            request.PurlName, request.OrgId, request.UserId, ct);

        var existing = await _packages.GetVersionByIdAsync(scanVersionId, ct);
        var decision = await _blockGate.EvaluateAsync(
            new BlockGateRequest(request.OrgId, request.Ecosystem, request.Purl, scanVersionId,
                existing?.ManualBlockState, DateTimeOffset.UtcNow,
                request.UserId, request.MaxOsvScoreTolerance, request.SourceIp), ct);

        return new ProxyFetchResult(decision, sha256, blobKey, scanVersionId);
    }
}

/// <summary>Inputs to <see cref="ProxyFetchService.RecordAndScanAsync"/>.</summary>
public sealed record ProxyFetchRequest(
    string OrgId,
    string Ecosystem,
    string PackageName,
    string PurlName,
    string Version,
    string Purl,
    string File,
    byte[] Bytes,
    Func<byte[], LicenseExtractor.ExtractedMetadata>? ExtractLicenses,
    string? UserId,
    string? SourceIp,
    double MaxOsvScoreTolerance,
    /// <summary>
    /// Optional #48 cache-access record. Pass null to skip (e.g. PyPI's pre-known-sha
    /// path tracks access elsewhere). The recorder updates Sha256/BlobKey/SizeBytes from
    /// the freshly-computed values regardless of what the caller seeded them with.
    /// </summary>
    CacheAccess? CacheAccess);

/// <summary>Outcome of <see cref="ProxyFetchService.RecordAndScanAsync"/>.</summary>
public sealed record ProxyFetchResult(
    BlockDecision Decision,
    string Sha256,
    string BlobKey,
    string? VersionId);
