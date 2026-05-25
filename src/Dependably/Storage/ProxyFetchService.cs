using System.Net.Http;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
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
    private readonly AuditRepository _audit;

    public ProxyFetchService(
        IBlobStore blobs,
        CacheAccessRecorder cacheRecorder,
        ProxyVersionRecorder proxyVersions,
        VulnerabilityScanService scanner,
        BlockGateService blockGate,
        PackageRepository packages,
        AuditRepository audit)
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
        _audit = audit;
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

        // Fail-fast verification against the upstream-supplied integrity hash (PyPI
        // #sha256=, npm dist.integrity / dist.shasum, NuGet packageHash). Run BEFORE the
        // blob put so we never cache bytes that upstream itself disagrees with. Caller
        // catches the ChecksumException and returns 502 Bad Gateway. Mirrors the
        // UpstreamClient pre-known-sha path so SIEM sees one consistent event shape.
        if (request.UpstreamChecksum is { } spec && !ChecksumVerifier.Verify(request.Bytes, spec))
        {
            DependablyMeter.UpstreamChecksumFailures.Add(1,
                new KeyValuePair<string, object?>("ecosystem", request.Ecosystem));
            await _audit.LogAsync(
                "checksum_failure",
                orgId: request.OrgId,
                ecosystem: request.Ecosystem,
                purl: request.Purl,
                detail: $"{{\"version\":\"{request.Version}\",\"file\":\"{request.File}\",\"algorithm\":\"{spec.Algorithm}\",\"expected\":\"{spec.ExpectedValue}\",\"actual_sha256\":\"{sha256}\"}}",
                ct: ct);
            throw new ChecksumException(
                $"Upstream-supplied {spec.Algorithm} hash for {request.Purl} did not match the downloaded bytes.");
        }

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
                UserId: request.UserId, SourceIp: request.SourceIp,
                PublishedAt: request.PublishedAt,
                Sha1Hex: request.Sha1Hex,
                UpstreamIntegrityValue: request.UpstreamIntegrityValue,
                UpstreamIntegrityAlgorithm: request.UpstreamIntegrityAlgorithm),
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

        var existing = await _packages.GetVersionByIdAsync(request.OrgId, scanVersionId, ct);
        var decision = await _blockGate.EvaluateAsync(
            new BlockGateRequest(request.OrgId, request.Ecosystem, request.Purl, scanVersionId,
                existing?.ManualBlockState, DateTimeOffset.UtcNow,
                request.UserId, request.MaxOsvScoreTolerance, request.SourceIp,
                MinReleaseAgeHours: request.MinReleaseAgeHours,
                PublishedAt: request.PublishedAt), ct);

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
    CacheAccess? CacheAccess,
    /// <summary>
    /// Tenant's <c>org_settings.min_release_age_hours</c> at the time of the fetch. NULL = no
    /// policy. Plumbed through to <see cref="BlockGateService"/>, where a positive value blocks
    /// versions whose upstream publish timestamp is younger than the hold window. Fail-open
    /// when <see cref="PublishedAt"/> is null.
    /// </summary>
    int? MinReleaseAgeHours = null,
    /// <summary>
    /// Upstream first-publish timestamp the caller extracted from registry metadata. Null
    /// when the caller couldn't reach or parse the metadata — captured fail-soft.
    /// </summary>
    DateTimeOffset? PublishedAt = null,
    /// <summary>
    /// Upstream-supplied integrity hash for fail-fast verification of the downloaded bytes.
    /// PyPI sets a SHA-256 from the simple-index fragment or the JSON API <c>digests</c>;
    /// npm sets a SHA-512 SRI from <c>dist.integrity</c> (or hex SHA-1 from <c>dist.shasum</c>);
    /// NuGet sets a SHA-512 from <c>packageHash</c>. Null when the metadata couldn't be parsed
    /// or didn't carry an integrity field — the request proceeds without verification, same
    /// fail-soft semantics as <see cref="PublishedAt"/>. On mismatch <see cref="ProxyFetchService"/>
    /// audits a <c>checksum_failure</c> event and throws <see cref="ChecksumException"/>.
    /// </summary>
    ChecksumSpec? UpstreamChecksum = null,
    /// <summary>
    /// Hex SHA-1 of the artefact bytes, captured by the npm controller from the packument's
    /// <c>dist.shasum</c> for persistence so the packument we re-emit later carries a correct
    /// SHA-1. Stored in <c>package_versions.checksum_sha1</c>. Null for non-npm ecosystems and
    /// when the upstream packument didn't include the field.
    /// </summary>
    string? Sha1Hex = null,
    /// <summary>
    /// Upstream-published integrity hash, stored verbatim in upstream's native encoding so
    /// the version detail UI can show "this is what npmjs.com / nuget.org / pypi.org claims"
    /// alongside our own SHA-256. Paired with <see cref="UpstreamIntegrityAlgorithm"/>.
    /// Null when the metadata couldn't be parsed or didn't carry an integrity field.
    /// </summary>
    string? UpstreamIntegrityValue = null,
    /// <summary>
    /// Tag describing <see cref="UpstreamIntegrityValue"/>: <c>'sha256'</c> (hex),
    /// <c>'sha512-sri'</c> (npm SRI form), or <c>'sha512-b64'</c> (NuGet packageHash).
    /// </summary>
    string? UpstreamIntegrityAlgorithm = null);

/// <summary>Outcome of <see cref="ProxyFetchService.RecordAndScanAsync"/>.</summary>
public sealed record ProxyFetchResult(
    BlockDecision Decision,
    string Sha256,
    string BlobKey,
    string? VersionId);
