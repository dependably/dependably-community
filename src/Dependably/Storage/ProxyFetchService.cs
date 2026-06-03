using System.Net.Http;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Protocol;
using Dependably.Security;

namespace Dependably.Storage;

/// <summary>
/// Orchestrates the post-fetch half of the proxy cache-miss flow shared by the three
/// ecosystem controllers (PyPI, npm, NuGet). Each ecosystem still owns its own upstream
/// URL shape and the per-format extractors; once those produce a verified, blob-cached
/// artefact (described by a <see cref="BlobHandle"/>), every controller does the same dance:
///
/// <list type="number">
///   <item>Trust-boundary checksum re-verify against an upstream-supplied integrity hash
///         (the SHA-256 itself is already known — <see cref="UpstreamClient"/> computed it
///         inline during hash-and-stage).</item>
///   <item>First-fetch deprecation gate (<see cref="BlockGateService.EvaluateFirstFetchDeprecationAsync"/>):
///         under <c>block_new</c>/<c>block_all</c> a deprecated version is refused here, before
///         the version row is recorded, so it never enters the cache catalogue.</item>
///   <item>Best-effort <see cref="CacheAccessRecorder"/> tick (per-tenant first/last access).</item>
///   <item>Record the version row via <see cref="ProxyVersionRecorder"/> (handles the
///         unique-constraint race when two concurrent first-fetches collide).</item>
///   <item>Synchronous OSV scan so the block gate can fire on the very first fetch.</item>
///   <item><see cref="BlockGateService"/> evaluate; on Blocked the caller returns 403.</item>
/// </list>
///
/// This service is the single home for that sequence. Each controller's proxy method
/// shrinks to: build the upstream URL → fetch+stage → call <see cref="RecordAndScanAsync"/>.
/// </summary>
public sealed class ProxyFetchService
{
    private readonly CacheAccessRecorder _cacheRecorder;
    private readonly ProxyVersionRecorder _proxyVersions;
    private readonly VulnerabilityScanService _scanner;
    private readonly BlockGateService _blockGate;
    private readonly PackageRepository _packages;
    private readonly AuditRepository _audit;

    public ProxyFetchService(
        CacheAccessRecorder cacheRecorder,
        ProxyVersionRecorder proxyVersions,
        VulnerabilityScanService scanner,
        BlockGateService blockGate,
        PackageRepository packages,
        AuditRepository audit)
    {
        _cacheRecorder = cacheRecorder;
        _proxyVersions = proxyVersions;
        _scanner = scanner;
        _blockGate = blockGate;
        _packages = packages;
        _audit = audit;
    }

    /// <summary>
    /// Runs the post-fetch pipeline: optional fail-fast checksum verify, cache-access
    /// tick, record version row, scan, evaluate block gate. The blob has already been
    /// written by <see cref="UpstreamClient.FetchAndStageAsync"/> and the
    /// SHA-256 was computed inline — both are passed through on <see cref="BlobHandle"/>.
    /// </summary>
    public async Task<ProxyFetchResult> RecordAndScanAsync(
        ProxyFetchRequest request, CancellationToken ct = default)
    {
        var sha256 = request.Blob.Sha256Hex;
        var blobKey = request.Blob.BlobKey;
        var sizeBytes = request.Blob.SizeBytes;

        // Fail-fast verification against the upstream-supplied integrity hash (PyPI
        // #sha256=, npm dist.integrity / dist.shasum, NuGet packageHash). The SHA-256
        // was already verified inline by UpstreamClient.FetchAndStageAsync; for other
        // algorithms we stream the cached blob through ChecksumVerifier rather than
        // re-buffering. On mismatch the caller catches ChecksumException → 502 Bad
        // Gateway. Mirrors the UpstreamClient pre-known-sha path so SIEM sees one
        // consistent event shape.
        if (request.UpstreamChecksum is { } spec && !await VerifyChecksumAsync(spec, sha256, request, ct))
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

        // First-fetch deprecation gate. Runs BEFORE the version row is recorded so a deprecated
        // version is never adopted into the cache catalogue under block_new / block_all: with no
        // version row, the controllers' cache-hit lookup misses and every subsequent request
        // re-enters this fetch path and re-blocks. (The blob bytes were already staged by
        // UpstreamClient; that orphan lives in the eviction-friendly cache tier and is never
        // served because nothing references it.) block_new vs block_all is resolved here — both
        // deny on the first fetch; only block_all additionally denies cached versions, which is
        // handled later by EvaluateAsync on the serve path.
        if (request.Deprecated is not null)
        {
            var firstFetch = await _blockGate.EvaluateFirstFetchDeprecationAsync(
                new BlockGateRequest(request.OrgId, request.Ecosystem, request.Purl, string.Empty,
                    null, null,
                    request.UserId, request.MaxOsvScoreTolerance, request.SourceIp,
                    ActorKind: request.ActorKind,
                    Deprecated: request.Deprecated,
                    BlockDeprecatedMode: request.BlockDeprecatedMode), ct);
            if (firstFetch == BlockDecision.Blocked)
                return new ProxyFetchResult(BlockDecision.Blocked, sha256, blobKey, VersionId: null);
        }

        // Cache-access record into cache_artifact + tenant_artifact_access. Best-effort: a recorder failure
        // shouldn't fail the proxy fetch, so the caller may pass null to opt out and the
        // controller can skip this entirely.
        if (request.CacheAccess is { } access)
        {
            await _cacheRecorder.RecordAccessAsync(access with { Sha256 = sha256, BlobKey = blobKey, SizeBytes = sizeBytes }, ct);
        }

        var scanVersionId = await _proxyVersions.RecordAsync(
            new ProxyVersionRequest(
                OrgId: request.OrgId, Ecosystem: request.Ecosystem,
                PackageName: request.PackageName, PurlName: request.PurlName,
                Version: request.Version, Purl: request.Purl,
                Sha256: sha256, File: request.File, Blob: request.Blob,
                UserId: request.UserId, ActorKind: request.ActorKind, SourceIp: request.SourceIp,
                PublishedAt: request.PublishedAt,
                Sha1Hex: request.Sha1Hex,
                UpstreamIntegrityValue: request.UpstreamIntegrityValue,
                UpstreamIntegrityAlgorithm: request.UpstreamIntegrityAlgorithm,
                Deprecated: request.Deprecated),
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
                PublishedAt: request.PublishedAt,
                ActorKind: request.ActorKind,
                Deprecated: existing?.Deprecated,
                BlockDeprecatedMode: request.BlockDeprecatedMode), ct);

        return new ProxyFetchResult(decision, sha256, blobKey, scanVersionId);
    }

    /// <summary>
    /// Stream the cached blob through <see cref="ChecksumVerifier.VerifyAsync"/> for
    /// non-SHA-256 specs. SHA-256 short-circuits against the already-known hex from
    /// <see cref="BlobHandle.Sha256Hex"/>.
    /// </summary>
    private static async Task<bool> VerifyChecksumAsync(
        ChecksumSpec spec, string sha256Hex, ProxyFetchRequest request, CancellationToken ct)
    {
        if (spec.Algorithm == ChecksumAlgorithm.Sha256)
        {
            return string.Equals(sha256Hex, spec.ExpectedValue.ToLowerInvariant(), StringComparison.Ordinal);
        }

        // SHA-1 (npm shasum) and SHA-512 (npm SRI / NuGet packageHash) — stream the
        // cached blob through the verifier rather than buffering. The stream comes
        // from BlobHandle, so the cost is one extra GET on remote backends.
        await using var stream = await request.Blob.OpenAsync(ct);
        return await ChecksumVerifier.VerifyAsync(stream, spec, ct);
    }
}

/// <summary>
/// Reference to a blob that's already been written to <see cref="IBlobStore"/> and whose
/// SHA-256 is known. Replaces the byte[]-shaped <c>Bytes</c>/<c>Sha256Hex</c>/<c>SizeBytes</c>
/// triple that ProxyFetchService still threaded through. <see cref="OpenAsync"/>
/// lazily opens a fresh blob-store stream when the consumer actually needs the bytes
/// (license extraction, non-SHA-256 checksum re-verify); cache HITs that only need to
/// stream the response body never call it.
/// </summary>
public sealed record BlobHandle(
    string BlobKey,
    string Sha256Hex,
    long SizeBytes,
    Func<CancellationToken, Task<Stream>> OpenAsync);

/// <summary>Inputs to <see cref="ProxyFetchService.RecordAndScanAsync"/>.</summary>
public sealed record ProxyFetchRequest(
    string OrgId,
    string Ecosystem,
    string PackageName,
    string PurlName,
    string Version,
    string Purl,
    string File,
    BlobHandle Blob,
    /// <summary>
    /// Per-ecosystem licence extractor. Receives a fresh, position-0 stream over the cached
    /// blob; the extractor takes ownership and disposes it. Failure-tolerant: any throw
    /// inside the extractor is swallowed by <see cref="Infrastructure.ProxyVersionRecorder"/>
    /// and the licence row is silently skipped — the first-fetch artefact still serves.
    /// </summary>
    Func<Stream, LicenseExtractor.ExtractedMetadata>? ExtractLicenses,
    string? UserId,
    /// <summary>
    /// Discriminator persisted alongside <see cref="UserId"/> in <c>activity.actor_kind</c>:
    /// <see cref="Infrastructure.ActorKinds.User"/> or <see cref="Infrastructure.ActorKinds.Service"/>
    /// (or NULL for truly-anonymous fetches). Without this, service-token first fetches show
    /// up as "anonymous" in the audit UI — see <see cref="Infrastructure.ProxyVersionRequest.ActorKind"/>.
    /// </summary>
    string? ActorKind,
    string? SourceIp,
    double MaxOsvScoreTolerance,
    /// <summary>
    /// Optional cache-access record. Pass null to skip (e.g. PyPI's pre-known-sha
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
    string? UpstreamIntegrityAlgorithm = null,
    /// <summary>
    /// Upstream deprecation message captured from registry metadata: npm
    /// <c>versions[v].deprecated</c> free-text; PyPI <c>yanked_reason</c> (or
    /// <c>"Yanked"</c> when reason is empty) when <c>yanked: true</c>; NuGet
    /// <c>"Unlisted upstream"</c> when the registration leaf reports
    /// <c>listed: false</c>. Persisted into <c>package_versions.deprecated</c> so
    /// the existing UI badge surfaces it. Null when upstream didn't flag the version.
    /// </summary>
    string? Deprecated = null,
    /// <summary>Tenant policy from <c>org_settings.block_deprecated</c>: 'off' | 'warn' | 'block'.</summary>
    string? BlockDeprecatedMode = null);

/// <summary>Outcome of <see cref="ProxyFetchService.RecordAndScanAsync"/>.</summary>
public sealed record ProxyFetchResult(
    BlockDecision Decision,
    string Sha256,
    string BlobKey,
    string? VersionId);
