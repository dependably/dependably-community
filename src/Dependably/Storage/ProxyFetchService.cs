using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Protocol;
using Dependably.Protocol.Provenance;

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
    private readonly CacheArtifactRepository _cacheArtifacts;
    private readonly TenantArtifactAccessRepository _tenantAccess;
    private readonly VulnerabilityScanService _scanner;
    private readonly BlockGateService _blockGate;
    private readonly PackageRepository _packages;
    private readonly AuditRepository _audit;
    private readonly TimeProvider _time;

    // DI constructor: 9 dependencies are required by the post-fetch pipeline stages (access
    // recording, version recording, artifact repository, tenant access, scan, block gate,
    // package CRUD, audit, and time). No cleaner grouping exists — each dependency serves a
    // distinct pipeline step and splitting the class would scatter the shared sequencing logic.
#pragma warning disable S107 // DI constructor — all 9 dependencies are distinct pipeline stages
    public ProxyFetchService(
        CacheAccessRecorder cacheRecorder,
        ProxyVersionRecorder proxyVersions,
        CacheArtifactRepository cacheArtifacts,
        TenantArtifactAccessRepository tenantAccess,
        VulnerabilityScanService scanner,
        BlockGateService blockGate,
        PackageRepository packages,
        AuditRepository audit,
        TimeProvider time)
#pragma warning restore S107
    {
        _cacheRecorder = cacheRecorder;
        _proxyVersions = proxyVersions;
        _cacheArtifacts = cacheArtifacts;
        _tenantAccess = tenantAccess;
        _scanner = scanner;
        _blockGate = blockGate;
        _packages = packages;
        _audit = audit;
        _time = time;
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
        string sha256 = request.Blob.Sha256Hex;
        string blobKey = request.Blob.BlobKey;
        long sizeBytes = request.Blob.SizeBytes;

        await VerifyChecksumOrThrowAsync(request, sha256, ct);
        var earlyBlock = await EvaluateFirstFetchGatesAsync(request, sha256, blobKey, ct);
        if (earlyBlock is not null)
        {
            return earlyBlock;
        }

        string? cacheArtifactId = await RecordCacheAccessAsync(request, sha256, blobKey, sizeBytes, ct);

        // When cacheArtifactId is non-null (proxy path), RecordAsync writes to the global plane
        // only (no package_versions INSERT) and returns null. When null, RecordAsync inserts a
        // package_versions row and returns its id for the per-version scan / block-gate path.
        string? scanVersionId = await _proxyVersions.RecordAsync(
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
            request.ExtractLicenses, ct, cacheArtifactId);

        // Proxy path: cacheArtifactId is set, RecordAsync returned null. Scan and gate via the
        // global plane.
        if (cacheArtifactId is not null && scanVersionId is null)
        {
            return await ScanAndGateGlobalPlaneAsync(request, sha256, blobKey, cacheArtifactId, ct);
        }

        if (scanVersionId is null)
        {
            // Race recovery in ProxyVersionRecorder returned null (no cacheArtifactId) — the parent
            // package row was deleted between the unique-constraint catch and the lookup. Rare; treat
            // as "served but unrecorded" so the bytes still flow to the client.
            return new ProxyFetchResult(BlockDecision.Allowed, sha256, blobKey, VersionId: null);
        }

        return await ScanAndGateVersionAsync(request, sha256, blobKey, scanVersionId, cacheArtifactId, ct);
    }

    // Fail-fast verification against the upstream-supplied integrity hash (PyPI #sha256=,
    // npm dist.integrity / dist.shasum, NuGet packageHash). The SHA-256 was already verified
    // inline by UpstreamClient.FetchAndStageAsync; for other algorithms we stream the cached
    // blob through ChecksumVerifier. On mismatch audits a checksum_failure event and throws
    // ChecksumException → caller returns 502 Bad Gateway.
    private async Task VerifyChecksumOrThrowAsync(
        ProxyFetchRequest request, string sha256, CancellationToken ct)
    {
        if (request.UpstreamChecksum is not { } spec)
        {
            return;
        }

        if (await VerifyChecksumAsync(spec, sha256, request, ct))
        {
            return;
        }

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

    // Runs the pre-record gates (deprecation + provenance) that must fire BEFORE the version row
    // is written. A blocked result means the version is never adopted into the cache catalogue.
    // Returns a blocked ProxyFetchResult when a gate fires, null when all gates pass.
    private async Task<ProxyFetchResult?> EvaluateFirstFetchGatesAsync(
        ProxyFetchRequest request, string sha256, string blobKey, CancellationToken ct)
    {
        // First-fetch deprecation gate. Runs BEFORE the version row is recorded so a deprecated
        // version is never adopted into the cache catalogue under block_new / block_all: with no
        // version row, the controllers' cache-hit lookup misses and every subsequent request
        // re-enters this fetch path and re-blocks. block_new vs block_all is resolved here — both
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
            {
                return new ProxyFetchResult(BlockDecision.Blocked, sha256, blobKey, VersionId: null);
            }
        }

        // First-fetch provenance gate. Runs BEFORE the version row is recorded so a version that
        // fails signature verification under a block policy is never adopted into the cache
        // catalogue (fail closed). The provenance result was computed by the ecosystem handler;
        // warn/off/NotApplicable proceed and the status is persisted on the recorded row.
        if (request.VerifyProvenanceMode == "block" &&
            request.ProvenanceStatus is ProvenanceStatuses.Failed or ProvenanceStatuses.Unsigned)
        {
            await _blockGate.RecordProvenanceBlockAsync(
                new BlockGateRequest(request.OrgId, request.Ecosystem, request.Purl, string.Empty,
                    null, null,
                    request.UserId, request.MaxOsvScoreTolerance, request.SourceIp,
                    ActorKind: request.ActorKind,
                    ProvenanceStatus: request.ProvenanceStatus,
                    VerifyProvenanceMode: request.VerifyProvenanceMode), ct);
            return new ProxyFetchResult(BlockDecision.Blocked, sha256, blobKey, VersionId: null);
        }

        return null;
    }

    // Records access into cache_artifact + tenant_artifact_access (best-effort: a recorder
    // failure must not fail the proxy fetch). Returns the cache_artifact id when the global
    // plane path is active, null when the caller passed no CacheAccess record.
    //
    // When PreRecordedCacheArtifactId is set, the cache-access recording was already done by
    // the caller (PyPI records it once in FetchAndCacheUpstreamAsync to cover both hit and miss
    // paths). The id is reused directly; UpsertStateAsync still fires to count this download.
    private async Task<string?> RecordCacheAccessAsync(
        ProxyFetchRequest request, string sha256, string blobKey, long sizeBytes, CancellationToken ct)
    {
        if (request.PreRecordedCacheArtifactId is { } preRecordedId)
        {
            // Cache-access was already recorded by the caller; tick the per-tenant download
            // count without writing a second cache_artifact row.
            await _tenantAccess.UpsertStateAsync(request.OrgId, preRecordedId, _time.GetUtcNow(), ct);
            return preRecordedId;
        }

        if (request.CacheAccess is not { } access)
        {
            return null;
        }

        // Name is overridden with request.PurlName (the canonical PURL name) so that
        // cache_artifact.name always equals packages.purl_name — the cross-plane version-count
        // and vuln-count joins depend on this equality. A caller-supplied CacheAccess.Name may
        // carry a raw, non-normalized form (e.g. mixed-case) that would silently break the join.
        string? cacheArtifactId = await _cacheRecorder.RecordAccessAsync(
            access with { Name = request.PurlName, Sha256 = sha256, BlobKey = blobKey, SizeBytes = sizeBytes }, ct);

        // Per-tenant download state on the global plane. Runs before RecordAsync so the
        // download_count is counted even when RecordAsync takes the global-plane path.
        if (cacheArtifactId is not null)
        {
            await _tenantAccess.UpsertStateAsync(request.OrgId, cacheArtifactId, _time.GetUtcNow(), ct);
        }

        return cacheArtifactId;
    }

    // Global-plane scan and block-gate path: cacheArtifactId is set, RecordAsync returned null.
    // Provenance facts are written to cache_artifact; the scan and block-gate use
    // the cache_artifact id rather than a version id.
    private async Task<ProxyFetchResult> ScanAndGateGlobalPlaneAsync(
        ProxyFetchRequest request, string sha256, string blobKey, string cacheArtifactId, CancellationToken ct)
    {
        if (request.ProvenanceStatus is not null)
        {
            await _cacheArtifacts.UpdateGlobalFactsAsync(
                cacheArtifactId,
                purl: null,
                checksumSha1: null,
                publishedAt: null,
                deprecated: null,
                hasInstallScript: false,
                installScriptKind: null,
                provenanceStatus: request.ProvenanceStatus,
                provenanceSigner: request.ProvenanceSigner,
                upstreamIntegrityValue: null,
                upstreamIntegrityAlgorithm: null,
                ct);
        }

        await _scanner.ScanCacheArtifactAsync(request.Purl, cacheArtifactId,
            request.Ecosystem, request.PurlName, ct);

        var caFacts = await _cacheArtifacts.GetByIdForGateAsync(cacheArtifactId, ct);
        var caDecision = await _blockGate.EvaluateAsync(
            new BlockGateRequest(request.OrgId, request.Ecosystem, request.Purl, string.Empty,
                caFacts?.ManualBlockState, caFacts?.VulnCheckedAt,
                request.UserId, request.MaxOsvScoreTolerance, request.SourceIp,
                MinReleaseAgeHours: request.MinReleaseAgeHours,
                PublishedAt: request.PublishedAt,
                ActorKind: request.ActorKind,
                Deprecated: caFacts?.Deprecated,
                BlockDeprecatedMode: request.BlockDeprecatedMode,
                BlockMaliciousMode: request.BlockMaliciousMode,
                BlockKevMode: request.BlockKevMode,
                MaxEpssTolerance: request.MaxEpssTolerance,
                Origin: "proxy",
                HasInstallScript: caFacts?.HasInstallScript ?? false,
                InstallScriptKind: caFacts?.InstallScriptKind,
                BlockInstallScriptsMode: request.BlockInstallScriptsMode,
                ProvenanceStatus: caFacts?.ProvenanceStatus,
                VerifyProvenanceMode: request.VerifyProvenanceMode,
                CacheArtifactId: cacheArtifactId), ct);

        return new ProxyFetchResult(caDecision, sha256, blobKey, VersionId: null);
    }

    // Uploaded-origin scan + block-gate path: scanVersionId is set. Persists provenance to
    // the per-version row (and optionally the global plane), scans, then evaluates the gate.
    private async Task<ProxyFetchResult> ScanAndGateVersionAsync(
        ProxyFetchRequest request, string sha256, string blobKey,
        string scanVersionId, string? cacheArtifactId, CancellationToken ct)
    {
        if (request.ProvenanceStatus is not null)
        {
            await _packages.UpdateProvenanceAsync(
                scanVersionId, request.ProvenanceStatus, request.ProvenanceSigner, ct);

            if (cacheArtifactId is not null)
            {
                await _cacheArtifacts.UpdateGlobalFactsAsync(
                    cacheArtifactId,
                    purl: null,
                    checksumSha1: null,
                    publishedAt: null,
                    deprecated: null,
                    hasInstallScript: false,
                    installScriptKind: null,
                    provenanceStatus: request.ProvenanceStatus,
                    provenanceSigner: request.ProvenanceSigner,
                    upstreamIntegrityValue: null,
                    upstreamIntegrityAlgorithm: null,
                    ct);
            }
        }

        // Synchronous scan so the block gate can act on the very first fetch.
        await _scanner.ScanVersionAsync(request.Purl, scanVersionId, request.Ecosystem,
            request.PurlName, request.OrgId, request.UserId, ct);

        var existing = await _packages.GetVersionByIdAsync(request.OrgId, scanVersionId, ct);
        var decision = await _blockGate.EvaluateAsync(
            new BlockGateRequest(request.OrgId, request.Ecosystem, request.Purl, scanVersionId,
                existing?.ManualBlockState, _time.GetUtcNow(),
                request.UserId, request.MaxOsvScoreTolerance, request.SourceIp,
                MinReleaseAgeHours: request.MinReleaseAgeHours,
                PublishedAt: request.PublishedAt,
                ActorKind: request.ActorKind,
                Deprecated: existing?.Deprecated,
                BlockDeprecatedMode: request.BlockDeprecatedMode,
                BlockMaliciousMode: request.BlockMaliciousMode,
                BlockKevMode: request.BlockKevMode,
                MaxEpssTolerance: request.MaxEpssTolerance,
                Origin: existing?.Origin,
                HasInstallScript: existing?.HasInstallScript ?? false,
                InstallScriptKind: existing?.InstallScriptKind,
                BlockInstallScriptsMode: request.BlockInstallScriptsMode,
                ProvenanceStatus: existing?.ProvenanceStatus,
                VerifyProvenanceMode: request.VerifyProvenanceMode), ct);

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
    /// Optional cache-access record. Pass null to skip recording. The recorder updates
    /// Sha256/BlobKey/SizeBytes from the freshly-computed values regardless of what the
    /// caller seeded them with.
    /// </summary>
    CacheAccess? CacheAccess,
    /// <summary>
    /// Pre-recorded cache_artifact id for ecosystems that record cache-access before calling
    /// <see cref="RecordAndScanAsync"/> (PyPI covers both hit and miss paths in
    /// FetchAndCacheUpstreamAsync). When set, <see cref="RecordCacheAccessAsync"/> skips the
    /// second <see cref="CacheAccessRecorder.RecordAccessAsync"/> call to avoid a duplicate
    /// row, and instead reuses this id for the global-plane dispatch and download-count tick.
    /// Mutually exclusive with <see cref="CacheAccess"/> (set one or the other, never both).
    /// </summary>
    string? PreRecordedCacheArtifactId = null,
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
    string? BlockDeprecatedMode = null,
    /// <summary>
    /// Tenant policy from <c>org_settings.block_malicious</c>: 'off' | 'warn' | 'block'.
    /// Evaluated by <see cref="Protocol.BlockGateService"/> right after the synchronous
    /// first-fetch OSV scan, so a version with a malicious-package advisory is denied on
    /// the very first fetch.
    /// </summary>
    string? BlockMaliciousMode = null,
    /// <summary>Tenant policy from <c>org_settings.block_kev</c>: 'off' | 'warn' | 'block'.</summary>
    string? BlockKevMode = null,
    /// <summary>Tenant ceiling from <c>org_settings.max_epss_tolerance</c> (0.0–1.0); null = off.</summary>
    double? MaxEpssTolerance = null,
    /// <summary>
    /// Tenant policy from <c>org_settings.block_install_scripts</c>: 'off' | 'warn' | 'block'.
    /// Evaluated on the serve path after the install-script signal is persisted at first-fetch,
    /// so a version that ships an install hook is denied once detection has run.
    /// </summary>
    string? BlockInstallScriptsMode = null,
    /// <summary>
    /// Provenance/signature-verification outcome the ecosystem handler computed for this version
    /// before staging: <c>'verified'</c> / <c>'failed'</c> / <c>'unsigned'</c>, or NULL when
    /// verification was not applicable (policy off, no verifier, no pinned keys). Persisted on the
    /// recorded row and fed to the provenance block-gate arm. Under a 'block' policy a
    /// Failed/Unsigned status is refused before the version is recorded (fail closed).
    /// </summary>
    string? ProvenanceStatus = null,
    /// <summary>Verifying trust-anchor keyid when <see cref="ProvenanceStatus"/> is verified; NULL otherwise.</summary>
    string? ProvenanceSigner = null,
    /// <summary>Tenant policy from <c>org_settings.verify_npm_signatures</c>: 'off' | 'warn' | 'block'.</summary>
    string? VerifyProvenanceMode = null);

/// <summary>Outcome of <see cref="ProxyFetchService.RecordAndScanAsync"/>.</summary>
public sealed record ProxyFetchResult(
    BlockDecision Decision,
    string Sha256,
    string BlobKey,
    string? VersionId);
